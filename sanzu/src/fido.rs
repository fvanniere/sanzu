//! FIDO/CTAP HID forwarding without USB device passthrough.
//!
//! The client opens only the FIDO HID interface. It does not detach a kernel
//! driver or claim the whole USB device, so the YubiKey CCID interfaces remain
//! available to GPG/PIV and CTAPHID logical channels can still be used by local
//! applications.

use anyhow::{Context, Result};
use sanzu_common::tunnel;

pub const FIDO_REPORT_SIZE: usize = 64;
const MAX_REPORTS_PER_CYCLE: usize = 64;
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE: u16 = 0x0001;

#[derive(Debug, PartialEq)]
enum FidoSelector<'a> {
    VidPid(u16, u16),
    Text(&'a str),
}

impl<'a> FidoSelector<'a> {
    fn parse(value: &'a str) -> Self {
        let value = value.trim();
        let mut parts = value.split(':');
        if let (Some(vendor), Some(product), None) = (parts.next(), parts.next(), parts.next()) {
            let vendor = vendor
                .strip_prefix("0x")
                .or_else(|| vendor.strip_prefix("0X"))
                .unwrap_or(vendor);
            let product = product
                .strip_prefix("0x")
                .or_else(|| product.strip_prefix("0X"))
                .unwrap_or(product);
            if let (Ok(vendor), Ok(product)) = (
                u16::from_str_radix(vendor, 16),
                u16::from_str_radix(product, 16),
            ) {
                return Self::VidPid(vendor, product);
            }
        }
        Self::Text(value)
    }
}

// Standard unnumbered 64-byte CTAPHID report descriptor from the FIDO CTAP
// USB HID binding (usage page 0xf1d0, usage 0x01).
#[cfg(target_os = "linux")]
const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x20, // Usage (Data In)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x75, 0x08, // Report Size (8)
    0x95, 0x40, // Report Count (64)
    0x81, 0x02, // Input (Data, Variable, Absolute)
    0x09, 0x21, // Usage (Data Out)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x75, 0x08, // Report Size (8)
    0x95, 0x40, // Report Count (64)
    0x91, 0x02, // Output (Data, Variable, Absolute)
    0xc0, // End Collection
];

pub struct FidoClient {
    #[cfg(any(target_os = "linux", windows))]
    device: hidapi::HidDevice,
    info: tunnel::FidoDevice,
}

impl FidoClient {
    pub fn open(requested_path: Option<&str>) -> Result<Self> {
        #[cfg(any(target_os = "linux", windows))]
        {
            let api = hidapi::HidApi::new().context("Cannot enumerate HID devices")?;
            let selector = requested_path.map(FidoSelector::parse);
            let mut matches = api
                .device_list()
                .filter(|device| {
                    device.usage_page() == FIDO_USAGE_PAGE && device.usage() == FIDO_USAGE
                })
                .filter(|device| match selector.as_ref() {
                    None => true,
                    Some(FidoSelector::VidPid(vendor, product)) => {
                        device.vendor_id() == *vendor && device.product_id() == *product
                    }
                    Some(FidoSelector::Text(text)) => {
                        let text = text.to_lowercase();
                        device
                            .path()
                            .to_string_lossy()
                            .to_lowercase()
                            .contains(&text)
                            || device
                                .manufacturer_string()
                                .map(|value| value.to_lowercase().contains(&text))
                                .unwrap_or(false)
                            || device
                                .product_string()
                                .map(|value| value.to_lowercase().contains(&text))
                                .unwrap_or(false)
                            || device
                                .serial_number()
                                .map(|value| value.to_lowercase().contains(&text))
                                .unwrap_or(false)
                    }
                })
                .collect::<Vec<_>>();

            if matches.is_empty() {
                return Err(if let Some(selector) = requested_path {
                    anyhow!("No FIDO HID authenticator matches {selector:?}")
                } else {
                    anyhow!("No FIDO HID authenticator found; check the key and hidraw permissions")
                });
            }

            if requested_path.is_some() && matches.len() > 1 {
                let candidates = matches
                    .iter()
                    .map(|device| {
                        format!(
                            "{} ({:04x}:{:04x}, {})",
                            device.product_string().unwrap_or("FIDO authenticator"),
                            device.vendor_id(),
                            device.product_id(),
                            device.path().to_string_lossy()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(anyhow!(
                    "FIDO selector {selector:?} is ambiguous; candidates: {candidates}",
                    selector = requested_path.unwrap_or_default()
                ));
            }

            if requested_path.is_none() && matches.len() > 1 {
                warn!("Several FIDO authenticators found; forwarding the first one. Use --fido-device to select one");
            }

            let device_info = matches.remove(0);

            let info = tunnel::FidoDevice {
                vendor_id: device_info.vendor_id() as u32,
                product_id: device_info.product_id() as u32,
                product_name: device_info
                    .product_string()
                    .unwrap_or("FIDO authenticator")
                    .chars()
                    .take(80)
                    .collect(),
            };
            let path = device_info.path().to_string_lossy().into_owned();
            let device = device_info
                .open_device(&api)
                .with_context(|| format!("Cannot open FIDO HID device {path}"))?;
            device
                .set_blocking_mode(false)
                .context("Cannot make FIDO HID device non-blocking")?;
            info!(
                "Forwarding FIDO authenticator {:?} ({:04x}:{:04x}) at {}",
                info.product_name, info.vendor_id, info.product_id, path
            );
            return Ok(Self { device, info });
        }

        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = requested_path;
            Err(anyhow!(
                "FIDO forwarding is supported only by Linux and Windows clients"
            ))
        }
    }

    pub fn info(&self) -> tunnel::FidoDevice {
        self.info.clone()
    }

    pub fn poll_reports(&self) -> Result<Vec<Vec<u8>>> {
        #[cfg(any(target_os = "linux", windows))]
        {
            let mut reports = Vec::new();
            for _ in 0..MAX_REPORTS_PER_CYCLE {
                let mut data = [0u8; FIDO_REPORT_SIZE + 1];
                let size = self
                    .device
                    .read_timeout(&mut data, 0)
                    .context("Cannot read FIDO HID report")?;
                if size == 0 {
                    break;
                }
                if size == FIDO_REPORT_SIZE {
                    reports.push(data[..size].to_vec());
                } else if size == FIDO_REPORT_SIZE + 1 && data[0] == 0 {
                    reports.push(data[1..size].to_vec());
                } else {
                    warn!("Ignoring unexpected FIDO HID input report size: {}", size);
                }
            }
            return Ok(reports);
        }

        #[cfg(not(any(target_os = "linux", windows)))]
        Ok(Vec::new())
    }

    pub fn write_reports(&self, reports: Vec<Vec<u8>>) -> Result<()> {
        if reports.len() > MAX_REPORTS_PER_CYCLE {
            return Err(anyhow!("Too many FIDO HID reports in one server packet"));
        }
        for report in reports {
            validate_report(&report)?;
            #[cfg(any(target_os = "linux", windows))]
            {
                // hidapi requires a report-id prefix. CTAPHID uses unnumbered
                // reports, hence the leading zero is not sent on the wire.
                let mut output = Vec::with_capacity(FIDO_REPORT_SIZE + 1);
                output.push(0);
                output.extend_from_slice(&report);
                let written = self
                    .device
                    .write(&output)
                    .context("Cannot write FIDO HID report")?;
                // The native Windows backend reports zero for an immediately
                // completed overlapped write; Linux reports the byte count.
                if written != 0 && written != output.len() {
                    return Err(anyhow!(
                        "Short FIDO HID write: {written}/{} bytes",
                        output.len()
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub struct FidoServer {
    device: uhid_virt::UHIDDevice<std::fs::File>,
}

#[cfg(not(target_os = "linux"))]
pub struct FidoServer;

impl FidoServer {
    pub fn create(info: &tunnel::FidoDevice, virtual_id: Option<&str>) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use uhid_virt::{Bus, CreateParams, UHIDDevice};

            if info.vendor_id > u16::MAX as u32 || info.product_id > u16::MAX as u32 {
                return Err(anyhow!("Invalid FIDO USB vendor/product identifier"));
            }
            let phys = virtual_fido_phys(virtual_id)?;
            let product_name: String = info.product_name.chars().take(80).collect();
            let device = UHIDDevice::create(CreateParams {
                name: format!("Sanzu forwarded {product_name}"),
                phys: phys.clone(),
                uniq: String::new(),
                bus: Bus::USB,
                vendor: info.vendor_id,
                product: info.product_id,
                version: 0,
                country: 0,
                rd_data: FIDO_REPORT_DESCRIPTOR.to_vec(),
            })
            .context("Cannot create /dev/uhid FIDO device")?;
            info!(
                "Created virtual FIDO authenticator {:?} ({:04x}:{:04x}) at {}",
                product_name, info.vendor_id, info.product_id, phys
            );
            return Ok(Self { device });
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (info, virtual_id);
            Err(anyhow!(
                "Virtual FIDO forwarding requires a Linux server with UHID"
            ))
        }
    }

    pub fn poll_reports(&mut self) -> Result<Vec<Vec<u8>>> {
        #[cfg(target_os = "linux")]
        {
            use std::io::ErrorKind;
            use uhid_virt::{OutputEvent, StreamError};

            let mut reports = Vec::new();
            for _ in 0..MAX_REPORTS_PER_CYCLE {
                match self.device.read() {
                    Ok(OutputEvent::Output { data }) => {
                        if data.len() == FIDO_REPORT_SIZE {
                            reports.push(data);
                        } else if data.len() == FIDO_REPORT_SIZE + 1 && data[0] == 0 {
                            reports.push(data[1..].to_vec());
                        } else {
                            warn!(
                                "Ignoring unexpected virtual FIDO output report size: {}",
                                data.len()
                            );
                        }
                    }
                    Ok(OutputEvent::GetReport { id, .. }) => {
                        self.device
                            .write_get_report_reply(id, libc::EIO as u16, Vec::new())
                            .context("Cannot reject virtual FIDO GET_REPORT")?;
                    }
                    Ok(OutputEvent::SetReport { id, .. }) => {
                        self.device
                            .write_set_report_reply(id, libc::EIO as u16)
                            .context("Cannot reject virtual FIDO SET_REPORT")?;
                    }
                    Ok(OutputEvent::Start { .. }) => debug!("Virtual FIDO device started"),
                    Ok(OutputEvent::Open) => debug!("Virtual FIDO device opened"),
                    Ok(OutputEvent::Close) => debug!("Virtual FIDO device closed"),
                    Ok(OutputEvent::Stop) => debug!("Virtual FIDO device stopped"),
                    Err(StreamError::Io(err)) if err.kind() == ErrorKind::WouldBlock => break,
                    Err(StreamError::Io(err)) => {
                        return Err(err).context("Cannot read virtual FIDO device")
                    }
                    Err(StreamError::UnknownEventType(event)) => {
                        return Err(anyhow!("Unknown UHID event type {event}"))
                    }
                }
            }
            return Ok(reports);
        }

        #[cfg(not(target_os = "linux"))]
        Ok(Vec::new())
    }

    pub fn write_reports(&mut self, reports: Vec<Vec<u8>>) -> Result<()> {
        if reports.len() > MAX_REPORTS_PER_CYCLE {
            return Err(anyhow!("Too many FIDO HID reports in one client packet"));
        }
        for report in reports {
            validate_report(&report)?;
            #[cfg(target_os = "linux")]
            self.device
                .write(&report)
                .context("Cannot write virtual FIDO input report")?;
        }
        Ok(())
    }
}

fn virtual_fido_phys(virtual_id: Option<&str>) -> Result<String> {
    let Some(virtual_id) = virtual_id else {
        return Ok("sanzu/fido0".to_owned());
    };
    if virtual_id.is_empty()
        || virtual_id.len() > 64
        || !virtual_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(anyhow!(
            "Invalid FIDO virtual identifier: expected 1 to 64 ASCII letters, digits, '_' or '-'"
        ));
    }
    Ok(format!("sanzu/fido/{virtual_id}"))
}

fn validate_report(report: &[u8]) -> Result<()> {
    if report.len() != FIDO_REPORT_SIZE {
        Err(anyhow!(
            "Invalid FIDO HID report size: {} (expected {FIDO_REPORT_SIZE})",
            report.len()
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_complete_ctaphid_reports() {
        assert!(validate_report(&[0; FIDO_REPORT_SIZE]).is_ok());
        assert!(validate_report(&[0; FIDO_REPORT_SIZE - 1]).is_err());
        assert!(validate_report(&[0; FIDO_REPORT_SIZE + 1]).is_err());
    }

    #[test]
    fn builds_isolated_virtual_fido_paths() {
        assert_eq!(virtual_fido_phys(None).unwrap(), "sanzu/fido0");
        assert_eq!(
            virtual_fido_phys(Some("fred-1")).unwrap(),
            "sanzu/fido/fred-1"
        );
        assert!(virtual_fido_phys(Some("")).is_err());
        assert!(virtual_fido_phys(Some("../fred")).is_err());
        assert!(virtual_fido_phys(Some("fréd")).is_err());
        assert!(virtual_fido_phys(Some(&"a".repeat(65))).is_err());
    }

    #[test]
    fn parses_vid_pid_selectors() {
        assert_eq!(
            FidoSelector::parse("1050:0407"),
            FidoSelector::VidPid(0x1050, 0x0407)
        );
        assert_eq!(
            FidoSelector::parse("0x1050:0x0407"),
            FidoSelector::VidPid(0x1050, 0x0407)
        );
        assert_eq!(
            FidoSelector::parse("YubiKey 5"),
            FidoSelector::Text("YubiKey 5")
        );
    }
}
