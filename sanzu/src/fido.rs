//! FIDO/CTAP HID forwarding without USB device passthrough.
//!
//! The client opens only the FIDO HID interface. It does not detach a kernel
//! driver or claim the whole USB device, so the YubiKey CCID interfaces remain
//! available to GPG/PIV and CTAPHID logical channels can still be used by local
//! applications.

use aes::Aes256;
use anyhow::{Context, Result};
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sanzu_common::tunnel;
use serde_cbor::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    convert::TryInto,
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const FIDO_REPORT_SIZE: usize = 64;
const MAX_REPORTS_PER_CYCLE: usize = 64;
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE: u16 = 0x0001;
const CTAPHID_CBOR: u8 = 0x10;
const CTAPHID_INIT: u8 = 0x06;
const CTAP_GET_INFO: u8 = 0x04;
const CTAP_CLIENT_PIN: u8 = 0x06;
const CTAP_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP_GET_ASSERTION: u8 = 0x02;
const CLIENT_PIN_GET_PIN_RETRIES: u8 = 0x01;
const CLIENT_PIN_GET_KEY_AGREEMENT: u8 = 0x02;
const CLIENT_PIN_GET_PIN_TOKEN: u8 = 0x05;
const CLIENT_PIN_TOKEN_USING_PIN: u8 = 0x06;
const CLIENT_PIN_GET_UV_RETRIES: u8 = 0x07;
const CLIENT_PIN_TOKEN_USING_UV: u8 = 0x09;
// Reported when the authenticator refuses to disclose its own counter; the
// value only sizes the remaining attempts a platform is willing to offer.
const DEFAULT_UV_RETRIES: u8 = 8;
const CTAP2_OK: u8 = 0x00;
const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
const CTAP2_ERR_INVALID_SUBCOMMAND: u8 = 0x3e;
const PIN_PERMISSION_MAKE_CREDENTIAL: u8 = 0x01;
const PIN_PERMISSION_GET_ASSERTION: u8 = 0x02;
const PIN_TOKEN_LIFETIME: Duration = Duration::from_secs(120);
const MAX_CTAPHID_PAYLOAD: usize = 4096;

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
    requests: CtapAssembler,
    responses: CtapAssembler,
    output: VecDeque<Vec<u8>>,
    pending_get_info: HashSet<u32>,
    proxy_secret: SecretKey,
    pin_session: Option<PinSession>,
    /// Forward everything untouched: no GetInfo rewrite, no ClientPIN broker,
    /// no proof translation. The remote session then talks to the raw
    /// authenticator and prompts for the PIN itself, which is what this
    /// forwarding did before the local broker existed. Kept as a diagnostic:
    /// it isolates the broker from the rest of the path in one flag.
    passthrough: bool,
}

impl FidoClient {
    pub fn open(requested_path: Option<&str>, passthrough: bool) -> Result<Self> {
        #[cfg(any(target_os = "linux", windows))]
        {
            let api = hidapi::HidApi::new().context("Cannot enumerate HID devices")?;
            let selector = requested_path.map(FidoSelector::parse);
            debug!("Looking for a FIDO HID interface with selector {selector:?}");
            if log_enabled!(log::Level::Debug) {
                for device in api.device_list() {
                    if device.usage_page() == FIDO_USAGE_PAGE && device.usage() == FIDO_USAGE {
                        debug!(
                            "FIDO HID interface {:04x}:{:04x} manufacturer {:?} product {:?} serial {:?} at {}",
                            device.vendor_id(),
                            device.product_id(),
                            device.manufacturer_string().unwrap_or_default(),
                            device.product_string().unwrap_or_default(),
                            device.serial_number().unwrap_or_default(),
                            device.path().to_string_lossy()
                        );
                    }
                }
            }
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
            debug!("{} FIDO HID interface(s) match the selector", matches.len());

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
                "Forwarding FIDO authenticator {:?} ({:04x}:{:04x}) at {}{}",
                info.product_name,
                info.vendor_id,
                info.product_id,
                path,
                if passthrough {
                    " in passthrough mode: the remote session asks for the PIN"
                } else {
                    ""
                }
            );
            return Ok(Self {
                device,
                info,
                requests: CtapAssembler::default(),
                responses: CtapAssembler::default(),
                output: VecDeque::new(),
                pending_get_info: HashSet::new(),
                proxy_secret: SecretKey::random(&mut OsRng),
                pin_session: None,
                passthrough,
            });
        }

        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = (requested_path, passthrough);
            Err(anyhow!(
                "FIDO forwarding is supported only by Linux and Windows clients"
            ))
        }
    }

    pub fn info(&self) -> tunnel::FidoDevice {
        self.info.clone()
    }

    pub fn poll_reports(&mut self) -> Result<Vec<Vec<u8>>> {
        #[cfg(any(target_os = "linux", windows))]
        {
            self.expire_pin_session();
            for _ in 0..MAX_REPORTS_PER_CYCLE {
                let Some(report) = read_hid_report(&self.device, 0)? else {
                    break;
                };
                trace!("Authenticator report: {}", describe_report(&report, false));
                if let Some(mut message) = self.responses.push(&report)? {
                    debug!(
                        "Authenticator answered {}",
                        describe_message(&message, false)
                    );
                    if message.command == CTAPHID_CBOR && self.pending_get_info.remove(&message.cid)
                    {
                        debug!("Rewriting the GetInfo answer for cid 0x{:08x}", message.cid);
                        advertise_local_pin_broker(&mut message.payload)?;
                        info!("FIDO GetInfo response exposes the local PIN broker");
                    }
                    trace_payload("Authenticator payload", &message.payload, false);
                    self.output.extend(fragment_message(&message)?);
                }
            }
            let reports = self.drain_output();
            if !reports.is_empty() {
                debug!(
                    "Forwarding {} FIDO report(s) to the remote session ({} still queued)",
                    reports.len(),
                    self.output.len()
                );
            }
            return Ok(reports);
        }

        #[cfg(not(any(target_os = "linux", windows)))]
        Ok(Vec::new())
    }

    pub fn write_reports(&mut self, reports: Vec<Vec<u8>>) -> Result<()> {
        if reports.len() > MAX_REPORTS_PER_CYCLE {
            return Err(anyhow!("Too many FIDO HID reports in one server packet"));
        }
        if !reports.is_empty() {
            debug!(
                "Received {} FIDO report(s) from the remote session",
                reports.len()
            );
        }
        for report in reports {
            validate_report(&report)?;
            #[cfg(any(target_os = "linux", windows))]
            {
                trace!("Remote report: {}", describe_report(&report, true));
                if let Some(message) = self.requests.push(&report)? {
                    self.handle_remote_message(message)?;
                }
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    fn handle_remote_message(&mut self, mut message: CtapMessage) -> Result<()> {
        debug!("Remote session sent {}", describe_message(&message, true));
        if self.passthrough {
            debug!("Passthrough mode: forwarding to the authenticator untouched");
            return self.write_message(&message);
        }
        if message.command != CTAPHID_CBOR || message.payload.is_empty() {
            debug!("Forwarding the message to the authenticator untouched");
            return self.write_message(&message);
        }

        match message.payload[0] {
            CTAP_GET_INFO => {
                info!("FIDO request: GetInfo");
                self.pending_get_info.insert(message.cid);
                self.write_message(&message)
            }
            CTAP_CLIENT_PIN => {
                match decode_map(&message.payload[1..]) {
                    Ok(map) => {
                        if let Ok(subcommand) = map_u8(&map, 2) {
                            info!(
                                "FIDO request: ClientPIN {} (0x{subcommand:02x})",
                                client_pin_subcommand_name(subcommand)
                            );
                        }
                        debug!(
                            "ClientPIN request: protocol {:?}, CBOR keys {:?}",
                            map_u8(&map, 1).ok(),
                            cbor_integer_keys(&map)
                        );
                    }
                    Err(err) => debug!("ClientPIN request is not a decodable CBOR map: {err:#}"),
                }
                let response = match self.handle_client_pin(message.cid, &message.payload[1..]) {
                    Ok(response) => response,
                    Err(err) => {
                        warn!("Local FIDO PIN broker denied a request: {err:#}");
                        ctap_error(CTAP2_ERR_OPERATION_DENIED)
                    }
                };
                let status = response.first().copied().unwrap_or(0xff);
                debug!(
                    "Local PIN broker answers with CTAP status 0x{status:02x} ({}), {} byte(s)",
                    ctap_status_name(status),
                    response.len()
                );
                self.queue_cbor_response(message.cid, response)
            }
            CTAP_MAKE_CREDENTIAL | CTAP_GET_ASSERTION => {
                let operation = if message.payload[0] == CTAP_MAKE_CREDENTIAL {
                    "MakeCredential"
                } else {
                    "GetAssertion"
                };
                info!("FIDO request: {operation}");
                match self.translate_pin_proof(&mut message.payload) {
                    Ok(()) => {
                        debug!(
                            "Forwarding {operation} to the authenticator ({} byte payload)",
                            message.payload.len()
                        );
                        self.write_message(&message)
                    }
                    Err(err) => {
                        warn!("Rejected a remote FIDO proof: {err:#}");
                        self.queue_cbor_response(
                            message.cid,
                            ctap_error(CTAP2_ERR_PIN_AUTH_INVALID),
                        )
                    }
                }
            }
            other => {
                debug!(
                    "Forwarding CTAP command {} (0x{other:02x}) to the authenticator untouched",
                    ctap_command_name(other)
                );
                self.write_message(&message)
            }
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    fn handle_client_pin(&mut self, cid: u32, cbor: &[u8]) -> Result<Vec<u8>> {
        let map = decode_map(cbor).context("Invalid ClientPIN request")?;
        require_protocol_one(&map)?;
        let subcommand = map_u8(&map, 2)?;
        let action = client_pin_action(subcommand);
        debug!(
            "Local PIN broker handles {} (0x{subcommand:02x}) as {action:?}",
            client_pin_subcommand_name(subcommand)
        );
        match action {
            ClientPinAction::KeyAgreement => {
                debug!("Publishing the broker P-256 public key to the remote session");
                let key = cose_public_key(&self.proxy_secret.public_key());
                Ok(ctap_success(map_of([(1, key)]))?)
            }
            ClientPinAction::PinRetries => self.pin_retries(cid),
            ClientPinAction::UvRetries => self.uv_retries(cid),
            ClientPinAction::IssueToken => self.issue_proxy_token(cid, &map),
            ClientPinAction::Unsupported => {
                warn!("Unsupported remote FIDO ClientPIN subcommand 0x{subcommand:02x}");
                Ok(ctap_error(CTAP2_ERR_INVALID_SUBCOMMAND))
            }
        }
    }

    /// Relayed verbatim: the authenticator is the only thing that knows how
    /// many attempts are left, and the answer carries no secret.
    #[cfg(any(target_os = "linux", windows))]
    fn pin_retries(&mut self, cid: u32) -> Result<Vec<u8>> {
        let request = encode_client_pin(map_of([
            (1, Value::Integer(1)),
            (2, Value::Integer(CLIENT_PIN_GET_PIN_RETRIES as i128)),
        ]))?;
        let response = self.physical_transact(cid, request)?;
        match successful_map(&response, "PIN retries").and_then(|map| map_u8(&map, 3)) {
            Ok(retries) => debug!("The authenticator reports {retries} PIN attempt(s) left"),
            Err(err) => debug!("Relaying an unreadable PIN retry answer: {err:#}"),
        }
        Ok(response)
    }

    #[cfg(any(target_os = "linux", windows))]
    fn uv_retries(&mut self, cid: u32) -> Result<Vec<u8>> {
        let retries = match self.physical_pin_retries(cid) {
            Ok(retries) => retries,
            Err(err) => {
                debug!("Cannot read the authenticator retry counter: {err:#}");
                DEFAULT_UV_RETRIES
            }
        };
        debug!("Answering the UV retry counter with {retries} attempt(s) left");
        Ok(ctap_success(map_of([(5, Value::Integer(retries as i128))]))?)
    }

    #[cfg(any(target_os = "linux", windows))]
    fn physical_pin_retries(&mut self, cid: u32) -> Result<u8> {
        let request = encode_client_pin(map_of([
            (1, Value::Integer(1)),
            (2, Value::Integer(CLIENT_PIN_GET_PIN_RETRIES as i128)),
        ]))?;
        let response = self.physical_transact(cid, request)?;
        let map = successful_map(&response, "physical PIN retries")?;
        map_u8(&map, 3)
    }

    #[cfg(any(target_os = "linux", windows))]
    fn issue_proxy_token(&mut self, cid: u32, request: &BTreeMap<Value, Value>) -> Result<Vec<u8>> {
        let permissions = map_u8(request, 9)?;
        if permissions == 0
            || permissions & !(PIN_PERMISSION_MAKE_CREDENTIAL | PIN_PERMISSION_GET_ASSERTION) != 0
        {
            return Err(anyhow!("Unsupported ClientPIN permission set"));
        }
        let rp_id = map_text(request, 10)?.to_owned();
        debug!("Remote session asks for a token on {rp_id:?} with permissions 0x{permissions:02x}");
        let remote_key = parse_cose_public(map_value(request, 3)?)?;
        let remote_secret = shared_secret(&self.proxy_secret, &remote_key);

        let physical_token = self.obtain_physical_pin_token(cid)?;
        debug!(
            "Binding a fresh proxy token to {rp_id:?} for {} s",
            PIN_TOKEN_LIFETIME.as_secs()
        );
        let mut proxy_token = Zeroizing::new(vec![0u8; 32]);
        OsRng.fill_bytes(&mut proxy_token);
        let encrypted = aes_cbc_encrypt(&remote_secret[..], &proxy_token)?;
        self.pin_session = Some(PinSession {
            proxy_token,
            physical_token,
            permissions,
            rp_id,
            expires_at: Instant::now() + PIN_TOKEN_LIFETIME,
        });
        info!("FIDO local PIN broker issued a scoped proxy token");
        Ok(ctap_success(map_of([(2, Value::Bytes(encrypted))]))?)
    }

    #[cfg(any(target_os = "linux", windows))]
    fn obtain_physical_pin_token(&mut self, cid: u32) -> Result<Zeroizing<Vec<u8>>> {
        for attempt in 1..=3 {
            info!("FIDO local PIN broker is opening pinentry on the client");
            debug!("Local PIN prompt, attempt {attempt} of 3");
            // `pin` is a Zeroizing<String> that is never formatted, logged or
            // derived into anything that is: only its SHA-256 prefix, encrypted
            // under the session key, leaves this function.
            let pin = prompt_for_pin()?;
            debug!("pinentry returned a PIN; the value itself is never logged");
            let physical_secret = SecretKey::random(&mut OsRng);
            let agreement_request = encode_client_pin(map_of([
                (1, Value::Integer(1)),
                (2, Value::Integer(CLIENT_PIN_GET_KEY_AGREEMENT as i128)),
            ]))?;
            let agreement_response = self.physical_transact(cid, agreement_request)?;
            let agreement = successful_map(&agreement_response, "physical key agreement")?;
            let authenticator_key = parse_cose_public(map_value(&agreement, 1)?)?;
            let secret = shared_secret(&physical_secret, &authenticator_key);

            let digest = Sha256::digest(pin.as_bytes());
            let pin_hash_enc = aes_cbc_encrypt(&secret[..], &digest[..16])?;
            let token_request = encode_client_pin(map_of([
                (1, Value::Integer(1)),
                (2, Value::Integer(CLIENT_PIN_GET_PIN_TOKEN as i128)),
                (3, cose_public_key(&physical_secret.public_key())),
                (6, Value::Bytes(pin_hash_enc)),
            ]))?;
            let token_response = self.physical_transact(cid, token_request)?;
            if token_response.first() == Some(&CTAP2_ERR_PIN_INVALID) {
                debug!("The authenticator rejected the PIN on attempt {attempt} of 3");
                continue;
            }
            let token_map = successful_map(&token_response, "physical PIN token")?;
            let encrypted = map_bytes(&token_map, 2)?;
            info!("FIDO authenticator accepted the locally entered PIN");
            return Ok(Zeroizing::new(aes_cbc_decrypt(&secret[..], encrypted)?));
        }
        Err(anyhow!("The authenticator rejected the PIN"))
    }

    #[cfg(any(target_os = "linux", windows))]
    fn translate_pin_proof(&mut self, payload: &mut Vec<u8>) -> Result<()> {
        let command = payload[0];
        let mut map = decode_map(&payload[1..])?;
        let auth_key = match command {
            CTAP_MAKE_CREDENTIAL => 8,
            CTAP_GET_ASSERTION => 6,
            _ => return Err(anyhow!("Unsupported PIN-authenticated command")),
        };
        // UV-discouraged and otherwise unprotected WebAuthn operations do not
        // carry pinUvAuthParam. They remain ordinary CTAP forwarding and must
        // not require a broker session.
        if !map.contains_key(&Value::Integer(auth_key)) {
            debug!(
                "{} carries no pinUvAuthParam; forwarding it without a broker session",
                ctap_command_name(command)
            );
            return Ok(());
        }
        self.expire_pin_session();
        let session = self
            .pin_session
            .as_ref()
            .ok_or_else(|| anyhow!("No active local PIN session"))?;
        let consumes_token = command == CTAP_MAKE_CREDENTIAL
            || (command == CTAP_GET_ASSERTION && get_assertion_tests_presence(&map)?);
        let (permission, hash_key, protocol_key, rp_id) = match command {
            CTAP_MAKE_CREDENTIAL => (
                PIN_PERMISSION_MAKE_CREDENTIAL,
                1,
                9,
                make_credential_rp_id(&map)?,
            ),
            CTAP_GET_ASSERTION => (
                PIN_PERMISSION_GET_ASSERTION,
                2,
                7,
                map_text(&map, 1)?.to_owned(),
            ),
            _ => return Err(anyhow!("Unsupported PIN-authenticated command")),
        };
        debug!(
            "Translating a {} proof for {rp_id:?} (session {:?}, permissions 0x{:02x}, token {})",
            ctap_command_name(command),
            session.rp_id,
            session.permissions,
            if consumes_token {
                "consumed"
            } else {
                "kept for silent assertions"
            }
        );
        if session.permissions & permission == 0 || session.rp_id != rp_id {
            return Err(anyhow!("PIN token permission or relying party mismatch"));
        }
        if map_u8(&map, protocol_key)? != 1 {
            return Err(anyhow!("Only PIN/UV protocol 1 is supported"));
        }
        let client_data_hash = map_bytes(&map, hash_key)?;
        let supplied = map_bytes(&map, auth_key)?;
        verify_hmac(&session.proxy_token, client_data_hash, supplied)?;
        let translated = hmac_16(&session.physical_token, client_data_hash)?;
        map.insert(Value::Integer(auth_key), Value::Bytes(translated));
        payload.truncate(1);
        payload.extend(serde_cbor::to_vec(&Value::Map(map))?);
        if consumes_token {
            // CTAP clears mc/ga permissions after an operation that tests user
            // presence. Silent up=false assertions used by Firefox for
            // credential filtering may reuse the token for the same RP.
            self.pin_session = None;
        }
        info!("FIDO PIN/UV proof translated on the client");
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    fn physical_transact(&mut self, cid: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        let sensitive = payload.first() == Some(&CTAP_CLIENT_PIN);
        if let Some(subcommand) = payload
            .get(1..)
            .and_then(|cbor| decode_map(cbor).ok())
            .and_then(|map| map_u8(&map, 2).ok())
        {
            debug!(
                "Broker to authenticator: ClientPIN {} (0x{subcommand:02x}) on cid 0x{cid:08x}",
                client_pin_subcommand_name(subcommand)
            );
        }
        trace_payload("Broker request", &payload, sensitive);
        let started_at = Instant::now();
        self.write_message(&CtapMessage {
            cid,
            command: CTAPHID_CBOR,
            payload,
        })?;
        let deadline = started_at + Duration::from_secs(10);
        while Instant::now() < deadline {
            let Some(report) = read_hid_report(&self.device, 100)? else {
                continue;
            };
            if let Some(message) = self.responses.push(&report)? {
                if message.cid == cid && message.command == CTAPHID_CBOR {
                    let status = message.payload.first().copied().unwrap_or(0xff);
                    debug!(
                        "Authenticator answered the broker with CTAP status 0x{status:02x} ({}) in {} ms",
                        ctap_status_name(status),
                        started_at.elapsed().as_millis()
                    );
                    trace_payload("Broker answer", &message.payload, sensitive);
                    return Ok(message.payload);
                }
                debug!(
                    "Queuing an unrelated answer while the broker waits: {}",
                    describe_message(&message, false)
                );
                self.output.extend(fragment_message(&message)?);
            }
        }
        debug!(
            "No broker answer on cid 0x{cid:08x} after {} ms",
            started_at.elapsed().as_millis()
        );
        Err(anyhow!(
            "Timed out while talking to the local authenticator"
        ))
    }

    #[cfg(any(target_os = "linux", windows))]
    fn write_message(&self, message: &CtapMessage) -> Result<()> {
        for report in fragment_message(message)? {
            write_hid_report(&self.device, &report)?;
        }
        Ok(())
    }

    fn queue_cbor_response(&mut self, cid: u32, payload: Vec<u8>) -> Result<()> {
        self.output.extend(fragment_message(&CtapMessage {
            cid,
            command: CTAPHID_CBOR,
            payload,
        })?);
        Ok(())
    }

    fn drain_output(&mut self) -> Vec<Vec<u8>> {
        let count = self.output.len().min(MAX_REPORTS_PER_CYCLE);
        self.output.drain(..count).collect()
    }

    fn expire_pin_session(&mut self) {
        if self
            .pin_session
            .as_ref()
            .is_some_and(|session| session.expires_at <= Instant::now())
        {
            debug!("The local FIDO PIN session expired; dropping the proxy token");
            self.pin_session = None;
        }
    }
}

struct PinSession {
    proxy_token: Zeroizing<Vec<u8>>,
    physical_token: Zeroizing<Vec<u8>>,
    permissions: u8,
    rp_id: String,
    expires_at: Instant,
}

#[derive(Clone, Debug, PartialEq)]
struct CtapMessage {
    cid: u32,
    command: u8,
    payload: Vec<u8>,
}

#[derive(Default)]
struct CtapAssembler {
    pending: HashMap<u32, PartialCtapMessage>,
}

struct PartialCtapMessage {
    command: u8,
    expected: usize,
    next_sequence: u8,
    payload: Vec<u8>,
}

impl CtapAssembler {
    fn push(&mut self, report: &[u8]) -> Result<Option<CtapMessage>> {
        validate_report(report)?;
        let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
        if report[4] & 0x80 != 0 {
            let command = report[4] & 0x7f;
            let expected = u16::from_be_bytes([report[5], report[6]]) as usize;
            if expected > MAX_CTAPHID_PAYLOAD {
                return Err(anyhow!("CTAPHID payload is too large"));
            }
            let copied = expected.min(57);
            let payload = report[7..7 + copied].to_vec();
            self.pending.remove(&cid);
            if copied == expected {
                return Ok(Some(CtapMessage {
                    cid,
                    command,
                    payload,
                }));
            }
            self.pending.insert(
                cid,
                PartialCtapMessage {
                    command,
                    expected,
                    next_sequence: 0,
                    payload,
                },
            );
            Ok(None)
        } else {
            let partial = self
                .pending
                .get_mut(&cid)
                .ok_or_else(|| anyhow!("Unexpected CTAPHID continuation report"))?;
            if report[4] != partial.next_sequence {
                self.pending.remove(&cid);
                return Err(anyhow!("Out-of-order CTAPHID continuation report"));
            }
            partial.next_sequence = partial.next_sequence.wrapping_add(1);
            let copied = (partial.expected - partial.payload.len()).min(59);
            partial.payload.extend_from_slice(&report[5..5 + copied]);
            if partial.payload.len() == partial.expected {
                let partial = self.pending.remove(&cid).unwrap();
                Ok(Some(CtapMessage {
                    cid,
                    command: partial.command,
                    payload: partial.payload,
                }))
            } else {
                Ok(None)
            }
        }
    }
}

fn fragment_message(message: &CtapMessage) -> Result<Vec<Vec<u8>>> {
    if message.payload.len() > MAX_CTAPHID_PAYLOAD || message.payload.len() > u16::MAX as usize {
        return Err(anyhow!("CTAPHID payload is too large"));
    }
    let mut reports = Vec::new();
    let mut first = vec![0u8; FIDO_REPORT_SIZE];
    first[..4].copy_from_slice(&message.cid.to_be_bytes());
    first[4] = message.command | 0x80;
    first[5..7].copy_from_slice(&(message.payload.len() as u16).to_be_bytes());
    let copied = message.payload.len().min(57);
    first[7..7 + copied].copy_from_slice(&message.payload[..copied]);
    reports.push(first);
    let mut offset = copied;
    let mut sequence = 0u8;
    while offset < message.payload.len() {
        if sequence > 0x7f {
            return Err(anyhow!("Too many CTAPHID continuation reports"));
        }
        let mut report = vec![0u8; FIDO_REPORT_SIZE];
        report[..4].copy_from_slice(&message.cid.to_be_bytes());
        report[4] = sequence;
        let copied = (message.payload.len() - offset).min(59);
        report[5..5 + copied].copy_from_slice(&message.payload[offset..offset + copied]);
        reports.push(report);
        offset += copied;
        sequence = sequence.wrapping_add(1);
    }
    Ok(reports)
}

#[cfg(any(target_os = "linux", windows))]
fn read_hid_report(device: &hidapi::HidDevice, timeout_ms: i32) -> Result<Option<Vec<u8>>> {
    let mut data = [0u8; FIDO_REPORT_SIZE + 1];
    let size = device
        .read_timeout(&mut data, timeout_ms)
        .context("Cannot read FIDO HID report")?;
    match (size, data[0]) {
        (0, _) => Ok(None),
        (FIDO_REPORT_SIZE, _) => Ok(Some(data[..size].to_vec())),
        (size, 0) if size == FIDO_REPORT_SIZE + 1 => Ok(Some(data[1..size].to_vec())),
        _ => Err(anyhow!("Unexpected FIDO HID input report size: {size}")),
    }
}

#[cfg(any(target_os = "linux", windows))]
fn write_hid_report(device: &hidapi::HidDevice, report: &[u8]) -> Result<()> {
    validate_report(report)?;
    let mut output = Vec::with_capacity(FIDO_REPORT_SIZE + 1);
    output.push(0);
    output.extend_from_slice(report);
    let written = device
        .write(&output)
        .context("Cannot write FIDO HID report")?;
    if written != 0 && written != output.len() {
        return Err(anyhow!(
            "Short FIDO HID write: {written}/{} bytes",
            output.len()
        ));
    }
    Ok(())
}

/// Human-readable CTAPHID transport command, for the RUST_LOG=debug traces.
#[cfg(any(target_os = "linux", windows))]
fn ctaphid_command_name(command: u8) -> &'static str {
    match command {
        0x03 => "MSG",
        0x08 => "WINK",
        0x0c => "LOCK",
        CTAPHID_INIT => "INIT",
        CTAPHID_CBOR => "CBOR",
        0x11 => "KEEPALIVE",
        0x3b => "PING",
        0x3e => "CANCEL",
        0x3f => "ERROR",
        _ => "vendor/unknown",
    }
}

#[cfg(any(target_os = "linux", windows))]
fn ctap_command_name(command: u8) -> &'static str {
    match command {
        CTAP_MAKE_CREDENTIAL => "MakeCredential",
        CTAP_GET_ASSERTION => "GetAssertion",
        CTAP_GET_INFO => "GetInfo",
        CTAP_CLIENT_PIN => "ClientPIN",
        0x07 => "Reset",
        0x08 => "GetNextAssertion",
        0x09 => "BioEnrollment",
        0x0a => "CredentialManagement",
        0x0b => "Selection",
        0x0c => "LargeBlobs",
        0x0d => "Config",
        _ => "unknown",
    }
}

/// The CTAP status codes a forwarded session realistically runs into. An
/// authenticator refusing a command it does not implement answers
/// CTAP1_ERR_INVALID_COMMAND, which is the signature of a platform using a
/// feature the physical key does not have.
#[cfg(any(target_os = "linux", windows))]
fn ctap_status_name(status: u8) -> &'static str {
    match status {
        CTAP2_OK => "OK",
        0x01 => "CTAP1_ERR_INVALID_COMMAND",
        0x02 => "CTAP1_ERR_INVALID_PARAMETER",
        0x03 => "CTAP1_ERR_INVALID_LENGTH",
        0x04 => "CTAP1_ERR_INVALID_SEQ",
        0x05 => "CTAP1_ERR_TIMEOUT",
        0x06 => "CTAP1_ERR_CHANNEL_BUSY",
        0x0a => "CTAP1_ERR_LOCK_REQUIRED",
        0x0b => "CTAP1_ERR_INVALID_CHANNEL",
        0x11 => "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
        0x12 => "CTAP2_ERR_INVALID_CBOR",
        0x14 => "CTAP2_ERR_MISSING_PARAMETER",
        0x15 => "CTAP2_ERR_LIMIT_EXCEEDED",
        0x19 => "CTAP2_ERR_CREDENTIAL_EXCLUDED",
        0x21 => "CTAP2_ERR_PROCESSING",
        0x22 => "CTAP2_ERR_INVALID_CREDENTIAL",
        0x23 => "CTAP2_ERR_USER_ACTION_PENDING",
        0x24 => "CTAP2_ERR_OPERATION_PENDING",
        0x25 => "CTAP2_ERR_NO_OPERATIONS",
        0x26 => "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
        CTAP2_ERR_OPERATION_DENIED => "CTAP2_ERR_OPERATION_DENIED",
        0x28 => "CTAP2_ERR_KEY_STORE_FULL",
        0x2b => "CTAP2_ERR_UNSUPPORTED_OPTION",
        0x2c => "CTAP2_ERR_INVALID_OPTION",
        0x2d => "CTAP2_ERR_KEEPALIVE_CANCEL",
        0x2e => "CTAP2_ERR_NO_CREDENTIALS",
        0x2f => "CTAP2_ERR_USER_ACTION_TIMEOUT",
        0x30 => "CTAP2_ERR_NOT_ALLOWED",
        CTAP2_ERR_PIN_INVALID => "CTAP2_ERR_PIN_INVALID",
        0x32 => "CTAP2_ERR_PIN_BLOCKED",
        CTAP2_ERR_PIN_AUTH_INVALID => "CTAP2_ERR_PIN_AUTH_INVALID",
        0x34 => "CTAP2_ERR_PIN_AUTH_BLOCKED",
        0x35 => "CTAP2_ERR_PIN_NOT_SET",
        0x36 => "CTAP2_ERR_PUAT_REQUIRED",
        0x37 => "CTAP2_ERR_PIN_POLICY_VIOLATION",
        0x39 => "CTAP2_ERR_REQUEST_TOO_LARGE",
        0x3a => "CTAP2_ERR_ACTION_TIMEOUT",
        0x3b => "CTAP2_ERR_UP_REQUIRED",
        0x3c => "CTAP2_ERR_UV_BLOCKED",
        0x3d => "CTAP2_ERR_INTEGRITY_FAILURE",
        CTAP2_ERR_INVALID_SUBCOMMAND => "CTAP2_ERR_INVALID_SUBCOMMAND",
        0x3f => "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
        0x7f => "CTAP1_ERR_OTHER",
        _ => "unknown",
    }
}

#[cfg(any(target_os = "linux", windows))]
fn client_pin_subcommand_name(subcommand: u8) -> &'static str {
    match subcommand {
        CLIENT_PIN_GET_PIN_RETRIES => "getPINRetries",
        CLIENT_PIN_GET_KEY_AGREEMENT => "getKeyAgreement",
        0x03 => "setPIN",
        0x04 => "changePIN",
        CLIENT_PIN_GET_PIN_TOKEN => "getPinToken",
        CLIENT_PIN_TOKEN_USING_PIN => "getPinUvAuthTokenUsingPinWithPermissions",
        CLIENT_PIN_GET_UV_RETRIES => "getUVRetries",
        CLIENT_PIN_TOKEN_USING_UV => "getPinUvAuthTokenUsingUvWithPermissions",
        _ => "unknown",
    }
}

/// CTAPHID_INIT carries the platform's 8-byte nonce, echoed by the
/// authenticator along with the channel it allocates. A platform that keeps
/// re-issuing INIT without moving on to CBOR is rejecting these answers, and
/// a nonce that does not come back unchanged is the usual reason -- so the
/// nonce and the allocated channel are the two things worth printing. Neither
/// is a secret: both travel in clear on the USB wire.
#[cfg(any(target_os = "linux", windows))]
fn describe_init(payload: &[u8], is_request: bool) -> Option<String> {
    if is_request && payload.len() == 8 {
        return Some(format!("nonce {}", hex(payload)));
    }
    if !is_request && payload.len() >= 17 {
        return Some(format!(
            "nonce {}, allocated cid 0x{:08x}, CTAPHID {}, device {}.{}.{}, caps 0x{:02x}",
            hex(&payload[..8]),
            u32::from_be_bytes(payload[8..12].try_into().unwrap()),
            payload[12],
            payload[13],
            payload[14],
            payload[15],
            payload[16]
        ));
    }
    None
}

/// One-line summary of an assembled CTAPHID message. `is_request` tells apart a
/// CBOR command byte from a CBOR status byte, which share the first payload
/// position in the two directions.
#[cfg(any(target_os = "linux", windows))]
fn describe_message(message: &CtapMessage, is_request: bool) -> String {
    let mut description = format!(
        "cid 0x{:08x} {} ({} byte payload)",
        message.cid,
        ctaphid_command_name(message.command),
        message.payload.len()
    );
    if message.command == CTAPHID_CBOR {
        match (is_request, message.payload.first()) {
            (true, Some(&command)) => description.push_str(&format!(
                ", {} (0x{command:02x})",
                ctap_command_name(command)
            )),
            (false, Some(&status)) => description.push_str(&format!(
                ", status 0x{status:02x} ({})",
                ctap_status_name(status)
            )),
            (_, None) => {}
        }
    } else if message.command == CTAPHID_INIT {
        if let Some(init) = describe_init(&message.payload, is_request) {
            description.push_str(&format!(", {init}"));
        }
    }
    description
}

/// Same summary from a single 64-byte report, without reassembling anything.
/// Used where no assembler state is available, on the virtual device side.
#[cfg(any(target_os = "linux", windows))]
fn describe_report(report: &[u8], is_request: bool) -> String {
    if report.len() != FIDO_REPORT_SIZE {
        return format!("malformed report of {} byte(s)", report.len());
    }
    let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
    if report[4] & 0x80 == 0 {
        return format!("cid 0x{cid:08x} continuation, sequence {}", report[4]);
    }
    let command = report[4] & 0x7f;
    let length = u16::from_be_bytes([report[5], report[6]]);
    let mut description = format!(
        "cid 0x{cid:08x} {} init ({length} byte payload)",
        ctaphid_command_name(command)
    );
    if command == CTAPHID_CBOR && length > 0 {
        let first = report[7];
        if is_request {
            description.push_str(&format!(", {} (0x{first:02x})", ctap_command_name(first)));
        } else {
            description.push_str(&format!(
                ", status 0x{first:02x} ({})",
                ctap_status_name(first)
            ));
        }
    } else if command == CTAPHID_INIT {
        // An INIT payload never spans more than this first report.
        let length = (length as usize).min(FIDO_REPORT_SIZE - 7);
        if let Some(init) = describe_init(&report[7..7 + length], is_request) {
            description.push_str(&format!(", {init}"));
        }
    }
    description
}

#[cfg(any(target_os = "linux", windows))]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Trace-level payload dump. `redact` is set for every PIN protocol exchange:
/// those payloads only ever carry ciphertext, but nothing on a PIN code path is
/// written to the log. The PIN itself never leaves pinentry and
/// `obtain_physical_pin_token`, and no logging path can reach it.
#[cfg(any(target_os = "linux", windows))]
fn trace_payload(label: &str, payload: &[u8], redact: bool) {
    if !log_enabled!(log::Level::Trace) {
        return;
    }
    if redact {
        trace!("{label}: {} byte(s) withheld (PIN protocol)", payload.len());
    } else {
        trace!("{label}: {}", hex(payload));
    }
}

#[cfg(any(target_os = "linux", windows))]
fn cbor_integer_keys(map: &BTreeMap<Value, Value>) -> Vec<i128> {
    map.keys()
        .filter_map(|key| match key {
            Value::Integer(key) => Some(*key),
            _ => None,
        })
        .collect()
}

fn decode_map(bytes: &[u8]) -> Result<BTreeMap<Value, Value>> {
    match serde_cbor::from_slice(bytes)? {
        Value::Map(map) => Ok(map),
        _ => Err(anyhow!("Expected a CBOR map")),
    }
}

fn map_of<const N: usize>(entries: [(i128, Value); N]) -> BTreeMap<Value, Value> {
    entries
        .iter()
        .map(|(key, value)| (Value::Integer(*key), value.clone()))
        .collect()
}

fn map_value(map: &BTreeMap<Value, Value>, key: i128) -> Result<&Value> {
    map.get(&Value::Integer(key))
        .ok_or_else(|| anyhow!("Missing CBOR map key {key}"))
}

fn map_u8(map: &BTreeMap<Value, Value>, key: i128) -> Result<u8> {
    match map_value(map, key)? {
        Value::Integer(value) if (0..=u8::MAX as i128).contains(value) => Ok(*value as u8),
        Value::Integer(_) => Err(anyhow!("CBOR map key {key} is not an unsigned byte")),
        _ => Err(anyhow!("CBOR map key {key} is not an integer")),
    }
}

fn map_bytes(map: &BTreeMap<Value, Value>, key: i128) -> Result<&[u8]> {
    match map_value(map, key)? {
        Value::Bytes(value) => Ok(value),
        _ => Err(anyhow!("CBOR map key {key} is not a byte string")),
    }
}

fn map_text(map: &BTreeMap<Value, Value>, key: i128) -> Result<&str> {
    match map_value(map, key)? {
        Value::Text(value) => Ok(value),
        _ => Err(anyhow!("CBOR map key {key} is not text")),
    }
}

#[derive(Debug, PartialEq)]
enum ClientPinAction {
    KeyAgreement,
    PinRetries,
    UvRetries,
    IssueToken,
    Unsupported,
}

/// Which ClientPIN subcommands the local broker answers, given the GetInfo it
/// advertises. Hiding `clientPin` while offering `uv` and `pinUvAuthToken`
/// makes a CTAP 2.1 platform verify through the built-in method, so the token
/// request arrives as `getPinUvAuthTokenUsingUvWithPermissions` and is preceded
/// by a read of the retry counter. Anything that would write to the
/// authenticator, `setPIN` and `changePIN` above all, stays out of reach of the
/// remote session.
fn client_pin_action(subcommand: u8) -> ClientPinAction {
    match subcommand {
        CLIENT_PIN_GET_KEY_AGREEMENT => ClientPinAction::KeyAgreement,
        // Both counters are read-only and disclose nothing about the PIN, and
        // platforms read them before offering to verify. Refusing them makes
        // the authenticator look broken and the operation is abandoned.
        CLIENT_PIN_GET_PIN_RETRIES => ClientPinAction::PinRetries,
        CLIENT_PIN_GET_UV_RETRIES => ClientPinAction::UvRetries,
        // The PIN variant only arrives from clients that ignore the missing
        // clientPin option; both are answered by the local PIN prompt.
        CLIENT_PIN_TOKEN_USING_UV | CLIENT_PIN_TOKEN_USING_PIN => ClientPinAction::IssueToken,
        _ => ClientPinAction::Unsupported,
    }
}

fn require_protocol_one(map: &BTreeMap<Value, Value>) -> Result<()> {
    if map_u8(map, 1)? != 1 {
        Err(anyhow!("Only PIN/UV protocol 1 is supported"))
    } else {
        Ok(())
    }
}

fn ctap_error(status: u8) -> Vec<u8> {
    vec![status]
}

fn ctap_success(map: BTreeMap<Value, Value>) -> Result<Vec<u8>> {
    let mut response = vec![CTAP2_OK];
    response.extend(serde_cbor::to_vec(&Value::Map(map))?);
    Ok(response)
}

fn encode_client_pin(map: BTreeMap<Value, Value>) -> Result<Vec<u8>> {
    let mut payload = vec![CTAP_CLIENT_PIN];
    payload.extend(serde_cbor::to_vec(&Value::Map(map))?);
    Ok(payload)
}

fn successful_map(payload: &[u8], operation: &str) -> Result<BTreeMap<Value, Value>> {
    let status = payload
        .first()
        .copied()
        .ok_or_else(|| anyhow!("Empty response from authenticator"))?;
    if status != CTAP2_OK {
        return Err(anyhow!(
            "Authenticator rejected {operation} with CTAP status 0x{status:02x}"
        ));
    }
    decode_map(&payload[1..])
}

fn cose_public_key(public: &PublicKey) -> Value {
    let point = public.to_encoded_point(false);
    Value::Map(map_of([
        (1, Value::Integer(2)),
        (3, Value::Integer(-25)),
        (-1, Value::Integer(1)),
        (-2, Value::Bytes(point.x().unwrap().to_vec())),
        (-3, Value::Bytes(point.y().unwrap().to_vec())),
    ]))
}

fn parse_cose_public(value: &Value) -> Result<PublicKey> {
    let Value::Map(map) = value else {
        return Err(anyhow!("ClientPIN key agreement is not a COSE map"));
    };
    if map_u8(map, 1)? != 2 || map_u8(map, -1)? != 1 {
        return Err(anyhow!("ClientPIN key agreement is not a P-256 EC2 key"));
    }
    let x = map_bytes(map, -2)?;
    let y = map_bytes(map, -3)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(anyhow!("Invalid P-256 coordinate size"));
    }
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(x);
    point[33..].copy_from_slice(y);
    PublicKey::from_sec1_bytes(&point).context("Invalid P-256 public key")
}

fn shared_secret(secret: &SecretKey, public: &PublicKey) -> Zeroizing<[u8; 32]> {
    let raw = diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let digest = Sha256::digest(raw.raw_secret_bytes());
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&digest);
    result
}

fn aes_cbc_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return Err(anyhow!("PIN protocol plaintext is not block-aligned"));
    }
    let mut result = plaintext.to_vec();
    let length = result.len();
    cbc::Encryptor::<Aes256>::new_from_slices(key, &[0u8; 16])
        .context("Invalid PIN protocol AES key")?
        .encrypt_padded_mut::<NoPadding>(&mut result, length)
        .map_err(|_| anyhow!("Cannot encrypt PIN protocol payload"))?;
    Ok(result)
}

fn aes_cbc_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(anyhow!("PIN protocol ciphertext is not block-aligned"));
    }
    let mut result = ciphertext.to_vec();
    let length = cbc::Decryptor::<Aes256>::new_from_slices(key, &[0u8; 16])
        .context("Invalid PIN protocol AES key")?
        .decrypt_padded_mut::<NoPadding>(&mut result)
        .map_err(|_| anyhow!("Cannot decrypt PIN protocol payload"))?
        .len();
    result.truncate(length);
    Ok(result)
}

fn hmac_16(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| anyhow!("Invalid PIN token for HMAC"))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes()[..16].to_vec())
}

fn verify_hmac(key: &[u8], message: &[u8], supplied: &[u8]) -> Result<()> {
    let expected = hmac_16(key, message)?;
    if supplied.len() != expected.len() {
        return Err(anyhow!("Invalid PIN/UV authentication parameter size"));
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&expected)
        .map_err(|_| anyhow!("Cannot initialize authentication comparison"))?;
    mac.update(b"sanzu-fido-proof");
    let tag = mac.clone().finalize().into_bytes();
    let mut supplied_mac = <Hmac<Sha256> as Mac>::new_from_slice(supplied)
        .map_err(|_| anyhow!("Cannot initialize authentication comparison"))?;
    supplied_mac.update(b"sanzu-fido-proof");
    supplied_mac
        .verify_slice(&tag)
        .map_err(|_| anyhow!("Invalid PIN/UV authentication parameter"))
}

fn make_credential_rp_id(map: &BTreeMap<Value, Value>) -> Result<String> {
    let Value::Map(rp) = map_value(map, 2)? else {
        return Err(anyhow!("MakeCredential relying party is not a map"));
    };
    match rp.get(&Value::Text("id".to_owned())) {
        Some(Value::Text(id)) => Ok(id.clone()),
        _ => Err(anyhow!("MakeCredential relying party has no id")),
    }
}

fn get_assertion_tests_presence(map: &BTreeMap<Value, Value>) -> Result<bool> {
    let Some(options) = map.get(&Value::Integer(5)) else {
        return Ok(true);
    };
    let Value::Map(options) = options else {
        return Err(anyhow!("GetAssertion options are not a map"));
    };
    match options.get(&Value::Text("up".to_owned())) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(anyhow!("GetAssertion up option is not boolean")),
        None => Ok(true),
    }
}

/// The GetInfo fields a platform bases its decision on. None of them is a
/// secret: they describe what the authenticator can do, not what it holds.
fn describe_get_info(info: &BTreeMap<Value, Value>) -> String {
    format!(
        "versions {:?}, extensions {:?}, options {:?}, maxMsgSize {:?}, pinUvAuthProtocols {:?}, transports {:?}, algorithms {:?}",
        info.get(&Value::Integer(1)),
        info.get(&Value::Integer(2)),
        info.get(&Value::Integer(4)),
        info.get(&Value::Integer(5)),
        info.get(&Value::Integer(6)),
        info.get(&Value::Integer(9)),
        info.get(&Value::Integer(10)),
    )
}

fn advertise_local_pin_broker(payload: &mut Vec<u8>) -> Result<()> {
    if payload.first() != Some(&CTAP2_OK) {
        return Ok(());
    }
    let mut info = decode_map(&payload[1..])?;
    debug!(
        "GetInfo from the authenticator: {}",
        describe_get_info(&info)
    );
    let versions = info
        .entry(Value::Integer(1))
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(versions) = versions else {
        return Err(anyhow!("Authenticator GetInfo versions are not an array"));
    };
    let fido_2_1 = Value::Text("FIDO_2_1".to_owned());
    if !versions.contains(&fido_2_1) {
        // pinUvAuthToken and its permission-scoped ClientPIN subcommands are
        // CTAP 2.1 semantics. Firefox discards an internally inconsistent
        // GetInfo response before issuing any credential operation.
        versions.push(fido_2_1);
    }
    let options = info
        .entry(Value::Integer(4))
        .or_insert_with(|| Value::Map(BTreeMap::new()));
    let Value::Map(options) = options else {
        return Err(anyhow!("Authenticator GetInfo options are not a map"));
    };
    options.insert(Value::Text("uv".to_owned()), Value::Bool(true));
    // Absence means unsupported. Advertising `false` would instead mean that
    // Client PIN exists but has not been configured, which can trigger a
    // remote PIN-setup UI in platform implementations.
    options.remove(&Value::Text("clientPin".to_owned()));
    options.insert(Value::Text("pinUvAuthToken".to_owned()), Value::Bool(true));
    info.insert(Value::Integer(6), Value::Array(vec![Value::Integer(1)]));
    // forcePINChange and minPINLength describe the Client PIN feature. Leaving
    // them in place while `clientPin` is hidden makes the answer contradict
    // itself: the authenticator would be stating a PIN policy for a PIN it
    // claims not to support. Platforms that validate GetInfo for internal
    // consistency drop such an authenticator without sending anything else.
    info.remove(&Value::Integer(12));
    info.remove(&Value::Integer(13));
    debug!(
        "GetInfo forwarded to the remote session: {}",
        describe_get_info(&info)
    );
    payload.truncate(1);
    payload.extend(serde_cbor::to_vec(&Value::Map(info))?);
    Ok(())
}

#[cfg(target_os = "linux")]
fn prompt_for_pin() -> Result<Zeroizing<String>> {
    for program in ["/usr/bin/pinentry-gnome3", "/usr/bin/pinentry"] {
        debug!("Trying the local PIN prompt with {program}");
        let mut child = match Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("Cannot start {program}")),
        };
        {
            let stdin = child.stdin.as_mut().context("Cannot open pinentry input")?;
            stdin.write_all(
                b"SETTITLE Sanzu - YubiKey locale\nSETPROMPT PIN:\nSETDESC Entrez le PIN de la YubiKey branchee sur cet ordinateur\nGETPIN\nBYE\n",
            )?;
        }
        let mut stdout = String::new();
        child
            .stdout
            .take()
            .context("Cannot open pinentry output")?
            .read_to_string(&mut stdout)?;
        let status = child.wait().context("Cannot wait for pinentry")?;
        // `stdout` carries the PIN on its `D ` line: only the exit status, the
        // Assuan status lines and the presence of that line are ever logged,
        // never the buffer itself.
        debug!("{program} exited with {status}");
        for line in stdout.lines() {
            if let Some(assuan) = line
                .strip_prefix("ERR ")
                .or_else(|| line.strip_prefix("S ERROR "))
            {
                // pinentry reports a missing terminal or display here, and then
                // still exits successfully, so this is the only trace of it.
                debug!("{program} reported an Assuan error: {assuan}");
            }
        }
        if !status.success() {
            return Err(anyhow!("The local PIN prompt was cancelled"));
        }
        if let Some(encoded) = stdout.lines().find_map(|line| line.strip_prefix("D ")) {
            let pin = decode_assuan_data(encoded)?;
            if pin.is_empty() {
                return Err(anyhow!("The local PIN prompt returned an empty PIN"));
            }
            return Ok(Zeroizing::new(pin));
        }
        debug!("{program} returned no PIN line; treating it as a cancellation");
        return Err(anyhow!("The local PIN prompt was cancelled"));
    }
    Err(anyhow!("pinentry is required for secure FIDO PIN entry"))
}

#[cfg(not(target_os = "linux"))]
fn prompt_for_pin() -> Result<Zeroizing<String>> {
    Err(anyhow!(
        "Secure local FIDO PIN entry is currently supported only by Linux clients"
    ))
}

fn decode_assuan_data(encoded: &str) -> Result<String> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(encoded.len()));
    let bytes = encoded.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(anyhow!("Invalid response from pinentry"));
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])?;
            decoded.push(
                u8::from_str_radix(hex, 16)
                    .map_err(|_| anyhow!("Invalid response from pinentry"))?,
            );
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded.to_vec()).context("pinentry returned a non-UTF-8 PIN")
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
                            trace!("Virtual FIDO out: {}", describe_report(&data, true));
                            reports.push(data);
                        } else if data.len() == FIDO_REPORT_SIZE + 1 && data[0] == 0 {
                            trace!("Virtual FIDO out: {}", describe_report(&data[1..], true));
                            reports.push(data[1..].to_vec());
                        } else {
                            warn!(
                                "Ignoring unexpected virtual FIDO output report size: {}",
                                data.len()
                            );
                        }
                    }
                    Ok(OutputEvent::GetReport { id, .. }) => {
                        debug!("Rejecting a virtual FIDO GET_REPORT (id {id})");
                        self.device
                            .write_get_report_reply(id, libc::EIO as u16, Vec::new())
                            .context("Cannot reject virtual FIDO GET_REPORT")?;
                    }
                    Ok(OutputEvent::SetReport { id, .. }) => {
                        debug!("Rejecting a virtual FIDO SET_REPORT (id {id})");
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
            if !reports.is_empty() {
                debug!(
                    "Virtual FIDO device emitted {} report(s) for the client",
                    reports.len()
                );
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
        if !reports.is_empty() {
            debug!(
                "Injecting {} FIDO report(s) from the client into the virtual device",
                reports.len()
            );
        }
        for report in reports {
            validate_report(&report)?;
            #[cfg(target_os = "linux")]
            {
                trace!("Virtual FIDO in: {}", describe_report(&report, false));
                self.device
                    .write(&report)
                    .context("Cannot write virtual FIDO input report")?;
            }
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

    #[test]
    fn fragments_and_reassembles_ctaphid_messages() {
        for size in [0, 1, 57, 58, 116, 512] {
            let message = CtapMessage {
                cid: 0x1020_3040,
                command: CTAPHID_CBOR,
                payload: (0..size).map(|index| index as u8).collect(),
            };
            let reports = fragment_message(&message).unwrap();
            let mut assembler = CtapAssembler::default();
            let mut rebuilt = None;
            for report in reports {
                rebuilt = assembler.push(&report).unwrap().or(rebuilt);
            }
            assert_eq!(rebuilt, Some(message));
        }
    }

    #[test]
    fn rejects_out_of_order_ctaphid_continuations() {
        let message = CtapMessage {
            cid: 7,
            command: CTAPHID_CBOR,
            payload: vec![0xaa; 100],
        };
        let mut reports = fragment_message(&message).unwrap();
        reports[1][4] = 1;
        let mut assembler = CtapAssembler::default();
        assert!(assembler.push(&reports[0]).unwrap().is_none());
        assert!(assembler.push(&reports[1]).is_err());
    }

    #[test]
    fn get_info_hides_remote_pin_and_advertises_local_uv() {
        let options = BTreeMap::from([
            (Value::Text("clientPin".to_owned()), Value::Bool(true)),
            (Value::Text("uv".to_owned()), Value::Bool(false)),
        ]);
        let mut payload = ctap_success(map_of([
            (1, Value::Array(vec![Value::Text("FIDO_2_0".to_owned())])),
            (4, Value::Map(options)),
            (12, Value::Bool(false)),
            (13, Value::Integer(4)),
        ]))
        .unwrap();
        advertise_local_pin_broker(&mut payload).unwrap();
        let info = successful_map(&payload, "test").unwrap();
        let Value::Array(versions) = map_value(&info, 1).unwrap() else {
            panic!("versions should be an array");
        };
        assert!(versions.contains(&Value::Text("FIDO_2_0".to_owned())));
        assert!(versions.contains(&Value::Text("FIDO_2_1".to_owned())));
        let Value::Map(options) = map_value(&info, 4).unwrap() else {
            panic!("options should be a map");
        };
        assert_eq!(options.get(&Value::Text("clientPin".to_owned())), None);
        assert_eq!(
            options.get(&Value::Text("uv".to_owned())),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            options.get(&Value::Text("pinUvAuthToken".to_owned())),
            Some(&Value::Bool(true))
        );
        // The Client PIN policy must not outlive the Client PIN option.
        assert_eq!(info.get(&Value::Integer(12)), None);
        assert_eq!(info.get(&Value::Integer(13)), None);
    }

    #[test]
    fn answers_the_client_pin_subcommands_the_advertisement_implies() {
        // GetInfo hides clientPin and offers uv, so a CTAP 2.1 platform asks
        // for a token with the built-in method rather than with a PIN.
        assert_eq!(
            client_pin_action(CLIENT_PIN_TOKEN_USING_UV),
            ClientPinAction::IssueToken
        );
        assert_eq!(
            client_pin_action(CLIENT_PIN_GET_UV_RETRIES),
            ClientPinAction::UvRetries
        );
        assert_eq!(
            client_pin_action(CLIENT_PIN_GET_KEY_AGREEMENT),
            ClientPinAction::KeyAgreement
        );
        assert_eq!(
            client_pin_action(CLIENT_PIN_TOKEN_USING_PIN),
            ClientPinAction::IssueToken
        );
        assert_eq!(
            client_pin_action(CLIENT_PIN_GET_PIN_RETRIES),
            ClientPinAction::PinRetries
        );
        // setPIN and changePIN would let the remote session take over the
        // authenticator, and getPinToken bypasses the permission scoping.
        for subcommand in [0x03, 0x04, CLIENT_PIN_GET_PIN_TOKEN] {
            assert_eq!(
                client_pin_action(subcommand),
                ClientPinAction::Unsupported,
                "subcommand 0x{subcommand:02x} must stay unreachable"
            );
        }
    }

    #[test]
    fn pin_protocol_crypto_round_trips() {
        let first = SecretKey::random(&mut OsRng);
        let second = SecretKey::random(&mut OsRng);
        let first_shared = shared_secret(&first, &second.public_key());
        let second_shared = shared_secret(&second, &first.public_key());
        assert_eq!(&*first_shared, &*second_shared);

        let plaintext = [0x42; 32];
        let encrypted = aes_cbc_encrypt(&first_shared[..], &plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(
            aes_cbc_decrypt(&second_shared[..], &encrypted).unwrap(),
            plaintext
        );

        let proof = hmac_16(&first_shared[..], b"client-data").unwrap();
        assert!(verify_hmac(&second_shared[..], b"client-data", &proof).is_ok());
        assert!(verify_hmac(&second_shared[..], b"other-data", &proof).is_err());
    }

    #[test]
    fn parses_pinentry_assuan_escaping() {
        assert_eq!(decode_assuan_data("12%2034%25").unwrap(), "12 34%");
        assert!(decode_assuan_data("12%2").is_err());
    }

    #[test]
    fn keeps_token_for_silent_get_assertion_only() {
        let silent = map_of([(
            5,
            Value::Map(BTreeMap::from([(
                Value::Text("up".to_owned()),
                Value::Bool(false),
            )])),
        )]);
        assert!(!get_assertion_tests_presence(&silent).unwrap());
        assert!(get_assertion_tests_presence(&BTreeMap::new()).unwrap());
    }
}
