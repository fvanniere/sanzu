use anyhow::{Context, Result};
extern crate libc;
use memmap2::MmapOptions;
use std::{collections::HashMap, fmt::Write as _, net::TcpStream, time::Instant};

use std::{
    convert::TryInto,
    fs, io,
    io::Read,
    io::Write,
    process::{ChildStdin, ChildStdout, Command, Stdio},
    thread,
};

use sanzu_common::{
    proto::{recv_server_msg_or_error, send_client_err_event, VERSION},
    tls_helper::make_client_config,
    tunnel, ReadWrite, Tunnel,
};

#[cfg(feature = "kerberos")]
use sanzu_common::auth_kerberos::do_kerberos_server_auth;

use crate::{
    client_graphics::*,
    client_utils::Area,
    config::ConfigClient,
    fido::FidoClient,
    osd::{draw_text, TestDisplay},
    //proto::{Tunnel, ReadWrite},
    sound::SoundDecoder,
    utils::{
        get_xwd_data, ClientArgsConfig, HasTimeout, MAX_BYTES_PER_LINE, MAX_CURSOR_HEIGHT,
        MAX_CURSOR_WIDTH, MAX_WINDOW_HEIGHT, MAX_WINDOW_WIDTH,
    },
    video_decoder::init_video_codec,
};

struct ShellAttr {
    path: &'static str,
    attr: &'static str,
}

#[cfg(target_family = "unix")]
const SHELL_ATTR: ShellAttr = ShellAttr {
    path: "/bin/sh",
    attr: "-c",
};

#[cfg(target_family = "windows")]
const SHELL_ATTR: ShellAttr = ShellAttr {
    path: "cmd",
    attr: "/C",
};

struct StreamPipes {
    pipe_in: ChildStdout,
    pipe_out: ChildStdin,
}

impl Read for StreamPipes {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.pipe_in.read(buf)
    }
}

impl Write for StreamPipes {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pipe_out.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.pipe_out.flush()
    }
}

fn check_img_size(width: u32, height: u32) -> Result<(u32, u32)> {
    if width > MAX_WINDOW_WIDTH || height > MAX_WINDOW_HEIGHT {
        Err(anyhow!("Err img too big {}x{}", width, height))
    } else {
        Ok((width, height))
    }
}

fn check_cusor_size(width: u32, height: u32, xhot: u32, yhot: u32) -> Result<(u32, u32, u32, u32)> {
    if width > MAX_CURSOR_WIDTH
        || height > MAX_CURSOR_HEIGHT
        || xhot > MAX_CURSOR_WIDTH
        || yhot > MAX_CURSOR_HEIGHT
    {
        Err(anyhow!(
            "Err cursor too big {}x{} ({} {})",
            width,
            height,
            xhot,
            yhot
        ))
    } else {
        Ok((width, height, xhot, yhot))
    }
}

fn zoomed_dimension(dimension: u32, zoom: f64) -> u32 {
    // Video encoders generally require even dimensions. Keep a non-zero minimum
    // for very small client windows.
    (((dimension as f64 / zoom).round() as u32).max(2)) & !1
}

fn scale_coordinate(value: u32, from: u32, to: u32) -> u32 {
    if from == 0 {
        return 0;
    }
    ((value as u64 * to as u64) / from as u64).min(to.saturating_sub(1) as u64) as u32
}

fn scale_client_events(
    msgs: &mut tunnel::MessagesClient,
    display_size: (u16, u16),
    remote_size: (u16, u16),
    zoom: f64,
) {
    for msg in &mut msgs.msgs {
        match &mut msg.msg {
            Some(tunnel::message_client::Msg::Move(event)) => {
                event.x = scale_coordinate(event.x, display_size.0 as u32, remote_size.0 as u32);
                event.y = scale_coordinate(event.y, display_size.1 as u32, remote_size.1 as u32);
            }
            Some(tunnel::message_client::Msg::Button(event)) => {
                event.x = scale_coordinate(event.x, display_size.0 as u32, remote_size.0 as u32);
                event.y = scale_coordinate(event.y, display_size.1 as u32, remote_size.1 as u32);
            }
            Some(tunnel::message_client::Msg::Display(event)) => {
                event.width = zoomed_dimension(event.width, zoom);
                event.height = zoomed_dimension(event.height, zoom);
            }
            _ => {}
        }
    }
}

fn scale_signed(value: i32, from: u32, to: u32) -> i32 {
    if from == 0 {
        return value;
    }
    ((value as i64 * to as i64) / from as i64).clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

fn scale_length(value: u32, from: u32, to: u32) -> u32 {
    if from == 0 {
        return value;
    }
    ((value as u64 * to as u64) / from as u64).min(u32::MAX as u64) as u32
}

fn scale_area(area: &mut Area, remote_size: (u16, u16), display_size: (u16, u16)) {
    area.position.0 = scale_signed(
        area.position.0 as i32,
        remote_size.0 as u32,
        display_size.0 as u32,
    )
    .clamp(i16::MIN as i32, i16::MAX as i32) as i16;
    area.position.1 = scale_signed(
        area.position.1 as i32,
        remote_size.1 as u32,
        display_size.1 as u32,
    )
    .clamp(i16::MIN as i32, i16::MAX as i32) as i16;
    area.size.0 = scale_length(
        area.size.0 as u32,
        remote_size.0 as u32,
        display_size.0 as u32,
    )
    .max(1) as u16;
    area.size.1 = scale_length(
        area.size.1 as u32,
        remote_size.1 as u32,
        display_size.1 as u32,
    )
    .max(1) as u16;
}

pub trait ClientInterface {
    fn pam_echo(&mut self, echo: String) -> Result<String>;

    fn pam_blind(&mut self, blind: String) -> Result<String>;

    fn pam_info(&mut self, info: String) -> Result<()>;

    fn pam_error(&mut self, error: String) -> Result<()>;

    fn pam_end(&mut self, end: bool) -> Result<()>;

    fn client_exit(&mut self, status: &Result<()>);
}

#[derive(Default)]
pub struct StdioClientInterface {}

impl ClientInterface for StdioClientInterface {
    fn pam_echo(&mut self, echo: String) -> Result<String> {
        println!("{echo}");
        let mut user = String::new();
        let stdin = std::io::stdin();
        std::io::stdout().flush().unwrap();
        stdin.read_line(&mut user).context("Error in read login")?;

        // We use trim here assuming it's suitable for logins
        // which should not end with a whitespace
        let len = user.trim().len();
        user.truncate(len);

        Ok(user)
    }

    fn pam_blind(&mut self, blind: String) -> Result<String> {
        rpassword::prompt_password(blind).context("Error in read password")
    }

    fn pam_info(&mut self, info: String) -> Result<()> {
        println!("{info}");
        Ok(())
    }

    fn pam_error(&mut self, error: String) -> Result<()> {
        println!("{error}");
        Ok(())
    }

    fn pam_end(&mut self, end: bool) -> Result<()> {
        match end {
            true => {
                info!("Pam end ok");
            }
            false => {
                info!("Pam end err");
            }
        }
        Ok(())
    }

    fn client_exit(&mut self, _status: &Result<()>) {}
}

/// Client main loop
///
/// The loop is composed of the following actions:
/// - poll client graphics events (mouse move, key down/up, clipboard, ...)
/// - send those events to the server
/// - receive events from the server
/// - decode and handle those events (image decoding, sound, notifications, clipboard, ...)
/// - image update if necessary
///

pub fn run(
    client_config: &ConfigClient,
    arguments: &ClientArgsConfig,
    mut client_interface: impl ClientInterface,
) -> Result<()> {
    let res = do_run(client_config, arguments, &mut client_interface);
    client_interface.client_exit(&res);
    res
}

pub fn do_run(
    client_config: &ConfigClient,
    arguments: &ClientArgsConfig,
    client_interface: &mut impl ClientInterface,
) -> Result<()> {
    if !arguments.zoom.is_finite() || arguments.zoom < 1.0 {
        return Err(anyhow!(
            "Zoom must be a finite number greater than or equal to 1"
        ));
    }
    let mut sound_obj = if arguments.audio {
        Some(
            SoundDecoder::new(
                "default",
                arguments.audio_sample_rate,
                arguments.audio_buffer_ms,
            )
            .context("Error in new SoundDecoder")?,
        )
    } else {
        None
    };

    let (audio, audio_sample_rate) = match &sound_obj {
        Some(ref sound_obj) => (true, sound_obj.sample_rate),
        None => (false, 0),
    };

    let connection_timeout = arguments
        .connection_timeout
        .map(|timeout| std::time::Duration::from_secs(timeout as u64));

    let mut socket: Box<dyn ReadWrite> = match &arguments.proxycommand {
        None => {
            #[cfg(unix)]
            if arguments.vsock {
                let port = arguments.server_port as u32;
                let address = arguments
                    .server_addr
                    .parse::<u32>()
                    .expect("Not a vsock address");
                let server = vsock::VsockStream::connect(&vsock::VsockAddr::new(address, port))
                    .context(format!(
                        "Error in vsock server connection {address:?} {port:?}"
                    ))?;
                server
                    .set_connection_timeout(connection_timeout)
                    .context("Cannot set timeout")?;
                info!("Connected to server");
                Box::new(server)
            } else {
                let port = arguments.server_port;
                let destination = format!("{}:{}", arguments.server_addr, port);
                let server = TcpStream::connect(&destination)
                    .context(format!("Error in tcp server connection {destination:?}"))?;
                server
                    .set_connection_timeout(connection_timeout)
                    .context("Cannot set timeout")?;
                info!("Connected to server");
                server.set_nodelay(true).expect("set_nodelay call failed");
                Box::new(server)
            }
            #[cfg(windows)]
            {
                let port = arguments.server_port;
                let destination = format!("{}:{}", arguments.server_addr, port);
                let server = TcpStream::connect(&destination)
                    .context(format!("Error in tcp server connection {destination:?}"))?;
                server
                    .set_connection_timeout(connection_timeout)
                    .context("Cannot set timeout")?;
                info!("Connected to server");
                server.set_nodelay(true).expect("set_nodelay call failed");
                Box::new(server)
            }
        }
        Some(commandline) => {
            /* Launch proxy command*/
            let mut child = Command::new(SHELL_ATTR.path)
                .arg(SHELL_ATTR.attr)
                .arg(commandline)
                .stdout(Stdio::piped())
                .stdin(Stdio::piped())
                .spawn()
                .context("Error in launch proxycommand")?;
            info!("Proxycommand {:?}", child);

            let pipe_child_in = child.stdin.take().context("Error in get stdin")?;
            let pipe_child_out = child.stdout.take().context("Error in get stdout")?;
            let stream = StreamPipes {
                pipe_in: pipe_child_out,
                pipe_out: pipe_child_in,
            };

            thread::spawn(move || {
                debug!("Wait proxycommand");
                child.wait().expect("Error in wait proxycommand");
                debug!("End proxycommand");
            });
            Box::new(stream)
        }
    };

    let extern_img_source = match arguments.extern_img_source.as_deref() {
        Some(extern_img_source) => {
            let file = fs::File::open(extern_img_source)
                .context(format!("Error in open shared mem {extern_img_source:?}"))?;
            unsafe {
                Some(
                    MmapOptions::new()
                        .map(&file)
                        .context("Error in map shared mem")?,
                )
            }
        }
        None => None,
    };

    debug!("Connected");

    let tls_server_name_ok = arguments
        .tls_server_name
        .clone()
        .unwrap_or_else(|| "no_server_name".to_string());
    let server_name = tls_server_name_ok
        .as_str()
        .try_into()
        .map_err(|err| anyhow!("Err {:?}", err))
        .context("Error in dns server tls name")?;
    let config = make_client_config(
        arguments.tls_ca.as_deref(),
        arguments.client_cert.as_deref(),
        arguments.client_key.as_deref(),
    )
    .context("Error in make client tls config")?;
    let mut conn = rustls::ClientConnection::new(config, server_name)
        .context("Error in new ClientConnection")?;
    let mut tls = rustls::Stream::new(&mut conn, &mut socket);

    let server: &mut dyn ReadWrite = if arguments.tls_server_name.is_some() {
        &mut tls
    } else {
        &mut socket
    };

    // Send client version
    let client_version = tunnel::Version {
        version: VERSION.to_owned(),
    };
    send_client_msg_type!(server, client_version, Version).context("Error in send Version")?;

    /* Recv client version */
    let server_version: tunnel::Version =
        recv_server_msg_type!(server, Version).context("Error in send server version")?;

    info!("Server version {:?}", server_version);
    if server_version.version != VERSION {
        return Err(anyhow!(
            "Version mismatch server: {:?} client: {:?}",
            server_version.version,
            VERSION,
        ));
    }

    #[cfg(feature = "kerberos")]
    if let Some(cname) = &arguments.server_cname {
        do_kerberos_server_auth(cname, server)
            .context("Error in perform_auth")
            .map_err(|err| send_client_err_event(server, err))?
    }
    #[cfg(not(feature = "kerberos"))]
    debug!("Skipping kerberos auth");

    if arguments.login {
        if arguments.tls_server_name.is_none() {
            println!("WARNING: no tls, password will be sent in clear text");
        }
        loop {
            let msg = recv_server_msg_type!(server, Pamconversation)
                .context("Error in recv PamConversation")?;

            match msg.msg {
                Some(tunnel::pam_conversation::Msg::Echo(echo)) => {
                    let user = client_interface
                        .pam_echo(echo)
                        .map_err(|err| send_client_err_event(server, err))?;
                    let client_user = tunnel::EventPamUser { user };
                    send_client_msg_type!(server, client_user, Pamuser)
                        .context("Error in send EventPamUser")?;
                }
                Some(tunnel::pam_conversation::Msg::Blind(blind)) => {
                    let password = client_interface
                        .pam_blind(blind)
                        .map_err(|err| send_client_err_event(server, err))?;
                    let client_pwd = tunnel::EventPamPwd { password };
                    send_client_msg_type!(server, client_pwd, Pampwd)
                        .context("Error in send EventPamPwd")?;
                }

                Some(tunnel::pam_conversation::Msg::Info(info)) => {
                    client_interface.pam_info(info)?;
                }
                Some(tunnel::pam_conversation::Msg::Error(err)) => {
                    client_interface.pam_error(err)?;
                }
                Some(tunnel::pam_conversation::Msg::End(end)) => {
                    client_interface.pam_end(end)?;
                    break;
                }
                None => {
                    return Err(anyhow!("Err on Pam conversation"));
                }
            }
        }
    }

    /* Receive image info & codec name */
    let msg = recv_server_msg_type!(server, Hello).context("Error in recv ServerHello")?;

    info!("{:?}", msg);
    let server_allows_fido = msg.fido;
    let codec_name = match &arguments.decoder {
        Some(decoder_name) => decoder_name.to_owned(),
        None => msg.codec_name.to_owned(),
    };
    let (seamless, server_size) = match msg.msg {
        Some(tunnel::server_hello::Msg::AdaptScreen(adapt_screen)) => (adapt_screen.seamless, None),
        Some(tunnel::server_hello::Msg::Fullscreen(msg)) => {
            (false, Some((msg.width as u16, msg.height as u16)))
        }
        _ => {
            panic!("Unknown Server hello");
        }
    };

    if server_size.is_some() && arguments.zoom != 1.0 {
        return Err(anyhow!(
            "Zoom requires adaptive server resolution; restart the server without --keep-server-resolution"
        ));
    }

    let fido_requested = arguments.fido || arguments.fido_device.is_some();
    if fido_requested && !server_allows_fido {
        return Err(anyhow!(
            "FIDO forwarding requested but the server was not started with --fido"
        ));
    }
    let fido = if fido_requested {
        Some(
            FidoClient::open(arguments.fido_device.as_deref())
                .map_err(|err| send_client_err_event(server, err))?,
        )
    } else {
        None
    };
    let fido_info = fido.as_ref().map(FidoClient::info);

    #[cfg(unix)]
    let mut client = init_x11rb(arguments, seamless, server_size)
        .context("Error in init_x11rb")
        .map_err(|err| send_client_err_event(server, err))?;
    #[cfg(windows)]
    let mut client = init_wind3d(arguments, seamless, server_size)
        .context("Error in init_wind3d")
        .map_err(|err| send_client_err_event(server, err))?;

    /* Send hello with audio bool */
    let (mut img_width, mut img_height) = match server_size {
        Some((width, height)) => {
            let client_hello = tunnel::ClientHelloFullscreen {
                audio,
                audio_sample_rate,
                fido: fido_info.clone(),
            };
            send_client_msg_type!(server, client_hello, Clienthellofullscreen)
                .context("Error in send ClientHelloFullscreen")?;
            (width, height)
        }
        None => {
            let (width, height) = client.size();
            let width_even = zoomed_dimension(width as u32, arguments.zoom);
            let height_event = zoomed_dimension(height as u32, arguments.zoom);
            let client_hello = tunnel::ClientHelloResolution {
                audio,
                audio_sample_rate,
                width: width_even,
                height: height_event,
                fido: fido_info.clone(),
            };
            send_client_msg_type!(server, client_hello, Clienthelloresolution)
                .context("Error in send ClientHelloResolution")?;
            (width_even as u16, height_event as u16)
        }
    };

    let mut decoder =
        init_video_codec(client_config.ffmpeg_options(Some(&codec_name)), &codec_name)
            .context("Cannot init video decoder")
            .map_err(|err| send_client_err_event(server, err))?;

    if let Some(ref mut sound_obj) = sound_obj {
        sound_obj
            .start()
            .context("Error in sound start")
            .map_err(|err| send_client_err_event(server, err))?;
    }

    let mut stats = "".to_owned();
    let mut img_bytes_per_line = None;
    loop {
        let mut areas = HashMap::new();
        let time_start = Instant::now();

        let display_size = client.size();
        let mut msgs = client.poll_events().context("Error in poll_events")?;
        if let Some(ref fido) = fido {
            msgs.fido_reports = fido
                .poll_reports()
                .context("Cannot poll forwarded FIDO authenticator")?;
        }
        scale_client_events(
            &mut msgs,
            display_size,
            (img_width, img_height),
            arguments.zoom,
        );

        let time_events = Instant::now();

        send_client_msg_type!(server, msgs, Msgsclient).context("Error in send client events")?;

        let time_send = Instant::now();

        /* Decode encoded img */
        let msg: tunnel::MessagesSrv =
            recv_server_msg_type!(server, Msgssrv).context("Error in recv MessagesSrv")?;

        let time_recv = Instant::now();

        let mut img_todo = None;

        if let Some(ref fido) = fido {
            fido.write_reports(msg.fido_reports)
                .context("Cannot forward reports to the local FIDO authenticator")?;
        } else if !msg.fido_reports.is_empty() {
            return Err(anyhow!("Server sent FIDO reports without negotiation"));
        }

        for msg in msg.msgs {
            match msg.msg {
                Some(tunnel::message_srv::Msg::ImgEncoded(img)) => {
                    let (width, height) = check_img_size(img.width, img.height)
                        .map_err(|err| send_client_err_event(server, err))?;
                    img_todo = Some((img.data, width, height));
                }
                Some(tunnel::message_srv::Msg::ImgRaw(img)) => {
                    let (data, width, height, bytes_per_line) = match &extern_img_source {
                        Some(ref video_shared_mem) => match arguments.source_is_xwd {
                            true => {
                                let (data, _xwd_width, _xwd_height, bytes_per_line) =
                                    get_xwd_data(video_shared_mem)?;
                                (data.to_owned(), img.width, img.height, bytes_per_line)
                            }
                            false => {
                                let size = img.bytes_per_line as usize * img.height as usize;
                                let data = video_shared_mem[..size].to_owned();
                                (data, img.width, img.height, img.bytes_per_line)
                            }
                        },
                        _ => (img.data, img.width, img.height, img.bytes_per_line),
                    };

                    let (width, height) = check_img_size(width, height)
                        .map_err(|err| send_client_err_event(server, err))?;
                    img_todo = Some((data, width, height));
                    if bytes_per_line > MAX_BYTES_PER_LINE {
                        return Err(anyhow!("Bytes per lines too big"));
                    }
                    img_bytes_per_line = Some(bytes_per_line as u16);
                }
                Some(tunnel::message_srv::Msg::SoundEncoded(sound)) => {
                    if let Some(ref mut sound_obj) = sound_obj {
                        for pkt in sound.data {
                            sound_obj.push(pkt);
                        }
                    }
                }
                Some(tunnel::message_srv::Msg::Clipboard(clipboard)) => {
                    info!("Clipboard retrieved from server");
                    if client.set_clipboard(&clipboard.data).is_err() {
                        error!("Cannot set clipboard");
                    }
                }
                Some(tunnel::message_srv::Msg::Cursor(cursor)) => {
                    if let Err(err) =
                        check_cusor_size(cursor.width, cursor.height, cursor.xhot, cursor.yhot)
                            .map_err(|err| err.context("Cursor size error"))
                            .map(|(width, height, xhot, yhot)| {
                                client.set_cursor(
                                    &cursor.data,
                                    (width, height),
                                    (xhot as u16, yhot as u16),
                                )
                            })
                            .map_err(|err| err.context("Set cursor error"))
                    {
                        error!("Updt cursor error");
                        err.chain().for_each(|cause| error!(" - due to {}", cause));
                    }
                }
                Some(tunnel::message_srv::Msg::AreaUpdt(area_updt)) => {
                    trace!("new updt: {:?}", area_updt);
                    let area = Area {
                        id: area_updt.id as usize,
                        size: (area_updt.width as u16, area_updt.height as u16),
                        position: (area_updt.x as i16, area_updt.y as i16),
                        mapped: area_updt.mapped,
                        is_app: area_updt.is_app,
                        name: area_updt.name.clone(),
                    };
                    areas.insert(area_updt.id as usize, area);
                }
                Some(tunnel::message_srv::Msg::Printfile(printfile)) => {
                    trace!("printfile: {:?}", printfile);
                    #[cfg(feature = "printfile")]
                    {
                        info!("printfile: {:?}", printfile);
                        if let Err(err) =
                            client.printfile(&printfile.path).context("Error in print")
                        {
                            err.chain().for_each(|cause| error!(" - due to {}", cause));
                        }
                    }
                }
                Some(tunnel::message_srv::Msg::Notifications(notifications)) => {
                    trace!("notifications: {:?}", notifications);
                    #[cfg(feature = "notify")]
                    {
                        let mut notification_title = None;
                        let mut notification_icon = None;
                        let mut strings = vec![];
                        if !notifications.notifications.is_empty() {
                            for notification in notifications.notifications {
                                match notification.msg {
                                    Some(tunnel::notification::Msg::Title(string)) => {
                                        notification_title = Some(string);
                                    }
                                    Some(tunnel::notification::Msg::Message(string)) => {
                                        strings.push(string);
                                    }
                                    Some(tunnel::notification::Msg::Icon(icon)) => {
                                        if let Ok(icon) = notify_rust::Image::from_rgba(
                                            icon.width as i32,
                                            icon.height as i32,
                                            icon.data,
                                        ) {
                                            notification_icon = Some(icon);
                                        } else {
                                            error!("Cannot create image");
                                        }
                                    }
                                    _ => {}
                                }
                            }

                            let message = strings.join("\n");
                            let mut notification = notify_rust::Notification::new();
                            if let Some(title) = notification_title {
                                notification.summary = title;
                            }
                            if let Some(icon) = notification_icon {
                                notification
                                    .hints
                                    .insert(notify_rust::Hint::ImageData(icon));
                            }
                            notification.body = message;
                            if notification.show().is_err() {
                                error!("Cannot notify");
                            }
                        }
                    }
                }
                Some(tunnel::message_srv::Msg::Stats(msg_stats)) => {
                    trace!("server stats: {:?}", stats);
                    stats = msg_stats.stats
                }
                _ => {}
            };
        }

        let time_decode_msgs = Instant::now();
        let mut time_decode = None;

        if let Some((img_data, new_img_width, new_img_height)) = img_todo {
            if img_width != new_img_width as u16 || img_height != new_img_height as u16 {
                info!("New resolution {}x{}", new_img_width, new_img_height);
                decoder = decoder.reload().context(format!(
                    "Cannot reload decode with size {new_img_width}x{new_img_height}"
                ))?;
                img_width = new_img_width as u16;
                img_height = new_img_height as u16;
                info!("New codec ok");
            }

            if let (Some(_img_updated), Some(mut timings)) =
                decoder.decode_img(&img_data, img_width, img_height, img_bytes_per_line)
            {
                let time_start = Instant::now();
                if let Some(data_rgba) = decoder.data_rgba().as_mut() {
                    if client.display_stats() {
                        let mut display = TestDisplay {
                            width: img_width as u32,
                            height: img_height as u32,
                            buffer: data_rgba,
                        };
                        let stats = stats.replace('µ', "u");
                        draw_text(&mut display, &stats, 0, img_height as i32 - 50);
                    }

                    client
                        .set_img(
                            &data_rgba[0..img_width as usize * img_height as usize * 4],
                            (img_width as u32, img_height as u32),
                        )
                        .context("Error in set_img")?;
                }
                let time_set_img = Instant::now();
                timings.times.push(("set", time_set_img - time_start));
                time_decode = Some(timings);
            }
        }

        let display_size = client.size();
        for area in areas.values_mut() {
            scale_area(area, (img_width, img_height), display_size);
        }
        client.update(&areas).context("Error in update")?;

        let time_stop = Instant::now();

        let mut timings_str = String::new();
        let times_img = if let Some(timings) = time_decode {
            for timing in timings.times {
                let time_str = format!("{:.1?}", timing.1);
                write!(timings_str, "{} {:8}", timing.0, time_str)?;
            }
            timings_str
        } else {
            "  -  ".to_owned()
        };

        debug!(
            "Total: {:>7} events: {:>7} send: {:>7} recv: {:>7} decode msg: {:>7} ({:14})",
            &format!("{:.1?}", time_stop - time_start),
            &format!("{:.1?}", time_events - time_start),
            &format!("{:.1?}", time_send - time_events),
            &format!("{:.1?}", time_recv - time_send),
            &format!("{:.1?}", time_decode_msgs - time_recv),
            &times_img,
        );
    }
}

#[cfg(test)]
mod zoom_tests {
    use super::*;

    #[test]
    fn zoom_two_turns_4k_into_1080p() {
        assert_eq!(zoomed_dimension(3840, 2.0), 1920);
        assert_eq!(zoomed_dimension(2160, 2.0), 1080);
    }

    #[test]
    fn zoom_dimensions_are_even() {
        assert_eq!(zoomed_dimension(1921, 1.5), 1280);
        assert_eq!(zoomed_dimension(3, 2.0), 2);
    }

    #[test]
    fn pointer_coordinates_are_mapped_back_to_remote_space() {
        assert_eq!(scale_coordinate(1920, 3840, 1920), 960);
        assert_eq!(scale_coordinate(3839, 3840, 1920), 1919);
    }
}
