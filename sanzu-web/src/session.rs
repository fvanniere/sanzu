//! One browser session: a WebSocket on one side, a sanzu server on the other
//!
//! The gateway plays the sanzu client, like guacd for Guacamole: the browser
//! gets the H.264 frames as they are, and the cursor, in binary messages, and
//! sends its input as JSON.
//!
//! Browser to gateway (text, JSON):
//! - `{"t":"hello","w":1920,"h":1080}` first, the display size in pixels
//! - `{"t":"move","x":..,"y":..}`, `{"t":"button","x":..,"y":..,"b":1,"d":true}`
//! - `{"t":"key","k":38,"d":true}` with X11 keycodes
//! - `{"t":"resize","w":..,"h":..}`, `{"t":"clipboard","data":".."}`
//!
//! Gateway to browser:
//! - text `{"t":"hello","codec":"h264"}`, `{"t":"clipboard","data":".."}`,
//!   `{"t":"error","message":".."}`
//! - binary, first byte 1: frame, then u32 LE width, height, H.264 Annex B
//! - binary, first byte 2: cursor, then u32 LE width, height, xhot, yhot,
//!   premultiplied BGRA pixels

use crate::config::Config;
use anyhow::{Context, Result};
use sanzu_common::{proto::*, tunnel, VERSION};
use serde::Deserialize;
use std::{
    fs::remove_file,
    io::ErrorKind,
    net::TcpStream,
    os::unix::net::{UnixListener, UnixStream},
    process,
    time::Duration,
};
use tungstenite::{protocol::Role, Message, WebSocket};

const TOKEN_USERNAME: &str = "%USERNAME%";
const TOKEN_CLIENT_ADDR: &str = "%CLIENT_ADDR%";
const TOKEN_UNIX_SOCKET_PATH: &str = "%UNIX_SOCK_PATH%";

const FRAME: u8 = 1;
const CURSOR: u8 = 2;

/// Largest display the browser may ask for
const MAX_SIZE: u32 = 8192;

#[derive(Deserialize, Debug)]
#[serde(tag = "t", rename_all = "lowercase")]
enum BrowserEvent {
    Hello { w: u32, h: u32 },
    Move { x: u32, y: u32 },
    Button { x: u32, y: u32, b: u32, d: bool },
    Key { k: u32, d: bool },
    Resize { w: u32, h: u32 },
    Clipboard { data: String },
}

/// Video encoders want even sizes
fn display_size(width: u32, height: u32) -> (u32, u32) {
    (
        width.clamp(2, MAX_SIZE) & !1,
        height.clamp(2, MAX_SIZE) & !1,
    )
}

/// Same replacement as sanzu_broker
fn replace_source(args: &[String], needle: &str, new_str: &str) -> Vec<String> {
    args.iter()
        .map(|arg| {
            if arg == needle {
                new_str.to_owned()
            } else {
                arg.to_owned()
            }
        })
        .collect()
}

/// Answer the WebSocket upgrade, already parsed and authorized
pub fn accept_websocket(
    mut stream: TcpStream,
    request: &crate::http::Request,
) -> Result<WebSocket<TcpStream>> {
    use std::io::Write;
    let key = request
        .header("sec-websocket-key")
        .context("No Sec-WebSocket-Key")?;
    let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    .context("Cannot answer the upgrade")?;
    Ok(WebSocket::from_raw_socket(stream, Role::Server, None))
}

fn send_json(ws: &mut WebSocket<TcpStream>, value: serde_json::Value) -> Result<()> {
    ws.send(Message::Text(value.to_string()))
        .context("Cannot send to the browser")
}

fn binary(kind: u8, fields: &[u32], data: &[u8]) -> Message {
    let mut message = Vec::with_capacity(1 + fields.len() * 4 + data.len());
    message.push(kind);
    for field in fields {
        message.extend_from_slice(&field.to_le_bytes());
    }
    message.extend_from_slice(data);
    Message::Binary(message)
}

/// Read the browser messages already there, without blocking
///
/// Returns None when the browser closed the WebSocket.
fn read_events(ws: &mut WebSocket<TcpStream>) -> Result<Option<Vec<BrowserEvent>>> {
    let mut events = vec![];
    loop {
        match ws.read() {
            Ok(Message::Text(text)) => match serde_json::from_str(&text) {
                Ok(event) => events.push(event),
                Err(err) => warn!("Bad browser message: {err}"),
            },
            Ok(Message::Close(_)) => return Ok(None),
            Ok(_) => {}
            Err(tungstenite::Error::Io(err))
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut =>
            {
                return Ok(Some(events))
            }
            Err(tungstenite::Error::ConnectionClosed) | Err(tungstenite::Error::AlreadyClosed) => {
                return Ok(None)
            }
            Err(err) => return Err(err).context("Cannot read from the browser"),
        }
    }
}

/// Start a sanzu server for `username` and wait for it on a unix socket
fn spawn_server(
    config: &Config,
    username: &str,
    client_addr: &str,
) -> Result<(UnixStream, String)> {
    let socket_path = format!("/tmp/video_{}", uuid::Uuid::new_v4());
    let on_connect = &config.cmd_callback.on_connect;
    let args = replace_source(&on_connect.command_args, TOKEN_USERNAME, username);
    let args = replace_source(&args, TOKEN_CLIENT_ADDR, client_addr);
    let args = replace_source(&args, TOKEN_UNIX_SOCKET_PATH, &socket_path);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Error in UnixListener bind {socket_path:?}"))?;
    debug!("bin {} args {:?}", on_connect.command_bin, args);
    let status = process::Command::new(&on_connect.command_bin)
        .args(&args)
        .status()
        .context("Cannot exec connect callback")?;
    if !status.success() {
        let _ = remove_file(&socket_path);
        return Err(anyhow!("Command execution failed"));
    }
    let (server, _) = listener.accept().context("failed to accept connection")?;
    Ok((server, socket_path))
}

/// Run a session until the browser or the server leaves
pub fn run(
    config: &Config,
    mut ws: WebSocket<TcpStream>,
    username: &str,
    client_addr: &str,
) -> Result<()> {
    // The browser speaks first: its display size
    let (width, height) = match ws.read().context("No hello from the browser")? {
        Message::Text(text) => match serde_json::from_str(&text) {
            Ok(BrowserEvent::Hello { w, h }) => display_size(w, h),
            _ => return Err(anyhow!("Expected the browser hello")),
        },
        _ => return Err(anyhow!("Expected the browser hello")),
    };

    let (server, socket_path) = spawn_server(config, username, client_addr)?;
    let result = serve(&mut ws, server, (width, height));
    let _ = remove_file(&socket_path);
    if let Err(err) = &result {
        let _ = send_json(
            &mut ws,
            serde_json::json!({"t": "error", "message": format!("{err:#}")}),
        );
    }
    let _ = ws.close(None);
    let _ = ws.flush();
    result
}

fn serve(ws: &mut WebSocket<TcpStream>, mut server: UnixStream, size: (u32, u32)) -> Result<()> {
    let server: &mut dyn ReadWrite = &mut server;
    let client_version = tunnel::Version {
        version: VERSION.to_owned(),
    };
    send_client_msg_type!(server, client_version, Version).context("Error in send Version")?;
    let server_version: tunnel::Version =
        recv_server_msg_type!(server, Version).context("Error in recv server version")?;
    if server_version.version != VERSION {
        return Err(anyhow!(
            "Version mismatch server: {:?} gateway: {:?}",
            server_version.version,
            VERSION
        ));
    }

    let hello = recv_server_msg_type!(server, Hello).context("Error in recv ServerHello")?;
    info!("{:?}", hello);
    match hello.msg {
        Some(tunnel::server_hello::Msg::AdaptScreen(_)) => {
            let client_hello = tunnel::ClientHelloResolution {
                audio: false,
                audio_sample_rate: 0,
                width: size.0,
                height: size.1,
                fido: None,
            };
            send_client_msg_type!(server, client_hello, Clienthelloresolution)
                .context("Error in send ClientHelloResolution")?;
        }
        Some(tunnel::server_hello::Msg::Fullscreen(_)) => {
            let client_hello = tunnel::ClientHelloFullscreen {
                audio: false,
                audio_sample_rate: 0,
                fido: None,
            };
            send_client_msg_type!(server, client_hello, Clienthellofullscreen)
                .context("Error in send ClientHelloFullscreen")?;
        }
        None => return Err(anyhow!("Unknown server hello")),
    }
    send_json(
        ws,
        serde_json::json!({"t": "hello", "codec": hello.codec_name}),
    )?;

    // The server waits for our events before each of its frames: poll the
    // browser without blocking, then hand over what came
    ws.get_mut()
        .set_read_timeout(Some(Duration::from_millis(1)))
        .context("Cannot set the WebSocket read timeout")?;
    ws.get_mut().set_nodelay(true).ok();

    loop {
        let events = match read_events(ws)? {
            Some(events) => events,
            None => {
                info!("Browser left");
                return Ok(());
            }
        };
        let mut msgs = vec![];
        let mut last_move = None;
        for event in events {
            let msg = match event {
                BrowserEvent::Move { x, y } => {
                    // If multiple mouse moves, keep only last one
                    last_move = Some(tunnel::message_client::Msg::Move(tunnel::EventMove {
                        x,
                        y,
                    }));
                    continue;
                }
                BrowserEvent::Button { x, y, b, d } => {
                    tunnel::message_client::Msg::Button(tunnel::EventButton {
                        x,
                        y,
                        button: b,
                        updown: d,
                    })
                }
                BrowserEvent::Key { k, d } => tunnel::message_client::Msg::Key(tunnel::EventKey {
                    keycode: k,
                    updown: d,
                }),
                BrowserEvent::Resize { w, h } => {
                    let (width, height) = display_size(w, h);
                    tunnel::message_client::Msg::Display(tunnel::EventDisplay { width, height })
                }
                BrowserEvent::Clipboard { data } => {
                    tunnel::message_client::Msg::Clipboard(tunnel::EventClipboard { data })
                }
                BrowserEvent::Hello { .. } => continue,
            };
            msgs.push(tunnel::MessageClient { msg: Some(msg) });
        }
        msgs.extend(last_move.map(|msg| tunnel::MessageClient { msg: Some(msg) }));
        let msgs = tunnel::MessagesClient {
            msgs,
            fido_reports: vec![],
        };
        send_client_msg_type!(server, msgs, Msgsclient).context("Error in send client events")?;

        let msgs = recv_server_msg_type!(server, Msgssrv).context("Error in recv MessagesSrv")?;
        for msg in msgs.msgs {
            match msg.msg {
                Some(tunnel::message_srv::Msg::ImgEncoded(img)) => {
                    ws.send(binary(FRAME, &[img.width, img.height], &img.data))
                        .context("Cannot send frame")?;
                }
                Some(tunnel::message_srv::Msg::Cursor(cursor)) => {
                    if cursor.data.len() as u64 != cursor.width as u64 * cursor.height as u64 * 4 {
                        warn!("Bad cursor size");
                        continue;
                    }
                    ws.send(binary(
                        CURSOR,
                        &[cursor.width, cursor.height, cursor.xhot, cursor.yhot],
                        &cursor.data,
                    ))
                    .context("Cannot send cursor")?;
                }
                Some(tunnel::message_srv::Msg::Clipboard(clipboard)) => {
                    send_json(
                        ws,
                        serde_json::json!({"t": "clipboard", "data": clipboard.data}),
                    )?;
                }
                Some(tunnel::message_srv::Msg::ImgRaw(_)) => {
                    return Err(anyhow!("Raw images are not supported in the browser"));
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_events_parse() {
        let event: BrowserEvent = serde_json::from_str(r#"{"t":"key","k":38,"d":true}"#).unwrap();
        assert!(matches!(event, BrowserEvent::Key { k: 38, d: true }));
        let event: BrowserEvent =
            serde_json::from_str(r#"{"t":"button","x":1,"y":2,"b":3,"d":false}"#).unwrap();
        assert!(matches!(
            event,
            BrowserEvent::Button {
                x: 1,
                y: 2,
                b: 3,
                d: false
            }
        ));
        assert!(serde_json::from_str::<BrowserEvent>(r#"{"t":"fido"}"#).is_err());
    }

    #[test]
    fn display_size_is_even_and_bounded() {
        assert_eq!(display_size(1921, 1081), (1920, 1080));
        assert_eq!(display_size(0, 99999), (2, MAX_SIZE));
    }
}
