//! Minimal HTTP/1.1: one request per connection, then close
//!
//! The gateway serves a handful of small pages and one WebSocket; keeping the
//! TcpStream at hand lets the session set its read timeout.

use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 16 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    /// Header names in lower case
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?.split(';').find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then_some(value)
        })
    }

    pub fn query_param(&self, name: &str) -> Option<String> {
        url::form_urlencoded::parse(self.query.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }

    pub fn form_param(&self, name: &str) -> Option<String> {
        url::form_urlencoded::parse(&self.body)
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }
}

pub fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let mut buffer = vec![];
    let mut chunk = [0u8; 4096];
    let head_len = loop {
        let size = stream.read(&mut chunk).context("Cannot read request")?;
        if size == 0 {
            return Err(anyhow!("Connection closed before the request head"));
        }
        buffer.extend_from_slice(&chunk[..size]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
        if buffer.len() > MAX_HEAD {
            return Err(anyhow!("Request head too big"));
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    parsed
        .parse(&buffer[..head_len])
        .context("Cannot parse request")?;
    let method = parsed.method.context("No method")?.to_owned();
    let target = parsed.path.context("No path")?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers: HashMap<String, String> = parsed
        .headers
        .iter()
        .map(|header| {
            (
                header.name.to_ascii_lowercase(),
                String::from_utf8_lossy(header.value).into_owned(),
            )
        })
        .collect();

    let body_len = match headers.get("content-length") {
        Some(len) => len.parse::<usize>().context("Bad Content-Length")?,
        None => 0,
    };
    if body_len > MAX_BODY {
        return Err(anyhow!("Request body too big"));
    }
    let mut body = buffer[head_len..].to_vec();
    while body.len() < body_len {
        let size = stream.read(&mut chunk).context("Cannot read body")?;
        if size == 0 {
            return Err(anyhow!("Connection closed in the request body"));
        }
        body.extend_from_slice(&chunk[..size]);
    }
    body.truncate(body_len);

    Ok(Request {
        method,
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body,
    })
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".to_owned(), content_type.to_owned())],
            body: body.into(),
        }
    }

    pub fn html(body: impl Into<Vec<u8>>) -> Response {
        Response::new(200, "text/html; charset=utf-8", body)
    }

    pub fn redirect(location: &str) -> Response {
        Response::new(303, "text/plain", "").header("Location", location)
    }

    pub fn error(status: u16, message: &str) -> Response {
        Response::new(status, "text/plain; charset=utf-8", message)
    }

    pub fn header(mut self, name: &str, value: &str) -> Response {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "",
    }
}

pub fn write_response(stream: &mut TcpStream, response: Response) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason(response.status)
    );
    let security = [
        // Pages, script and style come from the gateway only; the cursor is
        // a data: image
        (
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
        ),
        ("X-Content-Type-Options", "nosniff"),
        // no-referrer would make browsers send "Origin: null" on our own
        // form posts, which the origin check refuses
        ("Referrer-Policy", "same-origin"),
        ("Cache-Control", "no-store"),
    ];
    for (name, value) in security.iter() {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    for (name, value) in response.headers.iter() {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    ));
    stream
        .write_all(head.as_bytes())
        .context("Cannot write response head")?;
    stream
        .write_all(&response.body)
        .context("Cannot write response body")?;
    Ok(())
}
