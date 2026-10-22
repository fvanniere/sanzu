//! sanzu-web: the sanzu client in a browser
//!
//! An HTTP gateway serves the web client, logs users in (PAM login /
//! password, OpenID Connect), then starts their sanzu server like
//! sanzu_broker and relays the session over a WebSocket.

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
#[macro_use]
extern crate sanzu_common;

mod auth;
mod config;
mod http;
mod session;

use anyhow::{Context, Result};
use auth::{pam_login, Auth, OIDC_COOKIE, SESSION_COOKIE};
use clap::Parser;
use config::{read_config, Config};
use http::{read_request, write_response, Request, Response};
use std::{
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

const INDEX_HTML: &str = include_str!("../static/index.html");
const LOGIN_HTML: &str = include_str!("../static/login.html");
const SANZU_JS: &str = include_str!("../static/sanzu.js");
const SANZU_CSS: &str = include_str!("../static/sanzu.css");

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Configuration file
    #[clap(long, short = 'f', default_value = "sanzu_web.toml")]
    config: String,
}

struct App {
    config: Config,
    auth: Auth,
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

impl App {
    fn cookie(&self, name: &str, value: &str, max_age: u64) -> String {
        let secure = if self.config.secure_cookie {
            "; Secure"
        } else {
            ""
        };
        // Lax: the OIDC callback is a cross-site navigation that must carry
        // the state cookie
        format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}")
    }

    fn login_page(&self, message: Option<&str>) -> Response {
        let password = if self.config.pam.is_some() {
            r#"<form method="post" action="/login">
  <label>Login <input name="username" autocomplete="username" required autofocus></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Log in</button>
</form>"#
                .to_owned()
        } else {
            String::new()
        };
        let oidc = match &self.auth.oidc {
            Some((oidc, _)) => format!(
                r#"<a class="button" href="/oidc/login">{}</a>"#,
                html_escape(&oidc.label)
            ),
            None => String::new(),
        };
        let message = message
            .map(|message| format!(r#"<p class="error">{}</p>"#, html_escape(message)))
            .unwrap_or_default();
        Response::html(
            LOGIN_HTML
                .replace("{{message}}", &message)
                .replace("{{password}}", &password)
                .replace("{{oidc}}", &oidc),
        )
    }

    /// Logged in: set the session cookie and go to the viewer
    fn logged_in(&self, username: &str) -> Result<Response> {
        info!("Login: {:?}", username);
        let token = self.auth.login(username)?;
        Ok(Response::redirect("/").header(
            "Set-Cookie",
            &self.cookie(SESSION_COOKIE, &token, self.config.session_lifetime),
        ))
    }

    /// The WebSocket must come from our own pages
    fn origin_allowed(&self, request: &Request) -> bool {
        request.header("origin") == Some(self.config.public_origin.trim_end_matches('/'))
    }

    fn route(&self, request: &Request) -> Result<Response> {
        let user = self.auth.user(request.cookie(SESSION_COOKIE));
        Ok(match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/") => match user {
                Some(user) => Response::html(INDEX_HTML.replace("{{user}}", &html_escape(&user))),
                None => Response::redirect("/login"),
            },
            ("GET", "/sanzu.js") => Response::new(200, "text/javascript; charset=utf-8", SANZU_JS),
            ("GET", "/sanzu.css") => Response::new(200, "text/css; charset=utf-8", SANZU_CSS),
            ("GET", "/login") => self.login_page(None),
            ("POST", "/login") => {
                let service = match &self.config.pam {
                    Some(pam) => &pam.service,
                    None => return Ok(Response::error(404, "Password login is disabled")),
                };
                if !self.origin_allowed(request) {
                    warn!("Login from origin {:?} refused", request.header("origin"));
                    return Ok(Response::error(403, "Bad origin"));
                }
                let username = request.form_param("username").unwrap_or_default();
                let password = request.form_param("password").unwrap_or_default();
                match pam_login(service, &username, &password) {
                    Ok(username) => self.logged_in(&username)?,
                    Err(err) => {
                        warn!("Login failed for {:?}: {:#}", username, err);
                        // Slow down password guessing
                        thread::sleep(Duration::from_secs(2));
                        self.login_page(Some("Authentication failed"))
                    }
                }
            }
            ("GET", "/oidc/login") => {
                let (state, url) = self.auth.oidc_start()?;
                Response::redirect(&url)
                    .header("Set-Cookie", &self.cookie(OIDC_COOKIE, &state, 600))
            }
            ("GET", "/oidc/callback") => {
                if let Some(error) = request.query_param("error") {
                    warn!("OIDC provider error: {error}");
                    return Ok(self.login_page(Some("Single sign-on refused")));
                }
                let state = request.query_param("state").unwrap_or_default();
                let code = request.query_param("code").unwrap_or_default();
                match self
                    .auth
                    .oidc_finish(&state, request.cookie(OIDC_COOKIE), &code)
                {
                    Ok(username) => self
                        .logged_in(&username)?
                        .header("Set-Cookie", &self.cookie(OIDC_COOKIE, "", 0)),
                    Err(err) => {
                        warn!("OIDC login failed: {:#}", err);
                        self.login_page(Some("Single sign-on failed"))
                    }
                }
            }
            ("GET", "/logout") => {
                self.auth.logout(request.cookie(SESSION_COOKIE));
                Response::redirect("/login")
                    .header("Set-Cookie", &self.cookie(SESSION_COOKIE, "", 0))
            }
            (_, "/") | (_, "/login") | (_, "/logout") => Response::error(405, "Method not allowed"),
            _ => Response::error(404, "Not found"),
        })
    }
}

fn handle(app: &App, mut stream: TcpStream) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .context("Cannot set read timeout")?;
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    let request = read_request(&mut stream)?;
    debug!("{} {} {}", peer, request.method, request.path);

    if request.path == "/ws" {
        let user = match app.auth.user(request.cookie(SESSION_COOKIE)) {
            Some(user) => user,
            None => return write_response(&mut stream, Response::error(401, "Not logged in")),
        };
        // A WebSocket is not bound by the same-origin policy: refuse other
        // sites riding the session cookie
        if !app.origin_allowed(&request) {
            warn!(
                "WebSocket from origin {:?} refused",
                request.header("origin")
            );
            return write_response(&mut stream, Response::error(403, "Bad origin"));
        }
        stream.set_read_timeout(None).ok();
        let ws = session::accept_websocket(stream, &request)?;
        info!("Session start for {:?} from {}", user, peer);
        let result = session::run(&app.config, ws, &user, &peer);
        info!("Session end for {:?}", user);
        return result;
    }

    let response = match app.route(&request) {
        Ok(response) => response,
        Err(err) => {
            error!("{} {}: {:#}", request.method, request.path, err);
            Response::error(500, "Internal error")
        }
    };
    write_response(&mut stream, response)
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let config = read_config(&args.config)
        .with_context(|| format!("Cannot read configuration {:?}", args.config))?;
    if config.pam.is_none() && config.oidc.is_none() {
        return Err(anyhow!(
            "Configure [pam], [oidc] or both: nobody could log in"
        ));
    }
    let auth = Auth::new(&config)?;
    let listener = TcpListener::bind(&config.listen)
        .with_context(|| format!("Cannot listen on {:?}", config.listen))?;
    info!(
        "Listening on {} for {}",
        config.listen, config.public_origin
    );
    let app = Arc::new(App { config, auth });

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                warn!("Accept failed: {err}");
                continue;
            }
        };
        let app = app.clone();
        thread::spawn(move || {
            if let Err(err) = handle(&app, stream) {
                warn!("{:#}", err);
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_is_escaped() {
        assert_eq!(
            html_escape(r#"<a href="x">&</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;"
        );
    }
}
