use serde::Deserialize;
use std::{fs::File, io, io::Read, path::Path};

/// Same callback as sanzu_broker: the command starts a sanzu server for the
/// user, which connects back to the unix socket
#[derive(Debug, Deserialize, Clone)]
pub struct Command {
    pub command_bin: String,
    pub command_args: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CmdCallBack {
    pub on_connect: Command,
}

/// Login / password form, checked by PAM
#[derive(Debug, Deserialize, Clone)]
pub struct Pam {
    pub service: String,
}

/// OpenID Connect authorization code flow, with PKCE
#[derive(Debug, Deserialize, Clone)]
pub struct Oidc {
    /// Issuer URL, also the base of the discovery document
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Must be <public_origin>/oidc/callback, as registered at the provider
    pub redirect_uri: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// ID token claim holding the local user name
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
    /// Label of the login button
    #[serde(default = "default_oidc_label")]
    pub label: String,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".to_owned(), "profile".to_owned()]
}

fn default_username_claim() -> String {
    "preferred_username".to_owned()
}

fn default_oidc_label() -> String {
    "Single sign-on".to_owned()
}

fn default_session_lifetime() -> u64 {
    12 * 3600
}

fn default_secure_cookie() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Address and port to listen on, for example 127.0.0.1:8080
    pub listen: String,
    /// Origin the browsers use, for example https://sanzu.example.org: the
    /// WebSocket upgrade must come from it
    pub public_origin: String,
    /// Mark cookies Secure; disable only for a plain http test on localhost
    #[serde(default = "default_secure_cookie")]
    pub secure_cookie: bool,
    /// Seconds a login stays valid
    #[serde(default = "default_session_lifetime")]
    pub session_lifetime: u64,
    pub pam: Option<Pam>,
    pub oidc: Option<Oidc>,
    pub cmd_callback: CmdCallBack,
}

pub fn read_config<P: AsRef<Path>>(path: P) -> io::Result<Config> {
    let mut content = String::new();
    File::open(path)?.read_to_string(&mut content)?;
    toml::from_str(&content).map_err(io::Error::other)
}
