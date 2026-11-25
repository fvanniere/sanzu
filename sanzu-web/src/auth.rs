//! Logins: PAM login / password, or OpenID Connect
//!
//! A login yields a random session token in an HttpOnly cookie; the
//! WebSocket upgrade must present it.

use crate::config::{Config, Oidc};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const SESSION_COOKIE: &str = "sanzu_session";
pub const OIDC_COOKIE: &str = "sanzu_oidc";

/// Seconds an OIDC login may take at the provider
const OIDC_PENDING_LIFETIME: u64 = 600;

/// 256 bits from the OS, hex encoded
pub fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|err| anyhow!("getrandom: {err}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct Login {
    username: String,
    expires: u64,
}

/// An authorization request waiting for the provider's callback
struct PendingOidc {
    nonce: String,
    code_verifier: String,
    expires: u64,
}

/// What the gateway learnt from the provider's discovery document
#[derive(Debug, Deserialize, Clone)]
pub struct OidcMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

pub struct Auth {
    lifetime: u64,
    logins: Mutex<HashMap<String, Login>>,
    pending: Mutex<HashMap<String, PendingOidc>>,
    pub oidc: Option<(Oidc, OidcMetadata)>,
}

impl Auth {
    pub fn new(config: &Config) -> Result<Auth> {
        let oidc = match &config.oidc {
            Some(oidc) => {
                let metadata = discover(&oidc.issuer).context("OIDC discovery failed")?;
                info!("OIDC provider {}", metadata.issuer);
                Some((oidc.clone(), metadata))
            }
            None => None,
        };
        Ok(Auth {
            lifetime: config.session_lifetime,
            logins: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            oidc,
        })
    }

    /// Record a login, return its session token
    pub fn login(&self, username: &str) -> Result<String> {
        let token = random_token()?;
        let mut logins = self.logins.lock().unwrap();
        let now = now();
        logins.retain(|_, login| login.expires > now);
        logins.insert(
            token.clone(),
            Login {
                username: username.to_owned(),
                expires: now + self.lifetime,
            },
        );
        Ok(token)
    }

    pub fn user(&self, token: Option<&str>) -> Option<String> {
        let logins = self.logins.lock().unwrap();
        let login = logins.get(token?)?;
        (login.expires > now()).then(|| login.username.clone())
    }

    pub fn logout(&self, token: Option<&str>) {
        if let Some(token) = token {
            self.logins.lock().unwrap().remove(token);
        }
    }

    /// Start an authorization code request: return the state, which the
    /// browser keeps in a cookie, and the provider URL to redirect to
    pub fn oidc_start(&self) -> Result<(String, String)> {
        let (oidc, metadata) = self.oidc.as_ref().context("OIDC is not configured")?;
        let state = random_token()?;
        let nonce = random_token()?;
        let code_verifier = random_token()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

        let mut url = url::Url::parse(&metadata.authorization_endpoint)
            .context("Bad authorization endpoint")?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &oidc.client_id)
            .append_pair("redirect_uri", &oidc.redirect_uri)
            .append_pair("scope", &oidc.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");

        let mut pending = self.pending.lock().unwrap();
        let now = now();
        pending.retain(|_, request| request.expires > now);
        pending.insert(
            state.clone(),
            PendingOidc {
                nonce,
                code_verifier,
                expires: now + OIDC_PENDING_LIFETIME,
            },
        );
        Ok((state, url.into()))
    }

    /// Finish the request: check the state against the browser's cookie,
    /// redeem the code, return the user name from the ID token
    pub fn oidc_finish(
        &self,
        state: &str,
        cookie_state: Option<&str>,
        code: &str,
    ) -> Result<String> {
        let (oidc, metadata) = self.oidc.as_ref().context("OIDC is not configured")?;
        // The cookie binds the callback to the browser that started the login
        if cookie_state != Some(state) {
            return Err(anyhow!("OIDC state does not match the browser cookie"));
        }
        let request = self
            .pending
            .lock()
            .unwrap()
            .remove(state)
            .context("Unknown or reused OIDC state")?;
        if request.expires <= now() {
            return Err(anyhow!("OIDC login took too long"));
        }

        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", oidc.redirect_uri.as_str()),
            ("client_id", oidc.client_id.as_str()),
            ("code_verifier", request.code_verifier.as_str()),
        ];
        if let Some(secret) = &oidc.client_secret {
            form.push(("client_secret", secret.as_str()));
        }
        let response: TokenResponse = ureq::post(&metadata.token_endpoint)
            .timeout(Duration::from_secs(15))
            .send_form(&form)
            .context("Token request failed")?
            .into_json()
            .context("Bad token response")?;

        let claims = id_token_claims(&response.id_token)?;
        check_claims(
            &claims,
            &metadata.issuer,
            &oidc.client_id,
            &request.nonce,
            now(),
        )?;
        let username = claims
            .get(&oidc.username_claim)
            .and_then(|value| value.as_str())
            .with_context(|| format!("ID token has no {:?} claim", oidc.username_claim))?;
        Ok(username.to_owned())
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

fn discover(issuer: &str) -> Result<OidcMetadata> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let metadata: OidcMetadata = ureq::get(&url)
        .timeout(Duration::from_secs(15))
        .call()
        .with_context(|| format!("Cannot fetch {url}"))?
        .into_json()
        .context("Bad discovery document")?;
    if metadata.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(anyhow!(
            "Discovery issuer {:?} differs from the configured {:?}",
            metadata.issuer,
            issuer
        ));
    }
    Ok(metadata)
}

/// Decode the ID token payload
///
/// The signature is not checked: the token comes straight from the token
/// endpoint over TLS, which OpenID Connect Core 3.1.3.7 accepts in place of
/// the signature for a confidential client. The claims are checked.
fn id_token_claims(id_token: &str) -> Result<serde_json::Map<String, serde_json::Value>> {
    let payload = id_token
        .split('.')
        .nth(1)
        .context("ID token is not a JWT")?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .context("ID token payload is not base64url")?;
    serde_json::from_slice(&payload).context("ID token payload is not JSON")
}

fn check_claims(
    claims: &serde_json::Map<String, serde_json::Value>,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: u64,
) -> Result<()> {
    let iss = claims.get("iss").and_then(|value| value.as_str());
    if iss != Some(issuer) {
        return Err(anyhow!("ID token issuer {:?} is not {:?}", iss, issuer));
    }
    let audience_ok = match claims.get("aud") {
        Some(serde_json::Value::String(aud)) => aud == client_id,
        Some(serde_json::Value::Array(auds)) => auds.iter().any(|aud| aud == client_id),
        _ => false,
    };
    if !audience_ok {
        return Err(anyhow!("ID token is not issued to {:?}", client_id));
    }
    let exp = claims.get("exp").and_then(|value| value.as_u64());
    if !matches!(exp, Some(exp) if exp > now) {
        return Err(anyhow!("ID token expired"));
    }
    if claims.get("nonce").and_then(|value| value.as_str()) != Some(nonce) {
        return Err(anyhow!("ID token nonce does not match"));
    }
    Ok(())
}

/// Check a login / password with PAM, return the user name PAM settled on
pub fn pam_login(service: &str, username: &str, password: &str) -> Result<String> {
    let mut client = pam::Client::with_password(service).context("Failed to init PAM client")?;
    client
        .conversation_mut()
        .set_credentials(username, password);
    client
        .authenticate()
        .map_err(|err| anyhow!("PAM authentication failed: {err:?}"))?;
    client.get_user().context("Cannot get PAM user name")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(json: &str) -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn id_token_payload_is_decoded() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"42","preferred_username":"fred"}"#);
        let claims = id_token_claims(&format!("e30.{payload}.sig")).unwrap();
        assert_eq!(claims["preferred_username"], "fred");
        assert!(id_token_claims("not-a-jwt").is_err());
    }

    #[test]
    fn claims_must_match_issuer_audience_expiry_and_nonce() {
        let good =
            claims(r#"{"iss":"https://idp","aud":["other","sanzu"],"exp":2000,"nonce":"n1"}"#);
        assert!(check_claims(&good, "https://idp", "sanzu", "n1", 1000).is_ok());
        assert!(check_claims(&good, "https://evil", "sanzu", "n1", 1000).is_err());
        assert!(check_claims(&good, "https://idp", "web", "n1", 1000).is_err());
        assert!(check_claims(&good, "https://idp", "sanzu", "n2", 1000).is_err());
        assert!(check_claims(&good, "https://idp", "sanzu", "n1", 2000).is_err());
        let no_exp = claims(r#"{"iss":"https://idp","aud":"sanzu","nonce":"n1"}"#);
        assert!(check_claims(&no_exp, "https://idp", "sanzu", "n1", 1000).is_err());
    }
}
