pub use crate::ReadWrite;
use anyhow::{Context, Result};
use rustls::client::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, WebPkiVerifier,
};
use rustls::ServerConnection;
use rustls::{
    self,
    server::{AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient},
    Certificate, CertificateError, DigitallySignedStruct, Error as TlsError, OwnedTrustAnchor,
    RootCertStore, ServerName, SignatureScheme,
};
use std::{
    fs,
    io::{BufReader, Read, Write},
    sync::Arc,
    time::SystemTime,
};
use x509_parser::extensions::{GeneralName::RFC822Name, ParsedExtension, SubjectAlternativeName};
use x509_parser::prelude::FromDer;

/// Extract the subject alternative names of a parsed certificate
fn cert_alt_names(cert: &x509_parser::certificate::X509Certificate) -> Vec<String> {
    let mut alt_names = vec![];
    for extension in cert.extensions().iter() {
        if let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName { general_names }) =
            extension.parsed_extension()
        {
            for general_name in general_names {
                alt_names.push(format!("{general_name:?}"));
            }
        }
    }
    alt_names
}

/// Format a der encoded certificate into a human readable summary
fn describe_cert(der: &[u8]) -> String {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => format!(
            "subject: {:?} issuer: {:?} serial: {} not_before: {} not_after: {} is_ca: {} alt_names: {:?}",
            cert.subject().to_string(),
            cert.issuer().to_string(),
            cert.raw_serial_as_string(),
            cert.validity().not_before,
            cert.validity().not_after,
            cert.is_ca(),
            cert_alt_names(&cert),
        ),
        Err(err) => format!("Unparsable certificate ({} bytes): {:?}", der.len(), err),
    }
}

/// Format the issuer of a der encoded certificate
fn describe_cert_issuer(der: &[u8]) -> String {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => cert.issuer().to_string(),
        Err(err) => format!("Unparsable certificate ({} bytes): {:?}", der.len(), err),
    }
}

/// Prepend a der sequence header to @der
fn der_wrap_sequence(der: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30u8];
    let len = der.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let len_bytes = len.to_be_bytes();
        let start = len_bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(len_bytes.len() - 1);
        let len_bytes = &len_bytes[start..];
        out.push(0x80 | len_bytes.len() as u8);
        out.extend_from_slice(len_bytes);
    }
    out.extend_from_slice(der);
    out
}

/// Format a der encoded distinguished name (as stored in the root cert store)
/// The trust anchors keep the subject as the raw value of the name, ie without
/// its sequence header: rebuild it if the name cannot be parsed as is
fn describe_dn(der: &[u8]) -> String {
    if let Ok((_, name)) = x509_parser::x509::X509Name::from_der(der) {
        return name.to_string();
    }
    let wrapped = der_wrap_sequence(der);
    match x509_parser::x509::X509Name::from_der(&wrapped) {
        Ok((_, name)) => name.to_string(),
        Err(err) => format!("Unparsable name ({} bytes): {:?}", der.len(), err),
    }
}

/// Load private key from @filename
fn load_private_key(filename: &str) -> Result<rustls::PrivateKey> {
    debug!("Loading private key from {:?}", filename);
    let keyfile = fs::File::open(filename).context("Cannot open private key file")?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).context("Cannot parse private key file")? {
            Some(rustls_pemfile::Item::RSAKey(key)) => {
                debug!("Found rsa private key in {:?}", filename);
                return Ok(rustls::PrivateKey(key));
            }
            Some(rustls_pemfile::Item::PKCS8Key(key)) => {
                debug!("Found pkcs8 private key in {:?}", filename);
                return Ok(rustls::PrivateKey(key));
            }
            None => {
                return Err(anyhow!(
                    "No keys found in {:?} (encrypted keys not supported)",
                    filename
                ))
            }
            Some(item) => {
                debug!("Skipping non key pem item in {:?}: {:?}", filename, item);
            }
        }
    }
}

/// Load Certificates from @filename
fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>> {
    debug!("Loading certificates from {:?}", filename);
    let certfile = fs::File::open(filename).context("Cannot open certificate file")?;
    let mut reader = BufReader::new(certfile);
    let certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut reader)
        .context(format!("Cannot parse certificate file {filename:?}"))?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();
    debug!("Loaded {} certificate(s) from {:?}", certs.len(), filename);
    for (index, cert) in certs.iter().enumerate() {
        debug!("  {} cert {}: {}", filename, index, describe_cert(&cert.0));
    }
    if certs.is_empty() {
        warn!("No certificate found in {:?}", filename);
    }
    Ok(certs)
}

/// Apply tls operation to socket
fn tls_transfer<T: Read + Write>(server: &mut ServerConnection, socket: &mut T) -> Result<()> {
    if server.wants_write() {
        server.write_tls(socket)?;
    }

    if server.wants_read() {
        server.read_tls(socket)?;
    }
    Ok(())
}

/// Loop until tls handshake is done
pub fn tls_do_handshake<T: Read + Write>(
    server: &mut ServerConnection,
    socket: &mut T,
) -> Result<()> {
    while server.is_handshaking() {
        tls_transfer(server, socket).context("Error in tls_transfer")?;
        if let Err(err) = server.process_new_packets() {
            error!("Tls handshake error: {:?}", err);
            if let Some(certs) = server.peer_certificates() {
                error!("Peer sent {} certificate(s)", certs.len());
                for (index, cert) in certs.iter().enumerate() {
                    error!("  peer cert {}: {}", index, describe_cert(&cert.0));
                }
            } else {
                error!("Peer sent no certificate");
            }
            return Err(err).context("Error in process_new_packets");
        }
    }
    debug!(
        "Tls handshake done (protocol: {:?}, cipher suite: {:?})",
        server.protocol_version(),
        server.negotiated_cipher_suite()
    );
    if let Some(certs) = server.peer_certificates() {
        debug!("Client sent {} certificate(s)", certs.len());
        for (index, cert) in certs.iter().enumerate() {
            debug!("  client cert {}: {}", index, describe_cert(&cert.0));
        }
    }
    Ok(())
}

/// Make tls server config from config file
pub fn make_server_config(
    ca_file: &str,
    server_cert: &str,
    server_key: &str,
    auth_client: bool,
) -> Result<Arc<rustls::ServerConfig>> {
    debug!(
        "Making tls server config: ca: {:?} cert: {:?} key: {:?} auth_client: {}",
        ca_file, server_cert, server_key, auth_client
    );
    let mut client_auth_roots = RootCertStore::empty();
    let roots = load_certs(ca_file).context("Cannot load ca certificates")?;
    for root in roots {
        client_auth_roots
            .add(&root)
            .context(format!("Cannot add ca certificate from {ca_file:?}"))?;
    }
    debug!(
        "Client auth root store contains {} certificate(s)",
        client_auth_roots.roots.len()
    );
    let certs = load_certs(server_cert).context("Cannot load server ceritifactes")?;
    if certs.len() == 1 {
        debug!(
            "Only one certificate is sent to the client: if it is not directly \
             signed by a ca trusted by the client, add the intermediate \
             certificates to {:?}",
            server_cert
        );
    }

    let client_auth = if auth_client {
        AllowAnyAuthenticatedClient::new(client_auth_roots).boxed()
    } else {
        AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots).boxed()
    };

    let suites = rustls::ALL_CIPHER_SUITES.to_vec();

    let versions = rustls::ALL_VERSIONS.to_vec();

    let privkey = load_private_key(server_key).context("Cannot load private key")?;
    // TODO XXX: do OCSP?
    let mut config = rustls::ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .context("Inconsistent cipher-suite/versions selected")?
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .context("Bad certificates/private key")?;

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(Arc::new(config))
}

/// Get subject alternative name from certificate
/// In case of multiple subject alternative names, return None
pub fn get_subj_alt_names(cert: &x509_parser::certificate::X509Certificate) -> Result<String> {
    let extensions = cert.extensions();
    let mut alt_name = None;
    for extension in extensions.iter() {
        debug!("extension: {:?}", extension.parsed_extension());
        let extension = extension.parsed_extension();
        if let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName { general_names }) =
            extension
        {
            for general_name in general_names {
                if let RFC822Name(email) = &general_name {
                    debug!("Email: {:?}", email);
                    if alt_name.is_some() {
                        // If multiple alt name, return err
                        return Err(anyhow!("Unsupported multiple subject alternative name",));
                    }
                    alt_name = Some(email.to_string());
                }
            }
        }
    }
    match alt_name {
        Some(alt_name) => Ok(alt_name),
        None => Err(anyhow!("No subject alternative name found",)),
    }
}

/// Maximum number of certificates accepted in a client chain: the leaf, the
/// issuing intermediate and some slack for a deeper PKI. A longer chain is
/// refused rather than parsed.
pub const MAX_CLIENT_CHAIN_LEN: usize = 4;

/// Return the user name carried by a client certificate chain, once the TLS
/// handshake has succeeded.
///
/// The identity is read from the *leaf* certificate (`certs[0]`), which is the
/// only one rustls has verified (`AllowAnyAuthenticatedClient` validates
/// `certs[0]` with `certs[1..]` as candidate intermediates and silently ignores
/// the ones that do not chain). Any other certificate of the chain is chosen
/// by the client: reading the identity from it (as the former `certs.last()`
/// did) let a client append a self-signed certificate carrying another
/// account's rfc822 name and log in as that account.
pub fn client_username_from_peer_certs(
    certs: &[Certificate],
    allowed_client_domains: &[String],
) -> Result<String> {
    if certs.len() > MAX_CLIENT_CHAIN_LEN {
        return Err(anyhow!(
            "Client certificate chain too long ({} > {})",
            certs.len(),
            MAX_CLIENT_CHAIN_LEN
        ));
    }
    let leaf = certs.first().ok_or_else(|| anyhow!("No cert from user"))?;
    let (_data, leaf) = x509_parser::certificate::X509Certificate::from_der(&leaf.0)
        .context("Error in X509Certificate from der")?;
    let subj_alt_name =
        get_subj_alt_names(&leaf).context("Error in get subject alternative name")?;
    debug!("Alt name: {:?}", subj_alt_name);
    crate::utils::get_username_from_principal(&subj_alt_name, allowed_client_domains)
        .context("Principal doesnt match realm pattern")
}

/// Server certificate verifier which logs the certificate chain sent by the
/// server and the reason of the verification failures.
/// The verification itself is delegated to the standard webpki verifier, so the
/// trust decision is left unchanged.
struct DebugServerCertVerifier {
    verifier: WebPkiVerifier,
    /// Subjects of the trusted ca, kept for logging purpose
    root_subjects: Vec<String>,
}

impl DebugServerCertVerifier {
    fn new(roots: RootCertStore) -> Self {
        let root_subjects = roots
            .roots
            .iter()
            .map(|root| {
                let der: &[u8] = root.subject().as_ref();
                describe_dn(der)
            })
            .collect();
        DebugServerCertVerifier {
            verifier: WebPkiVerifier::new(roots, None),
            root_subjects,
        }
    }

    /// Log details on the trust chain we have been given
    fn log_chain(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
    ) {
        debug!("Verifying server certificate for name {:?}", server_name);
        debug!("Server certificate: {}", describe_cert(&end_entity.0));
        debug!(
            "Server sent {} intermediate certificate(s)",
            intermediates.len()
        );
        for (index, intermediate) in intermediates.iter().enumerate() {
            debug!(
                "  intermediate cert {}: {}",
                index,
                describe_cert(&intermediate.0)
            );
        }
        debug!(
            "Client trusts {} ca certificate(s)",
            self.root_subjects.len()
        );
        for (index, subject) in self.root_subjects.iter().enumerate() {
            debug!("  trusted ca {}: {:?}", index, subject);
        }
    }

    /// Log some hints on the cause of a verification error
    fn log_error(
        &self,
        err: &TlsError,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
    ) {
        error!("Server certificate verification failed: {:?}", err);
        match err {
            TlsError::InvalidCertificate(CertificateError::UnknownIssuer) => {
                let last = intermediates.last().unwrap_or(end_entity);
                let issuer = describe_cert_issuer(&last.0);
                error!(
                    "Issuer of the last certificate of the chain: {:?}",
                    issuer
                );
                error!("Trusted ca subjects: {:?}", self.root_subjects);
                if self.root_subjects.contains(&issuer) {
                    error!(
                        "A trusted ca has the same subject as this issuer: the chain \
                         could not be validated for another reason. Check that the ca \
                         certificate is the one which really signed the chain, that it \
                         has basicConstraints CA:true, that no certificate is expired, \
                         and that the signature algorithms and key sizes are supported \
                         (webpki rejects sha1, small rsa keys and the p521 curve)"
                    );
                } else {
                    error!(
                        "Hint: either the ca given to the client is not the one which \
                         signed the server certificate, or the server does not send \
                         the intermediate certificates of its chain"
                    );
                }
            }
            TlsError::InvalidCertificate(CertificateError::NotValidForName) => {
                error!(
                    "The server certificate is not valid for the requested name {:?}",
                    server_name
                );
                error!(
                    "Hint: the tls server name of the client must match the subject \
                     alternative name of the server certificate"
                );
            }
            TlsError::InvalidCertificate(CertificateError::Expired) => {
                error!("The server certificate chain is expired or not yet valid");
            }
            TlsError::InvalidCertificate(CertificateError::BadEncoding) => {
                error!("The server certificate is malformed");
            }
            _ => {}
        }
    }
}

impl ServerCertVerifier for DebugServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.log_chain(end_entity, intermediates, server_name);
        match self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        ) {
            Ok(verified) => {
                debug!("Server certificate chain is valid");
                Ok(verified)
            }
            Err(err) => {
                self.log_error(&err, end_entity, intermediates, server_name);
                Err(err)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier
            .verify_tls12_signature(message, cert, dss)
            .map_err(|err| {
                error!("Tls 1.2 signature verification failed: {:?}", err);
                err
            })
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier
            .verify_tls13_signature(message, cert, dss)
            .map_err(|err| {
                error!("Tls 1.3 signature verification failed: {:?}", err);
                err
            })
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }

    fn request_scts(&self) -> bool {
        self.verifier.request_scts()
    }
}

/// Make tls client config from config file
pub fn make_client_config(
    ca_file: Option<&str>,
    client_cert: Option<&str>,
    client_key: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>> {
    debug!(
        "Making tls client config: ca: {:?} client cert: {:?} client key: {:?}",
        ca_file, client_cert, client_key
    );
    let mut root_store = RootCertStore::empty();

    if ca_file.is_some() {
        let cafile = ca_file.as_ref().unwrap();

        debug!("Loading trusted ca from {:?}", cafile);
        let certfile = fs::File::open(cafile).context("Cannot open CA file")?;
        let mut reader = BufReader::new(certfile);
        let ca_certs = rustls_pemfile::certs(&mut reader)
            .context(format!("Cannot parse CA file {cafile:?}"))?;
        debug!("Found {} certificate(s) in {:?}", ca_certs.len(), cafile);
        for (index, ca_cert) in ca_certs.iter().enumerate() {
            debug!("  ca cert {}: {}", index, describe_cert(ca_cert));
        }
        let (added, ignored) = root_store.add_parsable_certificates(&ca_certs);
        debug!(
            "Added {} ca certificate(s) to the trust store, ignored {}",
            added, ignored
        );
        if ignored != 0 {
            warn!("{} certificate(s) of {:?} were rejected", ignored, cafile);
        }
        if added == 0 {
            warn!(
                "No usable ca certificate in {:?}: every server certificate \
                 will be rejected with 'UnknownCA'",
                cafile
            );
        }
    } else {
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        debug!(
            "No ca file given: using the {} builtin webpki roots",
            root_store.roots.len()
        );
    }

    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();

    let versions = rustls::DEFAULT_VERSIONS.to_vec();

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .context("Inconsistent cipher-suite/versions selected")?
        .with_root_certificates(root_store.clone());

    let mut config = match (client_cert, client_key) {
        (Some(client_cert), Some(client_key)) => {
            let certs = load_certs(client_cert).context("Cannot load ca certificates")?;
            let key = load_private_key(client_key).context("Cannot load private key")?;
            config
                .with_client_auth_cert(certs, key)
                .context("Invalid client auth certs/key")?
        }
        (None, None) => {
            debug!("No client certificate given");
            config.with_no_client_auth()
        }
        _ => {
            panic!("Give both client cert/key");
        }
    };

    // Keep the standard trust decision, but log the certificate chain and the
    // verification errors
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(DebugServerCertVerifier::new(root_store)));

    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.enable_sni = false;
    debug!("Tls client config ready (sni disabled)");
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;
    use std::time::{Duration, UNIX_EPOCH};

    // Real chain from a deployment: root CA and server certificate. The root
    // and the intermediate carry critical name constraints (DNS, IP and
    // rfc822). rustls-webpki 0.100 rejected this chain with `UnknownIssuer`;
    // 0.101, pulled by rustls 0.21.12, accepts it.
    const LAB_ROOT: &[u8] = include_bytes!("testdata/lab-root-g2.pem");
    const SURF_CHAIN: &[u8] = include_bytes!("testdata/surf-chain-g2.pem");

    /// 2026-09-21, within the validity of the server certificate
    /// (2026-09-13 to 2026-12-12): the test does not depend on today's date.
    fn during_validity() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_790_000_000)
    }

    fn certs(pem: &[u8]) -> Vec<Vec<u8>> {
        rustls_pemfile::certs(&mut &pem[..]).unwrap()
    }

    fn lab_verifier() -> DebugServerCertVerifier {
        let mut roots = RootCertStore::empty();
        let (added, ignored) = roots.add_parsable_certificates(&certs(LAB_ROOT));
        assert_eq!((added, ignored), (1, 0));
        DebugServerCertVerifier::new(roots)
    }

    fn verify(name: &str) -> Result<ServerCertVerified, TlsError> {
        let chain: Vec<Certificate> = certs(SURF_CHAIN).into_iter().map(Certificate).collect();
        lab_verifier().verify_server_cert(
            &chain[0],
            &chain[1..],
            &ServerName::try_from(name).unwrap(),
            &mut std::iter::empty(),
            &[],
            during_validity(),
        )
    }

    #[test]
    fn accepts_a_chain_under_a_name_constrained_root() {
        verify("surf.fred.lab").expect("a chain under a name constrained root must be accepted");
    }

    #[test]
    fn still_checks_the_server_name() {
        assert!(matches!(
            verify("surf.example.com"),
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidForName
            ))
        ));
    }

    // Self-signed test certificates carrying `email:fred@fred.lab` and
    // `email:jean@fred.lab`: only their subject alternative name matters here.
    const CLIENT_FRED: &[u8] = include_bytes!("testdata/client-fred.pem");
    const CLIENT_JEAN: &[u8] = include_bytes!("testdata/client-jean.pem");

    fn client_chain(pems: &[&[u8]]) -> Vec<Certificate> {
        pems.iter()
            .flat_map(|pem| certs(pem))
            .map(Certificate)
            .collect()
    }

    fn lab_domains() -> Vec<String> {
        vec!["fred.lab".to_owned()]
    }

    #[test]
    fn client_identity_comes_from_the_leaf() {
        let chain = client_chain(&[CLIENT_FRED]);
        assert_eq!(
            client_username_from_peer_certs(&chain, &lab_domains()).unwrap(),
            "fred"
        );
    }

    #[test]
    fn an_appended_certificate_cannot_impersonate_another_account() {
        // Regression for sanzu-broker-mtls-last-cert: fred's valid leaf
        // followed by a self-signed certificate naming jean must stay fred.
        let chain = client_chain(&[CLIENT_FRED, CLIENT_JEAN]);
        assert_eq!(
            client_username_from_peer_certs(&chain, &lab_domains()).unwrap(),
            "fred"
        );
    }

    #[test]
    fn refuses_an_empty_or_too_long_client_chain() {
        assert!(client_username_from_peer_certs(&[], &lab_domains()).is_err());
        let chain = client_chain(&[CLIENT_FRED; MAX_CLIENT_CHAIN_LEN + 1]);
        assert!(client_username_from_peer_certs(&chain, &lab_domains()).is_err());
    }

    #[test]
    fn refuses_a_leaf_outside_the_allowed_domains() {
        let chain = client_chain(&[CLIENT_FRED]);
        assert!(client_username_from_peer_certs(&chain, &["example.com".to_owned()]).is_err());
    }

    #[test]
    fn builds_a_client_config_from_the_builtin_roots() {
        make_client_config(None, None, None).expect("client config from the builtin webpki roots");
    }
}
