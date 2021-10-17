use std::convert::TryFrom;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use clap::Clap;

/// Try to make TLS connections with manipulated system time.
#[derive(Clap, Debug)]
struct Args {
    /// Domains to check.
    domain: Vec<String>,
    #[clap(flatten)]
    opt: Opt,
}

#[derive(Clap, Debug)]
struct Opt {
    /// Offset for system clock.
    #[clap(short, long, default_value = "0")]
    days: u32,
}

fn main() {
    let args = Args::parse();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(
        rustls_native_certs::load_native_certs()
            .expect("platform certs")
            .roots
            .iter()
            .map(|ta| {
                let ta = ta.to_trust_anchor();
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );

    let verifier = Box::leak(Box::new(rustls::client::WebPkiVerifier::new(
        root_store.clone(),
        None,
    )));

    let tls12_rsa_config = rustls::ClientConfig::builder()
        .with_cipher_suites(&[
            rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("tls12 works")
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();

    let modern_default_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();

    let mut success = true;
    success &= check_all(modern_default_config, "modern defaults", verifier, &args);
    success &= check_all(tls12_rsa_config, "tls12 rsa", verifier, &args);
    std::process::exit(if success { 0 } else { 1 });
}

fn check_all(
    mut config: rustls::ClientConfig,
    config_name: &str,
    verifier: &'static rustls::client::WebPkiVerifier,
    args: &Args,
) -> bool {
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(DelayedVerifier {
            inner: verifier,
            delay: Duration::from_secs(u64::from(args.opt.days) * 24 * 60 * 60),
        }));

    let config = Arc::new(config);

    let mut success = true;
    for domain in &args.domain {
        match check(domain, config.clone()) {
            Ok(()) => {}
            Err(err) => {
                println!(
                    "{} with {} in {} days: {}",
                    domain, config_name, args.opt.days, err
                );
                success = false;
            }
        }
    }
    success
}

fn check(domain: &str, config: Arc<rustls::ClientConfig>) -> Result<(), Box<dyn Error>> {
    let server_name = rustls::ServerName::try_from(domain).expect("server name");
    let mut client = rustls::ClientConnection::new(config, server_name)?;
    let mut socket = std::net::TcpStream::connect((domain, 443))?;
    client.complete_io(&mut socket)?;
    Ok(())
}

struct DelayedVerifier<'a> {
    inner: &'a rustls::client::WebPkiVerifier,
    delay: Duration,
}

impl rustls::client::ServerCertVerifier for DelayedVerifier<'_> {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &rustls::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now + self.delay,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
}
