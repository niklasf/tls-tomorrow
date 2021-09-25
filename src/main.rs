use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use clap::Clap;
use once_cell::sync::OnceCell;
use rustls::Session;

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

    static DAYS: OnceCell<u32> = OnceCell::new();
    DAYS.set(args.opt.days).unwrap();

    let mut config = rustls::ClientConfig::new();
    config.root_store = rustls_native_certs::load_native_certs().expect("platform certs");

    let mut danger_zone = config.dangerous();
    danger_zone.set_certificate_verifier(Arc::new(rustls::WebPKIVerifier {
        time: move || {
            Ok(webpki::Time::try_from(
                std::time::SystemTime::now()
                    + Duration::from_secs(u64::from(*DAYS.get().unwrap()) * 24 * 60 * 60),
            )
            .unwrap())
        },
    }));

    let config = Arc::new(config);

    let mut success = true;
    for domain in args.domain {
        match check(&domain, &config) {
            Ok(()) => {}
            Err(err) => {
                println!("{} in {} days: {}", domain, args.opt.days, err);
                success = false;
            }
        }
    }

    std::process::exit(if success { 0 } else { 1 });
}

fn check(domain: &str, config: &Arc<rustls::ClientConfig>) -> Result<(), Box<dyn Error>> {
    let subject = webpki::DNSNameRef::try_from_ascii_str(domain)?;
    let mut client = rustls::ClientSession::new(config, subject);
    let mut socket = std::net::TcpStream::connect((domain, 443))?;
    client.complete_io(&mut socket)?;
    Ok(())
}
