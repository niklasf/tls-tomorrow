use std::sync::Arc;
use std::time::Duration;
use std::error::Error;

use clap::Clap;
use once_cell::sync::OnceCell;
use rustls::Session;

#[derive(Clap, Debug)]
struct Args {
    domain: Vec<String>,
    #[clap(flatten)]
    opt: Opt,
}

#[derive(Clap, Debug)]
struct Opt {
    #[clap(short, long, default_value = "0")]
    days: u64,
}

static DAYS: OnceCell<u64> = OnceCell::new();

fn main() {
    let args = Args::parse();
    DAYS.set(args.opt.days).unwrap();

    let mut config = rustls::ClientConfig::new();
    config.root_store = rustls_native_certs::load_native_certs().expect("platform certs");

    let mut danger_zone = config.dangerous();
    danger_zone.set_certificate_verifier(Arc::new(rustls::WebPKIVerifier {
        time: move || {
            Ok(webpki::Time::try_from(
                std::time::SystemTime::now()
                    + Duration::from_secs(DAYS.get().expect("days initialized") * 24 * 60 * 60),
            )
            .unwrap())
        },
    }));

    let config = Arc::new(config);

    for domain in args.domain {
        match check(&domain, &config) {
            Ok(()) => {},
            Err(err) => println!("{} in {} days: {}", domain, args.opt.days, err),
        }
    }
}

fn check(domain: &str, config: &Arc<rustls::ClientConfig>) -> Result<(), Box<dyn Error>> {
    let subject = webpki::DNSNameRef::try_from_ascii_str(domain)?;
    let mut client = rustls::ClientSession::new(config, subject);
    let mut socket = std::net::TcpStream::connect((domain, 443))?;
    client.complete_io(&mut socket)?;
    Ok(())
}
