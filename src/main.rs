use clap::Clap;

#[derive(Clap, Debug)]
struct Args {
    domains: Vec<String>,
    #[clap(flatten)]
    opt: Opt,
}

#[derive(Clap, Debug)]
struct Opt {
    #[clap(short, long, default_value = "14")]
    days: u32,
}

fn main() {
    let args = Args::parse();
    for domain in args.domains {
        validate(domain, &args.opt)
    }
}

fn validate(domain: String, opt: &Opt) {
    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);


}
