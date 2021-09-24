use clap::Clap;

#[derive(Clap, Debug)]
struct Opt {
    #[clap(short, long, default_value = "14")]
    days: u32,
    domains: Vec<String>,
}

fn main() {
    let opt = Opt::parse();
    dbg!(opt);
}
