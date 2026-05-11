fn main() -> anyhow::Result<()> {
    use clap::Parser;
    let args = sigscan::Args::parse();
    sigscan::run(args)
}
