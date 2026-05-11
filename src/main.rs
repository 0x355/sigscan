#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use clap::Parser;

    let args = sigscan::Args::parse();
    sigscan::run(args)
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("sigscan only supports Windows (x64).");
    std::process::exit(1);
}
