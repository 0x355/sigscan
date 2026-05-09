#![cfg(target_os = "windows")]

mod cli;
mod memory;
mod modules;
mod pattern;
mod process;
mod scanner;
mod utils;

use anyhow::{Context, Result};
use cli::Args;
use clap::Parser;

fn main() -> Result<()> {
    let args = Args::parse();
    run(args)
}

fn run(args: Args) -> Result<()> {
    let pat = pattern::parse(&args.pattern)
        .with_context(|| format!("Failed to parse pattern {}", args.pattern))?;
    
    let proc_info = process::find(&args.target)
        .with_context(|| format!("Could not find process {}", args.target))?;

    utils::print_header(&proc_info);

    let handle = process::open(proc_info.pid)
        .with_context(|| format!("Failed to open process PID {}", proc_info.pid))?;

    let all_modules = modules::enumerate(proc_info.pid)
        .context("Failed to enumerate process modules")?;

    let target_modules: Vec<_> = match &args.module {
        Some(filter) => {
            let fl = filter.to_lowercase();
            let filtered: Vec<_> = all_modules
                .iter()
                .filter(|m| m.name.to_lowercase() == fl)
                .collect();

            if filtered.is_empty() {
                anyhow::bail!("Module '{}' not found in process", filter);
            }
            filtered
        }
        None => all_modules.iter().collect(),
    };

    let limit = if args.first { Some(1) } else { args.count };
    let mut total_matches = 0usize;

    for module in &target_modules {
        utils::print_module_header(module);

        let data = memory::read_module(&handle, module)
            .with_context(|| format!("Failed to read module '{}'", module.name))?;

        let matches = scanner::scan(&data, &pat);

        if matches.is_empty() {
            utils::print_no_matches();
            continue;
        }

        for hit in &matches {
            let abs_addr = module.base + hit.offset as u64;
            let rel_offset = hit.offset;

            utils::print_match(abs_addr, rel_offset, &hit.bytes);
            total_matches += 1;

            if let Some(lim) = limit {
                if total_matches >= lim {
                    utils::print_summary(total_matches);
                    return Ok(());
                }
            }
        }
    }

    utils::print_summary(total_matches);
    Ok(())
}