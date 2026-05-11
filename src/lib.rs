pub mod cli;
pub mod pattern;
pub mod pe;
pub mod scanner;

pub use cli::Args;

#[cfg(target_os = "windows")]
mod memory;
#[cfg(target_os = "windows")]
mod modules;
#[cfg(target_os = "windows")]
mod process;
#[cfg(target_os = "windows")]
mod utils;

#[cfg(target_os = "windows")]
pub fn run(args: Args) -> anyhow::Result<()> {
    use anyhow::Context;

    let pat = pattern::parse(&args.pattern)
        .with_context(|| format!("Failed to parse pattern {}", args.pattern))?;

    let proc_info = process::find(&args.target)
        .with_context(|| format!("Could not find process {}", args.target))?;

    let handle = process::open(proc_info.pid)
        .with_context(|| format!("Failed to open process PID {}", proc_info.pid))?;

    let is_wow64 = process::is_wow64(&handle);
    utils::print_header(&proc_info, is_wow64);

    let all_modules =
        modules::enumerate(proc_info.pid).context("Failed to enumerate process modules")?;

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

        let ranges: Vec<(String, usize, usize)> = if args.all_sections {
            vec![("entire module".to_string(), 0, data.len())]
        } else {
            match pe::executable_sections(&data) {
                Ok(secs) => {
                    let r: Vec<_> = secs
                        .into_iter()
                        .filter_map(|s| {
                            let start = s.virtual_address as usize;
                            let end = (start + s.virtual_size as usize).min(data.len());
                            (start < end && start < data.len()).then_some((s.name, start, end))
                        })
                        .collect();
                    if r.is_empty() {
                        utils::print_scope("no executable sections");
                        utils::print_no_matches();
                        continue;
                    }
                    r
                }
                Err(_) => vec![(
                    "entire module (PE headers not parseable)".to_string(),
                    0,
                    data.len(),
                )],
            }
        };

        let scope_label = ranges
            .iter()
            .map(|(name, _, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        utils::print_scope(&scope_label);

        let mut module_matches: Vec<scanner::Match> = Vec::new();
        for range in &ranges {
            let start = range.1;
            let end = range.2;
            for hit in scanner::scan(&data[start..end], &pat) {
                module_matches.push(scanner::Match {
                    offset: hit.offset + start,
                    bytes: hit.bytes,
                });
            }
        }

        if module_matches.is_empty() {
            utils::print_no_matches();
            continue;
        }

        for hit in &module_matches {
            let abs_addr = module.base + hit.offset as u64;
            utils::print_match(abs_addr, hit.offset, &hit.bytes);
            total_matches += 1;

            if let Some(lim) = limit
                && total_matches >= lim
            {
                utils::print_summary(total_matches);
                return Ok(());
            }
        }
    }

    utils::print_summary(total_matches);
    Ok(())
}
