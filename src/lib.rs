pub mod cli;
pub mod disasm;
pub mod json;
pub mod pattern;
pub mod patterns_file;
pub mod pe;
pub mod scanner;

mod utils;

#[cfg(target_os = "windows")]
mod memory;
#[cfg(target_os = "windows")]
mod modules;
#[cfg(target_os = "windows")]
mod process;

pub use cli::Args;
use patterns_file::NamedPattern;

struct ScanRange {
    name: String,
    data_start: usize,
    data_end: usize,
    rel_at_start: usize,
    abs_at_start: u64,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let named_patterns = load_patterns(&args)?;
    if is_file_target(&args.target) {
        scan_file(&args, &named_patterns)
    } else {
        scan_process(&args, &named_patterns)
    }
}

#[cfg(not(target_os = "windows"))]
fn scan_process(args: &Args, _named_patterns: &[NamedPattern]) -> anyhow::Result<()> {
    anyhow::bail!(
        "'{}' looks like a process name or PID, but live process scanning is only supported on Windows. \
         Pass a file path (with a / or \\ separator, or a drive letter) to scan a PE on disk.",
        args.target
    )
}

fn load_patterns(args: &Args) -> anyhow::Result<Vec<NamedPattern>> {
    use anyhow::Context;
    match (&args.pattern, &args.patterns) {
        (Some(p), None) => {
            let parsed =
                pattern::parse(p).with_context(|| format!("Failed to parse pattern {}", p))?;
            Ok(vec![NamedPattern {
                label: None,
                pattern: parsed,
            }])
        }
        (None, Some(path)) => patterns_file::load(path)
            .with_context(|| format!("Failed to load patterns from {}", path.display())),
        _ => anyhow::bail!("provide either a positional PATTERN or --patterns FILE"),
    }
}

fn is_file_target(s: &str) -> bool {
    if s.parse::<u32>().is_ok() {
        return false;
    }
    s.contains('/') || s.contains('\\') || s.contains(':')
}

fn scan_file(args: &Args, named_patterns: &[NamedPattern]) -> anyhow::Result<()> {
    use anyhow::Context;

    if args.module.is_some() {
        anyhow::bail!(
            "--module is not supported for on-disk file targets (the file is itself the module)"
        );
    }

    let path = std::path::Path::new(&args.target);
    let data =
        std::fs::read(path).with_context(|| format!("Failed to read file {}", path.display()))?;

    let m = pe::machine(&data)
        .with_context(|| format!("Failed to read PE headers in {}", path.display()))?;
    let image_base = pe::image_base(&data)
        .with_context(|| format!("Failed to read ImageBase in {}", path.display()))?;

    let bitness: u32 = match m {
        pe::MACHINE_I386 => 32,
        pe::MACHINE_AMD64 => 64,
        other => anyhow::bail!(
            "Unsupported PE Machine 0x{:04X} (only x86 and x64 are supported)",
            other
        ),
    };

    if !args.json {
        utils::print_file_header(path, bitness, image_base, data.len());
    }

    let ranges = build_file_ranges(&data, args.all_sections, image_base);

    let module_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());

    let json_target = || json::Target::File {
        path: path.display().to_string(),
        arch: json::arch_label(bitness),
        image_base: json::hex_addr(image_base),
        size_bytes: data.len(),
    };

    if ranges.is_empty() {
        if args.json {
            let output = json::Output {
                target: json_target(),
                modules: vec![json::Module {
                    name: module_name,
                    base: json::hex_addr(image_base),
                    size: data.len(),
                    scope: vec![],
                    matches: vec![],
                }],
                total_matches: 0,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            utils::print_scope("no executable sections");
            utils::print_no_matches();
            utils::print_summary(0);
        }
        return Ok(());
    }

    let scope_names: Vec<String> = ranges.iter().map(|r| r.name.clone()).collect();
    if !args.json {
        utils::print_scope(&scope_names.join(", "));
    }

    let limit = if args.first { Some(1) } else { args.count };
    let mut per_pattern_count = vec![0usize; named_patterns.len()];
    let mut total = 0usize;

    let (had_match, records) = scan_with_ranges(
        &data,
        &ranges,
        named_patterns,
        bitness,
        args,
        limit,
        &mut per_pattern_count,
        &mut total,
    );

    if args.json {
        let output = json::Output {
            target: json_target(),
            modules: vec![json::Module {
                name: module_name,
                base: json::hex_addr(image_base),
                size: data.len(),
                scope: scope_names,
                matches: records,
            }],
            total_matches: total,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if !had_match {
            utils::print_no_matches();
        }
        utils::print_summary(total);
    }
    Ok(())
}

fn build_file_ranges(data: &[u8], all_sections: bool, image_base: u64) -> Vec<ScanRange> {
    if all_sections {
        return vec![ScanRange {
            name: "entire file".to_string(),
            data_start: 0,
            data_end: data.len(),
            rel_at_start: 0,
            abs_at_start: image_base,
        }];
    }
    match pe::executable_sections(data) {
        Ok(secs) => secs
            .into_iter()
            .filter_map(|s| {
                let start = s.pointer_to_raw_data as usize;
                let end = (start + s.size_of_raw_data as usize).min(data.len());
                if start >= end || start >= data.len() {
                    return None;
                }
                Some(ScanRange {
                    name: s.name,
                    data_start: start,
                    data_end: end,
                    rel_at_start: s.virtual_address as usize,
                    abs_at_start: image_base + s.virtual_address as u64,
                })
            })
            .collect(),
        Err(_) => vec![ScanRange {
            name: "entire file (PE headers not parseable)".to_string(),
            data_start: 0,
            data_end: data.len(),
            rel_at_start: 0,
            abs_at_start: image_base,
        }],
    }
}

#[cfg(target_os = "windows")]
fn scan_process(args: &Args, named_patterns: &[NamedPattern]) -> anyhow::Result<()> {
    use anyhow::Context;

    let proc_info = process::find(&args.target)
        .with_context(|| format!("Could not find process {}", args.target))?;

    let handle = process::open(proc_info.pid)
        .with_context(|| format!("Failed to open process PID {}", proc_info.pid))?;

    let is_wow64 = process::is_wow64(&handle);
    if !args.json {
        utils::print_header(&proc_info, is_wow64);
    }

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
    let bitness: u32 = if is_wow64 { 32 } else { 64 };
    let mut per_pattern_count = vec![0usize; named_patterns.len()];
    let mut total = 0usize;
    let mut json_modules: Vec<json::Module> = Vec::new();

    for module in &target_modules {
        if !args.json {
            utils::print_module_header(module);
        }

        let data = memory::read_module(&handle, module)
            .with_context(|| format!("Failed to read module '{}'", module.name))?;

        let ranges = build_process_ranges(&data, args.all_sections, module.base);
        if ranges.is_empty() {
            if args.json {
                json_modules.push(json::Module {
                    name: module.name.clone(),
                    base: json::hex_addr(module.base),
                    size: module.size as usize,
                    scope: vec![],
                    matches: vec![],
                });
            } else {
                utils::print_scope("no executable sections");
                utils::print_no_matches();
            }
            continue;
        }

        let scope_names: Vec<String> = ranges.iter().map(|r| r.name.clone()).collect();
        if !args.json {
            utils::print_scope(&scope_names.join(", "));
        }

        let (had_match, records) = scan_with_ranges(
            &data,
            &ranges,
            named_patterns,
            bitness,
            args,
            limit,
            &mut per_pattern_count,
            &mut total,
        );

        if args.json {
            json_modules.push(json::Module {
                name: module.name.clone(),
                base: json::hex_addr(module.base),
                size: module.size as usize,
                scope: scope_names,
                matches: records,
            });
        } else if !had_match {
            utils::print_no_matches();
        }

        if limit.is_some_and(|l| per_pattern_count.iter().all(|c| *c >= l)) {
            break;
        }
    }

    if args.json {
        let output = json::Output {
            target: json::Target::Process {
                name: proc_info.name.clone(),
                pid: proc_info.pid,
                arch: if is_wow64 {
                    "x86 WOW64".to_string()
                } else {
                    "x64".to_string()
                },
            },
            modules: json_modules,
            total_matches: total,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        utils::print_summary(total);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn build_process_ranges(data: &[u8], all_sections: bool, module_base: u64) -> Vec<ScanRange> {
    if all_sections {
        return vec![ScanRange {
            name: "entire module".to_string(),
            data_start: 0,
            data_end: data.len(),
            rel_at_start: 0,
            abs_at_start: module_base,
        }];
    }
    match pe::executable_sections(data) {
        Ok(secs) => secs
            .into_iter()
            .filter_map(|s| {
                let start = s.virtual_address as usize;
                let end = (start + s.virtual_size as usize).min(data.len());
                if start >= end || start >= data.len() {
                    return None;
                }
                Some(ScanRange {
                    name: s.name,
                    data_start: start,
                    data_end: end,
                    rel_at_start: s.virtual_address as usize,
                    abs_at_start: module_base + s.virtual_address as u64,
                })
            })
            .collect(),
        Err(_) => vec![ScanRange {
            name: "entire module (PE headers not parseable)".to_string(),
            data_start: 0,
            data_end: data.len(),
            rel_at_start: 0,
            abs_at_start: module_base,
        }],
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_with_ranges(
    data: &[u8],
    ranges: &[ScanRange],
    named_patterns: &[NamedPattern],
    bitness: u32,
    args: &Args,
    limit: Option<usize>,
    per_pattern_count: &mut [usize],
    total: &mut usize,
) -> (bool, Vec<json::Match>) {
    let pats: Vec<_> = named_patterns.iter().map(|np| &np.pattern).collect();
    let per_range: Vec<Vec<Vec<scanner::Match>>> = ranges
        .iter()
        .map(|r| scanner::scan_multi(&data[r.data_start..r.data_end], &pats))
        .collect();

    let mut had_match = false;
    let mut records: Vec<json::Match> = Vec::new();
    for (i, np) in named_patterns.iter().enumerate() {
        let label = label_for(np, i, named_patterns.len());
        'ranges: for (r_idx, range) in ranges.iter().enumerate() {
            if limit.is_some_and(|l| per_pattern_count[i] >= l) {
                break 'ranges;
            }
            for hit in &per_range[r_idx][i] {
                if limit.is_some_and(|l| per_pattern_count[i] >= l) {
                    break 'ranges;
                }
                let abs_addr = range.abs_at_start + hit.offset as u64;
                let rel = range.rel_at_start + hit.offset;
                let data_off = range.data_start + hit.offset;

                let disasm_lines = if args.disasm {
                    Some(disasm::instructions_around(
                        data,
                        data_off,
                        abs_addr,
                        bitness,
                        args.disasm_before,
                        args.disasm_count,
                    ))
                } else {
                    None
                };

                if !args.json {
                    utils::print_match(&label, abs_addr, rel, &hit.bytes);
                    if let Some(lines) = &disasm_lines {
                        utils::print_disasm(lines, Some(abs_addr));
                    }
                }

                records.push(json::Match {
                    pattern: label.clone(),
                    address: json::hex_addr(abs_addr),
                    offset: json::hex_off(rel),
                    bytes: json::hex_bytes(&hit.bytes),
                    disasm: disasm_lines
                        .as_ref()
                        .map(|l| json::disasm_entries(l, abs_addr)),
                });

                per_pattern_count[i] += 1;
                *total += 1;
                had_match = true;
            }
        }
    }
    (had_match, records)
}

fn label_for(np: &NamedPattern, idx: usize, total: usize) -> String {
    match &np.label {
        Some(l) => l.clone(),
        None if total == 1 => "MATCH".to_string(),
        None => format!("pattern {}", idx + 1),
    }
}
