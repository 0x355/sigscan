use crate::{modules::ModuleInfo, process::ProcessInfo};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const MAGENTA: &str = "\x1b[35m";
const DIM: &str = "\x1b[2m";

pub fn print_header(proc: &ProcessInfo, is_wow64: bool) {
    let arch = if is_wow64 { "x86 WOW64" } else { "x64" };
    println!(
        "\n{BOLD}{GREEN}[+]{RESET} Process : {BOLD}{}{RESET}  {DIM}(PID {}, {}){RESET}",
        proc.name, proc.pid, arch
    );
}

pub fn print_module_header(module: &ModuleInfo) {
    let end = module.base + module.size as u64;
    println!(
        "{BOLD}{GREEN}[+]{RESET} Module  : {CYAN}{}{RESET}",
        module.name
    );
    println!(
        "{BOLD}{GREEN}[+]{RESET} Range   : {YELLOW}{:016X}{RESET} - {YELLOW}{:016X}{RESET}  \
         {DIM}({} KiB){RESET}",
        module.base,
        end,
        module.size / 1024,
    );
}

pub fn print_match(abs_addr: u64, rel_offset: usize, bytes: &[u8]) {
    let hex_bytes: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    let hex_str = hex_bytes.join(" ");

    println!();
    println!("  {BOLD}{MAGENTA}[MATCH]{RESET}");
    println!(
        "    {DIM}address{RESET} : {BOLD}{YELLOW}{:016X}{RESET}",
        abs_addr
    );
    println!("    {DIM}offset {RESET} : {BOLD}+0x{:X}{RESET}", rel_offset);
    println!("    {DIM}bytes  {RESET} : {CYAN}{}{RESET}", hex_str);
}

pub fn print_no_matches() {
    println!("  {DIM}  no matches{RESET}");
}

pub fn print_summary(count: usize) {
    if count == 0 {
        println!("\n{BOLD}{YELLOW}[-]{RESET} No matches found.\n");
    } else {
        println!(
            "\n{BOLD}{GREEN}[+]{RESET} Total matches: {BOLD}{}{RESET}\n",
            count
        );
    }
}

pub fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}
