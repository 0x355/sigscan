use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sigscan",
    version,
    about = "Windows x64 signature / pattern scanner",
    long_about = None,
    after_help = "\
EXAMPLES:
    sigscan notepad.exe \"48 8B ?? ?? ?? 89\"
    sigscan 4124 \"FF 15 ?? ?? ?? ??\"
    sigscan chrome.exe \"E8 ?? ?? ?? ??\" --module chrome.dll
    sigscan notepad.exe \"48 89\" --first
    sigscan notepad.exe \"48 89\" --count 5
    sigscan notepad.exe --patterns sigs.txt
"
)]
pub struct Args {
    pub target: String,

    #[arg(conflicts_with = "patterns", required_unless_present = "patterns")]
    pub pattern: Option<String>,

    #[arg(long, value_name = "FILE")]
    pub patterns: Option<PathBuf>,

    #[arg(long, short = 'm')]
    pub module: Option<String>,

    #[arg(long, short = 'f', conflicts_with = "count")]
    pub first: bool,

    #[arg(long, short = 'n', value_name = "N")]
    pub count: Option<usize>,

    #[arg(long)]
    pub all_sections: bool,

    #[arg(long)]
    pub disasm: bool,

    #[arg(long, value_name = "N", default_value_t = 5)]
    pub disasm_count: usize,

    #[arg(long, value_name = "N", default_value_t = 2)]
    pub disasm_before: usize,
}
