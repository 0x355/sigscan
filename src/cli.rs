use clap::Parser;

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
"
)]
pub struct Args {
    pub target: String,
    pub pattern: String,

    #[arg(long, short = 'm')]
    pub module: Option<String>,

    #[arg(long, short = 'f', conflicts_with = "count")]
    pub first: bool,

    #[arg(long, short = 'n', value_name = "N")]
    pub count: Option<usize>,
}
