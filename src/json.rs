use crate::disasm::DisasmLine;
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct Output {
    pub target: Target,
    pub modules: Vec<Module>,
    pub total_matches: usize,
}

#[derive(Serialize, Debug)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Target {
    Process {
        name: String,
        pid: u32,
        arch: String,
    },
    File {
        path: String,
        arch: String,
        image_base: String,
        size_bytes: usize,
    },
}

#[derive(Serialize, Debug)]
pub struct Module {
    pub name: String,
    pub base: String,
    pub size: usize,
    pub scope: Vec<String>,
    pub matches: Vec<Match>,
}

#[derive(Serialize, Debug)]
pub struct Match {
    pub pattern: String,
    pub address: String,
    pub offset: String,
    pub bytes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disasm: Option<Vec<DisasmEntry>>,
}

#[derive(Serialize, Debug)]
pub struct DisasmEntry {
    pub ip: String,
    pub bytes: String,
    pub text: String,
    pub is_match: bool,
}

pub fn hex_addr(addr: u64) -> String {
    format!("0x{:X}", addr)
}

pub fn hex_off(off: usize) -> String {
    format!("0x{:X}", off)
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn arch_label(bitness: u32) -> String {
    match bitness {
        32 => "x86".to_string(),
        64 => "x64".to_string(),
        _ => format!("bitness-{}", bitness),
    }
}

pub fn disasm_entries(lines: &[DisasmLine], match_ip: u64) -> Vec<DisasmEntry> {
    lines
        .iter()
        .map(|l| DisasmEntry {
            ip: hex_addr(l.ip),
            bytes: hex_bytes(&l.bytes),
            text: l.text.clone(),
            is_match: l.ip == match_ip,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_addr_uses_uppercase_no_pad() {
        assert_eq!(hex_addr(0x140001830), "0x140001830");
        assert_eq!(hex_addr(0), "0x0");
    }

    #[test]
    fn hex_off_uses_uppercase_no_pad() {
        assert_eq!(hex_off(0x1830), "0x1830");
        assert_eq!(hex_off(0), "0x0");
    }

    #[test]
    fn hex_bytes_space_separated_uppercase() {
        assert_eq!(hex_bytes(&[0x48, 0x89, 0x5C, 0x24]), "48 89 5C 24");
        assert_eq!(hex_bytes(&[]), "");
    }

    #[test]
    fn arch_label_known_bitness() {
        assert_eq!(arch_label(64), "x64");
        assert_eq!(arch_label(32), "x86");
    }

    #[test]
    fn file_target_serializes_with_kind_tag() {
        let t = Target::File {
            path: "x.exe".to_string(),
            arch: "x64".to_string(),
            image_base: "0x140000000".to_string(),
            size_bytes: 4096,
        };
        let s = serde_json::to_string(&t).unwrap();
        assert!(s.contains("\"kind\":\"file\""));
        assert!(s.contains("\"path\":\"x.exe\""));
        assert!(s.contains("\"image_base\":\"0x140000000\""));
    }

    #[test]
    fn process_target_serializes_with_kind_tag() {
        let t = Target::Process {
            name: "notepad.exe".to_string(),
            pid: 1234,
            arch: "x64".to_string(),
        };
        let s = serde_json::to_string(&t).unwrap();
        assert!(s.contains("\"kind\":\"process\""));
        assert!(s.contains("\"pid\":1234"));
    }

    #[test]
    fn match_without_disasm_omits_field() {
        let m = Match {
            pattern: "MATCH".to_string(),
            address: "0x1000".to_string(),
            offset: "0x100".to_string(),
            bytes: "48 89".to_string(),
            disasm: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains("disasm"));
    }

    #[test]
    fn match_with_disasm_includes_array() {
        let m = Match {
            pattern: "MATCH".to_string(),
            address: "0x1000".to_string(),
            offset: "0x100".to_string(),
            bytes: "48 89".to_string(),
            disasm: Some(vec![DisasmEntry {
                ip: "0x1000".to_string(),
                bytes: "48 89".to_string(),
                text: "mov ...".to_string(),
                is_match: true,
            }]),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"disasm\":[{"));
        assert!(s.contains("\"is_match\":true"));
    }

    #[test]
    fn disasm_entries_marks_match_ip() {
        let lines = vec![
            DisasmLine {
                ip: 0x1000,
                bytes: vec![0x90],
                text: "nop".to_string(),
            },
            DisasmLine {
                ip: 0x1001,
                bytes: vec![0xC3],
                text: "ret".to_string(),
            },
        ];
        let entries = disasm_entries(&lines, 0x1001);
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].is_match);
        assert!(entries[1].is_match);
    }

    #[test]
    fn output_top_level_keys_present() {
        let out = Output {
            target: Target::File {
                path: "x".to_string(),
                arch: "x64".to_string(),
                image_base: "0x0".to_string(),
                size_bytes: 0,
            },
            modules: vec![],
            total_matches: 0,
        };
        let s = serde_json::to_string(&out).unwrap();
        assert!(s.contains("\"target\""));
        assert!(s.contains("\"modules\":[]"));
        assert!(s.contains("\"total_matches\":0"));
    }
}
