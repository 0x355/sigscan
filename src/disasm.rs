use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

#[derive(Debug, Clone, PartialEq)]
pub struct DisasmLine {
    pub ip: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

pub fn instructions_at(
    data: &[u8],
    offset: usize,
    ip: u64,
    bitness: u32,
    count: usize,
) -> Vec<DisasmLine> {
    if offset >= data.len() || count == 0 {
        return Vec::new();
    }
    let slice = &data[offset..];
    let mut decoder = Decoder::with_ip(bitness, slice, ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut out = Vec::with_capacity(count);
    let mut instr = Instruction::default();
    while decoder.can_decode() && out.len() < count {
        decoder.decode_out(&mut instr);
        let rel = (instr.ip() - ip) as usize;
        let len = instr.len();
        if rel + len > slice.len() {
            break;
        }
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        out.push(DisasmLine {
            ip: instr.ip(),
            bytes: slice[rel..rel + len].to_vec(),
            text,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x64_prologue() {
        let data = [0x48, 0x89, 0x5C, 0x24, 0x18, 0xC3];
        let lines = instructions_at(&data, 0, 0x1000, 64, 5);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].ip, 0x1000);
        assert_eq!(lines[0].bytes, vec![0x48, 0x89, 0x5C, 0x24, 0x18]);
        assert!(lines[0].text.contains("mov"));
        assert_eq!(lines[1].ip, 0x1005);
        assert_eq!(lines[1].bytes, vec![0xC3]);
        assert!(lines[1].text.contains("ret"));
    }

    #[test]
    fn decodes_x86_prologue() {
        let data = [0x55, 0x8B, 0xEC, 0xC3];
        let lines = instructions_at(&data, 0, 0x9000, 32, 5);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].text.contains("push"));
        assert!(lines[1].text.contains("mov"));
        assert!(lines[2].text.contains("ret"));
    }

    #[test]
    fn respects_count_limit() {
        let data = vec![0x90u8; 100];
        let lines = instructions_at(&data, 0, 0, 64, 3);
        assert_eq!(lines.len(), 3);
        for line in &lines {
            assert!(line.text.contains("nop"));
        }
    }

    #[test]
    fn offset_at_end_returns_empty() {
        let data = [0x90u8; 4];
        let lines = instructions_at(&data, 4, 0, 64, 5);
        assert!(lines.is_empty());
    }

    #[test]
    fn offset_beyond_end_returns_empty() {
        let data = [0x90u8; 4];
        let lines = instructions_at(&data, 10, 0, 64, 5);
        assert!(lines.is_empty());
    }

    #[test]
    fn zero_count_returns_empty() {
        let data = [0x90u8; 8];
        let lines = instructions_at(&data, 0, 0, 64, 0);
        assert!(lines.is_empty());
    }

    #[test]
    fn ip_is_absolute_from_provided_base() {
        let data = [0x90u8, 0x90, 0x90];
        let lines = instructions_at(&data, 0, 0x7FFF_FFFF_0000, 64, 3);
        assert_eq!(lines[0].ip, 0x7FFF_FFFF_0000);
        assert_eq!(lines[1].ip, 0x7FFF_FFFF_0001);
        assert_eq!(lines[2].ip, 0x7FFF_FFFF_0002);
    }
}
