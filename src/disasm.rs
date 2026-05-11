use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

#[derive(Debug, Clone, PartialEq)]
pub struct DisasmLine {
    pub ip: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

pub fn instructions_around(
    data: &[u8],
    match_offset: usize,
    match_ip: u64,
    bitness: u32,
    backward_count: usize,
    forward_count: usize,
) -> Vec<DisasmLine> {
    if match_offset > data.len() {
        return Vec::new();
    }

    let mut backward_starts: Vec<(usize, u64)> = Vec::with_capacity(backward_count);
    let mut cur_off = match_offset;
    let mut cur_ip = match_ip;
    for _ in 0..backward_count {
        match sync_backward(data, cur_off, cur_ip, bitness) {
            Some((s, ip)) => {
                backward_starts.push((s, ip));
                cur_off = s;
                cur_ip = ip;
            }
            None => break,
        }
    }
    backward_starts.reverse();

    let mut out = Vec::with_capacity(backward_starts.len() + forward_count);
    let mut formatter = IntelFormatter::new();
    let mut instr = Instruction::default();

    for (start, start_ip) in &backward_starts {
        let slice = &data[*start..];
        let mut decoder = Decoder::with_ip(bitness, slice, *start_ip, DecoderOptions::NONE);
        if !decoder.can_decode() {
            continue;
        }
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            continue;
        }
        let len = instr.len();
        if len > slice.len() {
            continue;
        }
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        out.push(DisasmLine {
            ip: instr.ip(),
            bytes: slice[..len].to_vec(),
            text,
        });
    }

    if forward_count > 0 && match_offset < data.len() {
        let slice = &data[match_offset..];
        let mut decoder = Decoder::with_ip(bitness, slice, match_ip, DecoderOptions::NONE);
        let mut decoded = 0;
        while decoder.can_decode() && decoded < forward_count {
            decoder.decode_out(&mut instr);
            let rel = (instr.ip() - match_ip) as usize;
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
            decoded += 1;
        }
    }

    out
}

fn sync_backward(
    data: &[u8],
    match_offset: usize,
    match_ip: u64,
    bitness: u32,
) -> Option<(usize, u64)> {
    if match_offset == 0 {
        return None;
    }

    let max_back = 15usize.min(match_offset).min(match_ip as usize);
    for back in (1..=max_back).rev() {
        let start_offset = match_offset - back;
        let start_ip = match_ip - back as u64;
        let slice = &data[start_offset..];
        let mut decoder = Decoder::with_ip(bitness, slice, start_ip, DecoderOptions::NONE);
        if !decoder.can_decode() {
            continue;
        }
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            continue;
        }
        let end_ip = instr.ip().wrapping_add(instr.len() as u64);
        if end_ip == match_ip {
            return Some((start_offset, start_ip));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn around_decodes_x64_prologue_forward_only() {
        let data = [0x48, 0x89, 0x5C, 0x24, 0x18, 0xC3];
        let lines = instructions_around(&data, 0, 0x1000, 64, 0, 5);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].ip, 0x1000);
        assert_eq!(lines[0].bytes, vec![0x48, 0x89, 0x5C, 0x24, 0x18]);
        assert!(lines[0].text.contains("mov"));
        assert_eq!(lines[1].ip, 0x1005);
        assert!(lines[1].text.contains("ret"));
    }

    #[test]
    fn around_decodes_x86_prologue_forward_only() {
        let data = [0x55, 0x8B, 0xEC, 0xC3];
        let lines = instructions_around(&data, 0, 0x9000, 32, 0, 5);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].text.contains("push"));
        assert!(lines[1].text.contains("mov"));
        assert!(lines[2].text.contains("ret"));
    }

    #[test]
    fn around_respects_forward_count_limit() {
        let data = vec![0x90u8; 100];
        let lines = instructions_around(&data, 0, 0, 64, 0, 3);
        assert_eq!(lines.len(), 3);
        for line in &lines {
            assert!(line.text.contains("nop"));
        }
    }

    #[test]
    fn around_offset_at_end_returns_empty() {
        let data = [0x90u8; 4];
        let lines = instructions_around(&data, 4, 0, 64, 0, 5);
        assert!(lines.is_empty());
    }

    #[test]
    fn around_offset_beyond_end_returns_empty() {
        let data = [0x90u8; 4];
        let lines = instructions_around(&data, 10, 0, 64, 0, 5);
        assert!(lines.is_empty());
    }

    #[test]
    fn around_zero_count_returns_empty() {
        let data = [0x90u8; 8];
        let lines = instructions_around(&data, 0, 0, 64, 0, 0);
        assert!(lines.is_empty());
    }

    #[test]
    fn around_ip_is_absolute_from_provided_base() {
        let data = [0x90u8, 0x90, 0x90];
        let lines = instructions_around(&data, 0, 0x7FFF_FFFF_0000, 64, 0, 3);
        assert_eq!(lines[0].ip, 0x7FFF_FFFF_0000);
        assert_eq!(lines[1].ip, 0x7FFF_FFFF_0001);
        assert_eq!(lines[2].ip, 0x7FFF_FFFF_0002);
    }

    #[test]
    fn sync_one_step_returns_nop() {
        let data = [0x90, 0x90, 0xC3];
        let result = sync_backward(&data, 2, 0x1002, 64);
        assert_eq!(result, Some((1, 0x1001)));
    }

    #[test]
    fn sync_one_step_returns_multibyte_instruction() {
        let data = [0x48, 0x83, 0xEC, 0x20, 0xC3];
        let result = sync_backward(&data, 4, 0x1004, 64);
        assert_eq!(result, Some((0, 0x1000)));
    }

    #[test]
    fn sync_returns_none_at_offset_zero() {
        let data = [0x48, 0x89, 0x5C];
        let result = sync_backward(&data, 0, 0x1000, 64);
        assert_eq!(result, None);
    }

    #[test]
    fn around_with_backward_synced_on_nops() {
        let data = [0x90, 0x90, 0x48, 0x89, 0x5C, 0x24, 0x18, 0xC3];
        let lines = instructions_around(&data, 2, 0x1002, 64, 2, 2);
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].ip, 0x1000);
        assert!(lines[0].text.contains("nop"));
        assert_eq!(lines[1].ip, 0x1001);
        assert!(lines[1].text.contains("nop"));
        assert_eq!(lines[2].ip, 0x1002);
        assert!(lines[2].text.contains("mov"));
        assert_eq!(lines[3].ip, 0x1007);
        assert!(lines[3].text.contains("ret"));
    }

    #[test]
    fn around_with_backward_synced_on_multibyte() {
        let data = [0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0x5C, 0x24, 0x18, 0xC3];
        let lines = instructions_around(&data, 4, 0x1004, 64, 2, 2);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].ip, 0x1000);
        assert!(lines[0].text.contains("sub"));
        assert_eq!(lines[1].ip, 0x1004);
        assert!(lines[1].text.contains("mov"));
        assert_eq!(lines[2].ip, 0x1009);
        assert!(lines[2].text.contains("ret"));
    }
}
