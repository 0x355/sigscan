use thiserror::Error;

const DOS_MAGIC: u16 = 0x5A4D;
const PE_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SECTION_HEADER_SIZE: usize = 40;
const DOS_HEADER_SIZE: usize = 64;
const E_LFANEW_OFFSET: usize = 0x3C;
const FILE_HEADER_NUM_SECTIONS_OFFSET: usize = 2;
const FILE_HEADER_SIZE_OF_OPTIONAL_OFFSET: usize = 16;
const NT_HEADERS_FILE_HEADER_OFFSET: usize = 4;
const NT_HEADERS_OPTIONAL_OFFSET: usize = 24;
const SECTION_VIRTUAL_SIZE_OFFSET: usize = 8;
const SECTION_VIRTUAL_ADDRESS_OFFSET: usize = 12;
const SECTION_SIZE_OF_RAW_DATA_OFFSET: usize = 16;
const SECTION_POINTER_TO_RAW_DATA_OFFSET: usize = 20;
const SECTION_CHARACTERISTICS_OFFSET: usize = 36;
const OPT_MAGIC_PE32: u16 = 0x10B;
const OPT_MAGIC_PE32PLUS: u16 = 0x20B;
const OPT_IMAGE_BASE_PE32_OFFSET: usize = 28;
const OPT_IMAGE_BASE_PE32PLUS_OFFSET: usize = 24;

pub const MACHINE_I386: u16 = 0x014C;
pub const MACHINE_AMD64: u16 = 0x8664;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeError {
    #[error("buffer too small to be a PE image")]
    Truncated,
    #[error("not a PE image (missing MZ or PE signature)")]
    NotPe,
    #[error("unknown PE Optional Header magic 0x{0:04X}")]
    UnknownOptionalMagic(u16),
}

struct Headers {
    optional_header: usize,
    section_table: usize,
    num_sections: usize,
    machine: u16,
}

fn read_headers(data: &[u8]) -> Result<Headers, PeError> {
    if data.len() < DOS_HEADER_SIZE {
        return Err(PeError::Truncated);
    }

    let dos_magic = read_u16(data, 0).ok_or(PeError::Truncated)?;
    if dos_magic != DOS_MAGIC {
        return Err(PeError::NotPe);
    }

    let e_lfanew = read_u32(data, E_LFANEW_OFFSET).ok_or(PeError::Truncated)? as usize;
    let nt_min_end = e_lfanew
        .checked_add(NT_HEADERS_OPTIONAL_OFFSET)
        .ok_or(PeError::Truncated)?;
    if nt_min_end > data.len() {
        return Err(PeError::Truncated);
    }

    let signature = read_u32(data, e_lfanew).ok_or(PeError::Truncated)?;
    if signature != PE_SIGNATURE {
        return Err(PeError::NotPe);
    }

    let file_header = e_lfanew + NT_HEADERS_FILE_HEADER_OFFSET;
    let machine = read_u16(data, file_header).ok_or(PeError::Truncated)?;
    let num_sections = read_u16(data, file_header + FILE_HEADER_NUM_SECTIONS_OFFSET)
        .ok_or(PeError::Truncated)? as usize;
    let size_of_optional = read_u16(data, file_header + FILE_HEADER_SIZE_OF_OPTIONAL_OFFSET)
        .ok_or(PeError::Truncated)? as usize;
    let optional_header = e_lfanew + NT_HEADERS_OPTIONAL_OFFSET;
    let section_table = optional_header + size_of_optional;

    Ok(Headers {
        optional_header,
        section_table,
        num_sections,
        machine,
    })
}

pub fn machine(data: &[u8]) -> Result<u16, PeError> {
    Ok(read_headers(data)?.machine)
}

pub fn image_base(data: &[u8]) -> Result<u64, PeError> {
    let h = read_headers(data)?;
    let opt = h.optional_header;
    let magic = read_u16(data, opt).ok_or(PeError::Truncated)?;
    match magic {
        OPT_MAGIC_PE32 => read_u32(data, opt + OPT_IMAGE_BASE_PE32_OFFSET)
            .ok_or(PeError::Truncated)
            .map(|v| v as u64),
        OPT_MAGIC_PE32PLUS => {
            let lo = read_u32(data, opt + OPT_IMAGE_BASE_PE32PLUS_OFFSET)
                .ok_or(PeError::Truncated)? as u64;
            let hi = read_u32(data, opt + OPT_IMAGE_BASE_PE32PLUS_OFFSET + 4)
                .ok_or(PeError::Truncated)? as u64;
            Ok((hi << 32) | lo)
        }
        other => Err(PeError::UnknownOptionalMagic(other)),
    }
}

pub fn executable_sections(data: &[u8]) -> Result<Vec<Section>, PeError> {
    let h = read_headers(data)?;
    let table_end = h
        .section_table
        .checked_add(
            h.num_sections
                .checked_mul(SECTION_HEADER_SIZE)
                .ok_or(PeError::Truncated)?,
        )
        .ok_or(PeError::Truncated)?;
    if table_end > data.len() {
        return Err(PeError::Truncated);
    }

    let mut sections = Vec::new();
    for i in 0..h.num_sections {
        let off = h.section_table + i * SECTION_HEADER_SIZE;
        let characteristics =
            read_u32(data, off + SECTION_CHARACTERISTICS_OFFSET).ok_or(PeError::Truncated)?;
        if characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let name_bytes = &data[off..off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let virtual_size =
            read_u32(data, off + SECTION_VIRTUAL_SIZE_OFFSET).ok_or(PeError::Truncated)?;
        let virtual_address =
            read_u32(data, off + SECTION_VIRTUAL_ADDRESS_OFFSET).ok_or(PeError::Truncated)?;
        let size_of_raw_data =
            read_u32(data, off + SECTION_SIZE_OF_RAW_DATA_OFFSET).ok_or(PeError::Truncated)?;
        let pointer_to_raw_data =
            read_u32(data, off + SECTION_POINTER_TO_RAW_DATA_OFFSET).ok_or(PeError::Truncated)?;
        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            pointer_to_raw_data,
            size_of_raw_data,
        });
    }
    Ok(sections)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pe(sections: &[(&str, u32, u32, u32)]) -> Vec<u8> {
        let extended: Vec<_> = sections
            .iter()
            .map(|(n, va, vs, c)| (*n, *va, *vs, 0u32, 0u32, *c))
            .collect();
        build_pe_full(MACHINE_AMD64, OPT_MAGIC_PE32PLUS, 0x1_4000_0000, &extended)
    }

    fn build_pe_full(
        machine: u16,
        opt_magic: u16,
        image_base: u64,
        sections: &[(&str, u32, u32, u32, u32, u32)],
    ) -> Vec<u8> {
        let e_lfanew: usize = 0x80;
        let opt_size: usize = 0xE0;
        let section_table = e_lfanew + NT_HEADERS_OPTIONAL_OFFSET + opt_size;
        let total = section_table + sections.len() * SECTION_HEADER_SIZE;
        let mut buf = vec![0u8; total];
        buf[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
        buf[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        buf[e_lfanew..e_lfanew + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());

        let fh = e_lfanew + NT_HEADERS_FILE_HEADER_OFFSET;
        buf[fh..fh + 2].copy_from_slice(&machine.to_le_bytes());
        buf[fh + 2..fh + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[fh + FILE_HEADER_SIZE_OF_OPTIONAL_OFFSET..fh + FILE_HEADER_SIZE_OF_OPTIONAL_OFFSET + 2]
            .copy_from_slice(&(opt_size as u16).to_le_bytes());

        let opt = e_lfanew + NT_HEADERS_OPTIONAL_OFFSET;
        buf[opt..opt + 2].copy_from_slice(&opt_magic.to_le_bytes());
        match opt_magic {
            OPT_MAGIC_PE32 => {
                let v = image_base as u32;
                buf[opt + OPT_IMAGE_BASE_PE32_OFFSET..opt + OPT_IMAGE_BASE_PE32_OFFSET + 4]
                    .copy_from_slice(&v.to_le_bytes());
            }
            OPT_MAGIC_PE32PLUS => {
                let lo = image_base as u32;
                let hi = (image_base >> 32) as u32;
                buf[opt + OPT_IMAGE_BASE_PE32PLUS_OFFSET..opt + OPT_IMAGE_BASE_PE32PLUS_OFFSET + 4]
                    .copy_from_slice(&lo.to_le_bytes());
                buf[opt + OPT_IMAGE_BASE_PE32PLUS_OFFSET + 4
                    ..opt + OPT_IMAGE_BASE_PE32PLUS_OFFSET + 8]
                    .copy_from_slice(&hi.to_le_bytes());
            }
            _ => {}
        }

        for (i, (name, va, vsize, raw_ptr, raw_size, chars)) in sections.iter().enumerate() {
            let off = section_table + i * SECTION_HEADER_SIZE;
            let name_bytes = name.as_bytes();
            let n = name_bytes.len().min(8);
            buf[off..off + n].copy_from_slice(&name_bytes[..n]);
            buf[off + SECTION_VIRTUAL_SIZE_OFFSET..off + SECTION_VIRTUAL_SIZE_OFFSET + 4]
                .copy_from_slice(&vsize.to_le_bytes());
            buf[off + SECTION_VIRTUAL_ADDRESS_OFFSET..off + SECTION_VIRTUAL_ADDRESS_OFFSET + 4]
                .copy_from_slice(&va.to_le_bytes());
            buf[off + SECTION_SIZE_OF_RAW_DATA_OFFSET..off + SECTION_SIZE_OF_RAW_DATA_OFFSET + 4]
                .copy_from_slice(&raw_size.to_le_bytes());
            buf[off + SECTION_POINTER_TO_RAW_DATA_OFFSET
                ..off + SECTION_POINTER_TO_RAW_DATA_OFFSET + 4]
                .copy_from_slice(&raw_ptr.to_le_bytes());
            buf[off + SECTION_CHARACTERISTICS_OFFSET..off + SECTION_CHARACTERISTICS_OFFSET + 4]
                .copy_from_slice(&chars.to_le_bytes());
        }
        buf
    }

    #[test]
    fn empty_buffer_truncated() {
        assert_eq!(executable_sections(&[]), Err(PeError::Truncated));
    }

    #[test]
    fn short_buffer_truncated() {
        let buf = vec![0u8; 32];
        assert_eq!(executable_sections(&buf), Err(PeError::Truncated));
    }

    #[test]
    fn missing_mz_is_not_pe() {
        let buf = vec![0u8; 256];
        assert_eq!(executable_sections(&buf), Err(PeError::NotPe));
    }

    #[test]
    fn missing_pe_signature_is_not_pe() {
        let mut buf = vec![0u8; 512];
        buf[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
        buf[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&0x80u32.to_le_bytes());
        assert_eq!(executable_sections(&buf), Err(PeError::NotPe));
    }

    #[test]
    fn finds_single_text_section() {
        let buf = build_pe(&[(".text", 0x1000, 0x2000, IMAGE_SCN_MEM_EXECUTE)]);
        let secs = executable_sections(&buf).unwrap();
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0].name, ".text");
        assert_eq!(secs[0].virtual_address, 0x1000);
        assert_eq!(secs[0].virtual_size, 0x2000);
    }

    #[test]
    fn skips_non_executable_sections() {
        let buf = build_pe(&[
            (".text", 0x1000, 0x2000, IMAGE_SCN_MEM_EXECUTE),
            (".rdata", 0x3000, 0x1000, 0x4000_0000),
            (".data", 0x4000, 0x1000, 0xC000_0000),
        ]);
        let secs = executable_sections(&buf).unwrap();
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0].name, ".text");
    }

    #[test]
    fn finds_multiple_executable_sections() {
        let buf = build_pe(&[
            (".text", 0x1000, 0x2000, IMAGE_SCN_MEM_EXECUTE),
            (".rdata", 0x3000, 0x1000, 0x4000_0000),
            (".extra", 0x4000, 0x500, IMAGE_SCN_MEM_EXECUTE | 0x4000_0000),
        ]);
        let secs = executable_sections(&buf).unwrap();
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].name, ".text");
        assert_eq!(secs[1].name, ".extra");
    }

    #[test]
    fn handles_truncated_section_table() {
        let mut buf = build_pe(&[(".text", 0x1000, 0x2000, IMAGE_SCN_MEM_EXECUTE)]);
        buf.truncate(buf.len() - 10);
        assert_eq!(executable_sections(&buf), Err(PeError::Truncated));
    }

    #[test]
    fn machine_returns_amd64() {
        let buf = build_pe_full(MACHINE_AMD64, OPT_MAGIC_PE32PLUS, 0x1_4000_0000, &[]);
        assert_eq!(machine(&buf).unwrap(), MACHINE_AMD64);
    }

    #[test]
    fn machine_returns_i386() {
        let buf = build_pe_full(MACHINE_I386, OPT_MAGIC_PE32, 0x0040_0000, &[]);
        assert_eq!(machine(&buf).unwrap(), MACHINE_I386);
    }

    #[test]
    fn image_base_pe32plus_64bit() {
        let buf = build_pe_full(MACHINE_AMD64, OPT_MAGIC_PE32PLUS, 0x7FF7_1234_5678, &[]);
        assert_eq!(image_base(&buf).unwrap(), 0x7FF7_1234_5678);
    }

    #[test]
    fn image_base_pe32_32bit() {
        let buf = build_pe_full(MACHINE_I386, OPT_MAGIC_PE32, 0x0040_0000, &[]);
        assert_eq!(image_base(&buf).unwrap(), 0x0040_0000);
    }

    #[test]
    fn image_base_unknown_magic() {
        let buf = build_pe_full(MACHINE_AMD64, 0x1234, 0, &[]);
        assert!(matches!(
            image_base(&buf),
            Err(PeError::UnknownOptionalMagic(0x1234))
        ));
    }

    #[test]
    fn section_carries_raw_data_offsets() {
        let buf = build_pe_full(
            MACHINE_AMD64,
            OPT_MAGIC_PE32PLUS,
            0x1_4000_0000,
            &[(
                ".text",
                0x1000,
                0x2000,
                0x400,
                0x2000,
                IMAGE_SCN_MEM_EXECUTE,
            )],
        );
        let secs = executable_sections(&buf).unwrap();
        assert_eq!(secs[0].pointer_to_raw_data, 0x400);
        assert_eq!(secs[0].size_of_raw_data, 0x2000);
    }
}
