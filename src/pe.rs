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
const SECTION_CHARACTERISTICS_OFFSET: usize = 36;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeError {
    #[error("buffer too small to be a PE image")]
    Truncated,
    #[error("not a PE image (missing MZ or PE signature)")]
    NotPe,
}

pub fn executable_sections(data: &[u8]) -> Result<Vec<Section>, PeError> {
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
    let num_sections = read_u16(data, file_header + FILE_HEADER_NUM_SECTIONS_OFFSET)
        .ok_or(PeError::Truncated)? as usize;
    let size_of_optional = read_u16(data, file_header + FILE_HEADER_SIZE_OF_OPTIONAL_OFFSET)
        .ok_or(PeError::Truncated)? as usize;

    let section_table = e_lfanew + NT_HEADERS_OPTIONAL_OFFSET + size_of_optional;
    let table_end = section_table
        .checked_add(
            num_sections
                .checked_mul(SECTION_HEADER_SIZE)
                .ok_or(PeError::Truncated)?,
        )
        .ok_or(PeError::Truncated)?;
    if table_end > data.len() {
        return Err(PeError::Truncated);
    }

    let mut sections = Vec::new();
    for i in 0..num_sections {
        let off = section_table + i * SECTION_HEADER_SIZE;
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
        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
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
        let e_lfanew: usize = 0x80;
        let opt_size: usize = 0xE0;
        let section_table = e_lfanew + NT_HEADERS_OPTIONAL_OFFSET + opt_size;
        let total = section_table + sections.len() * SECTION_HEADER_SIZE;
        let mut buf = vec![0u8; total];
        buf[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
        buf[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        buf[e_lfanew..e_lfanew + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());

        let fh = e_lfanew + NT_HEADERS_FILE_HEADER_OFFSET;
        buf[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[fh + 2..fh + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[fh + FILE_HEADER_SIZE_OF_OPTIONAL_OFFSET..fh + FILE_HEADER_SIZE_OF_OPTIONAL_OFFSET + 2]
            .copy_from_slice(&(opt_size as u16).to_le_bytes());

        for (i, (name, va, vsize, chars)) in sections.iter().enumerate() {
            let off = section_table + i * SECTION_HEADER_SIZE;
            let name_bytes = name.as_bytes();
            let n = name_bytes.len().min(8);
            buf[off..off + n].copy_from_slice(&name_bytes[..n]);
            buf[off + SECTION_VIRTUAL_SIZE_OFFSET..off + SECTION_VIRTUAL_SIZE_OFFSET + 4]
                .copy_from_slice(&vsize.to_le_bytes());
            buf[off + SECTION_VIRTUAL_ADDRESS_OFFSET..off + SECTION_VIRTUAL_ADDRESS_OFFSET + 4]
                .copy_from_slice(&va.to_le_bytes());
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
}
