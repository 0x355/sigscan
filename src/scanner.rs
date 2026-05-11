use crate::pattern::Pattern;

#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

pub fn scan(data: &[u8], pattern: &Pattern) -> Vec<Match> {
    let pat_len = pattern.len();
    if pat_len == 0 || data.len() < pat_len {
        return Vec::new();
    }

    let first_byte = match pattern[0] {
        Some(b) => b,
        None => unreachable!("parser guarantees first element is not a wildcard"),
    };

    let limit = data.len() - pat_len + 1;
    let mut matches = Vec::new();

    let mut i = 0;
    while i < limit {
        if data[i] != first_byte {
            i += 1;
            continue;
        }

        if matches_at(data, i, pattern) {
            let bytes = data[i..i + pat_len].to_vec();
            matches.push(Match { offset: i, bytes });
        }

        i += 1;
    }

    matches
}

#[inline(always)]
fn matches_at(data: &[u8], offset: usize, pattern: &Pattern) -> bool {
    for (j, pat_byte) in pattern.iter().enumerate() {
        if let Some(expected) = pat_byte
            && data[offset + j] != *expected
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern;

    fn pat(s: &str) -> Pattern {
        pattern::parse(s).unwrap()
    }

    #[test]
    fn exact_match() {
        let data = [0x48u8, 0x8B, 0x05, 0x00, 0x01];
        let m = scan(&data, &pat("48 8B 05"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].offset, 0);
        assert_eq!(m[0].bytes, vec![0x48, 0x8B, 0x05]);
    }

    #[test]
    fn wildcard_match() {
        let data = [0x48u8, 0x8B, 0xAA, 0xBB, 0xCC, 0x89];
        let m = scan(&data, &pat("48 8B ?? ?? ?? 89"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].offset, 0);
        assert_eq!(m[0].bytes, vec![0x48, 0x8B, 0xAA, 0xBB, 0xCC, 0x89]);
    }

    #[test]
    fn multiple_matches() {
        let data = [0xE8u8, 0x01, 0xE8, 0x02, 0xE8, 0x03];
        let m = scan(&data, &pat("E8 ??"));
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].offset, 0);
        assert_eq!(m[1].offset, 2);
        assert_eq!(m[2].offset, 4);
    }

    #[test]
    fn no_match() {
        let data = [0x48u8, 0x8B, 0x05];
        let m = scan(&data, &pat("FF 15"));
        assert!(m.is_empty());
    }

    #[test]
    fn pattern_longer_than_data() {
        let data = [0x48u8, 0x8B];
        let m = scan(&data, &pat("48 8B 05 00 00"));
        assert!(m.is_empty());
    }

    #[test]
    fn match_at_end() {
        let data = [0x00u8, 0x00, 0x48, 0x89];
        let m = scan(&data, &pat("48 89"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].offset, 2);
    }

    #[test]
    fn overlapping_matches() {
        let data = [0xAAu8, 0xAA, 0xAA];
        let m = scan(&data, &pat("AA AA"));
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].offset, 0);
        assert_eq!(m[1].offset, 1);
    }

    #[test]
    fn all_wildcards_after_first_byte() {
        let data = [0xE8u8, 0x01, 0x02, 0x03, 0x04];
        let m = scan(&data, &pat("E8 ?? ?? ?? ??"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].bytes, vec![0xE8, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn empty_data_returns_no_matches() {
        let m = scan(&[], &pat("48 8B"));
        assert!(m.is_empty());
    }
}
