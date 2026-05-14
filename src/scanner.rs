use crate::pattern::Pattern;
use aho_corasick::AhoCorasick;

#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

pub fn scan(data: &[u8], pattern: &Pattern) -> Vec<Match> {
    let mut results = scan_multi(data, &[pattern]);
    results.pop().unwrap_or_default()
}

pub fn scan_multi(data: &[u8], patterns: &[&Pattern]) -> Vec<Vec<Match>> {
    let mut results: Vec<Vec<Match>> = (0..patterns.len()).map(|_| Vec::new()).collect();
    if data.is_empty() || patterns.is_empty() {
        return results;
    }

    let anchors: Vec<(usize, Vec<u8>)> = patterns.iter().map(|p| longest_literal_run(p)).collect();

    if anchors.iter().any(|(_, b)| b.is_empty()) {
        debug_assert!(
            false,
            "parser guarantees every pattern has at least one literal byte"
        );
        return results;
    }

    let needles: Vec<&[u8]> = anchors.iter().map(|(_, b)| b.as_slice()).collect();
    let ac = match AhoCorasick::new(&needles) {
        Ok(ac) => ac,
        Err(_) => return results,
    };

    for mat in ac.find_overlapping_iter(data) {
        let pat_idx = mat.pattern().as_usize();
        let pat = patterns[pat_idx];
        let anchor_offset = anchors[pat_idx].0;
        let anchor_pos = mat.start();
        if anchor_pos < anchor_offset {
            continue;
        }
        let start = anchor_pos - anchor_offset;
        if start + pat.len() > data.len() {
            continue;
        }
        if matches_at(data, start, pat) {
            results[pat_idx].push(Match {
                offset: start,
                bytes: data[start..start + pat.len()].to_vec(),
            });
        }
    }

    results
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

fn longest_literal_run(pattern: &Pattern) -> (usize, Vec<u8>) {
    let mut best_start = 0;
    let mut best_len = 0;
    let mut cur_start = 0;
    let mut cur_len = 0;
    for (i, b) in pattern.iter().enumerate() {
        match b {
            Some(_) => {
                if cur_len == 0 {
                    cur_start = i;
                }
                cur_len += 1;
                if cur_len > best_len {
                    best_len = cur_len;
                    best_start = cur_start;
                }
            }
            None => {
                cur_len = 0;
            }
        }
    }
    let bytes: Vec<u8> = pattern[best_start..best_start + best_len]
        .iter()
        .map(|b| b.expect("literal run cannot include wildcards"))
        .collect();
    (best_start, bytes)
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

    #[test]
    fn scan_multi_returns_per_pattern_results() {
        let data = [0x48u8, 0x8B, 0x05, 0xE8, 0x01, 0x02, 0x03, 0x04];
        let p1 = pat("48 8B 05");
        let p2 = pat("E8 ?? ?? ?? ??");
        let result = scan_multi(&data, &[&p1, &p2]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].len(), 1);
        assert_eq!(result[0][0].offset, 0);
        assert_eq!(result[1].len(), 1);
        assert_eq!(result[1][0].offset, 3);
    }

    #[test]
    fn scan_multi_uses_longest_literal_run_as_anchor() {
        let data = [0x48u8, 0x11, 0x22, 0x33, 0xE8, 0x89, 0xC0, 0xFF];
        let p = pat("48 ?? ?? ?? E8 89 C0");
        let result = scan_multi(&data, &[&p]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].len(), 1);
        assert_eq!(result[0][0].offset, 0);
        assert_eq!(
            result[0][0].bytes,
            vec![0x48, 0x11, 0x22, 0x33, 0xE8, 0x89, 0xC0]
        );
    }

    #[test]
    fn scan_multi_skips_when_anchor_before_data_start() {
        let data = [0xE8u8, 0x89, 0xC0];
        let p = pat("48 ?? ?? ?? E8 89 C0");
        let result = scan_multi(&data, &[&p]);
        assert!(result[0].is_empty());
    }

    #[test]
    fn scan_multi_empty_patterns_returns_empty() {
        let data = [0x00u8; 4];
        let result: Vec<Vec<Match>> = scan_multi(&data, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn scan_multi_empty_data_returns_empty_per_pattern_vecs() {
        let p1 = pat("48 8B");
        let p2 = pat("E8");
        let result = scan_multi(&[], &[&p1, &p2]);
        assert_eq!(result.len(), 2);
        assert!(result[0].is_empty());
        assert!(result[1].is_empty());
    }

    #[test]
    fn scan_multi_per_pattern_matches_in_offset_order() {
        let data = [0xE8u8, 0x00, 0xE8, 0x01, 0xE8, 0x02];
        let p = pat("E8 ??");
        let result = scan_multi(&data, &[&p]);
        assert_eq!(result[0].len(), 3);
        assert_eq!(result[0][0].offset, 0);
        assert_eq!(result[0][1].offset, 2);
        assert_eq!(result[0][2].offset, 4);
    }

    #[test]
    fn scan_multi_two_patterns_at_same_position() {
        let data = [0x48u8, 0x8B, 0x05, 0xFF, 0xFF];
        let p1 = pat("48 8B");
        let p2 = pat("48 8B 05");
        let result = scan_multi(&data, &[&p1, &p2]);
        assert_eq!(result[0].len(), 1);
        assert_eq!(result[0][0].offset, 0);
        assert_eq!(result[1].len(), 1);
        assert_eq!(result[1][0].offset, 0);
    }

    #[test]
    fn scan_handles_leading_wildcard_via_anchor() {
        let pat: Pattern = vec![None, Some(0x48), Some(0x89)];
        let data = [0xAAu8, 0x48, 0x89, 0xBB, 0xCC];
        let m = scan(&data, &pat);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].offset, 0);
        assert_eq!(m[0].bytes, vec![0xAA, 0x48, 0x89]);
    }

    #[test]
    fn longest_literal_run_picks_longest_not_first() {
        let p = pat("48 ?? ?? ?? E8 89 C0");
        let (start, bytes) = longest_literal_run(&p);
        assert_eq!(start, 4);
        assert_eq!(bytes, vec![0xE8, 0x89, 0xC0]);
    }

    #[test]
    fn longest_literal_run_all_literal() {
        let p = pat("48 8B 05");
        let (start, bytes) = longest_literal_run(&p);
        assert_eq!(start, 0);
        assert_eq!(bytes, vec![0x48, 0x8B, 0x05]);
    }
}
