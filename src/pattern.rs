use thiserror::Error;

pub type Pattern = Vec<Option<u8>>;

#[derive(Debug, Error, PartialEq)]
pub enum PatternError {
    #[error("Pattern is empty")]
    Empty,
    #[error("Invalid token '{0}': expected a two-digit hex byte or '??'")]
    InvalidToken(String),
    #[error("Pattern must start with an exact byte, not a wildcard")]
    StartsWithWildcard,
}

pub fn parse(input: &str) -> Result<Pattern, PatternError> {
    let tokens: Vec<&str> = input.split_whitespace().collect();

    if tokens.is_empty() {
        return Err(PatternError::Empty);
    }

    let mut pattern = Vec::with_capacity(tokens.len());

    for (i, token) in tokens.iter().enumerate() {
        let elem = parse_token(token)
            .map_err(|_| PatternError::InvalidToken(token.to_string()))?;

        if i == 0 && elem.is_none() {
            return Err(PatternError::StartsWithWildcard);
        }

        pattern.push(elem);
    }

    Ok(pattern)
}

pub fn display(pattern: &Pattern) -> String {
    pattern
        .iter()
        .map(|b| match b {
            Some(byte) => format!("{:02X}", byte),
            None => "??".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_token(token: &str) -> Result<Option<u8>, ()> {
    if token == "?" || token == "??" {
        return Ok(None);
    }

    if token.len() != 2 {
        return Err(());
    }

    u8::from_str_radix(token, 16).map(Some).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exact_bytes() {
        let p = parse("48 8B 05").unwrap();
        assert_eq!(p, vec![Some(0x48), Some(0x8B), Some(0x05)]);
    }

    #[test]
    fn parse_wildcards_double_question() {
        let p = parse("48 ?? 89").unwrap();
        assert_eq!(p, vec![Some(0x48), None, Some(0x89)]);
    }

    #[test]
    fn parse_wildcards_single_question() {
        let p = parse("48 ? 89").unwrap();
        assert_eq!(p, vec![Some(0x48), None, Some(0x89)]);
    }

    #[test]
    fn parse_all_wildcards_after_first() {
        let p = parse("E8 ?? ?? ?? ??").unwrap();
        assert_eq!(p.len(), 5);
        assert_eq!(p[0], Some(0xE8));
        assert!(p[1..].iter().all(|b| b.is_none()));
    }

    #[test]
    fn parse_empty_is_error() {
        assert_eq!(parse(""), Err(PatternError::Empty));
        assert_eq!(parse("   "), Err(PatternError::Empty));
    }

    #[test]
    fn parse_invalid_token_is_error() {
        assert!(matches!(
            parse("48 ZZ 89"),
            Err(PatternError::InvalidToken(_))
        ));
        assert!(matches!(
            parse("48 1"),
            Err(PatternError::InvalidToken(_))
        ));
        assert!(matches!(
            parse("48 ABC"),
            Err(PatternError::InvalidToken(_))
        ));
    }

    #[test]
    fn parse_starts_with_wildcard_is_error() {
        assert_eq!(parse("?? 48 89"), Err(PatternError::StartsWithWildcard));
    }

    #[test]
    fn display_roundtrip() {
        let s = "48 8B ?? ?? ?? 89";
        let p = parse(s).unwrap();
        assert_eq!(display(&p), s);
    }

    #[test]
    fn parse_case_insensitive() {
        let lower = parse("48 8b ff").unwrap();
        let upper = parse("48 8B FF").unwrap();
        assert_eq!(lower, upper);
    }

    #[test]
    fn parse_single_byte() {
        let p = parse("CC").unwrap();
        assert_eq!(p, vec![Some(0xCC)]);
    }
}
