use crate::pattern::{Pattern, PatternError, parse};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct NamedPattern {
    pub label: Option<String>,
    pub pattern: Pattern,
}

#[derive(Debug, Error)]
pub enum PatternsFileError {
    #[error("Failed to read patterns file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Patterns file contains no patterns")]
    Empty,
    #[error("Line {line}: {source}")]
    Parse {
        line: usize,
        #[source]
        source: PatternError,
    },
}

pub fn load(path: &Path) -> Result<Vec<NamedPattern>, PatternsFileError> {
    let contents = std::fs::read_to_string(path)?;
    parse_text(&contents)
}

pub fn parse_text(text: &str) -> Result<Vec<NamedPattern>, PatternsFileError> {
    let mut out = Vec::new();
    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = strip_comment(raw_line).trim();
        if stripped.is_empty() {
            continue;
        }
        let (label, body) = match stripped.split_once('=') {
            Some((l, p)) => {
                let l = l.trim();
                let label = if l.is_empty() {
                    None
                } else {
                    Some(l.to_string())
                };
                (label, p.trim())
            }
            None => (None, stripped),
        };
        let pat = parse(body).map_err(|source| PatternsFileError::Parse {
            line: line_no,
            source,
        })?;
        out.push(NamedPattern {
            label,
            pattern: pat,
        });
    }
    if out.is_empty() {
        return Err(PatternsFileError::Empty);
    }
    Ok(out)
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(pos) => &line[..pos],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_returns_empty_error() {
        assert!(matches!(parse_text(""), Err(PatternsFileError::Empty)));
    }

    #[test]
    fn whitespace_only_returns_empty_error() {
        assert!(matches!(
            parse_text("\n\n   \n"),
            Err(PatternsFileError::Empty)
        ));
    }

    #[test]
    fn comments_only_returns_empty_error() {
        assert!(matches!(
            parse_text("# comment one\n# comment two\n"),
            Err(PatternsFileError::Empty)
        ));
    }

    #[test]
    fn single_pattern_no_label() {
        let v = parse_text("48 8B 05").unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].label, None);
        assert_eq!(v[0].pattern.len(), 3);
    }

    #[test]
    fn single_pattern_with_label() {
        let v = parse_text("PrintFn = 48 8B 05").unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].label.as_deref(), Some("PrintFn"));
    }

    #[test]
    fn multiple_patterns_mixed() {
        let text = "\
# header comment
PrintFn = 48 8B 05 ?? ?? ?? ??

SomeOther = E8 ?? ?? ?? ??
48 89 5C 24 ?? # trailing comment
";
        let v = parse_text(text).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].label.as_deref(), Some("PrintFn"));
        assert_eq!(v[1].label.as_deref(), Some("SomeOther"));
        assert_eq!(v[2].label, None);
        assert_eq!(v[2].pattern.len(), 5);
    }

    #[test]
    fn invalid_pattern_reports_line_number() {
        let text = "good = 48 8B\nbad  = ZZ 89\n";
        let err = parse_text(text).unwrap_err();
        match err {
            PatternsFileError::Parse { line, .. } => assert_eq!(line, 2),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn empty_label_treated_as_none() {
        let v = parse_text(" = 48 8B").unwrap();
        assert_eq!(v[0].label, None);
    }

    #[test]
    fn trailing_comment_stripped() {
        let v = parse_text("foo = 48 8B # explanatory text").unwrap();
        assert_eq!(v[0].label.as_deref(), Some("foo"));
        assert_eq!(v[0].pattern.len(), 2);
    }
}
