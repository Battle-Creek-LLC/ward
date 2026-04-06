use crate::output::Match;
use regex::Regex;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Raw deserialized representation of a `.wardrc` file.
#[derive(Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    allowlist: RawAllowlist,
    #[serde(default)]
    disable: RawDisable,
}

#[derive(Deserialize, Default)]
struct RawAllowlist {
    #[serde(default)]
    values: Vec<String>,
    #[serde(default)]
    patterns: Vec<String>,
}

#[derive(Deserialize, Default)]
struct RawDisable {
    #[serde(default)]
    categories: Vec<String>,
}

/// Compiled configuration ready for evaluation.
pub struct WardConfig {
    values: Vec<String>,
    patterns: Vec<Regex>,
    categories: Vec<String>,
}

impl WardConfig {
    /// Returns `true` if the given match should be skipped (allowed).
    pub fn is_allowed(&self, m: &Match) -> bool {
        // Check disabled categories (case-insensitive)
        let cat_lower = m.category.to_lowercase();
        if self.categories.iter().any(|c| c == &cat_lower) {
            return true;
        }

        // Check exact value allowlist
        if self.values.iter().any(|v| v == &m.matched_text) {
            return true;
        }

        // Check pattern allowlist
        if self.patterns.iter().any(|re| re.is_match(&m.matched_text)) {
            return true;
        }

        false
    }
}

/// Walk up from `start` looking for `.wardrc`. Stops at filesystem root or
/// the user's home directory (whichever is reached first).
pub fn find_wardrc(start: &str) -> Option<PathBuf> {
    let mut dir = Path::new(start).to_path_buf();
    let home = dirs_stop();

    loop {
        let candidate = dir.join(".wardrc");
        if candidate.is_file() {
            return Some(candidate);
        }

        // Stop if we've reached home or the filesystem root
        if Some(dir.as_path()) == home.as_deref() {
            break;
        }

        if !dir.pop() {
            break;
        }
    }

    None
}

/// Load and compile the `.wardrc` for the given working directory.
/// Returns `None` if no config file is found or if parsing fails.
pub fn load_config(cwd: &str) -> Option<WardConfig> {
    let path = find_wardrc(cwd)?;
    let contents = std::fs::read_to_string(&path).ok()?;
    parse_config(&contents)
}

/// Parse TOML content into a compiled `WardConfig`.
fn parse_config(contents: &str) -> Option<WardConfig> {
    let raw: RawConfig = toml::from_str(contents).ok()?;

    let mut compiled_patterns = Vec::new();
    for p in &raw.allowlist.patterns {
        if let Ok(re) = Regex::new(p) {
            compiled_patterns.push(re);
        } else {
            eprintln!("ward: invalid regex in .wardrc allowlist.patterns: {}", p);
        }
    }

    let categories: Vec<String> = raw
        .disable
        .categories
        .iter()
        .map(|c| c.to_lowercase())
        .collect();

    Some(WardConfig {
        values: raw.allowlist.values,
        patterns: compiled_patterns,
        categories,
    })
}

/// Return the user's home directory as a stop boundary.
fn dirs_stop() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
[allowlist]
values = ["some-test-value"]
patterns = ["test_[a-z]+_key"]

[disable]
categories = ["Email", "Phone"]
"#;
        let config = parse_config(toml_str).unwrap();
        assert_eq!(config.values, vec!["some-test-value"]);
        assert_eq!(config.patterns.len(), 1);
        assert_eq!(config.categories, vec!["email", "phone"]);
    }

    #[test]
    fn test_parse_empty_config() {
        let config = parse_config("").unwrap();
        assert!(config.values.is_empty());
        assert!(config.patterns.is_empty());
        assert!(config.categories.is_empty());
    }

    #[test]
    fn test_parse_partial_config() {
        let toml_str = r#"
[disable]
categories = ["SSN"]
"#;
        let config = parse_config(toml_str).unwrap();
        assert!(config.values.is_empty());
        assert!(config.patterns.is_empty());
        assert_eq!(config.categories, vec!["ssn"]);
    }

    #[test]
    fn test_is_allowed_by_category() {
        let config = parse_config("[disable]\ncategories = [\"email\"]").unwrap();
        let m = Match {
            category: "Email",
            matched_text: "allowed-by-category".to_string(),
        };
        assert!(config.is_allowed(&m));
    }

    #[test]
    fn test_is_allowed_by_value() {
        let config =
            parse_config("[allowlist]\nvalues = [\"exact-match-value\"]").unwrap();
        let m = Match {
            category: "Generic API Key",
            matched_text: "exact-match-value".to_string(),
        };
        assert!(config.is_allowed(&m));
    }

    #[test]
    fn test_is_allowed_by_pattern() {
        let config =
            parse_config("[allowlist]\npatterns = [\"test_[a-z]+_key\"]").unwrap();
        let m = Match {
            category: "Generic API Key",
            matched_text: "test_foo_key".to_string(),
        };
        assert!(config.is_allowed(&m));
    }

    #[test]
    fn test_not_allowed() {
        let config =
            parse_config("[allowlist]\nvalues = [\"safe_value\"]").unwrap();
        let m = Match {
            category: "Generic API Key",
            matched_text: "not-in-allowlist".to_string(),
        };
        assert!(!config.is_allowed(&m));
    }

    #[test]
    fn test_find_wardrc_in_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let wardrc = tmp.path().join(".wardrc");
        std::fs::write(&wardrc, "[allowlist]\nvalues = []").unwrap();

        let found = find_wardrc(tmp.path().to_str().unwrap());
        assert_eq!(found, Some(wardrc));
    }

    #[test]
    fn test_find_wardrc_walk_up() {
        let tmp = tempfile::tempdir().unwrap();
        let wardrc = tmp.path().join(".wardrc");
        std::fs::write(&wardrc, "[allowlist]\nvalues = []").unwrap();

        let subdir = tmp.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&subdir).unwrap();

        let found = find_wardrc(subdir.to_str().unwrap());
        assert_eq!(found, Some(wardrc));
    }

    #[test]
    fn test_find_wardrc_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let found = find_wardrc(tmp.path().to_str().unwrap());
        assert!(found.is_none());
    }
}
