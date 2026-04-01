use crate::entropy::shannon_entropy;
use crate::leaks::stopwords::is_stopword;
use crate::output::Match;
use once_cell::sync::Lazy;
use regex::Regex;

static GENERIC_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)[\w.\-]{0,50}?(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}([\w.\-=]{10,150})"#).unwrap()
});

static CURL_AUTH_HEADER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)curl\b.*(?:-H|--header)\s*["']?Authorization:\s*(?:Bearer|Basic|Token)\s+\S+"#).unwrap()
});

static CURL_AUTH_USER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)curl\b.*(?:-u|--user)\s*["']?\S+:\S+"#).unwrap()
});

/// Allowlist: pure alphabetic/underscore/dot/dash values are not secrets
static ALPHA_ONLY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z_.\-]+$").unwrap());

/// Import statement allowlist
static IMPORT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"import[ \t]+\{[ \t\w,]+\}[ \t]+from[ \t]+['"][^'"]+['"]"#).unwrap()
});

pub fn scan(text: &str) -> Vec<Match> {
    let mut matches = Vec::new();
    let lower = text.to_lowercase();

    let has_generic_kw = lower.contains("access") || lower.contains("auth") || lower.contains("api")
        || lower.contains("credential") || lower.contains("creds") || lower.contains("key")
        || lower.contains("passw") || lower.contains("secret") || lower.contains("token");
    let has_curl = lower.contains("curl");

    if !has_generic_kw && !has_curl {
        return matches;
    }

    // Generic API key with entropy gating and stopword filtering
    if has_generic_kw {
        for caps in GENERIC_API_KEY.captures_iter(text) {
            let full_match = caps.get(0).unwrap();
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");

            // Skip pure alphabetic/underscore/dot/dash values
            if ALPHA_ONLY.is_match(value) {
                continue;
            }

            // Skip stopwords
            if is_stopword(value) {
                continue;
            }

            // Entropy gate: only fire if Shannon entropy >= 3.5
            if shannon_entropy(value) < 3.5 {
                continue;
            }

            // Check if the line contains an import statement — skip if so
            let line = get_line_containing(text, full_match.start());
            if IMPORT_PATTERN.is_match(line) {
                continue;
            }

            matches.push(Match {
                category: "Generic API Key",
                matched_text: full_match.as_str().to_string(),
            });
        }
    }

    // Curl auth header and user
    if has_curl {
        for m in CURL_AUTH_HEADER.find_iter(text) {
            matches.push(Match {
                category: "Curl Auth Header",
                matched_text: m.as_str().to_string(),
            });
        }
        for m in CURL_AUTH_USER.find_iter(text) {
            matches.push(Match {
                category: "Curl Auth User",
                matched_text: m.as_str().to_string(),
            });
        }
    }

    matches
}

/// Get the line of text containing the given byte offset
fn get_line_containing(text: &str, offset: usize) -> &str {
    let start = text[..offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = text[offset..]
        .find('\n')
        .map(|i| offset + i)
        .unwrap_or(text.len());
    &text[start..end]
}

/// Replace all Tier 3 pattern matches with [REDACTED] (raw regex, no entropy gating)
pub fn redact(text: &str) -> String {
    let mut result = text.to_string();
    result = GENERIC_API_KEY
        .replace_all(&result, "[REDACTED]")
        .to_string();
    result = CURL_AUTH_HEADER
        .replace_all(&result, "[REDACTED]")
        .to_string();
    result = CURL_AUTH_USER
        .replace_all(&result, "[REDACTED]")
        .to_string();
    result
}
