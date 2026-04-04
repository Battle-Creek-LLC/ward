use crate::output::Match;
use once_cell::sync::Lazy;
use regex::Regex;

static SSN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

static CREDIT_CARD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap());

static EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap()
});

static PHONE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b").unwrap()
});

pub fn scan(text: &str) -> Vec<Match> {
    let mut matches = Vec::new();

    for m in SSN.find_iter(text) {
        // Negative lookbehind simulation: skip if preceded by \d{4}- (ISO date prefix)
        let start = m.start();
        if start >= 5 {
            let prefix = &text[start.saturating_sub(5)..start];
            let bytes = prefix.as_bytes();
            if bytes.len() == 5
                && bytes[0].is_ascii_digit()
                && bytes[1].is_ascii_digit()
                && bytes[2].is_ascii_digit()
                && bytes[3].is_ascii_digit()
                && bytes[4] == b'-'
            {
                continue;
            }
        }
        matches.push(Match {
            category: "SSN",
            matched_text: m.as_str().to_string(),
        });
    }

    for m in CREDIT_CARD.find_iter(text) {
        matches.push(Match {
            category: "Credit Card",
            matched_text: m.as_str().to_string(),
        });
    }

    for m in EMAIL.find_iter(text) {
        // Skip git SSH remote URLs (user@host:path pattern)
        let end = m.end();
        if end < text.len() && text.as_bytes()[end] == b':' {
            continue;
        }
        // Skip git SSH connections (git@host with no colon path)
        let matched = m.as_str();
        if let Some(local) = matched.split('@').next() {
            if local == "git" {
                continue;
            }
        }
        matches.push(Match {
            category: "Email",
            matched_text: matched.to_string(),
        });
    }

    for m in PHONE.find_iter(text) {
        matches.push(Match {
            category: "Phone",
            matched_text: m.as_str().to_string(),
        });
    }

    matches
}

/// Replace all PII pattern matches with [REDACTED]
pub fn redact(text: &str) -> String {
    let mut result = text.to_string();
    // Process SSN with lookbehind simulation — collect ranges first to avoid borrow conflict
    let ssn_ranges: Vec<std::ops::Range<usize>> = SSN
        .find_iter(&result)
        .filter(|m| {
            let start = m.start();
            if start >= 5 {
                let prefix = &result[start.saturating_sub(5)..start];
                let bytes = prefix.as_bytes();
                !(bytes.len() == 5
                    && bytes[0].is_ascii_digit()
                    && bytes[1].is_ascii_digit()
                    && bytes[2].is_ascii_digit()
                    && bytes[3].is_ascii_digit()
                    && bytes[4] == b'-')
            } else {
                true
            }
        })
        .map(|m| m.range())
        .collect();
    // Replace SSN matches in reverse order to preserve positions
    for range in ssn_ranges.into_iter().rev() {
        result.replace_range(range, "[REDACTED]");
    }
    result = CREDIT_CARD.replace_all(&result, "[REDACTED]").to_string();
    // Redact emails but skip git SSH remote/connection patterns
    let email_ranges: Vec<std::ops::Range<usize>> = EMAIL
        .find_iter(&result)
        .filter(|m| {
            let end = m.end();
            if end < result.len() && result.as_bytes()[end] == b':' {
                return false;
            }
            if let Some(local) = m.as_str().split('@').next() {
                if local == "git" {
                    return false;
                }
            }
            true
        })
        .map(|m| m.range())
        .collect();
    for range in email_ranges.into_iter().rev() {
        result.replace_range(range, "[REDACTED]");
    }
    result = PHONE.replace_all(&result, "[REDACTED]").to_string();
    result
}
