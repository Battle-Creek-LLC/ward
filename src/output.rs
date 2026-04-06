pub struct Match {
    pub category: &'static str,
    pub matched_text: String,
}

pub fn pass() {
    println!("{{\"continue\": true}}");
}

pub fn block(guard_name: &str, matches: &[Match]) {
    let descriptions: Vec<String> = matches
        .iter()
        .map(|m| {
            let redacted = redact(&m.matched_text);
            format!("{} ({})", m.category, redacted)
        })
        .collect();

    eprintln!(
        "WARD {} BLOCKED: Detected {}. Remove sensitive data before proceeding.",
        guard_name,
        descriptions.join(", ")
    );
}

/// Redact the middle of a matched string, keeping first/last few chars
pub fn redact(s: &str) -> String {
    let len = s.len();
    if len <= 6 {
        return "*".repeat(len);
    }
    let keep = 3.min(len / 4);
    format!(
        "{}{}{}",
        &s[..keep],
        "*".repeat(len - keep * 2),
        &s[len - keep..]
    )
}
