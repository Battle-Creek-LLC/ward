use serde_json::Value;

pub struct Match {
    pub category: &'static str,
    pub matched_text: String,
}

pub fn pass() {
    println!("{{\"continue\": true}}");
}

/// PostToolUse: the tool already ran, so instead of blocking we rewrite the
/// tool output via `hookSpecificOutput.updatedToolOutput` with matches masked.
pub fn redact_output(guard_name: &str, tool_response: &Value, matches: &[Match]) {
    // Dedup needles (the same secret can match multiple tiers) and replace
    // longest-first so a secret nested inside a larger match is never orphaned.
    let mut needles: Vec<&Match> = Vec::new();
    for m in matches {
        if !m.matched_text.is_empty() && !needles.iter().any(|n| n.matched_text == m.matched_text) {
            needles.push(m);
        }
    }
    needles.sort_by_key(|m| std::cmp::Reverse(m.matched_text.len()));

    // A match found in the joined scan text but absent from any single string
    // (e.g. spanning a join boundary) can't be masked in place — withhold
    // the whole output rather than risk a partial leak.
    let maskable = needles
        .iter()
        .all(|m| value_contains(tool_response, &m.matched_text));

    let updated = if maskable {
        let mut redacted = tool_response.clone();
        for m in &needles {
            let marker = format!("[WARD {} REDACTED: {}]", guard_name, m.category);
            replace_in_value(&mut redacted, &m.matched_text, &marker);
        }
        match redacted {
            Value::String(s) => s,
            other => other.to_string(),
        }
    } else {
        let categories: Vec<&str> = matches.iter().map(|m| m.category).collect();
        format!(
            "[WARD {}] Tool output withheld: detected {}",
            guard_name,
            categories.join(", ")
        )
    };

    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": updated,
        }
    });
    println!("{response}");
}

fn value_contains(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(s) => s.contains(needle),
        Value::Object(map) => map.values().any(|v| value_contains(v, needle)),
        Value::Array(arr) => arr.iter().any(|v| value_contains(v, needle)),
        _ => false,
    }
}

fn replace_in_value(value: &mut Value, needle: &str, replacement: &str) {
    match value {
        Value::String(s) => {
            if s.contains(needle) {
                *s = s.replace(needle, replacement);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                replace_in_value(v, needle, replacement);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                replace_in_value(v, needle, replacement);
            }
        }
        _ => {}
    }
}

/// PreToolUse: hand the decision to the user via `permissionDecision: "ask"`
/// instead of a hard block. A false positive then costs one keystroke at the
/// permission prompt rather than an aborted turn. Must exit 0 — exit 2 blocks
/// regardless of what this JSON says.
pub fn ask(guard_name: &str, matches: &[Match]) {
    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": format!(
                "WARD {} detected {}. Approve only if this is safe to send.",
                guard_name,
                describe(matches)
            ),
        }
    });
    println!("{response}");
}

pub fn block(guard_name: &str, matches: &[Match]) {
    eprintln!(
        "WARD {} BLOCKED: Detected {}.\nRemove the sensitive data before proceeding.\nIf this is a false positive, run `ward disable -m 5` to skip scanning briefly.",
        guard_name,
        describe(matches)
    );
}

/// Render matches as "Category (ab***yz), Category (…)" with each match
/// partially redacted, so the user can judge a false positive without the
/// full secret being reprinted.
fn describe(matches: &[Match]) -> String {
    matches
        .iter()
        .map(|m| format!("{} ({})", m.category, redact(&m.matched_text)))
        .collect::<Vec<String>>()
        .join(", ")
}

/// Redact the middle of a matched string, keeping first/last few chars
fn redact(s: &str) -> String {
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
