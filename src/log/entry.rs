use crate::input::HookInput;
use crate::leaks;
use crate::pii;
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub session_id: Option<String>,
    pub hook_event: String,
    pub tool_name: Option<String>,
    pub tool_input_summary: Option<String>,
    pub cwd: Option<String>,
    pub permission_mode: Option<String>,
    pub duration_ms: Option<u64>,
}

impl LogEntry {
    pub fn from_hook_input(input: &HookInput) -> Self {
        let summary = extract_summary(input);
        let redacted_summary = summary.map(|s| redact_sensitive(&truncate(&s, 200)));

        LogEntry {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            session_id: input.session_id.clone(),
            hook_event: input.hook_event_name.clone(),
            tool_name: input.tool_name.clone(),
            tool_input_summary: redacted_summary,
            cwd: input.cwd.clone(),
            permission_mode: input.permission_mode.clone(),
            duration_ms: None,
        }
    }
}

fn extract_summary(input: &HookInput) -> Option<String> {
    match input.hook_event_name.as_str() {
        "PreToolUse" | "PostToolUse" => {
            if let Some(tool_input) = &input.tool_input {
                // Try common fields: command, content, new_string
                if let Some(cmd) = tool_input.get("command").and_then(Value::as_str) {
                    return Some(cmd.to_string());
                }
                if let Some(content) = tool_input.get("content").and_then(Value::as_str) {
                    return Some(content.to_string());
                }
                if let Some(new_str) = tool_input.get("new_string").and_then(Value::as_str) {
                    return Some(new_str.to_string());
                }
                // Fallback: serialize the whole tool_input
                return Some(tool_input.to_string());
            }
            None
        }
        "UserPromptSubmit" => input
            .extra
            .get("content")
            .and_then(Value::as_str)
            .map(String::from),
        _ => None,
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s[..max_len].to_string()
    }
}

fn redact_sensitive(text: &str) -> String {
    let mut result = pii::patterns::redact(text);
    result = leaks::tier1::redact(&result);
    result = leaks::tier2::redact(&result);
    result = leaks::tier3::redact(&result);
    result
}

fn get_log_path() -> PathBuf {
    if let Ok(custom) = std::env::var("WARD_LOG_PATH") {
        PathBuf::from(custom)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".ward").join("events.jsonl")
    }
}

pub fn append_to_log(entry: &LogEntry) -> std::io::Result<()> {
    append_to_log_at(&get_log_path(), entry)
}

pub fn append_to_log_at(path: &std::path::Path, entry: &LogEntry) -> std::io::Result<()> {

    // Auto-create directory
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string(entry)?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    writeln!(file, "{}", json)?;

    Ok(())
}
