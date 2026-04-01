use ward::input::HookInput;
use ward::log::entry::{append_to_log_at, LogEntry};

fn make_hook_input(json: &str) -> HookInput {
    serde_json::from_str(json).unwrap()
}

#[test]
fn test_log_session_start() {
    let input = make_hook_input(r#"{"hook_event_name":"SessionStart","session_id":"test123","cwd":"/tmp","permission_mode":"default"}"#);
    let entry = LogEntry::from_hook_input(&input);
    assert_eq!(entry.hook_event, "SessionStart");
    assert_eq!(entry.session_id.as_deref(), Some("test123"));
    assert!(entry.tool_name.is_none());
    assert!(entry.tool_input_summary.is_none());
}

#[test]
fn test_log_pre_tool_use() {
    let input = make_hook_input(r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm test"},"session_id":"s1","cwd":"/tmp","permission_mode":"default"}"#);
    let entry = LogEntry::from_hook_input(&input);
    assert_eq!(entry.hook_event, "PreToolUse");
    assert_eq!(entry.tool_name.as_deref(), Some("Bash"));
    assert_eq!(entry.tool_input_summary.as_deref(), Some("npm test"));
}

#[test]
fn test_log_post_tool_use() {
    let input = make_hook_input(r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s1","cwd":"/tmp","permission_mode":"default"}"#);
    let entry = LogEntry::from_hook_input(&input);
    assert_eq!(entry.hook_event, "PostToolUse");
    assert_eq!(entry.tool_name.as_deref(), Some("Bash"));
}

#[test]
fn test_log_stop() {
    let input = make_hook_input(r#"{"hook_event_name":"Stop","session_id":"s1","cwd":"/tmp","permission_mode":"default"}"#);
    let entry = LogEntry::from_hook_input(&input);
    assert_eq!(entry.hook_event, "Stop");
}

#[test]
fn test_log_truncation() {
    let long_cmd = "a".repeat(1000);
    let json = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{}"}},"session_id":"s1","cwd":"/tmp","permission_mode":"default"}}"#,
        long_cmd
    );
    let input = make_hook_input(&json);
    let entry = LogEntry::from_hook_input(&input);
    assert!(entry.tool_input_summary.as_ref().unwrap().len() <= 200, "Summary should be truncated to 200 chars");
}

#[test]
fn test_log_redaction() {
    let input = make_hook_input(r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"export PASSWORD=hunter2"},"session_id":"s1","cwd":"/tmp","permission_mode":"default"}"#);
    let entry = LogEntry::from_hook_input(&input);
    let summary = entry.tool_input_summary.unwrap();
    assert!(!summary.contains("hunter2"), "Secret should be redacted: {}", summary);
    assert!(summary.contains("[REDACTED]"), "Should contain [REDACTED]: {}", summary);
}

#[test]
fn test_log_creates_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("subdir").join("events.jsonl");

    let input = make_hook_input(r#"{"hook_event_name":"SessionStart","session_id":"s1","cwd":"/tmp","permission_mode":"default"}"#);
    let entry = LogEntry::from_hook_input(&input);
    let result = append_to_log_at(&log_path, &entry);
    assert!(result.is_ok(), "Should create dir and file");
    assert!(log_path.exists(), "Log file should exist");
}

#[test]
fn test_log_custom_path() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("custom.jsonl");

    let input = make_hook_input(r#"{"hook_event_name":"Stop","session_id":"s1","cwd":"/tmp","permission_mode":"default"}"#);
    let entry = LogEntry::from_hook_input(&input);
    let result = append_to_log_at(&log_path, &entry);
    assert!(result.is_ok());

    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(contents.contains("Stop"), "Custom path should contain log entry");
}

#[test]
fn test_log_always_exits_0() {
    let input = make_hook_input(r#"{"hook_event_name":"SessionStart","session_id":"s1","cwd":"/tmp","permission_mode":"default"}"#);
    let _entry = LogEntry::from_hook_input(&input);
}
