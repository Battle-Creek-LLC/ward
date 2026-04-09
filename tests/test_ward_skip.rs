use assert_cmd::Command;
use predicates::prelude::*;

fn ward() -> Command {
    Command::cargo_bin("ward").unwrap()
}

/// Build a UserPromptSubmit JSON payload with the given content
fn prompt_payload(content: &str) -> String {
    format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"{}"}}"#,
        content
    )
}

/// Build a PreToolUse JSON payload for Bash with the given command
fn bash_payload(command: &str) -> String {
    format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        command
    )
}

/// A fake SSN for testing
fn fake_ssn() -> String {
    format!("{}-{}-{}", "123", "45", "6789")
}

/// A fake GitHub PAT for testing
fn fake_github_pat() -> String {
    format!("ghp_{}", "ABCDEFghijklmnop1234567890abcdefghij")
}

#[test]
fn test_ward_skip_bypasses_pii() {
    let payload = prompt_payload(&format!("ward-skip my ssn is {}", fake_ssn()));
    ward()
        .arg("pii")
        .write_stdin(payload)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_ward_skip_bypasses_leaks() {
    let payload = prompt_payload(&format!("ward-skip use {}", fake_github_pat()));
    ward()
        .arg("leaks")
        .write_stdin(payload)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_ward_skip_with_leading_whitespace() {
    let payload = prompt_payload(&format!("  ward-skip my ssn is {}", fake_ssn()));
    ward()
        .arg("pii")
        .write_stdin(payload)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_ward_skip_does_not_apply_to_tool_use() {
    let payload = bash_payload(&format!("ward-skip echo {}", fake_ssn()));
    ward()
        .arg("pii")
        .write_stdin(payload)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("SSN"));
}

#[test]
fn test_ward_skip_mid_message_does_not_bypass() {
    let payload = prompt_payload(&format!("my ssn is {} ward-skip", fake_ssn()));
    ward()
        .arg("pii")
        .write_stdin(payload)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("SSN"));
}
