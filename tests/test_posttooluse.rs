use assert_cmd::Command;
use predicates::prelude::*;

fn ward() -> Command {
    let mut cmd = Command::cargo_bin("ward").unwrap();
    // Pin HOME to the target tmpdir so a real `ward disable -m N` on the
    // developer's machine can't silently turn every assertion into a pass.
    cmd.env("HOME", env!("CARGO_TARGET_TMPDIR"));
    cmd
}

#[test]
fn test_leaks_redacts_string_tool_response() {
    ward()
        .arg("leaks")
        .write_stdin(
            r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"curl https://api.example.com/token"},"tool_response":"token: ghp_ABCDEFghijklmnop1234567890abcdefghij\ndone"}"#,
        )
        .assert()
        .success()
        .stdout(
            predicate::str::contains("updatedToolOutput")
                .and(predicate::str::contains("WARD LEAKS REDACTED"))
                .and(predicate::str::contains("ghp_ABCDEFghijklmnop1234567890abcdefghij").not()),
        );
}

#[test]
fn test_leaks_redacts_object_tool_response() {
    ward()
        .arg("leaks")
        .write_stdin(
            r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"env"},"tool_response":{"stdout":"AWS_KEY=AKIAIOSFODNN7EXAMPLE","stderr":""}}"#,
        )
        .assert()
        .success()
        .stdout(
            predicate::str::contains("updatedToolOutput")
                .and(predicate::str::contains("WARD LEAKS REDACTED"))
                .and(predicate::str::contains("AKIAIOSFODNN7EXAMPLE").not()),
        );
}

#[test]
fn test_leaks_clean_tool_response_passes() {
    ward()
        .arg("leaks")
        .write_stdin(
            r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"npm test"},"tool_response":"All tests passed"}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_pii_redacts_ssn_in_tool_response() {
    ward()
        .arg("pii")
        .write_stdin(
            r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat users.csv"},"tool_response":"name,ssn\njane,123-45-6789"}"#,
        )
        .assert()
        .success()
        .stdout(
            predicate::str::contains("WARD PII REDACTED: SSN")
                .and(predicate::str::contains("123-45-6789").not()),
        );
}

#[test]
fn test_redacted_output_preserves_surrounding_text() {
    ward()
        .arg("pii")
        .write_stdin(
            r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat users.csv"},"tool_response":"before 123-45-6789 after"}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("before").and(predicate::str::contains("after")));
}

#[test]
fn test_posttooluse_does_not_scan_tool_input() {
    // Input-side secrets are PreToolUse's job; PostToolUse must only judge the response
    ward()
        .arg("leaks")
        .write_stdin(
            r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo ghp_ABCDEFghijklmnop1234567890abcdefghij"},"tool_response":"clean output"}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}
