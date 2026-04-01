use assert_cmd::Command;
use predicates::prelude::*;
fn ward() -> Command {
    Command::cargo_bin("ward").unwrap()
}

#[test]
fn test_pii_clean_prompt() {
    ward()
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"UserPromptSubmit","content":"just a normal rebalancing message"}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_pii_blocked_ssn() {
    ward()
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"UserPromptSubmit","content":"my ssn is 123-45-6789"}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("PII").and(predicate::str::contains("SSN")));
}

#[test]
fn test_pii_blocked_email_in_edit() {
    ward()
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"new_string":"contact john@example.com for details"}}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Email"));
}

#[test]
fn test_pii_clean_bash() {
    ward()
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm test"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_pii_clean_rebalance_fixture() {
    let fixture = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/fixture.json","content":"{\"household_id\": 101, \"accounts\": [{\"account_id\": 45758, \"name\": \"Investment Account\", \"account_type\": \"taxable\", \"holdings\": [{\"security_id\": 1, \"ticker\": \"VOO\", \"cusip\": \"12345678\", \"shares\": 150.0, \"market_value\": 60000.0, \"weight\": 0.6}], \"trade_date\": \"2023-08-22\", \"tolerance\": 0.05, \"avoid_wash_sales\": true}]}"}}"#;
    ward()
        .arg("pii")
        .write_stdin(fixture)
        .assert()
        .success();
}

#[test]
fn test_leaks_blocked_github_pat() {
    ward()
        .arg("leaks")
        .write_stdin(r#"{"hook_event_name":"UserPromptSubmit","content":"clone with ghp_ABCDEFghijklmnop1234567890abcdefghij"}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("LEAKS").and(predicate::str::contains("GitHub")));
}

#[test]
fn test_leaks_blocked_aws_key() {
    ward()
        .arg("leaks")
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKEK5Y"}}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("AWS"));
}

#[test]
fn test_leaks_blocked_stripe_key() {
    ward()
        .arg("leaks")
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"content":"STRIPE_KEY=sk_live_abc123def456ghi789jkl"}}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Stripe"));
}

#[test]
fn test_leaks_blocked_connection_string() {
    ward()
        .arg("leaks")
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"content":"DATABASE_URL=postgres://admin:s3cret@db.host:5432/prod"}}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Connection String").or(predicate::str::contains("Env Secret")));
}

#[test]
fn test_leaks_blocked_private_key() {
    ward()
        .arg("leaks")
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"new_string":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PkPfcLBBnBMBFOAlwLwHBLFkJQ\nmore_data_here_to_pad_the_key_to_sufficient_length\n-----END RSA PRIVATE KEY-----"}}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Private Key"));
}

#[test]
fn test_leaks_clean_ticker() {
    ward()
        .arg("leaks")
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"content":"VOO BND DGRO SPY AAPL rebalance tolerance 0.05"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_log_writes_event() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("events.jsonl");

    ward()
        .arg("log")
        .env("WARD_LOG_PATH", log_path.to_str().unwrap())
        .write_stdin(r#"{"hook_event_name":"SessionStart","session_id":"int-test","cwd":"/tmp","permission_mode":"default"}"#)
        .assert()
        .success();

    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(contents.contains("SessionStart"));
    assert!(contents.contains("int-test"));
}

#[test]
fn test_log_redacts_leaks() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("events.jsonl");

    ward()
        .arg("log")
        .env("WARD_LOG_PATH", log_path.to_str().unwrap())
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"export PASSWORD=hunter2"},"session_id":"s1","cwd":"/tmp","permission_mode":"default"}"#)
        .assert()
        .success();

    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(!contents.contains("hunter2"), "Secret should be redacted in log");
    assert!(contents.contains("[REDACTED]"), "Log should contain [REDACTED]");
}

#[test]
fn test_multiple_violations() {
    // PII should block
    ward()
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"UserPromptSubmit","content":"SSN 123-45-6789 and ghp_ABCDEFghijklmnop1234567890abcdefghij"}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("PII"));

    // Leaks should also block independently
    ward()
        .arg("leaks")
        .write_stdin(r#"{"hook_event_name":"UserPromptSubmit","content":"SSN 123-45-6789 and ghp_ABCDEFghijklmnop1234567890abcdefghij"}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("LEAKS"));
}

#[test]
fn test_malformed_stdin() {
    ward()
        .arg("pii")
        .write_stdin("{broken json")
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_empty_stdin() {
    ward()
        .arg("leaks")
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}
