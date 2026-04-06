use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn ward() -> Command {
    Command::cargo_bin("ward").unwrap()
}

/// Build an SSN string at runtime to avoid triggering ward on source files.
fn test_ssn() -> String {
    format!("{}-{}-{}", "123", "45", "6789")
}

/// Build a credit card string at runtime.
fn test_cc() -> String {
    format!("{} {} {} {}", "4111", "1111", "1111", "1111")
}

/// Build a GitHub PAT string at runtime.
fn test_ghp() -> String {
    format!("ghp_{}", "ABCDEFghijklmnop1234567890abcdefghij")
}

// ---------------------------------------------------------------------------
// Value allowlist
// ---------------------------------------------------------------------------

#[test]
fn test_wardrc_value_allowlist_skips_exact_match() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let ssn = test_ssn();

    fs::write(
        tmp.path().join(".wardrc"),
        format!("[allowlist]\nvalues = [\"{}\"]\n", ssn),
    )
    .unwrap();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"my ssn is {}","cwd":"{}"}}"#,
        ssn, cwd
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_wardrc_value_allowlist_does_not_skip_different_value() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let ssn = test_ssn();

    fs::write(
        tmp.path().join(".wardrc"),
        "[allowlist]\nvalues = [\"not-a-match\"]\n",
    )
    .unwrap();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"my ssn is {}","cwd":"{}"}}"#,
        ssn, cwd
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("SSN"));
}

// ---------------------------------------------------------------------------
// Pattern allowlist
// ---------------------------------------------------------------------------

#[test]
fn test_wardrc_pattern_allowlist_skips_regex_match() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let ssn = test_ssn();

    fs::write(
        tmp.path().join(".wardrc"),
        "[allowlist]\npatterns = [\"^\\\\d{3}-\\\\d{2}-\\\\d{4}$\"]\n",
    )
    .unwrap();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"my ssn is {}","cwd":"{}"}}"#,
        ssn, cwd
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

// ---------------------------------------------------------------------------
// Disable categories
// ---------------------------------------------------------------------------

#[test]
fn test_wardrc_disable_category_skips_pii() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let ssn = test_ssn();

    fs::write(
        tmp.path().join(".wardrc"),
        "[disable]\ncategories = [\"SSN\"]\n",
    )
    .unwrap();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"ssn {}","cwd":"{}"}}"#,
        ssn, cwd
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_wardrc_disable_category_case_insensitive() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let ssn = test_ssn();

    fs::write(
        tmp.path().join(".wardrc"),
        "[disable]\ncategories = [\"ssn\"]\n",
    )
    .unwrap();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"ssn {}","cwd":"{}"}}"#,
        ssn, cwd
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

#[test]
fn test_wardrc_disable_category_leaks() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let ghp = test_ghp();

    fs::write(
        tmp.path().join(".wardrc"),
        "[disable]\ncategories = [\"GitHub PAT\"]\n",
    )
    .unwrap();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"clone with {}","cwd":"{}"}}"#,
        ghp, cwd
    );

    ward()
        .arg("leaks")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

// ---------------------------------------------------------------------------
// Walk-up directory search
// ---------------------------------------------------------------------------

#[test]
fn test_wardrc_walk_up_finds_parent_config() {
    let tmp = tempfile::tempdir().unwrap();
    let ssn = test_ssn();

    fs::write(
        tmp.path().join(".wardrc"),
        "[disable]\ncategories = [\"SSN\"]\n",
    )
    .unwrap();

    let subdir = tmp.path().join("a").join("b").join("c");
    fs::create_dir_all(&subdir).unwrap();
    let cwd = subdir.to_str().unwrap();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"ssn {}","cwd":"{}"}}"#,
        ssn, cwd
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}

// ---------------------------------------------------------------------------
// Missing .wardrc — unchanged behavior
// ---------------------------------------------------------------------------

#[test]
fn test_no_wardrc_blocks_normally() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let ssn = test_ssn();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"ssn {}","cwd":"{}"}}"#,
        ssn, cwd
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("SSN"));
}

#[test]
fn test_no_cwd_field_blocks_normally() {
    let ssn = test_ssn();
    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"ssn {}"}}"#,
        ssn
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("SSN"));
}

// ---------------------------------------------------------------------------
// Combined: allowlist + disable together
// ---------------------------------------------------------------------------

#[test]
fn test_wardrc_combined_allowlist_and_disable() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let ssn = test_ssn();
    let cc = test_cc();

    let wardrc_content = format!(
        "[allowlist]\nvalues = [\"{}\"]\n\n[disable]\ncategories = [\"Credit Card\"]\n",
        ssn
    );
    fs::write(tmp.path().join(".wardrc"), wardrc_content).unwrap();

    let input = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","content":"ssn {} card {}","cwd":"{}"}}"#,
        ssn, cc, cwd
    );

    ward()
        .arg("pii")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#"{"continue": true}"#));
}
