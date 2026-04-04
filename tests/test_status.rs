use assert_cmd::Command;
use predicates::prelude::*;

fn ward() -> Command {
    Command::cargo_bin("ward").unwrap()
}

#[test]
fn test_status_below_threshold_no_output() {
    ward()
        .arg("status")
        .write_stdin(r#"{"context_window":{"used_percentage":10.0},"cost":{"total_cost_usd":0.50},"model":{"display_name":"Opus 4"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_status_at_show_threshold() {
    ward()
        .arg("status")
        .write_stdin(r#"{"context_window":{"used_percentage":15.0},"cost":{"total_cost_usd":1.00},"model":{"display_name":"Sonnet 4"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("15% ctx"))
        .stdout(predicate::str::contains("$1.00"))
        .stdout(predicate::str::contains("Sonnet 4"))
        // Should NOT contain ANSI red
        .stdout(predicate::str::contains("\x1b[31m").not());
}

#[test]
fn test_status_between_thresholds() {
    ward()
        .arg("status")
        .write_stdin(r#"{"context_window":{"used_percentage":17.5},"cost":{"total_cost_usd":2.00},"model":{"display_name":"Haiku"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("18% ctx"))
        .stdout(predicate::str::contains("$2.00"))
        .stdout(predicate::str::contains("Haiku"))
        .stdout(predicate::str::contains("\x1b[31m").not());
}

#[test]
fn test_status_at_warn_threshold_red() {
    ward()
        .arg("status")
        .write_stdin(r#"{"context_window":{"used_percentage":20.0},"cost":{"total_cost_usd":3.00},"model":{"display_name":"Opus 4"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[31m"))
        .stdout(predicate::str::contains("20% ctx"))
        .stdout(predicate::str::contains("⚠"));
}

#[test]
fn test_status_high_context_red() {
    ward()
        .arg("status")
        .write_stdin(r#"{"context_window":{"used_percentage":75.0},"cost":{"total_cost_usd":5.50},"model":{"display_name":"Opus 4"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[31m"))
        .stdout(predicate::str::contains("75% ctx"))
        .stdout(predicate::str::contains("⚠"))
        .stdout(predicate::str::contains("$5.50"));
}

#[test]
fn test_status_empty_json() {
    ward()
        .arg("status")
        .write_stdin("{}")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_status_invalid_json() {
    ward()
        .arg("status")
        .write_stdin("not json")
        .assert()
        .success()
        .stdout(predicate::str::contains("[ward]"));
}

#[test]
fn test_status_empty_stdin() {
    ward()
        .arg("status")
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::contains("[ward]"));
}

#[test]
fn test_status_no_cost_field() {
    ward()
        .arg("status")
        .write_stdin(r#"{"context_window":{"used_percentage":18.0},"model":{"display_name":"Haiku"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("18% ctx"))
        .stdout(predicate::str::contains("Haiku"))
        .stdout(predicate::str::contains("$").not());
}

#[test]
fn test_status_no_model_field() {
    ward()
        .arg("status")
        .write_stdin(r#"{"context_window":{"used_percentage":16.0},"cost":{"total_cost_usd":1.00}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("16% ctx"))
        .stdout(predicate::str::contains("?"));
}
