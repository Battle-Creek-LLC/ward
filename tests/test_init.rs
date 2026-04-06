use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn ward() -> Command {
    Command::cargo_bin("ward").unwrap()
}

/// Helper: set HOME to a temp dir so init writes settings there instead of the real home.
fn ward_with_home(home: &std::path::Path) -> Command {
    let mut cmd = ward();
    cmd.env("HOME", home.to_str().unwrap());
    cmd
}

#[test]
fn test_init_creates_settings_from_scratch() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    ward_with_home(home)
        .arg("init")
        .assert()
        .success()
        .stderr(predicate::str::contains("ward hooks configured"));

    let settings_path = home.join(".claude").join("settings.json");
    assert!(settings_path.exists());

    let content = fs::read_to_string(&settings_path).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

    // All five hook events should be present
    let hooks = settings.get("hooks").unwrap().as_object().unwrap();
    assert!(hooks.contains_key("UserPromptSubmit"));
    assert!(hooks.contains_key("PreToolUse"));
    assert!(hooks.contains_key("SessionStart"));
    assert!(hooks.contains_key("PostToolUse"));
    assert!(hooks.contains_key("Stop"));

    // PreToolUse should have a matcher
    let pre = &hooks["PreToolUse"][0];
    assert_eq!(pre["matcher"].as_str().unwrap(), "Bash|Edit|Write");
}

#[test]
fn test_init_dry_run_does_not_write() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    ward_with_home(home)
        .arg("init")
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("UserPromptSubmit"))
        .stdout(predicate::str::contains("PreToolUse"))
        .stdout(predicate::str::contains("ward pii"))
        .stdout(predicate::str::contains("ward leaks"))
        .stdout(predicate::str::contains("ward log"));

    let settings_path = home.join(".claude").join("settings.json");
    assert!(!settings_path.exists(), "dry-run should not create the file");
}

#[test]
fn test_init_errors_when_hooks_already_present() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    // Write existing settings with ward hooks
    let existing = serde_json::json!({
        "hooks": {
            "UserPromptSubmit": [
                {
                    "hooks": [
                        { "type": "command", "command": "/old/ward pii" }
                    ]
                }
            ]
        }
    });
    fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    ward_with_home(home)
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already configured"))
        .stderr(predicate::str::contains("--force"));
}

#[test]
fn test_init_force_replaces_existing_ward_hooks() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    // Write existing settings with ward hooks
    let existing = serde_json::json!({
        "hooks": {
            "UserPromptSubmit": [
                {
                    "hooks": [
                        { "type": "command", "command": "/old/ward pii" }
                    ]
                }
            ]
        }
    });
    fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    ward_with_home(home)
        .arg("init")
        .arg("--force")
        .assert()
        .success()
        .stderr(predicate::str::contains("ward hooks configured"));

    let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Old ward hook should be replaced, not duplicated
    let entries = settings["hooks"]["UserPromptSubmit"].as_array().unwrap();
    assert_eq!(entries.len(), 1);

    // Should use the current binary path, not the old one
    let cmd = entries[0]["hooks"][0]["command"].as_str().unwrap();
    assert!(!cmd.contains("/old/ward"));
}

#[test]
fn test_init_preserves_non_ward_hooks() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    // Write existing settings with a non-ward hook
    let existing = serde_json::json!({
        "hooks": {
            "UserPromptSubmit": [
                {
                    "hooks": [
                        { "type": "command", "command": "/usr/bin/my-linter check" }
                    ]
                }
            ]
        }
    });
    fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    ward_with_home(home)
        .arg("init")
        .assert()
        .success();

    let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Non-ward hook should still be present
    let entries = settings["hooks"]["UserPromptSubmit"].as_array().unwrap();
    assert!(entries.len() >= 2);
    assert_eq!(
        entries[0]["hooks"][0]["command"].as_str().unwrap(),
        "/usr/bin/my-linter check"
    );
}

#[test]
fn test_init_preserves_other_settings_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    let existing = serde_json::json!({
        "theme": "dark",
        "verbose": true
    });
    fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    ward_with_home(home)
        .arg("init")
        .assert()
        .success();

    let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(settings["theme"], "dark");
    assert_eq!(settings["verbose"], true);
    assert!(settings.get("hooks").is_some());
}

#[test]
fn test_init_remove() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    // First, install hooks
    ward_with_home(home)
        .arg("init")
        .assert()
        .success();

    // Then remove them
    ward_with_home(home)
        .arg("init")
        .arg("--remove")
        .assert()
        .success()
        .stderr(predicate::str::contains("ward hooks removed"));

    let content =
        fs::read_to_string(home.join(".claude").join("settings.json")).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

    // hooks key should be gone since all hooks were ward-managed
    assert!(settings.get("hooks").is_none());
}

#[test]
fn test_init_remove_preserves_non_ward_hooks() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    // Write settings with both ward and non-ward hooks
    let existing = serde_json::json!({
        "hooks": {
            "UserPromptSubmit": [
                {
                    "hooks": [
                        { "type": "command", "command": "/usr/bin/ward pii" }
                    ]
                },
                {
                    "hooks": [
                        { "type": "command", "command": "/usr/bin/my-linter check" }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "hooks": [
                        { "type": "command", "command": "/usr/bin/ward log" }
                    ]
                }
            ]
        }
    });
    fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    ward_with_home(home)
        .arg("init")
        .arg("--remove")
        .assert()
        .success();

    let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Non-ward hook should be preserved
    let entries = settings["hooks"]["UserPromptSubmit"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["hooks"][0]["command"].as_str().unwrap(),
        "/usr/bin/my-linter check"
    );

    // SessionStart (only had ward hooks) should be gone
    assert!(settings["hooks"].get("SessionStart").is_none());
}

#[test]
fn test_init_remove_no_settings_file() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    ward_with_home(home)
        .arg("init")
        .arg("--remove")
        .assert()
        .success()
        .stderr(predicate::str::contains("Nothing to remove"));
}

#[test]
fn test_init_remove_no_ward_hooks() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    let existing = serde_json::json!({
        "hooks": {
            "UserPromptSubmit": [
                {
                    "hooks": [
                        { "type": "command", "command": "/usr/bin/my-linter check" }
                    ]
                }
            ]
        }
    });
    fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    ward_with_home(home)
        .arg("init")
        .arg("--remove")
        .assert()
        .success()
        .stderr(predicate::str::contains("No ward hooks found"));
}

#[test]
fn test_init_remove_dry_run() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    // Install hooks first
    ward_with_home(home)
        .arg("init")
        .assert()
        .success();

    // Dry-run remove should print the result but not modify the file
    ward_with_home(home)
        .arg("init")
        .arg("--remove")
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("hooks").not());

    // Hooks should still be in the file
    let content =
        fs::read_to_string(home.join(".claude").join("settings.json")).unwrap();
    let settings: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(settings.get("hooks").is_some());
}

#[test]
fn test_init_does_not_read_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();

    // Pass garbage stdin — init should succeed regardless
    ward_with_home(home)
        .arg("init")
        .write_stdin("this is not json and init should not care")
        .assert()
        .success()
        .stderr(predicate::str::contains("ward hooks configured"));
}
