use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;
use tempfile::TempDir;

/// A ward invocation isolated from the developer's real `~/.ward`: HOME and
/// the config path both point into `home`, so nothing on the machine leaks in.
fn ward_in(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ward").unwrap();
    cmd.env("HOME", home);
    cmd.env("WARD_CONFIG_PATH", home.join("config.toml"));
    cmd
}

/// Write a user-level config and return the tempdir holding it.
fn with_config(toml: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("config.toml"), toml).unwrap();
    dir
}

/// A fake GitHub PAT: `ghp_` plus the 36 characters the pattern requires.
fn fake_github_pat() -> String {
    format!("ghp_{}", "ABCDEFghijklmnop1234567890abcdefghij")
}

fn pretooluse(command: &str) -> String {
    format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{command}"}}}}"#
    )
}

fn asks() -> impl Predicate<str> {
    predicate::str::contains(r#""permissionDecision":"ask""#)
}

fn warns() -> impl Predicate<str> {
    predicate::str::contains("additionalContext")
        .and(predicate::str::contains("warn` mode"))
}

fn passes() -> impl Predicate<str> {
    predicate::str::contains(r#"{"continue": true}"#)
}

// ---------------------------------------------------------------- defaults

/// With no config file, every event must behave exactly as it did before
/// configuration existed. Adding the feature changes nothing on its own.
#[test]
fn test_no_config_keeps_default_behavior() {
    let dir = TempDir::new().unwrap();

    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {}", fake_github_pat())))
        .assert()
        .success()
        .stdout(asks());

    ward_in(dir.path())
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"UserPromptSubmit","content":"ssn 123-45-6789"}"#)
        .assert()
        .code(2);

    ward_in(dir.path())
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat f"},"tool_response":"ssn 123-45-6789"}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("updatedToolOutput"));
}

// ------------------------------------------------------------------- modes

#[test]
fn test_category_off_suppresses_the_match() {
    let dir = with_config("[categories]\n\"Email\" = \"off\"\n");
    ward_in(dir.path())
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"new_string":"contact john@example.com"}}"#)
        .assert()
        .success()
        .stdout(passes());
}

#[test]
fn test_category_warn_passes_with_context() {
    let dir = with_config("[categories]\n\"GitHub PAT\" = \"warn\"\n");
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {}", fake_github_pat())))
        .assert()
        .success()
        .stdout(warns());
}

#[test]
fn test_event_mode_overrides_default() {
    let dir = with_config("[mode]\ndefault = \"block\"\nPreToolUse = \"warn\"\n");
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {}", fake_github_pat())))
        .assert()
        .success()
        .stdout(warns());
}

#[test]
fn test_category_beats_event_mode() {
    let dir = with_config(
        "[mode]\nPreToolUse = \"warn\"\n[categories]\n\"GitHub PAT\" = \"block\"\n",
    );
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {}", fake_github_pat())))
        .assert()
        .code(2);
}

/// Matches in one scan can resolve to different modes, but only one response
/// can be emitted — the strictest wins.
#[test]
fn test_strictest_mode_wins_across_categories() {
    let dir = with_config("[categories]\n\"Email\" = \"warn\"\n\"SSN\" = \"block\"\n");
    ward_in(dir.path())
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"UserPromptSubmit","content":"a@b.com and 123-45-6789"}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("SSN"));
}

// ------------------------------------------------------------- degradation

/// No hook API can prompt on a submitted prompt, so `ask` degrades to the
/// stricter `block` rather than silently letting the credential through.
#[test]
fn test_ask_degrades_to_block_on_userpromptsubmit() {
    let dir = with_config("[mode]\ndefault = \"ask\"\n");
    ward_in(dir.path())
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"UserPromptSubmit","content":"ssn 123-45-6789"}"#)
        .assert()
        .code(2);
}

/// The tool has already run at PostToolUse, so blocking is impossible.
#[test]
fn test_block_degrades_to_redact_on_posttooluse() {
    let dir = with_config("[mode]\ndefault = \"block\"\n");
    ward_in(dir.path())
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat f"},"tool_response":"ssn 123-45-6789"}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("updatedToolOutput"));
}

/// `warn` is expressible on every event, so it is never degraded.
#[test]
fn test_warn_survives_on_posttooluse() {
    let dir = with_config("[mode]\nPostToolUse = \"warn\"\n");
    ward_in(dir.path())
        .arg("pii")
        .write_stdin(r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat f"},"tool_response":"ssn 123-45-6789"}"#)
        .assert()
        .success()
        .stdout(warns().and(predicate::str::contains("updatedToolOutput").not()));
}

// -------------------------------------------------------------- allowlists

#[test]
fn test_allow_values_exempts_exact_match() {
    let pat = fake_github_pat();
    let dir = with_config(&format!("[allow]\nvalues = [\"{pat}\"]\n"));
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {pat}")))
        .assert()
        .success()
        .stdout(passes());
}

#[test]
fn test_allow_patterns_exempts_only_matching_values() {
    let dir = with_config("[allow]\npatterns = ['ghp_TESTONLY[A-Za-z0-9]+']\n");

    // 36 characters after the prefix, as the GitHub PAT pattern requires.
    let allowed = format!("ghp_TESTONLY{}", "abcdefghijklmnop1234567890ab");
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {allowed}")))
        .assert()
        .success()
        .stdout(passes());

    let denied = format!("ghp_REALKEYX{}", "abcdefghijklmnop1234567890ab");
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {denied}")))
        .assert()
        .success()
        .stdout(asks());
}

#[test]
fn test_allow_paths_exempts_the_whole_file() {
    let dir = with_config("[allow]\npaths = [\"**/docs/**\"]\n");
    let secret = "STRIPE_KEY=sk_live_abc123def456ghi789jkl";

    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{"file_path":"/repo/docs/setup.md","content":"{secret}"}}}}"#
        ))
        .assert()
        .success()
        .stdout(passes());

    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{"file_path":"/repo/src/config.rs","content":"{secret}"}}}}"#
        ))
        .assert()
        .success()
        .stdout(asks());
}

// ------------------------------------------------------------ repo overlay

/// `.ward.toml` found by walking up from `cwd` overrides the user config key
/// by key; keys it omits keep the user-level value.
#[test]
fn test_repo_config_overlays_user_config() {
    let dir = with_config("[mode]\ndefault = \"block\"\n");
    let repo = dir.path().join("repo").join("src");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        dir.path().join("repo").join(".ward.toml"),
        "[mode]\nPreToolUse = \"warn\"\n",
    )
    .unwrap();

    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(format!(
            r#"{{"hook_event_name":"PreToolUse","cwd":"{}","tool_name":"Bash","tool_input":{{"command":"echo {}"}}}}"#,
            repo.display(),
            fake_github_pat()
        ))
        .assert()
        .success()
        .stdout(warns());

    // Same payload without a cwd sees only the user config, which blocks.
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {}", fake_github_pat())))
        .assert()
        .code(2);
}

/// Allowlists concatenate across files so a repo can add exemptions without
/// discarding the user's.
#[test]
fn test_repo_allowlist_adds_to_user_allowlist() {
    let pat = fake_github_pat();
    let dir = with_config(&format!("[allow]\nvalues = [\"{pat}\"]\n"));
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join(".ward.toml"), "[allow]\nvalues = [\"other\"]\n").unwrap();

    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(format!(
            r#"{{"hook_event_name":"PreToolUse","cwd":"{}","tool_name":"Bash","tool_input":{{"command":"echo {pat}"}}}}"#,
            repo.display()
        ))
        .assert()
        .success()
        .stdout(passes());
}

// ----------------------------------------------------------- malformed input

/// A broken config must not disable ward — it falls back to the built-in
/// defaults and says so on stderr.
#[test]
fn test_malformed_config_falls_back_to_defaults() {
    let dir = with_config("[mode\ndefault = ask\n");
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {}", fake_github_pat())))
        .assert()
        .success()
        .stdout(asks())
        .stderr(predicate::str::contains("ignoring"));
}

#[test]
fn test_invalid_allow_pattern_is_skipped_not_fatal() {
    let dir = with_config("[allow]\npatterns = ['[unclosed']\n");
    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {}", fake_github_pat())))
        .assert()
        .success()
        .stdout(asks())
        .stderr(predicate::str::contains("ignoring allow pattern"));
}

// ------------------------------------------------------------- ward allow

#[test]
fn test_ward_allow_appends_and_dedups() {
    let dir = TempDir::new().unwrap();

    ward_in(dir.path())
        .args(["allow", "dummy-token-for-tests"])
        .assert()
        .success();

    let written = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert!(written.contains("dummy-token-for-tests"), "{written}");

    // A second add of the same value is a no-op, not a duplicate entry.
    ward_in(dir.path())
        .args(["allow", "dummy-token-for-tests"])
        .assert()
        .success()
        .stderr(predicate::str::contains("already contains"));

    let written = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert_eq!(written.matches("dummy-token-for-tests").count(), 1);
}

/// The entry `ward allow` writes must actually take effect on the next scan.
#[test]
fn test_ward_allow_entry_takes_effect() {
    let pat = fake_github_pat();
    let dir = TempDir::new().unwrap();

    ward_in(dir.path())
        .args(["allow", &pat])
        .assert()
        .success();

    ward_in(dir.path())
        .arg("leaks")
        .write_stdin(pretooluse(&format!("echo {pat}")))
        .assert()
        .success()
        .stdout(passes());
}

#[test]
fn test_ward_allow_preserves_comments() {
    let dir = with_config("# keep me\n[allow]\nvalues = [\"first\"]\n");

    ward_in(dir.path())
        .args(["allow", "second"])
        .assert()
        .success();

    let written = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert!(written.contains("# keep me"), "{written}");
    assert!(written.contains("first"), "{written}");
    assert!(written.contains("second"), "{written}");
}

#[test]
fn test_ward_allow_pattern_and_path_target_their_own_lists() {
    let dir = TempDir::new().unwrap();

    ward_in(dir.path())
        .args(["allow", "--pattern", r"@example\.com"])
        .assert()
        .success();
    ward_in(dir.path())
        .args(["allow", "--path", "tests/fixtures/**"])
        .assert()
        .success();

    let written = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert!(written.contains("patterns"), "{written}");
    assert!(written.contains("paths"), "{written}");
}

#[test]
fn test_ward_allow_needs_an_entry() {
    let dir = TempDir::new().unwrap();
    ward_in(dir.path())
        .arg("allow")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("needs a value"));
}

#[test]
fn test_ward_allow_list_shows_the_user_config() {
    let dir = with_config("[allow]\nvalues = [\"listed-value\"]\n");
    ward_in(dir.path())
        .args(["allow", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("listed-value"));
}
