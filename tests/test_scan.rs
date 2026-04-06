use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn ward() -> Command {
    Command::cargo_bin("ward").unwrap()
}

/// Build a fake GitHub PAT for testing.
fn fake_ghp() -> String {
    let prefix = "ghp_";
    let body = "ABCDEFghijklmnop1234567890abcdefghij";
    format!("{}{}", prefix, body)
}

/// Build a fake env secret line.
fn fake_env_secret() -> String {
    let key = ["PASS", "WORD"].concat();
    format!("{}=super_s3cret_value", key)
}

/// Build a fake SSN.
fn fake_ssn() -> String {
    format!("{}-{}-{}", "123", "45", "6789")
}

/// Build a fake email.
fn fake_email() -> String {
    let user = "john.doe";
    let domain = "example.com";
    format!("{}@{}", user, domain)
}

// -- Basic scanning --

#[test]
fn test_scan_finds_env_secret() {
    let dir = tempdir().unwrap();
    let env_file = dir.path().join(".env");
    fs::write(
        &env_file,
        format!("DB_HOST=localhost\n{}\nPORT=5432\n", fake_env_secret()),
    )
    .unwrap();

    ward()
        .args(["scan", env_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Env Secret"));
}

#[test]
fn test_scan_finds_github_pat() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("config.txt");
    fs::write(&file, format!("token = {}\n", fake_ghp())).unwrap();

    ward()
        .args(["scan", file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("GitHub PAT"));
}

#[test]
fn test_scan_finds_pii_email() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("contacts.txt");
    fs::write(&file, format!("Contact: {}\n", fake_email())).unwrap();

    ward()
        .args(["scan", file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("PII").and(predicate::str::contains("Email")));
}

#[test]
fn test_scan_finds_ssn() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("data.txt");
    fs::write(&file, format!("SSN: {}\n", fake_ssn())).unwrap();

    ward()
        .args(["scan", file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("SSN"));
}

#[test]
fn test_scan_clean_file_no_findings() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("clean.txt");
    fs::write(
        &file,
        "This is a clean file with no secrets.\nJust normal text.\n",
    )
    .unwrap();

    ward()
        .args(["scan", file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 findings"));
}

#[test]
fn test_scan_directory_recursive() {
    let dir = tempdir().unwrap();
    let subdir = dir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    let file = subdir.join("secrets.txt");
    fs::write(
        &file,
        format!("{}={}\n", ["TOK", "EN"].concat(), fake_ghp()),
    )
    .unwrap();

    ward()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("GitHub PAT"));
}

// -- Output formats --

#[test]
fn test_scan_json_output_is_valid() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("test.env");
    fs::write(
        &file,
        format!("{}={}\n", ["SEC", "RET"].concat(), fake_ghp()),
    )
    .unwrap();

    let output = ward()
        .args(["scan", "--format", "json", file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON output should be valid JSON");

    assert!(parsed.get("findings").is_some());
    assert!(parsed.get("summary").is_some());
    assert!(parsed["summary"]["files_scanned"].as_u64().unwrap() >= 1);
    assert!(parsed["summary"]["total_findings"].as_u64().unwrap() >= 1);
}

#[test]
fn test_scan_json_clean_file() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("clean.txt");
    fs::write(&file, "nothing to see here\n").unwrap();

    let output = ward()
        .args(["scan", "--format", "json", file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON output should be valid JSON");

    assert_eq!(parsed["summary"]["total_findings"].as_u64().unwrap(), 0);
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn test_scan_json_finding_fields() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("secret.txt");
    fs::write(
        &file,
        format!(
            "# config\nn{}={}\n",
            ["TOK", "EN"].concat(),
            fake_ghp()
        ),
    )
    .unwrap();

    let output = ward()
        .args(["scan", "--format", "json", file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let findings = parsed["findings"].as_array().unwrap();
    let pat_finding = findings
        .iter()
        .find(|f| f["category"].as_str().unwrap().contains("GitHub"));
    assert!(pat_finding.is_some(), "Should find a GitHub PAT");

    let finding = pat_finding.unwrap();
    assert!(finding.get("file").is_some());
    assert!(finding.get("line").is_some());
    assert!(finding.get("category").is_some());
    assert!(finding.get("guard").is_some());
    assert!(finding.get("redacted_match").is_some());
    assert_eq!(finding["guard"].as_str().unwrap(), "leaks");
    assert_eq!(finding["line"].as_u64().unwrap(), 2);
}

// -- Exit code flag --

#[test]
fn test_scan_exit_code_dirty() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("secrets.txt");
    fs::write(&file, format!("{}\n", fake_env_secret())).unwrap();

    ward()
        .args(["scan", "--exit-code", file.to_str().unwrap()])
        .assert()
        .code(2);
}

#[test]
fn test_scan_exit_code_clean() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("clean.txt");
    fs::write(&file, "This file is clean.\n").unwrap();

    ward()
        .args(["scan", "--exit-code", file.to_str().unwrap()])
        .assert()
        .success();
}

// -- Filter flags --

#[test]
fn test_scan_pii_only() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("mixed.txt");
    fs::write(
        &file,
        format!(
            "email: {}\nn{}={}\n",
            fake_email(),
            ["TOK", "EN"].concat(),
            fake_ghp()
        ),
    )
    .unwrap();

    let output = ward()
        .args(["scan", "--pii", "--format", "json", file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let findings = parsed["findings"].as_array().unwrap();
    for f in findings {
        assert_eq!(
            f["guard"].as_str().unwrap(),
            "pii",
            "Should only have PII findings"
        );
    }
    assert!(!findings.is_empty(), "Should find the email PII");
}

#[test]
fn test_scan_leaks_only() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("mixed.txt");
    fs::write(
        &file,
        format!(
            "email: {}\nn{}={}\n",
            fake_email(),
            ["TOK", "EN"].concat(),
            fake_ghp()
        ),
    )
    .unwrap();

    let output = ward()
        .args([
            "scan",
            "--leaks",
            "--format",
            "json",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let findings = parsed["findings"].as_array().unwrap();
    for f in findings {
        assert_eq!(
            f["guard"].as_str().unwrap(),
            "leaks",
            "Should only have leak findings"
        );
    }
    assert!(!findings.is_empty(), "Should find the GitHub PAT leak");
}

// -- Binary file skipping --

#[test]
fn test_scan_skips_binary_files() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("binary.bin");
    let mut content = fake_env_secret().into_bytes();
    content.push(b'\n');
    content.extend_from_slice(&[0x00, 0x01, 0x02]);
    fs::write(&file, content).unwrap();

    let output = ward()
        .args(["scan", "--format", "json", file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(
        parsed["summary"]["files_scanned"].as_u64().unwrap(),
        0,
        "Binary file should be skipped"
    );
}

// -- Max size skipping --

#[test]
fn test_scan_max_size_skips_large_files() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("large.txt");
    let mut content = format!("{}\n", fake_env_secret());
    for _ in 0..20 {
        content.push_str("padding line of text to make the file larger\n");
    }
    fs::write(&file, &content).unwrap();

    let output = ward()
        .args([
            "scan",
            "--max-size",
            "100",
            "--format",
            "json",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(
        parsed["summary"]["files_scanned"].as_u64().unwrap(),
        0,
        "File exceeding max-size should be skipped"
    );
}

// -- Summary format includes line numbers --

#[test]
fn test_scan_summary_shows_line_numbers() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("multi.txt");
    fs::write(
        &file,
        format!(
            "line one\nline two\n{}\nline four\n",
            fake_env_secret()
        ),
    )
    .unwrap();

    ward()
        .args(["scan", file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(":3\t"));
}

// -- Scan multiple specific files --

#[test]
fn test_scan_multiple_files() {
    let dir = tempdir().unwrap();
    let file1 = dir.path().join("a.txt");
    let file2 = dir.path().join("b.txt");
    fs::write(&file1, format!("{}\n", fake_env_secret())).unwrap();
    fs::write(&file2, format!("SSN: {}\n", fake_ssn())).unwrap();

    let output = ward()
        .args([
            "scan",
            "--format",
            "json",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["summary"]["files_scanned"].as_u64().unwrap(), 2);
    assert!(parsed["summary"]["total_findings"].as_u64().unwrap() >= 2);
}

// -- Include and exclude globs --

#[test]
fn test_scan_include_glob() {
    let dir = tempdir().unwrap();
    let env_file = dir.path().join("config.env");
    let txt_file = dir.path().join("config.txt");
    fs::write(&env_file, format!("{}\n", fake_env_secret())).unwrap();
    fs::write(
        &txt_file,
        format!("n{}={}\n", ["TOK", "EN"].concat(), fake_ghp()),
    )
    .unwrap();

    let output = ward()
        .args([
            "scan",
            "--include",
            "*.env",
            "--format",
            "json",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["summary"]["files_scanned"].as_u64().unwrap(), 1);
}

#[test]
fn test_scan_exclude_glob() {
    let dir = tempdir().unwrap();
    let subdir = dir.path().join("vendor");
    fs::create_dir(&subdir).unwrap();
    let vendor_file = subdir.join("dep.txt");
    let root_file = dir.path().join("app.txt");
    fs::write(&vendor_file, format!("{}\n", fake_env_secret())).unwrap();
    fs::write(
        &root_file,
        format!("n{}={}\n", ["TOK", "EN"].concat(), fake_ghp()),
    )
    .unwrap();

    let output = ward()
        .args([
            "scan",
            "--exclude",
            "vendor/**",
            "--format",
            "json",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let findings = parsed["findings"].as_array().unwrap();
    for f in findings {
        let file_path = f["file"].as_str().unwrap();
        assert!(
            !file_path.contains("vendor"),
            "Vendor files should be excluded"
        );
    }
}

// -- Redacted output --

#[test]
fn test_scan_redacts_matched_text() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("secrets.txt");
    let ghp = fake_ghp();
    fs::write(&file, format!("token = {}\n", ghp)).unwrap();

    let output = ward()
        .args(["scan", "--format", "json", file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let findings = parsed["findings"].as_array().unwrap();
    assert!(!findings.is_empty());

    for f in findings {
        let redacted = f["redacted_match"].as_str().unwrap();
        assert!(
            !redacted.contains(&ghp),
            "Match should be redacted, got: {}",
            redacted
        );
    }
}
