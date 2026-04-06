use crate::leaks;
use crate::output;
use crate::pii;
use ignore::WalkBuilder;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process;

/// Output format for scan results.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Summary,
    Json,
}

/// Arguments for the scan subcommand.
#[derive(Debug)]
pub struct ScanArgs {
    pub paths: Vec<String>,
    pub pii: bool,
    pub leaks: bool,
    pub format: OutputFormat,
    pub exit_code: bool,
    pub no_gitignore: bool,
    pub max_size: String,
    pub include: Option<String>,
    pub exclude: Option<String>,
}

/// A single finding from a file scan.
#[derive(Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub category: String,
    pub guard: &'static str,
    pub redacted_match: String,
}

#[derive(Serialize)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub files_with_findings: usize,
    pub total_findings: usize,
}

#[derive(Serialize)]
pub struct ScanOutput {
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

/// Default max file size: 1 MB.
const DEFAULT_MAX_SIZE: u64 = 1_048_576;

/// Directories always skipped regardless of gitignore.
const ALWAYS_SKIP: &[&str] = &[".git", "node_modules", "target", ".venv"];

pub fn run(args: ScanArgs) {
    let max_size = parse_size(&args.max_size).unwrap_or_else(|| {
        eprintln!("ward scan: invalid --max-size value: {}", args.max_size);
        process::exit(1);
    });

    let scan_pii = !args.leaks || args.pii;
    let scan_leaks = !args.pii || args.leaks;

    let paths: Vec<String> = if args.paths.is_empty() {
        vec![".".to_string()]
    } else {
        args.paths.clone()
    };

    let include_globs: Vec<String> = args
        .include
        .as_deref()
        .map(|s: &str| -> Vec<String> {
            s.split(',')
                .map(|g: &str| g.trim().to_string())
                .collect()
        })
        .unwrap_or_default();

    let exclude_globs: Vec<String> = args
        .exclude
        .as_deref()
        .map(|s: &str| -> Vec<String> {
            s.split(',')
                .map(|g: &str| g.trim().to_string())
                .collect()
        })
        .unwrap_or_default();

    let mut findings: Vec<Finding> = Vec::new();
    let mut files_scanned: usize = 0;
    let mut files_with_findings: HashSet<String> = HashSet::new();

    for path_str in &paths {
        let path = Path::new(path_str);

        if path.is_file() {
            if let Some(file_findings) = scan_file(path, max_size, scan_pii, scan_leaks) {
                files_scanned += 1;
                if !file_findings.is_empty() {
                    let file_display = path.display().to_string();
                    files_with_findings.insert(file_display);
                    findings.extend(file_findings);
                }
            }
            continue;
        }

        let mut builder = WalkBuilder::new(path);
        builder
            .hidden(false)
            .git_ignore(!args.no_gitignore)
            .git_global(!args.no_gitignore)
            .git_exclude(!args.no_gitignore);

        // Build overrides for always-skip directories, exclude/include globs
        let mut overrides = ignore::overrides::OverrideBuilder::new(path);
        for dir in ALWAYS_SKIP {
            let _ = overrides.add(&format!("!{}/**", dir));
            let _ = overrides.add(&format!("!{}", dir));
        }
        for glob in &exclude_globs {
            let _ = overrides.add(&format!("!{}", glob));
        }
        if !include_globs.is_empty() {
            for glob in &include_globs {
                let _ = overrides.add(glob);
            }
        }
        if let Ok(built) = overrides.build() {
            builder.overrides(built);
        }

        let walker = builder.build();

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                continue;
            }

            let file_path = entry.path();

            if let Some(file_findings) = scan_file(file_path, max_size, scan_pii, scan_leaks) {
                files_scanned += 1;
                if !file_findings.is_empty() {
                    let file_display = file_path.display().to_string();
                    files_with_findings.insert(file_display);
                    findings.extend(file_findings);
                }
            }
        }
    }

    let total_findings = findings.len();
    let scan_output = ScanOutput {
        findings,
        summary: ScanSummary {
            files_scanned,
            files_with_findings: files_with_findings.len(),
            total_findings,
        },
    };

    match args.format {
        OutputFormat::Summary => print_summary(&scan_output),
        OutputFormat::Json => print_json(&scan_output),
    }

    if args.exit_code && total_findings > 0 {
        process::exit(2);
    }
}

/// Scan a single file. Returns None if the file should be skipped (binary, too large, etc.).
/// Returns Some(vec) with findings (possibly empty) if the file was scanned.
fn scan_file(
    path: &Path,
    max_size: u64,
    scan_pii: bool,
    scan_leaks: bool,
) -> Option<Vec<Finding>> {
    // Check file size
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() > max_size {
        return None;
    }

    // Read first 8KB to detect binary content
    let mut file = fs::File::open(path).ok()?;
    let mut header = vec![0u8; 8192];
    let bytes_read = std::io::Read::read(&mut file, &mut header).ok()?;
    header.truncate(bytes_read);

    if header.contains(&0) {
        return None; // Binary file
    }

    // Read full file contents
    let content = fs::read_to_string(path).ok()?;

    let file_display = path.display().to_string();
    let mut findings = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;

        if scan_leaks {
            let leak_matches = leaks::tier1::scan(line);
            for m in &leak_matches {
                findings.push(Finding {
                    file: file_display.clone(),
                    line: line_num,
                    category: m.category.to_string(),
                    guard: "leaks",
                    redacted_match: output::redact(&m.matched_text),
                });
            }

            let tier2_matches = leaks::tier2::scan(line);
            for m in &tier2_matches {
                findings.push(Finding {
                    file: file_display.clone(),
                    line: line_num,
                    category: m.category.to_string(),
                    guard: "leaks",
                    redacted_match: output::redact(&m.matched_text),
                });
            }

            let tier3_matches = leaks::tier3::scan(line);
            for m in &tier3_matches {
                findings.push(Finding {
                    file: file_display.clone(),
                    line: line_num,
                    category: m.category.to_string(),
                    guard: "leaks",
                    redacted_match: output::redact(&m.matched_text),
                });
            }
        }

        if scan_pii {
            let pii_matches = pii::patterns::scan(line);
            for m in &pii_matches {
                findings.push(Finding {
                    file: file_display.clone(),
                    line: line_num,
                    category: m.category.to_string(),
                    guard: "pii",
                    redacted_match: output::redact(&m.matched_text),
                });
            }
        }
    }

    Some(findings)
}

fn print_summary(output: &ScanOutput) {
    for f in &output.findings {
        let guard_label = match f.guard {
            "leaks" => "SECRET",
            "pii" => "PII",
            _ => "UNKNOWN",
        };
        eprintln!(
            "{}:{}\t{}\t{}\t{}",
            f.file, f.line, guard_label, f.category, f.redacted_match
        );
    }

    if output.summary.total_findings > 0 || output.summary.files_scanned > 0 {
        eprintln!();
        eprintln!(
            "{} findings in {} files ({} files scanned)",
            output.summary.total_findings,
            output.summary.files_with_findings,
            output.summary.files_scanned
        );
    }
}

fn print_json(output: &ScanOutput) {
    let json = serde_json::to_string_pretty(output).unwrap();
    println!("{}", json);
}

/// Parse a human-readable size string like "1M", "500K", "2G" into bytes.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(DEFAULT_MAX_SIZE);
    }

    let (num_part, suffix) = if s.ends_with(|c: char| c.is_ascii_alphabetic()) {
        let boundary = s.len() - 1;
        (&s[..boundary], &s[boundary..])
    } else {
        (s, "")
    };

    let num: f64 = num_part.parse().ok()?;

    let multiplier: u64 = match suffix.to_uppercase().as_str() {
        "" | "B" => 1,
        "K" => 1024,
        "M" => 1_048_576,
        "G" => 1_073_741_824,
        _ => return None,
    };

    Some((num * multiplier as f64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size_megabytes() {
        assert_eq!(parse_size("1M"), Some(1_048_576));
        assert_eq!(parse_size("5M"), Some(5_242_880));
    }

    #[test]
    fn test_parse_size_kilobytes() {
        assert_eq!(parse_size("500K"), Some(512_000));
    }

    #[test]
    fn test_parse_size_gigabytes() {
        assert_eq!(parse_size("2G"), Some(2_147_483_648));
    }

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("1024B"), Some(1024));
    }

    #[test]
    fn test_parse_size_invalid() {
        assert_eq!(parse_size("abc"), None);
    }
}
