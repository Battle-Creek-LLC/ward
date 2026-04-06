use crate::output::Match;
use once_cell::sync::Lazy;
use regex::Regex;

static PRIVATE_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)-----BEGIN[ A-Z0-9_\-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,}?-----END[ A-Z0-9_\-]{0,100}KEY(?: BLOCK)?-----").unwrap()
});

static JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_\-]{17,}\.(?:[a-zA-Z0-9/\\_\-]{10,}={0,2})?)\b").unwrap()
});

static CONNECTION_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s"']+"#).unwrap()
});

static ENV_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:SECRET|PASSWORD|TOKEN|CLIENT_SECRET|DATABASE_URL|PRIVATE_KEY)=(\S+)").unwrap()
});

/// Source code extensions where the Env Secret (KEY=VALUE) pattern produces
/// too many false positives (keyword args, format strings, field lists).
const SOURCE_CODE_EXTENSIONS: &[&str] = &[
    ".py", ".js", ".ts", ".go", ".java", ".rb", ".rs",
    ".jsx", ".tsx", ".cs", ".cpp", ".c", ".h", ".hpp",
    ".kt", ".scala", ".swift", ".m", ".mm", ".lua",
    ".php", ".pl", ".pm", ".r", ".jl", ".ex", ".exs",
    ".zig", ".nim", ".dart", ".groovy", ".v", ".cr",
];

/// Returns true if the file path has a source-code extension where the
/// ENV_SECRET pattern should be skipped.
fn is_source_code(file_path: Option<&str>) -> bool {
    match file_path {
        Some(p) => {
            let lower = p.to_lowercase();
            SOURCE_CODE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
        }
        None => false,
    }
}

pub fn scan(text: &str) -> Vec<Match> {
    scan_with_path(text, None)
}

pub fn scan_with_path(text: &str, file_path: Option<&str>) -> Vec<Match> {
    let mut matches = Vec::new();
    let lower = text.to_lowercase();

    let skip_env = is_source_code(file_path);

    let has_env_kw = !skip_env
        && (lower.contains("secret=") || lower.contains("password=") || lower.contains("token=")
            || lower.contains("client_secret=") || lower.contains("database_url=") || lower.contains("private_key="));

    if !lower.contains("-----begin") && !lower.contains("ey") && !lower.contains("://")
        && !has_env_kw
    {
        return matches;
    }

    for m in PRIVATE_KEY.find_iter(text) {
        matches.push(Match {
            category: "Private Key",
            matched_text: m.as_str().chars().take(40).collect::<String>() + "...",
        });
    }

    for m in JWT.find_iter(text) {
        matches.push(Match {
            category: "JWT",
            matched_text: m.as_str().to_string(),
        });
    }

    for m in CONNECTION_STRING.find_iter(text) {
        matches.push(Match {
            category: "Connection String",
            matched_text: m.as_str().to_string(),
        });
    }

    if !skip_env {
        for m in ENV_SECRET.captures_iter(text) {
            let full_match = m.get(0).unwrap().as_str();
            let value = m.get(1).map(|v| v.as_str()).unwrap_or("");
            // Skip template variables like ${MY_SECRET}
            if value.starts_with("${") || value.starts_with("$(") {
                continue;
            }
            // Skip empty values
            if value.is_empty() {
                continue;
            }
            // Skip schema/DDL patterns like VARCHAR(255)
            if full_match.contains("VARCHAR")
                || full_match.contains("TIMESTAMP")
                || full_match.contains("TEXT")
                || full_match.contains("INT")
            {
                continue;
            }
            matches.push(Match {
                category: "Env Secret",
                matched_text: full_match.to_string(),
            });
        }
    }

    matches
}

/// Replace all Tier 2 pattern matches with [REDACTED]
pub fn redact(text: &str) -> String {
    let mut result = text.to_string();
    result = PRIVATE_KEY.replace_all(&result, "[REDACTED]").to_string();
    result = JWT.replace_all(&result, "[REDACTED]").to_string();
    result = CONNECTION_STRING
        .replace_all(&result, "[REDACTED]")
        .to_string();
    result = ENV_SECRET.replace_all(&result, "[REDACTED]").to_string();
    result
}
