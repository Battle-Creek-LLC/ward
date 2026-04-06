use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "ward", about = "Claude Code hook CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan for personally identifiable information (SSN, credit card, email, phone)
    Pii,
    /// Scan for secrets and credentials (API keys, cloud keys, passwords, tokens, private keys)
    Leaks,
    /// Log hook events to ~/.ward/events.jsonl
    Log,
    /// Scan files and directories for secrets and PII
    Scan(CliScanArgs),
}

#[derive(Parser, Debug)]
pub struct CliScanArgs {
    /// Paths to scan (files or directories). Defaults to current directory.
    #[arg()]
    pub paths: Vec<String>,

    /// Scan for PII patterns only
    #[arg(long)]
    pub pii: bool,

    /// Scan for secret/leak patterns only
    #[arg(long)]
    pub leaks: bool,

    /// Output format
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Summary)]
    pub format: CliOutputFormat,

    /// Exit with code 2 if any findings are detected
    #[arg(long)]
    pub exit_code: bool,

    /// Don't respect .gitignore rules
    #[arg(long)]
    pub no_gitignore: bool,

    /// Maximum file size to scan (e.g. 1M, 500K, 2G). Default: 1M.
    #[arg(long, default_value = "1M")]
    pub max_size: String,

    /// Only scan files matching these comma-separated globs
    #[arg(long)]
    pub include: Option<String>,

    /// Skip files matching these comma-separated globs
    #[arg(long)]
    pub exclude: Option<String>,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum CliOutputFormat {
    Summary,
    Json,
}
