use clap::{Parser, Subcommand};

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
    /// Status line for Claude Code (reads statusLine JSON from stdin)
    Status,
    /// Temporarily disable ward scanning
    Disable {
        /// Minutes to disable for (default: 30)
        #[arg(short, long, default_value_t = 30)]
        minutes: u64,
    },
    /// Re-enable ward scanning (removes disable file)
    Enable,
}
