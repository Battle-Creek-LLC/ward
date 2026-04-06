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
    /// Configure Claude Code hooks in ~/.claude/settings.json
    Init {
        /// Print the resulting config without modifying any files
        #[arg(long)]
        dry_run: bool,

        /// Overwrite existing ward hooks instead of erroring
        #[arg(long)]
        force: bool,

        /// Remove ward hooks from settings.json
        #[arg(long)]
        remove: bool,
    },
}
