use clap::Parser;
use std::io::{self, Read};
use std::process;

mod cli;
mod entropy;
mod input;
mod leaks;
mod log;
mod output;
mod pii;
mod status;

fn main() {
    let args = cli::Cli::parse();

    // Status reads its own stdin format (statusLine JSON, not hook JSON)
    if matches!(args.command, cli::Command::Status) {
        status::run();
        return;
    }

    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).unwrap_or_default();

    let hook_input: input::HookInput = match serde_json::from_str(&buffer) {
        Ok(v) => v,
        Err(_) => {
            output::pass();
            process::exit(0);
        }
    };

    match args.command {
        cli::Command::Pii => pii::run(&hook_input),
        cli::Command::Leaks => leaks::run(&hook_input),
        cli::Command::Log => log::run(&hook_input),
        cli::Command::Status => unreachable!(),
    }
}
