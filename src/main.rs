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
mod scan;

fn main() {
    let args = cli::Cli::parse();

    // The scan command reads files from disk, not stdin.
    if let cli::Command::Scan(cli_args) = args.command {
        let format = match cli_args.format {
            cli::CliOutputFormat::Summary => scan::OutputFormat::Summary,
            cli::CliOutputFormat::Json => scan::OutputFormat::Json,
        };
        let scan_args = scan::ScanArgs {
            paths: cli_args.paths,
            pii: cli_args.pii,
            leaks: cli_args.leaks,
            format,
            exit_code: cli_args.exit_code,
            no_gitignore: cli_args.no_gitignore,
            max_size: cli_args.max_size,
            include: cli_args.include,
            exclude: cli_args.exclude,
        };
        scan::run(scan_args);
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
        cli::Command::Scan(_) => unreachable!(),
    }
}
