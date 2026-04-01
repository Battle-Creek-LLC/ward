pub mod entry;

use crate::input::HookInput;
use crate::output;
use std::process;

pub fn run(input: &HookInput) {
    let log_entry = entry::LogEntry::from_hook_input(input);

    if let Err(e) = entry::append_to_log(&log_entry) {
        eprintln!("ward log: failed to write log entry: {}", e);
    }

    output::pass();
    process::exit(0);
}
