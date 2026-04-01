pub mod patterns;

use crate::input::HookInput;
use crate::output;
use std::process;

pub fn run(input: &HookInput) {
    let text = input.extract_text();
    if text.is_empty() {
        output::pass();
        process::exit(0);
    }

    let matches = patterns::scan(&text);

    if matches.is_empty() {
        output::pass();
        process::exit(0);
    }

    output::block("PII", &matches);
    process::exit(2);
}
