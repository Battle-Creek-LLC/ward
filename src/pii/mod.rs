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

    // PostToolUse can't block (the tool already ran) — redact the output instead
    if input.hook_event_name == "PostToolUse" {
        if let Some(response) = &input.tool_response {
            output::redact_output("PII", response, &matches);
            process::exit(0);
        }
    }

    output::block("PII", &matches);
    process::exit(2);
}
