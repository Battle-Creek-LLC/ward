use crate::input::HookInput;
use crate::output;
use std::process;

pub mod stopwords;
pub mod tier1;
pub mod tier2;
pub mod tier3;

pub fn run(input: &HookInput) {
    let text = input.extract_text();
    if text.is_empty() {
        output::pass();
        process::exit(0);
    }

    let file_path = input.file_path();

    let mut matches = Vec::new();
    matches.extend(tier1::scan(&text));
    matches.extend(tier2::scan_with_path(&text, file_path));
    matches.extend(tier3::scan(&text));

    if matches.is_empty() {
        output::pass();
        process::exit(0);
    }

    // PostToolUse can't block (the tool already ran) — redact the output instead
    if input.hook_event_name == "PostToolUse" {
        if let Some(response) = &input.tool_response {
            output::redact_output("LEAKS", response, &matches);
            process::exit(0);
        }
    }

    output::block("LEAKS", &matches);
    process::exit(2);
}
