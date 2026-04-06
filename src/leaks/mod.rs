use crate::config;
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

    let mut matches = Vec::new();
    matches.extend(tier1::scan(&text));
    matches.extend(tier2::scan(&text));
    matches.extend(tier3::scan(&text));

    // Apply per-project allowlist if a .wardrc is present
    if let Some(cwd) = &input.cwd {
        if let Some(cfg) = config::load_config(cwd) {
            matches.retain(|m| !cfg.is_allowed(m));
        }
    }

    if matches.is_empty() {
        output::pass();
        process::exit(0);
    }

    output::block("LEAKS", &matches);
    process::exit(2);
}
