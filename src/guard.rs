//! The shared decision path for `ward pii` and `ward leaks`: take the raw
//! matches a scanner produced, drop whatever the allowlist covers, resolve a
//! mode per match, and emit the one response the hook event allows.

use crate::config::{Config, Mode};
use crate::input::HookInput;
use crate::output::{self, Match};
use std::process;

/// Precedence when matches in one scan resolve to different modes. Only one
/// response can be emitted, so the strictest one wins and the response names
/// only the matches at that level.
fn severity(mode: Mode) -> u8 {
    match mode {
        Mode::Block => 4,
        Mode::Ask => 3,
        Mode::Redact => 2,
        Mode::Warn => 1,
        Mode::Off => 0,
    }
}

/// Decide and respond. Never returns — every path exits.
pub fn respond(guard_name: &str, input: &HookInput, matches: Vec<Match>) -> ! {
    let config = Config::load(input.cwd.as_deref());
    let event = input.hook_event_name.as_str();

    let matches = config.filter(matches, input.file_path());
    if matches.is_empty() {
        output::pass();
        process::exit(0);
    }

    // Resolve each match, keep only those at the strictest surviving mode.
    let modes: Vec<Mode> = matches
        .iter()
        .map(|m| config.mode_for(event, m.category))
        .collect();

    let winner = modes
        .iter()
        .copied()
        .max_by_key(|m| severity(*m))
        .unwrap_or(Mode::Off);

    if winner == Mode::Off {
        output::pass();
        process::exit(0);
    }

    let acting: Vec<Match> = matches
        .into_iter()
        .zip(&modes)
        .filter(|(_, m)| **m == winner)
        .map(|(hit, _)| hit)
        .collect();

    match winner {
        Mode::Block => {
            output::block(guard_name, &acting);
            process::exit(2);
        }
        Mode::Ask => {
            output::ask(guard_name, &acting);
            process::exit(0);
        }
        Mode::Redact => {
            // `mode_for` only yields Redact on PostToolUse, where a response
            // is always present; fall back to warn if one somehow isn't.
            match &input.tool_response {
                Some(response) => output::redact_output(guard_name, response, &acting),
                None => output::warn(guard_name, event, &acting),
            }
            process::exit(0);
        }
        Mode::Warn => {
            output::warn(guard_name, event, &acting);
            process::exit(0);
        }
        Mode::Off => unreachable!("filtered above"),
    }
}
