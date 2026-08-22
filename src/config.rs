//! Ward configuration: per-event and per-category response modes, plus
//! allowlists that drop known-good matches before any decision is made.
//!
//! Two files are consulted, both optional. `~/.ward/config.toml` holds your
//! defaults; a `.ward.toml` found by walking up from the hook's `cwd` holds
//! per-repo overrides. The repo file wins key by key — an unset key inherits
//! rather than resetting to the built-in default.

use crate::output::Match;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// How ward responds to a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Abort: exit 2. Available on UserPromptSubmit and PreToolUse.
    Block,
    /// Hand the decision to the user at the permission prompt. PreToolUse only.
    Ask,
    /// Let it through, but tell Claude what was seen via `additionalContext`.
    Warn,
    /// Mask the match in the tool output. PostToolUse only.
    Redact,
    /// Ignore the match entirely.
    Off,
}

impl Mode {
    /// Not every mode is expressible on every event — the hook API decides
    /// that, not ward. An unsupported mode degrades to the nearest supported
    /// mode that is no weaker, so a config typo can never silently let a
    /// credential through. Set the event's mode explicitly to overrule this.
    pub fn resolve_for(self, event: &str) -> Mode {
        match event {
            // No API exists to rewrite or prompt on a submitted prompt.
            "UserPromptSubmit" => match self {
                Mode::Ask | Mode::Redact => Mode::Block,
                other => other,
            },
            // Rewriting tool input via `updatedInput` would corrupt the real
            // file or command on a false positive, so redact degrades to ask.
            "PreToolUse" => match self {
                Mode::Redact => Mode::Ask,
                other => other,
            },
            // The tool already ran; blocking is impossible.
            "PostToolUse" => match self {
                Mode::Block | Mode::Ask => Mode::Redact,
                other => other,
            },
            _ => self,
        }
    }
}

/// Built-in defaults. These reproduce ward's behavior with no config file
/// present, so adding this feature changes nothing until you write one.
fn default_mode_for(event: &str) -> Mode {
    match event {
        "PreToolUse" => Mode::Ask,
        "PostToolUse" => Mode::Redact,
        _ => Mode::Block,
    }
}

#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    mode: RawModes,
    /// Per-category overrides, keyed by the category name ward reports
    /// ("Generic API Key", "Email", ...).
    #[serde(default)]
    categories: std::collections::HashMap<String, Mode>,
    #[serde(default)]
    allow: RawAllow,
}

#[derive(Debug, Default, Deserialize)]
struct RawModes {
    default: Option<Mode>,
    #[serde(rename = "UserPromptSubmit")]
    user_prompt_submit: Option<Mode>,
    #[serde(rename = "PreToolUse")]
    pre_tool_use: Option<Mode>,
    #[serde(rename = "PostToolUse")]
    post_tool_use: Option<Mode>,
}

#[derive(Debug, Default, Deserialize)]
struct RawAllow {
    /// Regexes tested against the matched text.
    #[serde(default)]
    patterns: Vec<String>,
    /// Globs tested against the tool's `file_path`; a hit exempts the whole file.
    #[serde(default)]
    paths: Vec<String>,
    /// Literal matched-text values to ignore.
    #[serde(default)]
    values: Vec<String>,
}

pub struct Config {
    raw: RawConfig,
    patterns: Vec<Regex>,
    paths: Option<GlobSet>,
}

impl Config {
    /// Load `~/.ward/config.toml`, then overlay any `.ward.toml` found by
    /// walking up from `cwd`. A malformed file is reported on stderr and
    /// skipped — ward falls back to its built-in defaults rather than
    /// silently running with no policy at all.
    pub fn load(cwd: Option<&str>) -> Config {
        let mut raw = RawConfig::default();

        for path in config_paths(cwd) {
            match std::fs::read_to_string(&path) {
                Ok(text) => match toml::from_str::<RawConfig>(&text) {
                    Ok(parsed) => raw.overlay(parsed),
                    Err(e) => eprintln!("ward: ignoring {} — {}", path.display(), e),
                },
                Err(_) => continue,
            }
        }

        Config::from_raw(raw)
    }

    fn from_raw(raw: RawConfig) -> Config {
        let patterns = raw
            .allow
            .patterns
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(re) => Some(re),
                Err(e) => {
                    eprintln!("ward: ignoring allow pattern {p:?} — {e}");
                    None
                }
            })
            .collect();

        let mut builder = GlobSetBuilder::new();
        let mut any_path = false;
        for g in &raw.allow.paths {
            match Glob::new(g) {
                Ok(glob) => {
                    builder.add(glob);
                    any_path = true;
                }
                Err(e) => eprintln!("ward: ignoring allow path {g:?} — {e}"),
            }
        }
        let paths = if any_path { builder.build().ok() } else { None };

        Config {
            raw,
            patterns,
            paths,
        }
    }

    /// The mode for one match on one event. A category override beats the
    /// event mode, which beats `default`, which beats the built-in. The
    /// winner is then degraded to what the event can actually express.
    pub fn mode_for(&self, event: &str, category: &str) -> Mode {
        let chosen = self
            .raw
            .categories
            .get(category)
            .copied()
            .or_else(|| self.raw.mode.for_event(event))
            .or(self.raw.mode.default)
            .unwrap_or_else(|| default_mode_for(event));

        chosen.resolve_for(event)
    }

    /// True if this file is exempt from scanning entirely.
    pub fn path_allowed(&self, file_path: Option<&str>) -> bool {
        match (&self.paths, file_path) {
            (Some(set), Some(p)) => set.is_match(Path::new(p)),
            _ => false,
        }
    }

    /// True if this specific matched text is allowlisted.
    pub fn value_allowed(&self, matched_text: &str) -> bool {
        self.raw.allow.values.iter().any(|v| v == matched_text)
            || self.patterns.iter().any(|re| re.is_match(matched_text))
    }

    /// Drop every match the allowlist covers. An exempt path drops all of them.
    pub fn filter<'a>(&self, matches: Vec<Match>, file_path: Option<&'a str>) -> Vec<Match> {
        if self.path_allowed(file_path) {
            return Vec::new();
        }
        matches
            .into_iter()
            .filter(|m| !self.value_allowed(&m.matched_text))
            .collect()
    }
}

impl RawModes {
    fn for_event(&self, event: &str) -> Option<Mode> {
        match event {
            "UserPromptSubmit" => self.user_prompt_submit,
            "PreToolUse" => self.pre_tool_use,
            "PostToolUse" => self.post_tool_use,
            _ => None,
        }
    }
}

impl RawConfig {
    /// Overlay `other` onto self: a key `other` sets wins, a key it omits
    /// leaves the existing value alone. Allowlists concatenate rather than
    /// replace, so a repo can add exemptions without dropping user-level ones.
    fn overlay(&mut self, other: RawConfig) {
        self.mode.default = other.mode.default.or(self.mode.default);
        self.mode.user_prompt_submit = other.mode.user_prompt_submit.or(self.mode.user_prompt_submit);
        self.mode.pre_tool_use = other.mode.pre_tool_use.or(self.mode.pre_tool_use);
        self.mode.post_tool_use = other.mode.post_tool_use.or(self.mode.post_tool_use);
        self.categories.extend(other.categories);
        self.allow.patterns.extend(other.allow.patterns);
        self.allow.paths.extend(other.allow.paths);
        self.allow.values.extend(other.allow.values);
    }
}

/// User config first, then repo config, so the repo's values overlay.
fn config_paths(cwd: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    paths.push(user_config_path());
    if let Some(repo) = cwd.and_then(find_repo_config) {
        paths.push(repo);
    }
    paths
}

pub fn user_config_path() -> PathBuf {
    if let Ok(custom) = std::env::var("WARD_CONFIG_PATH") {
        return PathBuf::from(custom);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".ward").join("config.toml")
}

/// Walk up from `cwd` looking for `.ward.toml`, stopping at the filesystem root.
pub fn find_repo_config(cwd: &str) -> Option<PathBuf> {
    let mut dir = Path::new(cwd);
    loop {
        let candidate = dir.join(".ward.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
}
