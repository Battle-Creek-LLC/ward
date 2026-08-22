//! `ward allow` — append an exemption to a config file after a false positive,
//! without hand-editing TOML. Writes through `toml_edit` so existing comments
//! and key order survive.

use crate::config;
use std::path::PathBuf;
use toml_edit::{Array, DocumentMut, Item, Table, Value};

/// Which allowlist an entry goes into.
pub enum Kind {
    Value,
    Pattern,
    Path,
}

impl Kind {
    fn key(&self) -> &'static str {
        match self {
            Kind::Value => "values",
            Kind::Pattern => "patterns",
            Kind::Path => "paths",
        }
    }
}

/// Append `entry` to the chosen allowlist. `local` targets `./.ward.toml`
/// (creating it in the current directory) instead of `~/.ward/config.toml`.
pub fn add(entry: &str, kind: Kind, local: bool) {
    let path = target_path(local);

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc: DocumentMut = match existing.parse() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ward: {} is not valid TOML — {}", path.display(), e);
            std::process::exit(1);
        }
    };

    let allow = doc
        .entry("allow")
        .or_insert(Item::Table(Table::new()))
        .as_table_mut();
    let Some(allow) = allow else {
        eprintln!("ward: [allow] in {} is not a table", path.display());
        std::process::exit(1);
    };
    allow.set_implicit(false);

    let key = kind.key();
    let list = allow
        .entry(key)
        .or_insert(Item::Value(Value::Array(Array::new())));
    let Some(array) = list.as_array_mut() else {
        eprintln!("ward: allow.{key} in {} is not an array", path.display());
        std::process::exit(1);
    };

    if array.iter().any(|v| v.as_str() == Some(entry)) {
        eprintln!("ward: allow.{key} already contains {entry:?}");
        return;
    }
    array.push(entry);

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, doc.to_string()) {
        eprintln!("ward: could not write {} — {}", path.display(), e);
        std::process::exit(1);
    }
    eprintln!("ward: added {entry:?} to allow.{key} in {}", path.display());
}

/// Print both config files and what each contributes, so a surprising
/// decision can be traced to the file that caused it.
pub fn list() {
    let user = config::user_config_path();
    print_file("user", &user);

    match std::env::current_dir()
        .ok()
        .and_then(|d| config::find_repo_config(&d.to_string_lossy()))
    {
        Some(repo) => print_file("repo", &repo),
        None => println!("repo: none found (no .ward.toml above the current directory)"),
    }
}

fn print_file(label: &str, path: &PathBuf) {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            println!("{label}: {}", path.display());
            for line in text.lines() {
                println!("  {line}");
            }
        }
        Err(_) => println!("{label}: {} (not present)", path.display()),
    }
}

fn target_path(local: bool) -> PathBuf {
    if local {
        PathBuf::from(".ward.toml")
    } else {
        config::user_config_path()
    }
}
