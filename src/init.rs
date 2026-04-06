use serde_json::{json, Value};
use std::path::PathBuf;

/// Marker substring used to identify ward-managed hooks.
const WARD_MARKER: &str = "ward ";

/// Run the init subcommand.
pub fn run(dry_run: bool, force: bool, remove: bool) {
    let ward_bin = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            eprintln!("Error: could not resolve ward binary path: {}", e);
            std::process::exit(1);
        }
    };

    let settings_path = settings_path();

    if remove {
        run_remove(&settings_path, dry_run);
    } else {
        run_install(&settings_path, &ward_bin, dry_run, force);
    }
}

/// Return the path to `~/.claude/settings.json`.
fn settings_path() -> PathBuf {
    let home = dirs_home();
    home.join(".claude").join("settings.json")
}

/// Resolve the user's home directory.
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            eprintln!("Error: could not determine home directory");
            std::process::exit(1);
        })
}

/// Install ward hooks into settings.json.
fn run_install(settings_path: &PathBuf, ward_bin: &str, dry_run: bool, force: bool) {
    let mut settings = read_settings(settings_path);
    let ward_hooks = build_hooks(ward_bin);

    // Check for existing ward hooks
    if !force && has_ward_hooks(&settings) {
        eprintln!(
            "Error: ward hooks are already configured in {}. \
             Use --force to overwrite or --remove to remove them.",
            settings_path.display()
        );
        std::process::exit(1);
    }

    // Merge hooks into settings
    merge_hooks(&mut settings, &ward_hooks, force);

    if dry_run {
        println!("{}", serde_json::to_string_pretty(&settings).unwrap());
    } else {
        write_settings(settings_path, &settings);
        eprintln!(
            "ward hooks configured in {}",
            settings_path.display()
        );
    }
}

/// Remove ward hooks from settings.json.
fn run_remove(settings_path: &PathBuf, dry_run: bool) {
    if !settings_path.exists() {
        eprintln!("Nothing to remove: {} does not exist.", settings_path.display());
        return;
    }

    let mut settings = read_settings(settings_path);

    if !has_ward_hooks(&settings) {
        eprintln!("No ward hooks found in {}.", settings_path.display());
        return;
    }

    strip_ward_hooks(&mut settings);

    if dry_run {
        println!("{}", serde_json::to_string_pretty(&settings).unwrap());
    } else {
        write_settings(settings_path, &settings);
        eprintln!(
            "ward hooks removed from {}",
            settings_path.display()
        );
    }
}

/// Read and parse settings.json, returning an empty object if the file is missing.
fn read_settings(path: &PathBuf) -> Value {
    if !path.exists() {
        return json!({});
    }
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", path.display(), e);
        std::process::exit(1);
    });
    if content.trim().is_empty() {
        return json!({});
    }
    serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Error parsing {}: {}", path.display(), e);
        std::process::exit(1);
    })
}

/// Write settings back to disk, creating parent directories if needed.
fn write_settings(path: &PathBuf, settings: &Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Error creating directory {}: {}", parent.display(), e);
            std::process::exit(1);
        });
    }
    let content = serde_json::to_string_pretty(settings).unwrap();
    std::fs::write(path, content + "\n").unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        std::process::exit(1);
    });
}

/// Check whether the settings already contain any ward-managed hooks.
fn has_ward_hooks(settings: &Value) -> bool {
    let hooks = match settings.get("hooks") {
        Some(h) => h,
        None => return false,
    };
    let hooks_obj = match hooks.as_object() {
        Some(o) => o,
        None => return false,
    };
    for (_event, entries) in hooks_obj {
        if let Some(arr) = entries.as_array() {
            for entry in arr {
                if entry_has_ward_command(entry) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a hook entry contains any ward commands.
fn entry_has_ward_command(entry: &Value) -> bool {
    if let Some(hooks_arr) = entry.get("hooks").and_then(|v| v.as_array()) {
        for hook in hooks_arr {
            if let Some(cmd) = hook.get("command").and_then(|v| v.as_str()) {
                if cmd.contains(WARD_MARKER) {
                    return true;
                }
            }
        }
    }
    false
}

/// Merge ward hooks into existing settings, preserving non-ward hooks.
fn merge_hooks(settings: &mut Value, ward_hooks: &Value, force: bool) {
    let settings_obj = settings.as_object_mut().unwrap();
    let ward_hooks_obj = ward_hooks.get("hooks").unwrap().as_object().unwrap();

    if !settings_obj.contains_key("hooks") {
        settings_obj.insert("hooks".to_string(), json!({}));
    }

    let existing_hooks = settings_obj
        .get_mut("hooks")
        .unwrap()
        .as_object_mut()
        .unwrap();

    for (event, ward_entries) in ward_hooks_obj {
        if let Some(existing_entries) = existing_hooks.get_mut(event) {
            let arr = existing_entries.as_array_mut().unwrap();
            if force {
                // Remove existing ward entries, keep non-ward ones
                arr.retain(|entry| !entry_has_ward_command(entry));
            }
            // Append ward entries
            for entry in ward_entries.as_array().unwrap() {
                arr.push(entry.clone());
            }
        } else {
            existing_hooks.insert(event.clone(), ward_entries.clone());
        }
    }
}

/// Remove all ward-managed hooks from settings, cleaning up empty event arrays.
fn strip_ward_hooks(settings: &mut Value) {
    let hooks = match settings.get_mut("hooks").and_then(|v| v.as_object_mut()) {
        Some(h) => h,
        None => return,
    };

    let mut empty_events = Vec::new();

    for (event, entries) in hooks.iter_mut() {
        if let Some(arr) = entries.as_array_mut() {
            arr.retain(|entry| !entry_has_ward_command(entry));
            if arr.is_empty() {
                empty_events.push(event.clone());
            }
        }
    }

    for event in empty_events {
        hooks.remove(&event);
    }

    // If hooks object is now empty, remove it
    if hooks.is_empty() {
        settings.as_object_mut().unwrap().remove("hooks");
    }
}

/// Build the hook configuration JSON for the given ward binary path.
pub fn build_hooks(ward_bin: &str) -> Value {
    let pii_cmd = format!("{} pii", ward_bin);
    let leaks_cmd = format!("{} leaks", ward_bin);
    let log_cmd = format!("{} log", ward_bin);

    json!({
        "hooks": {
            "UserPromptSubmit": [
                {
                    "hooks": [
                        { "type": "command", "command": pii_cmd, "timeout": 5 },
                        { "type": "command", "command": leaks_cmd, "timeout": 5 }
                    ]
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "Bash|Edit|Write",
                    "hooks": [
                        { "type": "command", "command": pii_cmd, "timeout": 5 },
                        { "type": "command", "command": leaks_cmd, "timeout": 5 }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "hooks": [
                        { "type": "command", "command": log_cmd, "timeout": 5, "async": true }
                    ]
                }
            ],
            "PostToolUse": [
                {
                    "hooks": [
                        { "type": "command", "command": log_cmd, "timeout": 5, "async": true }
                    ]
                }
            ],
            "Stop": [
                {
                    "hooks": [
                        { "type": "command", "command": log_cmd, "timeout": 5, "async": true }
                    ]
                }
            ]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_hooks_contains_all_events() {
        let hooks = build_hooks("/usr/local/bin/ward");
        let hooks_obj = hooks.get("hooks").unwrap().as_object().unwrap();
        assert!(hooks_obj.contains_key("UserPromptSubmit"));
        assert!(hooks_obj.contains_key("PreToolUse"));
        assert!(hooks_obj.contains_key("SessionStart"));
        assert!(hooks_obj.contains_key("PostToolUse"));
        assert!(hooks_obj.contains_key("Stop"));
    }

    #[test]
    fn test_build_hooks_uses_absolute_path() {
        let hooks = build_hooks("/opt/bin/ward");
        let cmd = hooks["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("/opt/bin/ward"));
    }

    #[test]
    fn test_has_ward_hooks_empty() {
        let settings = json!({});
        assert!(!has_ward_hooks(&settings));
    }

    #[test]
    fn test_has_ward_hooks_with_ward() {
        let settings = json!({
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/ward pii" }
                        ]
                    }
                ]
            }
        });
        assert!(has_ward_hooks(&settings));
    }

    #[test]
    fn test_has_ward_hooks_without_ward() {
        let settings = json!({
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/other-tool check" }
                        ]
                    }
                ]
            }
        });
        assert!(!has_ward_hooks(&settings));
    }

    #[test]
    fn test_merge_preserves_non_ward_hooks() {
        let mut settings = json!({
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/my-linter check" }
                        ]
                    }
                ]
            }
        });
        let ward_hooks = build_hooks("/usr/bin/ward");
        merge_hooks(&mut settings, &ward_hooks, false);

        let entries = settings["hooks"]["UserPromptSubmit"].as_array().unwrap();
        // Should have the original plus the ward entry
        assert_eq!(entries.len(), 2);
        // First entry is preserved
        assert_eq!(
            entries[0]["hooks"][0]["command"].as_str().unwrap(),
            "/usr/bin/my-linter check"
        );
    }

    #[test]
    fn test_merge_force_replaces_ward_hooks() {
        let mut settings = json!({
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            { "type": "command", "command": "/old/path/ward pii" }
                        ]
                    },
                    {
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/my-linter check" }
                        ]
                    }
                ]
            }
        });
        let ward_hooks = build_hooks("/new/path/ward");
        merge_hooks(&mut settings, &ward_hooks, true);

        let entries = settings["hooks"]["UserPromptSubmit"].as_array().unwrap();
        // Old ward entry removed, non-ward preserved, new ward added
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0]["hooks"][0]["command"].as_str().unwrap(),
            "/usr/bin/my-linter check"
        );
        assert!(entries[1]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("/new/path/ward"));
    }

    #[test]
    fn test_strip_ward_hooks_removes_only_ward() {
        let mut settings = json!({
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/ward pii" }
                        ]
                    },
                    {
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/my-linter check" }
                        ]
                    }
                ],
                "SessionStart": [
                    {
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/ward log" }
                        ]
                    }
                ]
            }
        });
        strip_ward_hooks(&mut settings);

        // UserPromptSubmit should still exist with the non-ward hook
        let entries = settings["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["hooks"][0]["command"].as_str().unwrap(),
            "/usr/bin/my-linter check"
        );

        // SessionStart should be removed entirely (was only ward hooks)
        assert!(settings["hooks"].get("SessionStart").is_none());
    }

    #[test]
    fn test_strip_ward_hooks_removes_hooks_key_when_empty() {
        let mut settings = json!({
            "hooks": {
                "SessionStart": [
                    {
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/ward log" }
                        ]
                    }
                ]
            },
            "other_setting": true
        });
        strip_ward_hooks(&mut settings);

        assert!(settings.get("hooks").is_none());
        assert_eq!(settings["other_setting"], true);
    }

    #[test]
    fn test_preserves_other_settings() {
        let mut settings = json!({
            "theme": "dark",
            "verbose": true
        });
        let ward_hooks = build_hooks("/usr/bin/ward");
        merge_hooks(&mut settings, &ward_hooks, false);

        assert_eq!(settings["theme"], "dark");
        assert_eq!(settings["verbose"], true);
        assert!(settings.get("hooks").is_some());
    }
}
