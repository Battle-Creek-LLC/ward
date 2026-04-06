use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn disable_file() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".ward").join("disable_until")
}

/// Write a disable file containing a Unix timestamp for when scanning should resume.
pub fn set(minutes: u64) {
    let path = disable_file();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + minutes * 60;
    fs::write(&path, expires.to_string()).expect("failed to write disable file");
    eprintln!("ward disabled for {} minutes (until {})", minutes, format_time(expires));
}

/// Remove the disable file.
pub fn clear() {
    let path = disable_file();
    if path.exists() {
        let _ = fs::remove_file(&path);
        eprintln!("ward re-enabled");
    } else {
        eprintln!("ward is already enabled");
    }
}

/// Returns true if ward is currently disabled (disable file exists and hasn't expired).
pub fn is_disabled() -> bool {
    let path = disable_file();
    match fs::read_to_string(&path) {
        Ok(contents) => {
            if let Ok(expires) = contents.trim().parse::<u64>() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now < expires {
                    return true;
                }
                // Expired — clean up
                let _ = fs::remove_file(&path);
            }
            false
        }
        Err(_) => false,
    }
}

fn format_time(epoch_secs: u64) -> String {
    let secs = epoch_secs % 60;
    let mins = (epoch_secs / 60) % 60;
    let hours = (epoch_secs / 3600) % 24;
    format!("{:02}:{:02}:{:02} UTC", hours, mins, secs)
}
