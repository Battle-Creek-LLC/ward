use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
struct StatusInput {
    #[serde(default)]
    context_window: Option<ContextWindow>,
    #[serde(default)]
    cost: Option<Cost>,
    #[serde(default)]
    model: Option<Model>,
}

#[derive(Deserialize)]
struct ContextWindow {
    used_percentage: Option<f64>,
}

#[derive(Deserialize)]
struct Cost {
    total_cost_usd: Option<f64>,
}

#[derive(Deserialize)]
struct Model {
    display_name: Option<String>,
}

const SHOW_THRESHOLD: f64 = 15.0;
const WARN_THRESHOLD: f64 = 20.0;

pub fn run() {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).unwrap_or_default();

    let input: StatusInput = match serde_json::from_str(&buffer) {
        Ok(v) => v,
        Err(_) => {
            println!("[ward]");
            return;
        }
    };

    let pct = input
        .context_window
        .as_ref()
        .and_then(|c| c.used_percentage)
        .unwrap_or(0.0);

    let model = input
        .model
        .as_ref()
        .and_then(|m| m.display_name.as_deref())
        .unwrap_or("?");

    let cost = input.cost.as_ref().and_then(|c| c.total_cost_usd);

    let mut parts = Vec::new();

    // Context usage: only show above 15%, red above 20%
    if pct >= WARN_THRESHOLD {
        parts.push(format!("\x1b[31m{:.0}% ctx\x1b[0m", pct));
    } else if pct >= SHOW_THRESHOLD {
        parts.push(format!("{:.0}% ctx", pct));
    }

    // Cost
    if let Some(usd) = cost {
        parts.push(format!("${:.2}", usd));
    }

    // Model
    parts.push(model.to_string());

    // Below show threshold, output nothing so Claude falls back to default
    if pct < SHOW_THRESHOLD {
        return;
    }

    let line = parts.join(" · ");

    if pct >= WARN_THRESHOLD {
        println!("\x1b[31m⚠\x1b[0m {line}");
    } else {
        println!("{line}");
    }
}
