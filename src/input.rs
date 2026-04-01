use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub struct HookInput {
    pub session_id: Option<String>,
    pub hook_event_name: String,
    pub tool_name: Option<String>,
    pub tool_input: Option<Value>,
    pub cwd: Option<String>,
    pub permission_mode: Option<String>,
    #[serde(flatten)]
    pub extra: Value,
}

impl HookInput {
    /// Extract all scannable text from the hook input
    pub fn extract_text(&self) -> String {
        let mut parts = Vec::new();

        match self.hook_event_name.as_str() {
            "UserPromptSubmit" => {
                // Claude Code sends the prompt in the "prompt" field
                if let Some(prompt) = self.extra.get("prompt") {
                    collect_strings(prompt, &mut parts);
                }
                // Also check "content" for compatibility with test fixtures
                if let Some(content) = self.extra.get("content") {
                    collect_strings(content, &mut parts);
                }
            }
            "PreToolUse" => {
                if let Some(input) = &self.tool_input {
                    collect_strings(input, &mut parts);
                }
            }
            _ => {}
        }

        parts.join("\n")
    }
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Object(map) => {
            for v in map.values() {
                collect_strings(v, out);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_strings(v, out);
            }
        }
        _ => {}
    }
}
