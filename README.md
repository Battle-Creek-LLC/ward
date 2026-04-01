# Ward

A fast, local CLI that integrates with [Claude Code hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) to block PII, secrets, and credentials from leaking through your AI coding workflow. Ships as a single Rust binary — no runtime dependencies.

## What It Does

Ward scans every prompt you send and every tool call Claude makes, blocking sensitive data before it leaves your machine.

| Subcommand | Hook Events | Purpose |
|---|---|---|
| `ward pii` | UserPromptSubmit, PreToolUse | Block SSNs, credit cards, emails, phone numbers |
| `ward leaks` | UserPromptSubmit, PreToolUse | Block API keys, cloud credentials, tokens, passwords, private keys, connection strings |
| `ward log` | All events | Structured event logging to `~/.ward/events.jsonl` |

## Detection Coverage

### PII Patterns
- Social Security Numbers (with ISO date false-positive prevention)
- Credit card numbers (spaces and dashes)
- Email addresses
- US phone numbers

### Leak Detection — 3 Tiers

**Tier 1: Provider-Specific Keys** (32 patterns, high confidence)
- AWS (access key, secret key, Bedrock), GCP, Azure
- Anthropic, OpenAI
- GitHub (PAT, fine-grained, OAuth, app tokens), GitLab
- Slack (bot, app, user, webhook, legacy tokens)
- Stripe, SendGrid, Twilio, Linear, Databricks
- Heroku, Vercel, Grafana, Sentry, Datadog
- HashiCorp Vault, NPM, PyPI

**Tier 2: Structural Patterns** (medium confidence)
- PEM-encoded private keys (RSA, EC, OPENSSH)
- JWT tokens
- Connection strings (postgres, mysql, mongodb, redis, amqp, mssql)
- Environment variable secret assignments (PASSWORD, TOKEN, SECRET, etc.)

**Tier 3: Generic Detection** (entropy-gated)
- Generic key-value secrets with Shannon entropy >= 3.5
- 1,446 stopwords from [betterleaks](https://github.com/betterleaks/betterleaks) for false-positive filtering
- Curl auth headers and user:pass patterns

### False-Positive Prevention
Zero false positives on financial data, tickers, CUSIPs, dollar amounts, percentages, ISO dates, schema DDL, import statements, URL paths, and code identifiers.

## Install

```bash
# Build from source
cargo build --release

# Install
cp target/release/ward ~/.local/bin/ward

# Verify
ward --help
```

## Configure Claude Code Hooks

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/ward pii",
            "timeout": 5,
            "statusMessage": "Scanning for PII..."
          },
          {
            "type": "command",
            "command": "/path/to/ward leaks",
            "timeout": 5,
            "statusMessage": "Scanning for secrets..."
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/ward pii",
            "timeout": 5,
            "statusMessage": "Scanning for PII..."
          },
          {
            "type": "command",
            "command": "/path/to/ward leaks",
            "timeout": 5,
            "statusMessage": "Scanning for secrets..."
          }
        ]
      }
    ],
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "/path/to/ward log", "timeout": 5, "async": true }] }
    ],
    "PostToolUse": [
      { "hooks": [{ "type": "command", "command": "/path/to/ward log", "timeout": 5, "async": true }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "/path/to/ward log", "timeout": 5, "async": true }] }
    ]
  }
}
```

Replace `/path/to/ward` with the absolute path to your binary (e.g., `/Users/you/.local/bin/ward`).

## How It Works

```
You type a prompt
    |
    v
ward pii + ward leaks  (UserPromptSubmit hook)
    |
    +-- Secret found -> exit 2 -> BLOCKED, prompt never sent
    +-- Clean -> exit 0 -> prompt proceeds to Claude
                |
                v
          Claude responds with a tool call
                |
                v
          ward pii + ward leaks  (PreToolUse hook)
                |
                +-- Secret found -> exit 2 -> tool call blocked
                +-- Clean -> exit 0 -> tool executes
```

Everything runs locally. Nothing leaves your machine.

## Performance

- Binary size: **1.8 MB** (release build with LTO + strip)
- Scan latency: **~6ms** for clean input (keyword pre-filtering skips regex compilation)
- Fail-safe: malformed JSON input always passes through (exit 0)

## Testing

```bash
# Run all unit and integration tests (105 tests)
cargo test

# Run example fixture tests (82 tests)
bash examples/run_all.sh
```

## Event Logging

`ward log` appends structured JSONL to `~/.ward/events.jsonl` (override with `WARD_LOG_PATH`). Sensitive data in tool input summaries is automatically redacted using the same PII and leak patterns.

```json
{
  "timestamp": "2026-04-01T15:30:00.123Z",
  "session_id": "abc123",
  "hook_event": "PreToolUse",
  "tool_name": "Bash",
  "tool_input_summary": "export [REDACTED]",
  "cwd": "/Users/dev/project",
  "permission_mode": "default"
}
```

## Project Structure

```
src/
  main.rs           # CLI entry point
  cli.rs            # Clap subcommand definitions
  input.rs          # Hook JSON parsing + text extraction
  output.rs         # Pass/block output formatting
  entropy.rs        # Shannon entropy for Tier 3 gating
  pii/
    mod.rs           # PII scanner
    patterns.rs      # SSN, credit card, email, phone regexes
  leaks/
    mod.rs           # Leaks scanner dispatch
    tier1.rs         # 32 provider-specific key patterns
    tier2.rs         # Private keys, JWTs, connection strings
    tier3.rs         # Generic detection + entropy gating
    stopwords.rs     # 1,446 betterleaks stopwords
  log/
    mod.rs           # Event logger
    entry.rs         # Log entry struct + file I/O
```

## Known Limitations

- **File reads are not scanned**: When Claude reads a file via the Read tool, ward cannot scan the contents before they are sent to the API. This is a [known gap](https://github.com/anthropics/claude-code/issues/25053) in the Claude Code hook architecture. Ward catches secrets when Claude tries to *use* them (in Bash commands, file writes, etc.).
- **No network calls**: Ward runs entirely locally. It does not phone home or validate tokens against provider APIs.

## Acknowledgments

Leak detection patterns adapted from [betterleaks](https://github.com/betterleaks/betterleaks) — a secrets scanner built for configurability and speed by former Gitleaks maintainers.
