# Ward

A fast, local CLI that integrates with [Claude Code hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) to block PII, secrets, and credentials from leaking through your AI coding workflow. Ships as a single Rust binary — no runtime dependencies.

## What It Does

Ward scans every prompt you send and every tool call Claude makes, blocking sensitive data before it leaves your machine.

| Subcommand | Hook Events | Purpose |
|---|---|---|
| `ward pii` | UserPromptSubmit, PreToolUse, PostToolUse | Catch SSNs, credit cards, emails, phone numbers |
| `ward leaks` | UserPromptSubmit, PreToolUse, PostToolUse | Catch API keys, cloud credentials, tokens, passwords, private keys, connection strings |
| `ward log` | All events | Structured event logging to `~/.ward/events.jsonl` |

Each hook event gets the strongest response its API allows:

| Event | On a match | Why |
|---|---|---|
| UserPromptSubmit | **blocks** (exit 2) | no API exists to rewrite a submitted prompt |
| PreToolUse | **asks** — you approve or reject at the permission prompt | the tool hasn't run; a false positive costs one keystroke |
| PostToolUse | **redacts** the output in place | the tool already ran, so blocking is impossible |

On PreToolUse ward returns `permissionDecision: "ask"` with a reason naming the
category and a partially-masked excerpt, so you can tell a real credential from
a false positive before deciding. Rejecting stops the tool call exactly as a
block would.

On PostToolUse ward rewrites the tool output via the hook's `updatedToolOutput`
field, replacing each secret with a `[WARD LEAKS REDACTED: <category>]` (or
`WARD PII`) marker before Claude ever sees it. If a match can't be masked in
place, the whole output is withheld.

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

From crates.io:

```bash
cargo install bcl-ward
```

Or download a prebuilt binary from the [latest release](https://github.com/Battle-Creek-LLC/ward/releases/latest)
(macOS arm64/x86_64, Linux arm64/x86_64, Windows x86_64):

```bash
curl -sL https://github.com/Battle-Creek-LLC/ward/releases/latest/download/ward-aarch64-apple-darwin.tar.gz | tar xz
mv ward ~/.local/bin/ward
```

Or build from source:

```bash
cargo build --release
cp target/release/ward ~/.local/bin/ward
```

Verify with `ward --help`.

## Upgrading

Replace the binary using the same method you installed with
(`cargo install bcl-ward --force`, or re-download the release archive).
Hooks pick up the new binary on the next event — no restart needed. Check the
[CHANGELOG](CHANGELOG.md) for release-specific steps.

**Upgrading to 0.2.0:** output redaction only runs if `ward pii` and
`ward leaks` are registered under `PostToolUse`. Existing installs have them
under `UserPromptSubmit`/`PreToolUse` only — add the `PostToolUse` entries
shown in the hook configuration below to enable it.

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
      {
        "matcher": "Bash|Read|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/ward pii",
            "timeout": 5,
            "statusMessage": "Scanning output for PII..."
          },
          {
            "type": "command",
            "command": "/path/to/ward leaks",
            "timeout": 5,
            "statusMessage": "Scanning output for secrets..."
          }
        ]
      },
      { "hooks": [{ "type": "command", "command": "/path/to/ward log", "timeout": 5, "async": true }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "/path/to/ward log", "timeout": 5, "async": true }] }
    ]
  }
}
```

Replace `/path/to/ward` with the absolute path to your binary (e.g., `/Users/you/.local/bin/ward`).

## Configuration

Ward reads two optional TOML files. `~/.ward/config.toml` holds your defaults;
a `.ward.toml` found by walking up from the working directory holds per-repo
overrides. The repo file wins key by key — a key it omits keeps the user-level
value, and allowlists concatenate rather than replace. With neither file
present ward behaves exactly as it does without this feature.

See [`examples/config.toml`](examples/config.toml) for an annotated starting point.

```toml
[mode]
default          = "ask"
UserPromptSubmit = "block"
PostToolUse      = "redact"

[categories]
"Generic API Key" = "warn"
"Email"           = "off"

[allow]
patterns = ['@yourcompany\.com']
paths    = ["tests/fixtures/**", "**/*.md"]
values   = ["dummy-token-for-tests"]
```

### Modes

| Mode | Effect | Available on |
|---|---|---|
| `block` | Abort with exit 2 | UserPromptSubmit, PreToolUse |
| `ask` | You approve or reject at the permission prompt | PreToolUse |
| `warn` | Allow, but tell Claude what was seen via `additionalContext` | all events |
| `redact` | Mask the match in the tool output | PostToolUse |
| `off` | Ignore the match | all events |

A mode the event can't express degrades to the nearest mode that is **no
weaker**, so a typo can't silently let a credential through: `ask` becomes
`block` on UserPromptSubmit, `block` and `ask` become `redact` on PostToolUse,
`redact` becomes `ask` on PreToolUse. Set that event's mode explicitly to
overrule the degradation.

Precedence is category → event → `default` → built-in. When one scan produces
matches at different modes, the strictest one decides the response.

### Allowlists

- `patterns` — regexes tested against the detected text
- `paths` — globs tested against the tool's `file_path`; a hit exempts the whole file
- `values` — literal detected values to ignore

A malformed config file, bad regex, or bad glob is reported on stderr and
skipped. Ward falls back to its built-in defaults rather than running with no
policy.

### `ward allow`

Append an exemption after a false positive instead of hand-editing TOML.
Comments and key order in the file are preserved.

```bash
ward allow 'dummy-token-for-tests'      # literal value
ward allow --pattern '@yourcompany\.com' # regex
ward allow --path 'tests/fixtures/**'   # file glob
ward allow --local 'value'              # write ./.ward.toml, not ~/.ward/config.toml
ward allow --list                       # show both config files and their contents
```

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
                +-- Secret found -> permissionDecision "ask" -> you approve or reject
                +-- Clean -> exit 0 -> tool executes
                          |
                          v
                    tool output returns
                          |
                          v
          ward pii + ward leaks  (PostToolUse hook)
                |
                +-- Secret found -> output rewritten with [WARD ... REDACTED] markers
                +-- Clean -> output passes through unchanged
```

Everything runs locally. Nothing leaves your machine.

## Performance

- Binary size: **1.8 MB** (release build with LTO + strip)
- Scan latency: **~6ms** for clean input (keyword pre-filtering skips regex compilation)
- Fail-safe: malformed JSON input always passes through (exit 0)

## Testing

```bash
# Run all unit and integration tests (138 tests)
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
  output.rs         # Pass/block/ask/warn/redact output formatting
  config.rs         # Config discovery, modes, allowlists
  guard.rs          # Shared decision path: filter, resolve mode, respond
  allow.rs          # `ward allow` config writer
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
