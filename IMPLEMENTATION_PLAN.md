# Ward — Implementation Plan

Each phase is a self-contained prompt you can hand to Claude Code. After each phase, run the listed tests to verify before moving on.

---

## Phase 1: Project Scaffold + CLI Skeleton

### Prompt

```
Read ~/Development/ward/ward-spec.md for full context.

Scaffold a new Rust project at ~/Development/ward:
- cargo init with the Cargo.toml from the spec (clap, serde, serde_json, regex, once_cell, chrono, plus dev-dependencies assert_cmd, predicates, tempfile)
- Include the [profile.release] optimizations from the spec
- Create src/main.rs that reads all of stdin into a string and parses CLI args via clap
- Create src/cli.rs with the three subcommands: Pii, Leaks, Log
- Create src/input.rs with HookInput deserialization and the extract_text() method including the recursive collect_strings helper
- Create src/output.rs with pass(), block(), and redact() functions
- For now, all three subcommands should just call output::pass() and exit 0 (stub implementations)
- Malformed JSON stdin should fail safe: exit 0, print {"continue": true}

Do NOT create the scanner modules yet — just the skeleton that compiles and runs.
```

### Test After

```bash
cd ~/Development/ward
cargo build
# Should compile clean

# Stub subcommands pass through
echo '{"hook_event_name":"UserPromptSubmit","content":"hello"}' | cargo run -- pii
# → {"continue": true}, exit 0

echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}' | cargo run -- leaks
# → {"continue": true}, exit 0

echo '{"hook_event_name":"SessionStart","session_id":"abc"}' | cargo run -- log
# → {"continue": true}, exit 0

# Malformed JSON fails safe
echo '{broken' | cargo run -- pii
# → {"continue": true}, exit 0

# No stdin fails safe
echo '' | cargo run -- leaks
# → {"continue": true}, exit 0

# clap shows help
cargo run -- --help
cargo run -- pii --help
```

---

## Phase 2: PII Scanner

### Prompt

```
Read ~/Development/ward/ward-spec.md — specifically the "Subcommand: ward pii" section.

Create the PII scanner module in the existing ward project at ~/Development/ward:
- Create src/pii/mod.rs with the run() function that extracts text, scans, and either blocks (exit 2) or passes (exit 0)
- Create src/pii/patterns.rs with compiled regex patterns using OnceCell for: SSN, Credit Card, Email, Phone
- SSN pattern MUST use negative lookbehind to avoid matching ISO dates (YYYY-MM-DD)
- Wire pii::run into main.rs for the Pii subcommand
- Add unit tests in tests/test_pii.rs covering all detection AND false positive cases from the spec

Run `cargo test` after writing the tests to make sure they all pass.
```

### Test After

```bash
cd ~/Development/ward

# All unit tests pass
cargo test test_pii

# Detection tests — manual verification
echo '{"hook_event_name":"UserPromptSubmit","content":"my ssn is 123-45-6789"}' | cargo run -- pii
# → exit 2, stderr mentions SSN

echo '{"hook_event_name":"UserPromptSubmit","content":"card 4111 1111 1111 1111"}' | cargo run -- pii
# → exit 2, stderr mentions Credit Card

echo '{"hook_event_name":"UserPromptSubmit","content":"email john@example.com"}' | cargo run -- pii
# → exit 2, stderr mentions Email

echo '{"hook_event_name":"UserPromptSubmit","content":"call (555) 123-4567"}' | cargo run -- pii
# → exit 2, stderr mentions Phone

# False positive tests — these MUST pass clean
echo '{"hook_event_name":"UserPromptSubmit","content":"date: 2023-08-22"}' | cargo run -- pii
# → exit 0

echo '{"hook_event_name":"UserPromptSubmit","content":"VOO BND DGRO SPY AAPL"}' | cargo run -- pii
# → exit 0

echo '{"hook_event_name":"UserPromptSubmit","content":"value: 100000.0, weight: 0.6"}' | cargo run -- pii
# → exit 0

echo '{"hook_event_name":"UserPromptSubmit","content":"cusip: 12345678, account_id: 45758"}' | cargo run -- pii
# → exit 0

# PreToolUse extraction works
echo '{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"new_string":"ssn 123-45-6789"}}' | cargo run -- pii
# → exit 2
```

---

## Phase 3: Leaks Tier 1 — Provider-Specific Keys

### Prompt

```
Read ~/Development/ward/ward-spec.md — specifically the "Tier 1: Provider-Specific Keys" table.

Create the leaks scanner module in the existing ward project at ~/Development/ward:
- Create src/leaks/mod.rs with the run() function that extracts text, scans across all tiers, blocks or passes
- Create src/leaks/tier1.rs with compiled regex patterns for ALL 30 provider-specific rules from the spec:
  AWS (access key, secret key, bedrock), GCP, Azure, Anthropic (api + admin), OpenAI, GitHub (pat, fine-grained, oauth, app), GitLab PAT, Slack (bot, app, user, webhook, legacy), Stripe, SendGrid, Twilio, Linear, Databricks, Heroku, Vercel, Grafana (api + cloud), Sentry, Datadog, Vault, NPM, PyPI
- Create stub files for tier2.rs and tier3.rs that return empty Vec (we'll fill them in later phases)
- Create stub stopwords.rs
- Wire leaks::run into main.rs for the Leaks subcommand
- Add unit tests in tests/test_leaks_tier1.rs covering all Tier 1 detection cases from the spec
- Include the EXAMPLE-suffix allowlist for AWS keys

Run `cargo test` after writing the tests to make sure they all pass.
```

### Test After

```bash
cd ~/Development/ward

# All Tier 1 tests pass
cargo test test_leaks_tier1

# Spot check key providers manually
echo '{"hook_event_name":"UserPromptSubmit","content":"ghp_ABCDEFghijklmnop1234567890abcdefghij"}' | cargo run -- leaks
# → exit 2, stderr mentions GitHub

echo '{"hook_event_name":"UserPromptSubmit","content":"sk_live_abc123def456ghi789jkl"}' | cargo run -- leaks
# → exit 2, stderr mentions Stripe

echo '{"hook_event_name":"UserPromptSubmit","content":"xoxb-1234567890123-1234567890123-abcdef"}' | cargo run -- leaks
# → exit 2, stderr mentions Slack

echo '{"hook_event_name":"UserPromptSubmit","content":"AKIAIOSFODNN7EXAMPLE"}' | cargo run -- leaks
# → exit 0 (EXAMPLE allowlisted)

echo '{"hook_event_name":"UserPromptSubmit","content":"lin_api_abcdef1234567890abcdef1234567890abcd"}' | cargo run -- leaks
# → exit 2, stderr mentions Linear

# Clean input still passes
echo '{"hook_event_name":"UserPromptSubmit","content":"VOO BND rebalance tolerance 0.05"}' | cargo run -- leaks
# → exit 0
```

---

## Phase 4: Leaks Tier 2 — Structural Patterns

### Prompt

```
Read ~/Development/ward/ward-spec.md — specifically the "Tier 2: Structural Patterns" table.

Fill in src/leaks/tier2.rs in the ward project at ~/Development/ward:
- Private key detection: PEM-encoded keys matching -----BEGIN ... PRIVATE KEY-----
- JWT detection: base64 header.payload.signature format
- Connection string detection: postgres, postgresql, mysql, mongodb, mongodb+srv, redis, amqp, mssql URIs
- Env secret detection: KEY=VALUE patterns for SECRET, PASSWORD, TOKEN, CLIENT_SECRET, DATABASE_URL, PRIVATE_KEY

Add unit tests in tests/test_leaks_tier2.rs covering all Tier 2 detection cases and false positives from the spec.

Run `cargo test` after writing the tests to make sure they all pass.
```

### Test After

```bash
cd ~/Development/ward

# All Tier 2 tests pass
cargo test test_leaks_tier2

# Manual verification
echo '{"hook_event_name":"UserPromptSubmit","content":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PkPfcLBBnBMBFOAlwLwHBLFkJQ\n-----END RSA PRIVATE KEY-----"}' | cargo run -- leaks
# → exit 2, stderr mentions Private Key

echo '{"hook_event_name":"UserPromptSubmit","content":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}' | cargo run -- leaks
# → exit 2, stderr mentions JWT

echo '{"hook_event_name":"UserPromptSubmit","content":"postgres://admin:s3cret@db.host:5432/prod"}' | cargo run -- leaks
# → exit 2, stderr mentions Connection String

echo '{"hook_event_name":"UserPromptSubmit","content":"PASSWORD=hunter2"}' | cargo run -- leaks
# → exit 2, stderr mentions Env Secret

# False positives
echo '{"hook_event_name":"UserPromptSubmit","content":"https://api.example.com/v1/tokens"}' | cargo run -- leaks
# → exit 0

echo '{"hook_event_name":"UserPromptSubmit","content":"password VARCHAR(255)"}' | cargo run -- leaks
# → exit 0
```

---

## Phase 5: Leaks Tier 3 — Generic Detection + Entropy + Stopwords

### Prompt

```
Read ~/Development/ward/ward-spec.md — specifically the "Tier 3: Generic Secret Detection" section.

Fill in the remaining leaks modules in the ward project at ~/Development/ward:

1. Create src/entropy.rs with the shannon_entropy() function from the spec
2. Create src/leaks/stopwords.rs containing the FULL stopword list from betterleaks (all ~800 words). Get the complete list from ~/Development/betterleaks/config/betterleaks.toml — extract every entry in the stopwords array under the generic-api-key rule. Store as a static HashSet<&str>.
3. Fill in src/leaks/tier3.rs with:
   - Generic API key pattern: key=value assignments where the key contains access|auth|api|credential|creds|key|password|secret|token
   - Curl auth header pattern
   - Curl auth user pattern
   - Entropy gate: only fire generic rule if Shannon entropy of captured value >= 3.5
   - Stopword filter: reject if captured value is in the stopword set

Add unit tests in tests/test_leaks_tier3.rs covering:
- High-entropy secret that should match
- Low-entropy value that should NOT match
- Stopword value that should NOT match
- Curl patterns
- All false positive cases from the spec

Run `cargo test` after writing the tests to make sure they all pass.
```

### Test After

```bash
cd ~/Development/ward

# All Tier 3 tests pass
cargo test test_leaks_tier3

# Entropy tests
echo '{"hook_event_name":"UserPromptSubmit","content":"api_key = aK9mP2xR7qL4wB5nJ8cF3vD"}' | cargo run -- leaks
# → exit 2 (high entropy)

echo '{"hook_event_name":"UserPromptSubmit","content":"api_key = changeme"}' | cargo run -- leaks
# → exit 0 (low entropy / stopword)

echo '{"hook_event_name":"UserPromptSubmit","content":"password = password"}' | cargo run -- leaks
# → exit 0 (stopword)

# Curl patterns
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl -H \"Authorization: Bearer sk-realtoken123abc\" https://api.com"}}' | cargo run -- leaks
# → exit 2

echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl -u admin:s3cretP@ss https://api.com"}}' | cargo run -- leaks
# → exit 2

# Full suite — all tiers together
cargo test
```

---

## Phase 6: Event Logger

### Prompt

```
Read ~/Development/ward/ward-spec.md — specifically the "Subcommand: ward log" section.

Create the log module in the ward project at ~/Development/ward:
- Create src/log/mod.rs with the run() function
- Create src/log/entry.rs with the LogEntry struct and from_hook_input() constructor
- Log file default path: ~/.ward/events.jsonl (override via WARD_LOG_PATH env var)
- Auto-create the directory if it doesn't exist
- Each entry is one JSON line with: timestamp, session_id, hook_event, tool_name, tool_input_summary, cwd, permission_mode
- tool_input_summary: first 200 chars, with PII and leaks patterns redacted to [REDACTED]
- Always exit 0 — never block Claude
- Wire log::run into main.rs for the Log subcommand

Add unit tests in tests/test_log.rs covering:
- Log entry creation from each event type
- Truncation to 200 chars
- Redaction of sensitive data in summaries
- Directory auto-creation
- Custom path via WARD_LOG_PATH
- Always exits 0

Run `cargo test` after writing the tests to make sure they all pass.
```

### Test After

```bash
cd ~/Development/ward

# All log tests pass
cargo test test_log

# Manual verification — check file creation
rm -rf ~/.ward/events.jsonl
echo '{"hook_event_name":"SessionStart","session_id":"test123","cwd":"/tmp","permission_mode":"default"}' | cargo run -- log
cat ~/.ward/events.jsonl
# → JSON line with timestamp, session_id: "test123", hook_event: "SessionStart"

# Verify redaction in logs
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"export PASSWORD=hunter2"},"session_id":"test123","cwd":"/tmp","permission_mode":"default"}' | cargo run -- log
tail -1 ~/.ward/events.jsonl
# → tool_input_summary should contain [REDACTED], not "hunter2"

# Verify truncation
python3 -c "import json; print(json.dumps({'hook_event_name':'PreToolUse','tool_name':'Bash','tool_input':{'command':'a'*1000},'session_id':'x','cwd':'/tmp','permission_mode':'default'}))" | cargo run -- log
tail -1 ~/.ward/events.jsonl
# → tool_input_summary should be <= 200 chars

# Custom path
WARD_LOG_PATH=/tmp/ward-test.jsonl echo '{"hook_event_name":"Stop","session_id":"x","cwd":"/tmp","permission_mode":"default"}' | cargo run -- log
cat /tmp/ward-test.jsonl
```

---

## Phase 7: Cross-Cutting False Positive Tests

### Prompt

```
Read ~/Development/ward/ward-spec.md — specifically all the false positive sections.

Create tests/test_false_positives.rs in the ward project at ~/Development/ward.

This file should test BOTH ward pii AND ward leaks against real-world data from the advice-cloud rebalance codebase. Include tests with:

1. A full rebalance JSON fixture (copy a representative fixture from ~/Development/advice-cloud/python/master/src/rebalance/tests/payloads/ — pick one that has typical data like account IDs, tickers, dollar amounts, percentages, dates, CUSIPs, share quantities)
2. Strings containing: account_id, household_id, security_id values (integers like 45758)
3. Ticker symbols: VOO, BND, DGRO, SPY, VTIP, AAPL, VXUS
4. CUSIP codes: "12345678", "87654321", "CASH"
5. Dollar amounts: 100000.0, 60000.0, 400.0
6. Percentages: 0.6, 0.05, 5, 2
7. Share quantities: 150.0, 86000.0
8. ISO dates: "2023-08-22", "2023-01-01"
9. Account names: "Investment Account", "Taxable Model Account"
10. Enum strings: "IRA", "taxable", "L", "tolerance", "avoid_wash_sales"
11. Code variable names: gains_budget_lt, abs_units, avoid_wash_sales
12. Schema DDL: "password VARCHAR(255)", "token_expires_at TIMESTAMP"
13. Import statements: "import { token } from './config'"
14. URL paths: "https://api.example.com/v1/tokens"
15. Key-type identifiers: "primary_key", "foreign_key", "public_key"

Every single one of these must return NO matches from both the PII and leaks scanners.

Run `cargo test` after writing to make sure they all pass.
```

### Test After

```bash
cd ~/Development/ward

# All false positive tests pass
cargo test test_false_positive

# Full test suite — everything green
cargo test
```

---

## Phase 8: Integration Tests

### Prompt

```
Read ~/Development/ward/ward-spec.md — specifically the "Integration Tests" table.

Create tests/test_integration.rs in the ward project at ~/Development/ward.

These are end-to-end tests using assert_cmd that invoke the actual ward binary with JSON on stdin and assert:
- Exit code (0 or 2)
- Stdout content ({"continue": true})
- Stderr content (WARD PII BLOCKED / WARD LEAKS BLOCKED messages with redacted values)

Cover every row in the Integration Tests table from the spec:
- test_pii_clean_prompt
- test_pii_blocked_ssn
- test_pii_blocked_email_in_edit
- test_pii_clean_bash
- test_pii_clean_rebalance_fixture
- test_leaks_blocked_github_pat
- test_leaks_blocked_aws_key
- test_leaks_blocked_stripe_key
- test_leaks_blocked_connection_string
- test_leaks_blocked_private_key
- test_leaks_clean_ticker
- test_log_writes_event
- test_log_redacts_leaks
- test_multiple_violations (run pii and leaks separately, both exit 2)
- test_malformed_stdin

Run `cargo test` after writing to make sure they all pass.
```

### Test After

```bash
cd ~/Development/ward

# All integration tests pass
cargo test test_integration

# Full suite — every test across all files
cargo test

# Check test count
cargo test 2>&1 | tail -1
# Should show 80+ tests, 0 failures
```

---

## Phase 9: Release Build + Install

### Prompt

```
In the ward project at ~/Development/ward:

1. Run `cargo build --release` and verify it succeeds
2. Check binary size (should be under 5MB with strip + lto)
3. Run a quick benchmark: time the binary on a typical input to verify < 10ms latency
4. Copy the binary to ~/.local/bin/ward (create dir if needed)
5. Verify `ward --help`, `ward pii --help`, `ward leaks --help`, `ward log --help` all work from PATH
6. Create a .gitignore that excludes target/
7. Do NOT set up Claude Code hooks config yet — just get the binary installed
```

### Test After

```bash
# Binary exists and runs from PATH
which ward
ward --help

# Size check
ls -lh ~/.local/bin/ward
# Should be < 5MB

# Latency check
time echo '{"hook_event_name":"UserPromptSubmit","content":"just a normal message about rebalancing VOO and BND"}' | ward pii
# Should be well under 10ms (real time)

time echo '{"hook_event_name":"UserPromptSubmit","content":"just a normal message about rebalancing VOO and BND"}' | ward leaks
# Should be well under 10ms (real time)

# Final smoke test — all three subcommands
echo '{"hook_event_name":"UserPromptSubmit","content":"hello world"}' | ward pii && echo "PASS: pii clean"
echo '{"hook_event_name":"UserPromptSubmit","content":"hello world"}' | ward leaks && echo "PASS: leaks clean"
echo '{"hook_event_name":"SessionStart","session_id":"smoke","cwd":"/tmp","permission_mode":"default"}' | ward log && echo "PASS: log"
```

---

## Phase 10: Hook Configuration + Live Test

### Prompt

```
Read ~/Development/ward/ward-spec.md — specifically the "Hook Configuration" section.

Configure Claude Code to use ward hooks:

1. Add the hook configuration to ~/.claude/settings.json (user-level, applies to all projects):
   - UserPromptSubmit: ward pii + ward leaks (blocking, timeout 5s)
   - PreToolUse with matcher "Bash|Edit|Write": ward pii + ward leaks (blocking, timeout 5s)
   - SessionStart, PostToolUse, Stop, SessionEnd: ward log (async, non-blocking, timeout 5s)

2. After configuring, test live in a Claude Code session:
   - Type a normal message — should pass through with "Scanning for PII..." / "Scanning for secrets..." status messages
   - Type a message containing "my ssn is 123-45-6789" — should be BLOCKED with a PII warning
   - Type a message containing "ghp_ABCDEFghijklmnop1234567890abcdefghij" — should be BLOCKED with a leaks warning
   - Check ~/.ward/events.jsonl is being populated with log entries

Do NOT modify the ward source code in this phase.
```

### Test After

```
Live in Claude Code:
- Normal prompts work without interruption
- PII in prompts is blocked with clear message
- Secrets in prompts are blocked with clear message
- Tool use with secrets (e.g., writing a file with a password) is blocked
- ~/.ward/events.jsonl shows session events
- No noticeable latency increase in normal usage
```

---

## Summary

| Phase | What | Tests | Est. Complexity |
|-------|------|-------|-----------------|
| 1 | Scaffold + CLI skeleton | Compile, stubs pass through, malformed JSON safe | Low |
| 2 | PII scanner (4 patterns) | 11 detection + false positive tests | Medium |
| 3 | Leaks Tier 1 (30 provider patterns) | 24+ detection tests | High |
| 4 | Leaks Tier 2 (4 structural patterns) | 11 detection + false positive tests | Medium |
| 5 | Leaks Tier 3 (generic + entropy + 800 stopwords) | Entropy, stopword, curl tests | High |
| 6 | Event logger | 9 log tests (creation, redaction, truncation) | Medium |
| 7 | Cross-cutting false positives | 15+ real-world data tests | Medium |
| 8 | Integration tests (end-to-end) | 15 binary-level tests | Medium |
| 9 | Release build + install | Size, latency, PATH verification | Low |
| 10 | Hook config + live test | Manual live testing in Claude Code | Low |
