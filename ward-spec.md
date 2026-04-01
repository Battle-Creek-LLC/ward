# Ward — Claude Code Hook CLI

**Linear Issue**: APP-1044
**Goal**: Build a fast, local CLI in Rust with subcommands that integrate with Claude Code hooks. Ships as a single binary — no runtime dependencies.

**Inspiration**: Rule patterns for `ward leaks` are informed by [betterleaks](https://github.com/betterleaks/betterleaks) (265 rules, Go, 693 stars) — a secrets scanner built for configurability and speed by former Gitleaks maintainers. We adapt their regex patterns and entropy-based filtering approach for a real-time Claude Code hook context.

---

## Why Rust?

- **Speed**: Regex matching on every prompt and tool invocation must be near-instant. Rust's `regex` crate compiles patterns to native code.
- **Single binary**: No runtime dependencies. No `python3` path issues. Ship one binary, done.
- **Reliability**: No GC pauses, no startup latency, type-safe JSON parsing.

---

## Subcommands

Ward ships three subcommands, each targeting different hook events:

| Subcommand | Hook Events | Purpose |
|---|---|---|
| `ward pii` | UserPromptSubmit, PreToolUse | Block personally identifiable information (SSNs, credit cards, emails, phone numbers) |
| `ward leaks` | UserPromptSubmit, PreToolUse | Block credentials and secrets — API keys, cloud provider keys, tokens, passwords, connection strings, private keys (patterns sourced from betterleaks) |
| `ward log` | All events | Structured event logging to a local JSON log file for audit and observability |

---

## Architecture

```
Claude Code Hook Event
        │
        ▼
   ward <subcommand>  (LOCAL — nothing leaves machine)
        │
        ├─ Read JSON from stdin
        ├─ Parse hook_event_name + extract relevant text
        │
        ├─ ward pii:
        │   ├─ SSN, Credit Card, Email, Phone
        │   ├─ Match found → exit 2 + stderr → BLOCKED
        │   └─ Clean → exit 0 + stdout JSON → proceeds
        │
        ├─ ward leaks:
        │   ├─ Provider-specific keys (AWS, GCP, Azure, GitHub, Slack, Stripe, OpenAI, Anthropic, ...)
        │   ├─ Generic secrets (password=, token=, connection strings, private keys, JWTs)
        │   ├─ Match found → exit 2 + stderr → BLOCKED
        │   └─ Clean → exit 0 + stdout JSON → proceeds
        │
        └─ ward log:
            ├─ Append structured event to ~/.ward/events.jsonl
            └─ Always exit 0 (non-blocking)
```

---

## Hook Configuration

After building the binary, configure in `.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "ward pii",
            "timeout": 5,
            "statusMessage": "Scanning for PII..."
          },
          {
            "type": "command",
            "command": "ward leaks",
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
            "command": "ward pii",
            "timeout": 5,
            "statusMessage": "Scanning for PII..."
          },
          {
            "type": "command",
            "command": "ward leaks",
            "timeout": 5,
            "statusMessage": "Scanning for secrets..."
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "ward log",
            "timeout": 5,
            "async": true
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "ward log",
            "timeout": 5,
            "async": true
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "ward log",
            "timeout": 5,
            "async": true
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "ward log",
            "timeout": 5,
            "async": true
          }
        ]
      }
    ]
  }
}
```

---

## Hook Input/Output Contract

### Input (JSON on stdin)

**Common fields on all events:**

```json
{
  "session_id": "abc123",
  "transcript_path": "/path/to/transcript.jsonl",
  "cwd": "/current/working/dir",
  "permission_mode": "default",
  "hook_event_name": "UserPromptSubmit | PreToolUse | PostToolUse | SessionStart | Stop | SessionEnd"
}
```

**UserPromptSubmit** — the prompt text is in the input JSON. Extract and scan the user's message content.

**PreToolUse** — additional fields:

```json
{
  "tool_name": "Bash | Edit | Write",
  "tool_input": {
    "command": "...",       // Bash
    "content": "...",       // Write
    "old_string": "...",    // Edit
    "new_string": "..."     // Edit
  }
}
```

**PostToolUse** — additional fields:

```json
{
  "tool_name": "Bash | Edit | Write",
  "tool_input": { "command": "..." },
  "tool_result": "output here"
}
```

### Output — Blocking hooks (pii, leaks)

**Clean (nothing detected):**
- Exit code: `0`
- Stdout: `{"continue": true}`

**Violation detected (blocked):**
- Exit code: `2`
- Stderr: Human-readable message, e.g.:
  ```
  WARD PII BLOCKED: Detected SSN pattern (***-**-6789) in input. Remove sensitive data before proceeding.
  ```
  ```
  WARD LEAKS BLOCKED: Detected AWS Access Key (AKIA********MPLE). Remove credentials before proceeding.
  ```

### Output — Non-blocking hooks (log)

- Exit code: `0` (always)
- Stdout: `{"continue": true}`
- Side effect: appends structured JSON line to `~/.ward/events.jsonl`

---

## Subcommand: `ward pii`

Detects personally identifiable information about individuals.

### Regex Patterns

All patterns compiled once at startup via `OnceCell`.

| PII Type | Pattern | Notes |
|----------|---------|-------|
| SSN | `(?<!\d{4}-)\b\d{3}-\d{2}-\d{4}\b` | Negative lookbehind prevents matching ISO dates (YYYY-MM-DD) |
| Credit Card | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` | Luhn check optional but recommended |
| Email | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` | |
| Phone | `\b(\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b` | US format |

### False Positive Mitigation

These must NOT trigger:

- **ISO dates**: `"2023-08-22"` — negative lookbehind on SSN pattern
- **CUSIPs**: `"12345678"` — 8 digits, not SSN's 3-2-4 dash pattern
- **Dollar amounts**: `100000.0`, `60000.0` — decimals, not card numbers
- **Percentages/weights**: `0.6`, `0.05`
- **Numeric IDs**: `1`, `2`, `101`, `45758`
- **Tickers**: `VOO`, `BND`, `DGRO`, `SPY`, `AAPL`
- **Variable names**: `gains_budget_lt`, `abs_units`
- **Enum strings**: `"IRA"`, `"taxable"`, `"L"`, `"tolerance"`

### Test Plan — PII Detection

| Test | Input | Expected |
|------|-------|----------|
| `test_ssn_detected` | `"SSN: 123-45-6789"` | Match: SSN |
| `test_credit_card_spaces` | `"Card: 4111 1111 1111 1111"` | Match: Credit Card |
| `test_credit_card_dashes` | `"Card: 4111-1111-1111-1111"` | Match: Credit Card |
| `test_email_detected` | `"john.doe@example.com"` | Match: Email |
| `test_phone_parens` | `"Call (555) 123-4567"` | Match: Phone |
| `test_phone_plus1` | `"+1 555-123-4567"` | Match: Phone |
| `test_iso_date_no_match` | `"2023-08-22"` | No match |
| `test_cusip_no_match` | `"cusip: \"12345678\""` | No match |
| `test_dollar_amounts_no_match` | `"value: 100000.0"` | No match |
| `test_tickers_no_match` | `"VOO BND DGRO SPY"` | No match |
| `test_rebalance_fixture_no_match` | Full JSON fixture | No match |

---

## Subcommand: `ward leaks`

Detects credentials, API keys, passwords, tokens, and other secrets that should never leave the machine. Patterns are organized into tiers by specificity, inspired by betterleaks' rule architecture.

### Tier 1: Provider-Specific Keys (High Confidence)

These patterns match known token formats with fixed prefixes — very low false positive risk.

| Rule ID | Pattern | Source |
|---------|---------|--------|
| `aws-access-key` | `\b((?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16})\b` | betterleaks |
| `aws-secret-key` | `(?i)[\w.-]{0,50}?(?:secret\|access\|key\|token)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}([A-Za-z0-9/+=]{40})` | betterleaks |
| `aws-bedrock-key` | `\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})\b` | betterleaks |
| `gcp-api-key` | `\b(AIza[\w-]{35})\b` | betterleaks |
| `azure-ad-client-secret` | `(?i)[\w.-]{0,50}?(?:administrator_login_password\|password)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}("[a-z0-9=_\-]{8,20}")` | betterleaks |
| `anthropic-api-key` | `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b` | betterleaks |
| `anthropic-admin-key` | `\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)\b` | betterleaks |
| `openai-api-key` | `\b(sk-(?:proj\|svcacct\|admin)-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b` | betterleaks |
| `github-pat` | `ghp_[0-9a-zA-Z]{36}` | betterleaks |
| `github-fine-grained-pat` | `github_pat_\w{82}` | betterleaks |
| `github-oauth` | `gho_[0-9a-zA-Z]{36}` | betterleaks |
| `github-app-token` | `(?:ghu\|ghs)_[0-9a-zA-Z]{36}` | betterleaks |
| `gitlab-pat` | `glpat-[\w\-]{20,}` | betterleaks |
| `slack-bot-token` | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` | betterleaks |
| `slack-app-token` | `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+` | betterleaks |
| `slack-user-token` | `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}` | betterleaks |
| `slack-webhook` | `(?:https?://)?hooks\.slack\.com/(?:services\|workflows\|triggers)/[A-Za-z0-9+/]{43,56}` | betterleaks |
| `slack-legacy-token` | `xox[os]-\d+-\d+-\d+-[a-fA-F\d]+` | betterleaks |
| `stripe-key` | `\b((?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99})\b` | betterleaks |
| `sendgrid-api-token` | `\b(SG\.[\w-]{22}\.[\w-]{43})\b` | common format |
| `twilio-api-key` | `\bSK[0-9a-fA-F]{32}\b` | betterleaks |
| `linear-api-key` | `lin_api_(?i)[a-z0-9]{40}` | betterleaks |
| `databricks-api-token` | `\b(dapi[a-f0-9]{32}(?:-\d)?)\b` | betterleaks |
| `heroku-api-key` | `(?i)[\w.-]{0,50}?(?:heroku)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})` | betterleaks |
| `vercel-api-token` | `(?i)\b(vc[karic]_[A-Za-z0-9_-]{56})\b` | betterleaks |
| `grafana-api-key` | `(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})\b` | betterleaks |
| `grafana-cloud-token` | `(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})\b` | betterleaks |
| `sentry-org-token` | `\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}\b` | betterleaks |
| `datadog-access-token` | `(?i)[\w.-]{0,50}?(?:datadog)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}([a-z0-9]{40})` | betterleaks |
| `hashicorp-vault-token` | `\b((?:hvs\.[\w-]{90,120}\|s\.(?i:[a-z0-9]{24})))\b` | betterleaks |
| `npm-access-token` | `\b(npm_[A-Za-z0-9]{36})\b` | betterleaks |
| `pypi-upload-token` | `\b(pypi-[A-Za-z0-9_-]{50,})\b` | betterleaks |

### Tier 2: Structural Patterns (Medium Confidence)

These match known secret formats without a specific provider prefix.

| Rule ID | Pattern | Notes |
|---------|---------|-------|
| `private-key` | `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----` | PEM-encoded keys (RSA, EC, OPENSSH, DSA, PGP). From betterleaks. |
| `jwt` | `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?)\b` | Base64-encoded JWT (header.payload.signature). From betterleaks. |
| `connection-string` | `(?i)(postgres\|postgresql\|mysql\|mongodb(\+srv)?\|redis\|amqp\|mssql)://[^\s"']+` | Database/service URIs with embedded credentials |
| `env-secret` | `(?i)(SECRET\|PASSWORD\|TOKEN\|CLIENT_SECRET\|DATABASE_URL\|PRIVATE_KEY)=\S+` | Key=value assignments in env files |

### Tier 3: Generic Secret Detection (Lower Confidence, Entropy-Gated)

Adapted from betterleaks' `generic-api-key` rule. These patterns are broader and require additional validation to avoid false positives.

| Rule ID | Pattern | Notes |
|---------|---------|-------|
| `generic-api-key` | `(?i)[\w.-]{0,50}?(?:access\|auth\|api\|credential\|creds\|key\|passw(?:or)?d\|secret\|token)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}([\w.=-]{10,150})` | From betterleaks. Requires Shannon entropy >= 3.5 on the captured value to fire. |
| `curl-auth-header` | `(?i)curl\b.*(?:-H\|--header)\s*["']?Authorization:\s*(?:Bearer\|Basic\|Token)\s+\S+` | Auth headers in curl commands |
| `curl-auth-user` | `(?i)curl\b.*(?:-u\|--user)\s*["']?\S+:\S+` | User:password in curl commands |

**Entropy gating** (from betterleaks): For Tier 3 rules, compute Shannon entropy of the captured secret value. Only fire if entropy >= 3.5. This filters out low-randomness strings like `password=changeme` in documentation while catching real secrets like `password=aK9#mP2$xR7!qL4w`.

**Stopword filtering** (from betterleaks): Reject matches where the captured value is a common English/tech word (betterleaks ships a list of ~800 stopwords including `account`, `admin`, `config`, `default`, `example`, `password`, `public`, `secret`, `server`, `test`, `token`, `value`, etc.). This dramatically reduces false positives on the generic rule.

### False Positive Mitigation

These must NOT trigger:

- **Tickers**: `VOO`, `BND`, `AAPL` — short uppercase, won't hit key patterns
- **Account names**: `"Investment Account"` — no key=value structure
- **Test JSON fixtures**: rebalance payloads with numeric values
- **Code identifiers**: `avoid_wash_sales`, `gains_budget_lt`
- **Placeholder values**: `SECRET=` with no value, template variables like `${SECRET}`
- **Schema definitions**: `password VARCHAR(255)` — DDL, not an actual password
- **URL paths without credentials**: `https://api.example.com/v1/tokens` — no embedded auth
- **Import statements**: `import { token } from './config'` — code structure, not a secret
- **Example/dummy keys**: Values ending in `EXAMPLE` (per betterleaks AWS allowlist)

### Test Plan — Leak Detection

#### Tier 1: Provider-Specific Keys

| Test | Input | Expected |
|------|-------|----------|
| `test_aws_access_key_akia` | `"AKIAIOSFODNN7EXAMPLE"` | No match (EXAMPLE suffix allowlisted) |
| `test_aws_access_key_real` | `"AKIAI44QH8DHBEXAMPLE"` stripped of EXAMPLE | Match: AWS Access Key |
| `test_aws_secret_key` | `"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY"` | Match: AWS Secret Key |
| `test_aws_bedrock_key` | `"ABSK" + 120 alphanumeric chars` | Match: AWS Bedrock Key |
| `test_gcp_api_key` | `"AIzaSyC-fake35charskeydata012345"` | Match: GCP API Key |
| `test_anthropic_api_key` | `"sk-ant-api03-" + 93 chars + "AA"` | Match: Anthropic API Key |
| `test_anthropic_admin_key` | `"sk-ant-admin01-" + 93 chars + "AA"` | Match: Anthropic Admin Key |
| `test_openai_api_key` | `"sk-proj-" + 20 chars + "T3BlbkFJ" + 20 chars` | Match: OpenAI API Key |
| `test_github_pat` | `"ghp_ABCDEFghijklmnop1234567890abcdefghij"` | Match: GitHub PAT |
| `test_github_fine_grained_pat` | `"github_pat_" + 82 word chars` | Match: GitHub Fine-Grained PAT |
| `test_github_oauth` | `"gho_ABCDEFghijklmnop1234567890abcdefghij"` | Match: GitHub OAuth |
| `test_github_app_token` | `"ghs_ABCDEFghijklmnop1234567890abcdefghij"` | Match: GitHub App Token |
| `test_slack_bot_token` | `"xoxb-1234567890123-1234567890123-abc"` | Match: Slack Bot Token |
| `test_slack_app_token` | `"xapp-1-A0123BCDE-1234567890-abcdef"` | Match: Slack App Token |
| `test_slack_webhook` | `"https://hooks.slack.com/services/T00/B00/xxxx"` | Match: Slack Webhook |
| `test_stripe_live_key` | `"sk_live_abc123def456ghi789"` | Match: Stripe Key |
| `test_stripe_test_key` | `"sk_test_abc123def456ghi789"` | Match: Stripe Key |
| `test_sendgrid_token` | `"SG.abcdefghijklmnopqrstuv.wxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZab"` | Match: SendGrid Token |
| `test_linear_api_key` | `"lin_api_" + 40 alphanumeric chars` | Match: Linear API Key |
| `test_databricks_token` | `"dapi1234abcd5678efgh9012ijkl3456"` | Match: Databricks Token |
| `test_npm_token` | `"npm_ABCDEFghijklmnop1234567890abcdefghij"` | Match: NPM Token |
| `test_pypi_token` | `"pypi-AgEIcHlwaS5vcmc..." (50+ chars)` | Match: PyPI Token |
| `test_grafana_api_key` | `"eyJrIjoi" + 70 alphanumeric chars` | Match: Grafana API Key |
| `test_vault_token` | `"hvs." + 90 chars` | Match: Vault Token |

#### Tier 2: Structural Patterns

| Test | Input | Expected |
|------|-------|----------|
| `test_private_key_rsa` | `"-----BEGIN RSA PRIVATE KEY-----\nMIIE..."` | Match: Private Key |
| `test_private_key_openssh` | `"-----BEGIN OPENSSH PRIVATE KEY-----\nb3..."` | Match: Private Key |
| `test_private_key_ec` | `"-----BEGIN EC PRIVATE KEY-----\nMHQ..."` | Match: Private Key |
| `test_jwt_token` | `"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"` | Match: JWT |
| `test_postgres_uri` | `"postgres://admin:s3cret@db.host:5432/prod"` | Match: Connection String |
| `test_mysql_uri` | `"mysql://root:password@localhost/mydb"` | Match: Connection String |
| `test_mongodb_srv_uri` | `"mongodb+srv://user:pass@cluster.mongodb.net/db"` | Match: Connection String |
| `test_redis_uri` | `"redis://default:password@cache:6379"` | Match: Connection String |
| `test_env_password` | `"PASSWORD=hunter2"` | Match: Env Secret |
| `test_env_client_secret` | `"BRIDGEFT_CLIENT_SECRET=abc123secret"` | Match: Env Secret |
| `test_env_database_url` | `"DATABASE_URL=postgresql://user:pw@host/db"` | Match: Env Secret |

#### Tier 3: Generic + Entropy

| Test | Input | Expected |
|------|-------|----------|
| `test_generic_high_entropy` | `"api_key = 'aK9mP2xR7qL4wB5nJ8cF3'"` | Match: Generic API Key (entropy > 3.5) |
| `test_generic_low_entropy_no_match` | `"api_key = 'changeme'"` | No match (entropy too low, stopword) |
| `test_generic_stopword_no_match` | `"password = 'password'"` | No match (stopword) |
| `test_curl_bearer` | `"curl -H 'Authorization: Bearer sk-realtoken123'"` | Match: Curl Auth Header |
| `test_curl_user_pass` | `"curl -u admin:s3cretP@ss https://api.com"` | Match: Curl Auth User |

#### False Positive Prevention

| Test | Input | Expected |
|------|-------|----------|
| `test_ticker_no_match` | `"VOO BND DGRO SPY AAPL"` | No match |
| `test_schema_ddl_no_match` | `"password VARCHAR(255)"` | No match |
| `test_url_path_no_match` | `"https://api.example.com/v1/tokens"` | No match |
| `test_placeholder_no_match` | `"SECRET=${MY_SECRET}"` | No match |
| `test_import_no_match` | `"import { token } from './config'"` | No match |
| `test_key_type_no_match` | `"primary_key, foreign_key, public_key"` | No match |
| `test_example_suffix_no_match` | `"AKIAIOSFODNN7EXAMPLE"` | No match |
| `test_rebalance_fixture_no_match` | Full JSON fixture from test files | No match |
| `test_code_identifiers_no_match` | `"avoid_wash_sales, gains_budget_lt"` | No match |
| `test_account_names_no_match` | `"Investment Account", "Taxable Model Account"` | No match |

---

## Subcommand: `ward log`

Non-blocking structured event logger. Appends one JSON line per hook invocation to a local log file.

### Log File

- **Default path**: `~/.ward/events.jsonl`
- **Override via env**: `WARD_LOG_PATH=/custom/path/events.jsonl`
- Created automatically if it doesn't exist.

### Log Entry Schema

Each line is a JSON object:

```json
{
  "timestamp": "2026-03-31T15:30:00.123Z",
  "session_id": "abc123",
  "hook_event": "PreToolUse",
  "tool_name": "Bash",
  "tool_input_summary": "npm test",
  "cwd": "/Users/dev/project",
  "permission_mode": "default",
  "duration_ms": null
}
```

Field details:

| Field | Source | Notes |
|---|---|---|
| `timestamp` | System clock | ISO 8601 UTC |
| `session_id` | `stdin.session_id` | Groups events within a session |
| `hook_event` | `stdin.hook_event_name` | Event type |
| `tool_name` | `stdin.tool_name` | Present for tool events, null otherwise |
| `tool_input_summary` | `stdin.tool_input` | First 200 chars of primary input field (command, content, etc.). Truncated to avoid bloat. |
| `cwd` | `stdin.cwd` | Working directory at time of event |
| `permission_mode` | `stdin.permission_mode` | Active permission mode |
| `duration_ms` | `stdin.tool_result` timing | For PostToolUse, duration if available; null otherwise |

### Sensitive Data in Logs

The logger must NOT write raw tool input/output that might contain secrets. The `tool_input_summary` field is:
- Truncated to 200 characters
- Stripped through the same regex patterns used by `ward pii` and `ward leaks` — any match is replaced with `[REDACTED]`
- This means the log is safe to retain even in shared environments

### Log Rotation

Ward does not handle rotation itself. Recommend:
- `logrotate` on Linux/macOS
- Or a future `ward log --rotate` subcommand that archives files over a size threshold

### Hook Configuration for Logging

For full observability, attach `ward log` to multiple events using `async: true` so it never blocks Claude:

```json
"SessionStart":    [{ "hooks": [{ "type": "command", "command": "ward log", "async": true }] }],
"UserPromptSubmit":[{ "hooks": [{ "type": "command", "command": "ward log", "async": true }] }],
"PreToolUse":      [{ "hooks": [{ "type": "command", "command": "ward log", "async": true }] }],
"PostToolUse":     [{ "hooks": [{ "type": "command", "command": "ward log", "async": true }] }],
"Stop":            [{ "hooks": [{ "type": "command", "command": "ward log", "async": true }] }],
"SessionEnd":      [{ "hooks": [{ "type": "command", "command": "ward log", "async": true }] }]
```

### Test Plan — Logging

| Test | Input | Expected |
|------|-------|----------|
| `test_log_session_start` | SessionStart event JSON | Appends line with `hook_event: "SessionStart"` |
| `test_log_pre_tool_use` | PreToolUse Bash event | Appends line with `tool_name: "Bash"`, summary of command |
| `test_log_post_tool_use` | PostToolUse event | Appends line with tool result summary |
| `test_log_stop` | Stop event | Appends line with `hook_event: "Stop"` |
| `test_log_truncation` | PreToolUse with 1000-char command | `tool_input_summary` is 200 chars max |
| `test_log_redaction` | PreToolUse with SSN in command | `tool_input_summary` contains `[REDACTED]` not the SSN |
| `test_log_creates_dir` | No `~/.ward/` dir exists | Creates dir and file automatically |
| `test_log_custom_path` | `WARD_LOG_PATH` env set | Writes to custom path |
| `test_log_always_exits_0` | Any event | Exit code 0, stdout `{"continue": true}` |

---

## Project Structure

```
ward/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI entry: parse subcommand, read stdin, dispatch
│   ├── cli.rs               # clap subcommand definitions
│   ├── input.rs             # JSON deserialization + text extraction from hook events
│   ├── output.rs            # JSON stdout + stderr formatting + redaction
│   ├── entropy.rs           # Shannon entropy calculation for Tier 3 rules
│   ├── pii/
│   │   ├── mod.rs           # PII scanner: SSN, credit card, email, phone
│   │   └── patterns.rs      # Compiled regex patterns for PII
│   ├── leaks/
│   │   ├── mod.rs           # Leaks scanner: dispatch across tiers
│   │   ├── tier1.rs         # Provider-specific key patterns (AWS, GitHub, Slack, Stripe, etc.)
│   │   ├── tier2.rs         # Structural patterns (private keys, JWTs, connection strings, env secrets)
│   │   ├── tier3.rs         # Generic patterns with entropy gating
│   │   └── stopwords.rs     # Stopword list for generic rule false positive filtering
│   └── log/
│       ├── mod.rs           # Event logger: parse, redact, append
│       └── entry.rs         # Log entry struct + serialization
└── tests/
    ├── test_pii.rs               # PII pattern detection + false positives
    ├── test_leaks_tier1.rs        # Provider-specific key tests
    ├── test_leaks_tier2.rs        # Structural pattern tests
    ├── test_leaks_tier3.rs        # Generic + entropy tests
    ├── test_log.rs                # Log entry creation, redaction, file I/O
    ├── test_false_positives.rs    # Cross-cutting: rebalance fixtures, codebase data
    └── test_integration.rs        # End-to-end: stdin JSON → exit code + output
```

---

## Dependencies (Cargo.toml)

```toml
[package]
name = "ward"
version = "0.1.0"
edition = "2021"
description = "Claude Code hook CLI — PII guard, leak detection, event logging"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
regex = "1"
once_cell = "1"
chrono = { version = "0.4", features = ["serde"] }

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"

[profile.release]
opt-level = 3
lto = true
strip = true
codegen-units = 1
```

---

## Implementation Details

### main.rs

```rust
use clap::Parser;
use std::io::{self, Read};
use std::process;

mod cli;
mod entropy;
mod input;
mod output;
mod pii;
mod leaks;
mod log;

fn main() {
    let args = cli::Cli::parse();

    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).unwrap_or_default();

    let hook_input: input::HookInput = match serde_json::from_str(&buffer) {
        Ok(v) => v,
        Err(_) => {
            // Can't parse input — let it through, don't block Claude
            output::pass();
            process::exit(0);
        }
    };

    match args.command {
        cli::Command::Pii => pii::run(&hook_input),
        cli::Command::Leaks => leaks::run(&hook_input),
        cli::Command::Log => log::run(&hook_input),
    }
}
```

### cli.rs

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ward", about = "Claude Code hook CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan for personally identifiable information (SSN, credit card, email, phone)
    Pii,
    /// Scan for secrets and credentials (API keys, cloud keys, passwords, tokens, private keys)
    Leaks,
    /// Log hook events to ~/.ward/events.jsonl
    Log,
}
```

### entropy.rs

```rust
use std::collections::HashMap;

/// Compute Shannon entropy of a string (bits per character).
/// Used by Tier 3 generic rules to filter low-randomness matches.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}
```

### input.rs

```rust
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
```

### leaks/mod.rs

```rust
use crate::input::HookInput;
use crate::output;
use std::process;

mod tier1;
mod tier2;
mod tier3;
mod stopwords;

pub fn run(input: &HookInput) {
    let text = input.extract_text();
    if text.is_empty() {
        output::pass();
        process::exit(0);
    }

    let mut matches = Vec::new();
    matches.extend(tier1::scan(&text));
    matches.extend(tier2::scan(&text));
    matches.extend(tier3::scan(&text));

    if matches.is_empty() {
        output::pass();
        process::exit(0);
    }

    output::block("LEAKS", &matches);
    process::exit(2);
}
```

### output.rs

```rust
pub struct Match {
    pub category: &'static str,
    pub matched_text: String,
}

pub fn pass() {
    println!("{{\"continue\": true}}");
}

pub fn block(guard_name: &str, matches: &[Match]) {
    let descriptions: Vec<String> = matches
        .iter()
        .map(|m| {
            let redacted = redact(&m.matched_text);
            format!("{} ({})", m.category, redacted)
        })
        .collect();

    eprintln!(
        "WARD {} BLOCKED: Detected {}. Remove sensitive data before proceeding.",
        guard_name,
        descriptions.join(", ")
    );
}

/// Redact the middle of a matched string, keeping first/last few chars
fn redact(s: &str) -> String {
    let len = s.len();
    if len <= 6 {
        return "*".repeat(len);
    }
    let keep = 3.min(len / 4);
    format!(
        "{}{}{}",
        &s[..keep],
        "*".repeat(len - keep * 2),
        &s[len - keep..]
    )
}
```

---

## Integration Tests (`test_integration.rs`)

| Test | Stdin | Expected Exit | Expected Output |
|------|-------|---------------|-----------------|
| `test_pii_clean_prompt` | UserPromptSubmit, clean text | `0` | `{"continue": true}` |
| `test_pii_blocked_ssn` | UserPromptSubmit with SSN | `2` | stderr contains "PII" and "SSN" |
| `test_pii_blocked_email_in_edit` | PreToolUse Edit with email in new_string | `2` | stderr contains "Email" |
| `test_pii_clean_bash` | PreToolUse Bash `npm test` | `0` | `{"continue": true}` |
| `test_pii_clean_rebalance_fixture` | PreToolUse Write with full fixture JSON | `0` | `{"continue": true}` |
| `test_leaks_blocked_github_pat` | UserPromptSubmit with `ghp_` token | `2` | stderr contains "LEAKS" and "GitHub" |
| `test_leaks_blocked_aws_key` | PreToolUse Bash with AKIA key | `2` | stderr contains "AWS" |
| `test_leaks_blocked_stripe_key` | PreToolUse Write with `sk_live_` key | `2` | stderr contains "Stripe" |
| `test_leaks_blocked_connection_string` | PreToolUse Write with postgres:// URI | `2` | stderr contains "Connection" |
| `test_leaks_blocked_private_key` | PreToolUse Edit with PEM header | `2` | stderr contains "Private Key" |
| `test_leaks_clean_ticker` | PreToolUse with tickers | `0` | `{"continue": true}` |
| `test_log_writes_event` | SessionStart event | `0` | events.jsonl has new line |
| `test_log_redacts_leaks` | PreToolUse with API key in command | `0` | Log entry has `[REDACTED]` |
| `test_multiple_violations` | Input with SSN + API key (run both pii and leaks) | `2` each | Both report independently |
| `test_malformed_stdin` | `{broken json` | `0` | Fails safe — doesn't block |

---

## Build & Install

```bash
# Build release binary
cd ward && cargo build --release

# Binary at: target/release/ward
# Install globally:
cargo install --path .

# Or copy manually:
cp target/release/ward ~/.local/bin/ward

# Verify:
echo '{"hook_event_name":"UserPromptSubmit","content":"hello"}' | ward leaks
# → {"continue": true}

echo '{"hook_event_name":"UserPromptSubmit","content":"key is sk_live_abc123def456ghi789"}' | ward leaks
# → exit 2, stderr: WARD LEAKS BLOCKED: Detected Stripe Key (sk_**************789)...
```

---

## Acceptance Criteria

- [ ] Rust binary named `ward` with subcommands: `pii`, `leaks`, `log`
- [ ] `ward pii` detects: SSNs, credit cards, emails, phone numbers
- [ ] `ward leaks` Tier 1 detects: AWS keys, GCP keys, Azure secrets, Anthropic keys, OpenAI keys, GitHub tokens (PAT, fine-grained, OAuth, app), GitLab PATs, Slack tokens (bot, app, user, webhook, legacy), Stripe keys, SendGrid tokens, Twilio keys, Linear keys, Databricks tokens, Heroku keys, Vercel tokens, Grafana keys, Sentry tokens, Datadog tokens, Vault tokens, NPM tokens, PyPI tokens
- [ ] `ward leaks` Tier 2 detects: PEM private keys, JWTs, connection strings (postgres, mysql, mongodb, redis, amqp, mssql), env secret assignments
- [ ] `ward leaks` Tier 3 detects: generic key=value secrets gated by Shannon entropy >= 3.5 and stopword filtering, curl auth headers, curl user:pass
- [ ] Both blocking commands exit 2 with clear stderr identifying the violation type and a redacted match
- [ ] Both blocking commands exit 0 with `{"continue": true}` on clean input
- [ ] `ward log` appends structured JSONL to `~/.ward/events.jsonl` and always exits 0
- [ ] `ward log` redacts sensitive data in `tool_input_summary` using the same patterns from pii + leaks
- [ ] Zero false positives on: tickers, IDs, amounts, percentages, dates, CUSIPs, JSON fixtures, variable names, DDL, URL paths, import statements, `*EXAMPLE` suffixed keys
- [ ] Malformed stdin fails safe (exit 0, don't block Claude)
- [ ] All unit tests pass (`cargo test`)
- [ ] All integration tests pass
- [ ] No external network calls — everything runs locally
- [ ] Binary size under 5MB (release build)
- [ ] Startup + scan latency under 10ms for typical inputs

---

## Future Subcommands

| Subcommand | Hook Events | Purpose |
|---|---|---|
| `ward inject` | PostToolUse | Scan tool output for prompt injection attempts |
| `ward cmd` | PreToolUse (Bash) | Decompose compound commands, block dangerous ops (rm -rf, DROP TABLE) |
| `ward lint` | PostToolUse (Write/Edit) | Run linter on changed files |
| `ward notify` | Stop, Notification | Desktop/Slack/Pushover alerts on completion |
| `ward cost` | PostToolUse | Token counting and cost tracking per session |

---

## References

- [betterleaks](https://github.com/betterleaks/betterleaks) — 265 rules, Go, secret scanner by former Gitleaks maintainers. Tier 1 and Tier 2 patterns adapted from their config.
- [Claude Code Hooks docs](https://docs.anthropic.com/en/docs/claude-code/hooks) — Official hook API reference.
- [APP-1044](https://linear.app/advicecloud-ft/issue/APP-1044) — Original Linear issue.
