# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-29

First tagged release. Ward integrates with Claude Code hooks to block PII,
secrets, and credentials from leaking through the AI coding workflow. Ships
as a single Rust binary with no runtime dependencies.

### Added

- `ward pii` — blocks SSNs, credit cards, emails, and US phone numbers on
  `UserPromptSubmit` and `PreToolUse` events. ISO-date and financial false-
  positive guards built in.
- `ward leaks` — three-tier detector covering provider-specific keys
  (AWS, GCP, Azure, Anthropic, OpenAI, GitHub, GitLab, Slack, Stripe,
  SendGrid, Twilio, Linear, Databricks, Heroku, Vercel, Grafana, Sentry,
  Datadog, Vault, NPM, PyPI), structural patterns (PEM keys, JWTs,
  connection strings, env-var secret assignments), and entropy-gated
  generic detection with a 1,446-word stopword list from
  [betterleaks](https://github.com/betterleaks/betterleaks).
- `ward log` — structured event logging to `~/.ward/events.jsonl`,
  fires on every Claude Code hook event.
- Prebuilt binaries on each tagged release for Linux (x86_64, aarch64),
  macOS (x86_64, aarch64), and Windows (x86_64).

[0.1.0]: https://github.com/Battle-Creek-LLC/ward/releases/tag/v0.1.0
