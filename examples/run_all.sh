#!/bin/bash
# Ward example test runner
# Run after building: cargo build
# Usage: ./examples/run_all.sh

set -euo pipefail

WARD="cargo run --"
PASS=0
FAIL=0
TOTAL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
gray()  { printf "\033[90m%s\033[0m\n" "$1"; }

# Test a fixture that SHOULD be blocked (exit 2)
expect_block() {
    local subcommand="$1"
    local fixture="$2"
    local label="$3"
    TOTAL=$((TOTAL + 1))

    if $WARD "$subcommand" < "$fixture" > /dev/null 2>&1; then
        red "FAIL: $label — expected block (exit 2), got pass (exit 0)"
        FAIL=$((FAIL + 1))
    else
        exit_code=$?
        if [ "$exit_code" -eq 2 ]; then
            green "PASS: $label"
            PASS=$((PASS + 1))
        else
            red "FAIL: $label — expected exit 2, got exit $exit_code"
            FAIL=$((FAIL + 1))
        fi
    fi
}

# Test a fixture that SHOULD pass clean (exit 0)
expect_pass() {
    local subcommand="$1"
    local fixture="$2"
    local label="$3"
    TOTAL=$((TOTAL + 1))

    if $WARD "$subcommand" < "$fixture" > /dev/null 2>&1; then
        green "PASS: $label"
        PASS=$((PASS + 1))
    else
        exit_code=$?
        red "FAIL: $label — expected pass (exit 0), got exit $exit_code"
        FAIL=$((FAIL + 1))
    fi
}

# Test that log always exits 0 and writes to the log file
expect_log() {
    local fixture="$1"
    local label="$2"
    TOTAL=$((TOTAL + 1))

    local log_file="/tmp/ward-test-events.jsonl"
    local before_lines=0
    if [ -f "$log_file" ]; then
        before_lines=$(wc -l < "$log_file")
    fi

    if WARD_LOG_PATH="$log_file" $WARD log < "$fixture" > /dev/null 2>&1; then
        if [ -f "$log_file" ]; then
            after_lines=$(wc -l < "$log_file")
            if [ "$after_lines" -gt "$before_lines" ]; then
                green "PASS: $label"
                PASS=$((PASS + 1))
            else
                red "FAIL: $label — exit 0 but no new log line written"
                FAIL=$((FAIL + 1))
            fi
        else
            red "FAIL: $label — log file not created"
            FAIL=$((FAIL + 1))
        fi
    else
        exit_code=$?
        red "FAIL: $label — expected exit 0, got exit $exit_code"
        FAIL=$((FAIL + 1))
    fi
}

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================"
echo "  Ward Example Test Suite"
echo "========================================"
echo ""

# --- PII: Should Block ---
echo "--- PII: Should Block ---"
expect_block pii "$DIR/pii/ssn_in_prompt.json"          "pii: SSN in prompt"
expect_block pii "$DIR/pii/credit_card_in_prompt.json"   "pii: Credit card (spaces) in prompt"
expect_block pii "$DIR/pii/credit_card_dashes.json"      "pii: Credit card (dashes) in prompt"
expect_block pii "$DIR/pii/email_in_prompt.json"         "pii: Email in prompt"
expect_block pii "$DIR/pii/phone_in_prompt.json"         "pii: Phone (parens) in prompt"
expect_block pii "$DIR/pii/phone_plus1.json"             "pii: Phone (+1) in prompt"
expect_block pii "$DIR/pii/ssn_in_edit.json"             "pii: SSN in Edit tool_input"
expect_block pii "$DIR/pii/email_in_write.json"          "pii: Email in Write tool_input"
expect_block pii "$DIR/pii/multiple_pii.json"            "pii: Multiple PII types"
echo ""

# --- Leaks Tier 1: Should Block ---
echo "--- Leaks Tier 1: Provider Keys — Should Block ---"
expect_block leaks "$DIR/leaks/aws_access_key.json"          "leaks: AWS access key"
expect_block leaks "$DIR/leaks/aws_secret_key.json"          "leaks: AWS secret key"
expect_block leaks "$DIR/leaks/gcp_api_key.json"             "leaks: GCP API key"
expect_block leaks "$DIR/leaks/anthropic_api_key.json"       "leaks: Anthropic API key"
expect_block leaks "$DIR/leaks/openai_api_key.json"          "leaks: OpenAI API key"
expect_block leaks "$DIR/leaks/github_pat.json"              "leaks: GitHub PAT"
expect_block leaks "$DIR/leaks/github_fine_grained_pat.json" "leaks: GitHub fine-grained PAT"
expect_block leaks "$DIR/leaks/github_oauth.json"            "leaks: GitHub OAuth token"
expect_block leaks "$DIR/leaks/github_app_token.json"        "leaks: GitHub App token"
expect_block leaks "$DIR/leaks/slack_bot_token.json"         "leaks: Slack bot token"
expect_block leaks "$DIR/leaks/slack_webhook.json"           "leaks: Slack webhook URL"
expect_block leaks "$DIR/leaks/stripe_live_key.json"         "leaks: Stripe live key"
expect_block leaks "$DIR/leaks/stripe_test_key.json"         "leaks: Stripe test key"
expect_block leaks "$DIR/leaks/linear_api_key.json"          "leaks: Linear API key"
expect_block leaks "$DIR/leaks/sendgrid_token.json"          "leaks: SendGrid token"
expect_block leaks "$DIR/leaks/npm_token.json"               "leaks: NPM token"
expect_block leaks "$DIR/leaks/pypi_token.json"              "leaks: PyPI token"
expect_block leaks "$DIR/leaks/databricks_token.json"        "leaks: Databricks token"
expect_block leaks "$DIR/leaks/vault_token.json"             "leaks: Vault token"
echo ""

# --- Leaks Tier 1: Should Pass (Allowlisted) ---
echo "--- Leaks Tier 1: Allowlisted — Should Pass ---"
expect_pass leaks "$DIR/leaks/aws_access_key_example_allowlisted.json" "leaks: AWS EXAMPLE key (allowlisted)"
echo ""

# --- Leaks Tier 2: Should Block ---
echo "--- Leaks Tier 2: Structural Patterns — Should Block ---"
expect_block leaks "$DIR/leaks/private_key_rsa.json"             "leaks: RSA private key"
expect_block leaks "$DIR/leaks/private_key_openssh.json"         "leaks: OpenSSH private key"
expect_block leaks "$DIR/leaks/jwt_token.json"                   "leaks: JWT token"
expect_block leaks "$DIR/leaks/connection_string_postgres.json"  "leaks: Postgres connection string"
expect_block leaks "$DIR/leaks/connection_string_mysql.json"     "leaks: MySQL connection string"
expect_block leaks "$DIR/leaks/connection_string_mongodb.json"   "leaks: MongoDB connection string"
expect_block leaks "$DIR/leaks/connection_string_redis.json"     "leaks: Redis connection string"
expect_block leaks "$DIR/leaks/env_secret_password.json"         "leaks: PASSWORD= env secret"
expect_block leaks "$DIR/leaks/env_secret_client.json"           "leaks: CLIENT_SECRET= env secret"
echo ""

# --- Leaks Tier 3: Should Block ---
echo "--- Leaks Tier 3: Generic + Entropy — Should Block ---"
expect_block leaks "$DIR/leaks/generic_high_entropy.json"   "leaks: Generic high-entropy API key"
expect_block leaks "$DIR/leaks/curl_bearer.json"            "leaks: curl Bearer auth header"
expect_block leaks "$DIR/leaks/curl_user_pass.json"         "leaks: curl -u user:pass"
expect_block leaks "$DIR/leaks/multiple_leaks.json"         "leaks: Multiple leak types"
echo ""

# --- Leaks Tier 3: Should Pass ---
echo "--- Leaks Tier 3: Low Entropy — Should Pass ---"
expect_pass leaks "$DIR/leaks/generic_low_entropy_should_pass.json" "leaks: Generic low-entropy (stopword)"
echo ""

# --- Clean: Should Pass (PII) ---
echo "--- Clean: False Positives — PII ---"
expect_pass pii "$DIR/clean/normal_prompt.json"                    "pii clean: Normal prompt"
expect_pass pii "$DIR/clean/tickers_and_ids.json"                  "pii clean: Tickers and IDs"
expect_pass pii "$DIR/clean/dollar_amounts_and_percentages.json"   "pii clean: Dollar amounts"
expect_pass pii "$DIR/clean/iso_dates.json"                        "pii clean: ISO dates"
expect_pass pii "$DIR/clean/cusips_and_shares.json"                "pii clean: CUSIPs and shares"
expect_pass pii "$DIR/clean/account_names_and_enums.json"          "pii clean: Account names and enums"
expect_pass pii "$DIR/clean/code_variables.json"                   "pii clean: Code variables"
expect_pass pii "$DIR/clean/schema_ddl.json"                       "pii clean: Schema DDL"
expect_pass pii "$DIR/clean/import_statements.json"                "pii clean: Import statements"
expect_pass pii "$DIR/clean/url_paths.json"                        "pii clean: URL paths"
expect_pass pii "$DIR/clean/key_type_identifiers.json"             "pii clean: Key type identifiers"
expect_pass pii "$DIR/clean/placeholder_values.json"               "pii clean: Placeholder values"
expect_pass pii "$DIR/clean/rebalance_fixture.json"                "pii clean: Rebalance fixture"
expect_pass pii "$DIR/clean/malformed_json.json"                   "pii clean: Malformed JSON (fail safe)"
expect_pass pii "$DIR/clean/empty_input.json"                      "pii clean: Empty input (fail safe)"
echo ""

# --- Clean: Should Pass (Leaks) ---
echo "--- Clean: False Positives — Leaks ---"
expect_pass leaks "$DIR/clean/normal_prompt.json"                  "leaks clean: Normal prompt"
expect_pass leaks "$DIR/clean/tickers_and_ids.json"                "leaks clean: Tickers and IDs"
expect_pass leaks "$DIR/clean/dollar_amounts_and_percentages.json" "leaks clean: Dollar amounts"
expect_pass leaks "$DIR/clean/iso_dates.json"                      "leaks clean: ISO dates"
expect_pass leaks "$DIR/clean/cusips_and_shares.json"              "leaks clean: CUSIPs and shares"
expect_pass leaks "$DIR/clean/account_names_and_enums.json"        "leaks clean: Account names and enums"
expect_pass leaks "$DIR/clean/code_variables.json"                 "leaks clean: Code variables"
expect_pass leaks "$DIR/clean/schema_ddl.json"                     "leaks clean: Schema DDL"
expect_pass leaks "$DIR/clean/import_statements.json"              "leaks clean: Import statements"
expect_pass leaks "$DIR/clean/url_paths.json"                      "leaks clean: URL paths"
expect_pass leaks "$DIR/clean/key_type_identifiers.json"           "leaks clean: Key type identifiers"
expect_pass leaks "$DIR/clean/placeholder_values.json"             "leaks clean: Placeholder values"
expect_pass leaks "$DIR/clean/rebalance_fixture.json"              "leaks clean: Rebalance fixture"
expect_pass leaks "$DIR/clean/malformed_json.json"                 "leaks clean: Malformed JSON (fail safe)"
expect_pass leaks "$DIR/clean/empty_input.json"                    "leaks clean: Empty input (fail safe)"
echo ""

# --- Log ---
echo "--- Log: Event Logging ---"
rm -f /tmp/ward-test-events.jsonl
expect_log "$DIR/log/session_start.json"          "log: SessionStart"
expect_log "$DIR/log/pre_tool_use_bash.json"      "log: PreToolUse Bash"
expect_log "$DIR/log/post_tool_use.json"          "log: PostToolUse"
expect_log "$DIR/log/stop.json"                   "log: Stop"
expect_log "$DIR/log/session_end.json"            "log: SessionEnd"
expect_log "$DIR/log/with_secret_to_redact.json"  "log: Redaction in summary"
expect_log "$DIR/log/long_command_to_truncate.json" "log: Truncation"
echo ""

# --- Log: Verify Redaction ---
echo "--- Log: Verify Redaction ---"
TOTAL=$((TOTAL + 1))
if grep -q "BRIDGEFT_CLIENT_SECRET" /tmp/ward-test-events.jsonl; then
    red "FAIL: log redaction — secret found in log file"
    FAIL=$((FAIL + 1))
else
    green "PASS: log redaction — secret not in log file"
    PASS=$((PASS + 1))
fi

# --- Log: Verify Truncation ---
TOTAL=$((TOTAL + 1))
longest_summary=$(python3 -c "
import json, sys
for line in open('/tmp/ward-test-events.jsonl'):
    entry = json.loads(line)
    s = entry.get('tool_input_summary', '') or ''
    if len(s) > 200:
        print(f'TOO_LONG:{len(s)}')
        sys.exit(0)
print('OK')
")
if [ "$longest_summary" = "OK" ]; then
    green "PASS: log truncation — all summaries <= 200 chars"
    PASS=$((PASS + 1))
else
    red "FAIL: log truncation — $longest_summary"
    FAIL=$((FAIL + 1))
fi

# Cleanup
rm -f /tmp/ward-test-events.jsonl

echo ""
echo "========================================"
echo "  Results: $PASS passed, $FAIL failed, $TOTAL total"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
