use ward::leaks::tier1;

#[test]
fn test_aws_access_key_example_allowlisted() {
    let matches = tier1::scan("AKIAIOSFODNN7EXAMPLE");
    assert!(matches.is_empty(), "EXAMPLE suffix should be allowlisted");
}

#[test]
fn test_aws_access_key_real() {
    let matches = tier1::scan("AKIAIOSFODNN7FAKEK5Y");
    assert!(!matches.is_empty(), "Real AWS access key should match");
    assert_eq!(matches[0].category, "AWS Access Key");
}

#[test]
fn test_aws_secret_key() {
    let matches = tier1::scan("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYabcdefghij");
    assert!(!matches.is_empty(), "AWS secret key should match");
    assert_eq!(matches[0].category, "AWS Secret Key");
}

#[test]
fn test_aws_bedrock_key() {
    let key = format!("ABSK{}", "A".repeat(120));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "AWS Bedrock key should match");
    assert_eq!(matches[0].category, "AWS Bedrock Key");
}

#[test]
fn test_gcp_api_key() {
    let key = format!("AIzaSyC{}", "a".repeat(32));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "GCP API key should match");
    assert_eq!(matches[0].category, "GCP API Key");
}

#[test]
fn test_anthropic_api_key() {
    let key = format!("sk-ant-api03-{}AA", "a".repeat(93));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "Anthropic API key should match");
    assert_eq!(matches[0].category, "Anthropic API Key");
}

#[test]
fn test_anthropic_admin_key() {
    let key = format!("sk-ant-admin01-{}AA", "a".repeat(93));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "Anthropic Admin key should match");
    assert_eq!(matches[0].category, "Anthropic Admin Key");
}

#[test]
fn test_openai_api_key() {
    let key = format!("sk-proj-{}T3BlbkFJ{}", "a".repeat(20), "b".repeat(20));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "OpenAI API key should match");
    assert_eq!(matches[0].category, "OpenAI API Key");
}

#[test]
fn test_github_pat() {
    let matches = tier1::scan("ghp_ABCDEFghijklmnop1234567890abcdefghij");
    assert!(!matches.is_empty(), "GitHub PAT should match");
    assert_eq!(matches[0].category, "GitHub PAT");
}

#[test]
fn test_github_fine_grained_pat() {
    let key = format!("github_pat_{}", "a".repeat(82));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "GitHub fine-grained PAT should match");
    assert_eq!(matches[0].category, "GitHub Fine-Grained PAT");
}

#[test]
fn test_github_oauth() {
    let matches = tier1::scan("gho_ABCDEFghijklmnop1234567890abcdefghij");
    assert!(!matches.is_empty(), "GitHub OAuth should match");
    assert_eq!(matches[0].category, "GitHub OAuth");
}

#[test]
fn test_github_app_token() {
    let matches = tier1::scan("ghs_ABCDEFghijklmnop1234567890abcdefghij");
    assert!(!matches.is_empty(), "GitHub App Token should match");
    assert_eq!(matches[0].category, "GitHub App Token");
}

#[test]
fn test_gitlab_pat() {
    let key = format!("glpat-{}", "a".repeat(20));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "GitLab PAT should match");
    assert_eq!(matches[0].category, "GitLab PAT");
}

#[test]
fn test_slack_bot_token() {
    let matches = tier1::scan("xoxb-1234567890123-1234567890123-abcdef");
    assert!(!matches.is_empty(), "Slack Bot Token should match");
    assert_eq!(matches[0].category, "Slack Bot Token");
}

#[test]
fn test_slack_app_token() {
    let matches = tier1::scan("xapp-1-A0123BCDE-1234567890-abcdef1234");
    assert!(!matches.is_empty(), "Slack App Token should match");
    assert_eq!(matches[0].category, "Slack App Token");
}

#[test]
fn test_slack_webhook() {
    let url = format!("https://hooks.slack.com/services/{}", "A".repeat(44));
    let matches = tier1::scan(&url);
    assert!(!matches.is_empty(), "Slack Webhook should match");
    assert_eq!(matches[0].category, "Slack Webhook");
}

#[test]
fn test_stripe_live_key() {
    let matches = tier1::scan("sk_live_abc123def456ghi789jkl");
    assert!(!matches.is_empty(), "Stripe live key should match");
    assert_eq!(matches[0].category, "Stripe Key");
}

#[test]
fn test_stripe_test_key() {
    let matches = tier1::scan("sk_test_abc123def456ghi789jkl");
    assert!(!matches.is_empty(), "Stripe test key should match");
    assert_eq!(matches[0].category, "Stripe Key");
}

#[test]
fn test_sendgrid_token() {
    let key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(43));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "SendGrid token should match");
    assert_eq!(matches[0].category, "SendGrid Token");
}

#[test]
fn test_linear_api_key() {
    let key = format!("lin_api_{}", "a".repeat(40));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "Linear API key should match");
    assert_eq!(matches[0].category, "Linear API Key");
}

#[test]
fn test_databricks_token() {
    let matches = tier1::scan("dapi1234abcd5678efab9012cdef3456abcd");
    assert!(!matches.is_empty(), "Databricks token should match");
    assert_eq!(matches[0].category, "Databricks Token");
}

#[test]
fn test_npm_token() {
    let key = format!("npm_{}", "A".repeat(36));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "NPM token should match");
    assert_eq!(matches[0].category, "NPM Token");
}

#[test]
fn test_pypi_token() {
    let key = format!("pypi-{}", "A".repeat(50));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "PyPI token should match");
    assert_eq!(matches[0].category, "PyPI Token");
}

#[test]
fn test_grafana_api_key() {
    let key = format!("eyJrIjoi{}", "A".repeat(70));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "Grafana API key should match");
    assert_eq!(matches[0].category, "Grafana API Key");
}

#[test]
fn test_vault_token() {
    let key = format!("hvs.{}", "a".repeat(95));
    let matches = tier1::scan(&key);
    assert!(!matches.is_empty(), "Vault token should match");
    assert_eq!(matches[0].category, "Vault Token");
}

#[test]
fn test_clean_input_no_match() {
    let matches = tier1::scan("VOO BND rebalance tolerance 0.05");
    assert!(matches.is_empty(), "Clean input should not match any Tier 1 rule");
}
