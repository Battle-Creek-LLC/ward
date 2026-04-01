use crate::output::Match;
use once_cell::sync::Lazy;
use regex::Regex;

struct Rule {
    id: &'static str,
    pattern: &'static Lazy<Regex>,
    category: &'static str,
    keywords: &'static [&'static str],
}

static AWS_ACCESS_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b").unwrap());

static AWS_SECRET_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)[\w.\-]{0,50}?(?:secret|access|key|token)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}([A-Za-z0-9/+=]{40})"#).unwrap()
});

static AWS_BEDROCK_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})\b").unwrap());

static GCP_API_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(AIza[\w\-]{35})\b").unwrap());

static AZURE_AD_CLIENT_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)[\w.\-]{0,50}?(?:administrator_login_password|password)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}("[a-z0-9=_\-]{8,20}")"#).unwrap()
});

static ANTHROPIC_API_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b").unwrap());

static ANTHROPIC_ADMIN_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)\b").unwrap());

static OPENAI_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b")
        .unwrap()
});

static GITHUB_PAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap());

static GITHUB_FINE_GRAINED_PAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"github_pat_\w{82}").unwrap());

static GITHUB_OAUTH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"gho_[0-9a-zA-Z]{36}").unwrap());

static GITHUB_APP_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}").unwrap());

static GITLAB_PAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"glpat-[\w\-]{20,}").unwrap());

static SLACK_BOT_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*").unwrap());

static SLACK_APP_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+").unwrap());

static SLACK_USER_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9\-]{28,34}").unwrap()
});

static SLACK_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}").unwrap()
});

static SLACK_LEGACY_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"xox[os]-\d+-\d+-\d+-[a-fA-F\d]+").unwrap());

static STRIPE_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b").unwrap()
});

static SENDGRID_API_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(SG\.[\w\-]{22}\.[\w\-]{43})\b").unwrap());

static TWILIO_API_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bSK[0-9a-fA-F]{32}\b").unwrap());

static LINEAR_API_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)lin_api_[a-z0-9]{40}").unwrap());

static DATABRICKS_API_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b").unwrap());

static HEROKU_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)[\w.\-]{0,50}?(?:heroku)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"#).unwrap()
});

static VERCEL_API_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(vc[karic]_[A-Za-z0-9_\-]{56})\b").unwrap());

static GRAFANA_API_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})\b").unwrap());

static GRAFANA_CLOUD_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})\b").unwrap());

static SENTRY_ORG_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}").unwrap()
});

static DATADOG_ACCESS_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)[\w.\-]{0,50}?(?:datadog)[\s'"]{0,3}[=:>][\x60'"\s=]{0,5}([a-z0-9]{40})"#)
        .unwrap()
});

static HASHICORP_VAULT_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b((?:hvs\.[\w\-]{90,120}|s\.(?i:[a-z0-9]{24})))\b").unwrap()
});

static NPM_ACCESS_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(npm_[A-Za-z0-9]{36})\b").unwrap());

static PYPI_UPLOAD_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(pypi-[A-Za-z0-9_\-]{50,})\b").unwrap());

static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        Rule { id: "aws-access-key", pattern: &AWS_ACCESS_KEY, category: "AWS Access Key", keywords: &["akia", "asia", "abia", "acca", "a3t"] },
        Rule { id: "aws-secret-key", pattern: &AWS_SECRET_KEY, category: "AWS Secret Key", keywords: &["secret", "access"] },
        Rule { id: "aws-bedrock-key", pattern: &AWS_BEDROCK_KEY, category: "AWS Bedrock Key", keywords: &["absk"] },
        Rule { id: "gcp-api-key", pattern: &GCP_API_KEY, category: "GCP API Key", keywords: &["aiza"] },
        Rule { id: "azure-ad-client-secret", pattern: &AZURE_AD_CLIENT_SECRET, category: "Azure AD Client Secret", keywords: &["password"] },
        Rule { id: "anthropic-api-key", pattern: &ANTHROPIC_API_KEY, category: "Anthropic API Key", keywords: &["sk-ant-api03"] },
        Rule { id: "anthropic-admin-key", pattern: &ANTHROPIC_ADMIN_KEY, category: "Anthropic Admin Key", keywords: &["sk-ant-admin01"] },
        Rule { id: "openai-api-key", pattern: &OPENAI_API_KEY, category: "OpenAI API Key", keywords: &["sk-proj-", "sk-svcacct-", "sk-admin-"] },
        Rule { id: "github-pat", pattern: &GITHUB_PAT, category: "GitHub PAT", keywords: &["ghp_"] },
        Rule { id: "github-fine-grained-pat", pattern: &GITHUB_FINE_GRAINED_PAT, category: "GitHub Fine-Grained PAT", keywords: &["github_pat_"] },
        Rule { id: "github-oauth", pattern: &GITHUB_OAUTH, category: "GitHub OAuth", keywords: &["gho_"] },
        Rule { id: "github-app-token", pattern: &GITHUB_APP_TOKEN, category: "GitHub App Token", keywords: &["ghu_", "ghs_"] },
        Rule { id: "gitlab-pat", pattern: &GITLAB_PAT, category: "GitLab PAT", keywords: &["glpat-"] },
        Rule { id: "slack-bot-token", pattern: &SLACK_BOT_TOKEN, category: "Slack Bot Token", keywords: &["xoxb-"] },
        Rule { id: "slack-app-token", pattern: &SLACK_APP_TOKEN, category: "Slack App Token", keywords: &["xapp-"] },
        Rule { id: "slack-user-token", pattern: &SLACK_USER_TOKEN, category: "Slack User Token", keywords: &["xoxp", "xoxe"] },
        Rule { id: "slack-webhook", pattern: &SLACK_WEBHOOK, category: "Slack Webhook", keywords: &["hooks.slack.com"] },
        Rule { id: "slack-legacy-token", pattern: &SLACK_LEGACY_TOKEN, category: "Slack Legacy Token", keywords: &["xoxo-", "xoxs-"] },
        Rule { id: "stripe-key", pattern: &STRIPE_KEY, category: "Stripe Key", keywords: &["sk_live", "sk_test", "sk_prod", "rk_live", "rk_test", "rk_prod"] },
        Rule { id: "sendgrid-api-token", pattern: &SENDGRID_API_TOKEN, category: "SendGrid Token", keywords: &["sg."] },
        Rule { id: "twilio-api-key", pattern: &TWILIO_API_KEY, category: "Twilio API Key", keywords: &["sk"] },
        Rule { id: "linear-api-key", pattern: &LINEAR_API_KEY, category: "Linear API Key", keywords: &["lin_api_"] },
        Rule { id: "databricks-api-token", pattern: &DATABRICKS_API_TOKEN, category: "Databricks Token", keywords: &["dapi"] },
        Rule { id: "heroku-api-key", pattern: &HEROKU_API_KEY, category: "Heroku API Key", keywords: &["heroku"] },
        Rule { id: "vercel-api-token", pattern: &VERCEL_API_TOKEN, category: "Vercel API Token", keywords: &["vck_", "vca_", "vcr_", "vci_", "vcc_"] },
        Rule { id: "grafana-api-key", pattern: &GRAFANA_API_KEY, category: "Grafana API Key", keywords: &["eyjrijoi"] },
        Rule { id: "grafana-cloud-token", pattern: &GRAFANA_CLOUD_TOKEN, category: "Grafana Cloud Token", keywords: &["glc_"] },
        Rule { id: "sentry-org-token", pattern: &SENTRY_ORG_TOKEN, category: "Sentry Org Token", keywords: &["sntrys_"] },
        Rule { id: "datadog-access-token", pattern: &DATADOG_ACCESS_TOKEN, category: "Datadog Access Token", keywords: &["datadog"] },
        Rule { id: "hashicorp-vault-token", pattern: &HASHICORP_VAULT_TOKEN, category: "Vault Token", keywords: &["hvs."] },
        Rule { id: "npm-access-token", pattern: &NPM_ACCESS_TOKEN, category: "NPM Token", keywords: &["npm_"] },
        Rule { id: "pypi-upload-token", pattern: &PYPI_UPLOAD_TOKEN, category: "PyPI Token", keywords: &["pypi-"] },
    ]
});

pub fn scan(text: &str) -> Vec<Match> {
    let mut matches = Vec::new();
    let lower = text.to_lowercase();

    for rule in RULES.iter() {
        // Keyword pre-filter: skip regex compilation if no keyword matches
        if !rule.keywords.iter().any(|kw| lower.contains(kw)) {
            continue;
        }

        if rule.id == "aws-access-key" {
            // EXAMPLE suffix allowlist
            for m in rule.pattern.find_iter(text) {
                let val = m.as_str();
                if !val.ends_with("EXAMPLE") {
                    matches.push(Match {
                        category: rule.category,
                        matched_text: val.to_string(),
                    });
                }
            }
        } else {
            for m in rule.pattern.find_iter(text) {
                matches.push(Match {
                    category: rule.category,
                    matched_text: m.as_str().to_string(),
                });
            }
        }
    }

    matches
}

/// Replace all Tier 1 pattern matches with [REDACTED]
pub fn redact(text: &str) -> String {
    let mut result = text.to_string();
    for rule in RULES.iter() {
        result = rule.pattern.replace_all(&result, "[REDACTED]").to_string();
    }
    result
}
