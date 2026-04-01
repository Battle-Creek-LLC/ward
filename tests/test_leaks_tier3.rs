use ward::leaks::tier3;

#[test]
fn test_generic_high_entropy() {
    let matches = tier3::scan("api_key = 'aK9mP2xR7qL4wB5nJ8cF3vD'");
    assert!(!matches.is_empty(), "High-entropy API key should match");
    assert_eq!(matches[0].category, "Generic API Key");
}

#[test]
fn test_generic_low_entropy_no_match() {
    let matches = tier3::scan("api_key = 'changeme'");
    assert!(matches.is_empty(), "Low-entropy value should not match (too short for regex)");
}

#[test]
fn test_generic_stopword_no_match() {
    let matches = tier3::scan("password = 'password'");
    assert!(matches.is_empty(), "Stopword value should not match (too short for regex)");
}

#[test]
fn test_generic_long_stopword_no_match() {
    // Even with 10+ chars, a stopword-like low-entropy value shouldn't match
    let matches = tier3::scan("api_key = 'changeme1234'");
    // 'changeme1234' entropy might be below 3.5 since chars repeat
    // This tests the entropy gate
    assert!(matches.is_empty(), "Low-entropy extended stopword should not match");
}

#[test]
fn test_generic_alpha_only_no_match() {
    // Pure alphabetic values are filtered by the allowlist
    let matches = tier3::scan("api_key = 'abcdefghijklmnop'");
    assert!(matches.is_empty(), "Pure alphabetic value should not match");
}

#[test]
fn test_curl_bearer() {
    let matches = tier3::scan("curl -H 'Authorization: Bearer sk-realtoken123abc' https://api.com");
    assert!(!matches.is_empty(), "Curl Bearer auth should match");
    assert!(matches.iter().any(|m| m.category == "Curl Auth Header"), "Should be Curl Auth Header");
}

#[test]
fn test_curl_user_pass() {
    let matches = tier3::scan("curl -u admin:s3cretP@ss https://api.com");
    assert!(!matches.is_empty(), "Curl user:pass should match");
    assert!(matches.iter().any(|m| m.category == "Curl Auth User"), "Should be Curl Auth User");
}

#[test]
fn test_ticker_no_match() {
    let matches = tier3::scan("VOO BND DGRO SPY AAPL");
    assert!(matches.is_empty(), "Tickers should not match");
}

#[test]
fn test_import_no_match() {
    let matches = tier3::scan("import { token } from './config'");
    assert!(matches.is_empty(), "Import statement should not match");
}

#[test]
fn test_key_type_no_match() {
    let matches = tier3::scan("primary_key, foreign_key, public_key");
    assert!(matches.is_empty(), "Key type identifiers should not match");
}

#[test]
fn test_code_identifiers_no_match() {
    let matches = tier3::scan("avoid_wash_sales, gains_budget_lt");
    assert!(matches.is_empty(), "Code identifiers should not match");
}

#[test]
fn test_account_names_no_match() {
    let matches = tier3::scan("Investment Account, Taxable Model Account");
    assert!(matches.is_empty(), "Account names should not match");
}

#[test]
fn test_example_suffix_no_match() {
    let matches = tier3::scan("AKIAIOSFODNN7EXAMPLE");
    assert!(matches.is_empty(), "EXAMPLE suffix key should not match tier3");
}
