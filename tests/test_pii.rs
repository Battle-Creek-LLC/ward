use ward::pii::patterns;

#[test]
fn test_ssn_detected() {
    let matches = patterns::scan("SSN: 123-45-6789");
    assert!(!matches.is_empty(), "SSN should be detected");
    assert_eq!(matches[0].category, "SSN");
}

#[test]
fn test_credit_card_spaces() {
    let matches = patterns::scan("Card: 4111 1111 1111 1111");
    assert!(!matches.is_empty(), "Credit card with spaces should be detected");
    assert_eq!(matches[0].category, "Credit Card");
}

#[test]
fn test_credit_card_dashes() {
    let matches = patterns::scan("Card: 4111-1111-1111-1111");
    assert!(!matches.is_empty(), "Credit card with dashes should be detected");
    assert_eq!(matches[0].category, "Credit Card");
}

#[test]
fn test_email_detected() {
    let matches = patterns::scan("john.doe@example.com");
    assert!(!matches.is_empty(), "Email should be detected");
    assert_eq!(matches[0].category, "Email");
}

#[test]
fn test_phone_parens() {
    let matches = patterns::scan("Call (555) 123-4567");
    assert!(!matches.is_empty(), "Phone with parens should be detected");
    assert_eq!(matches[0].category, "Phone");
}

#[test]
fn test_phone_plus1() {
    let matches = patterns::scan("+1 555-123-4567");
    assert!(!matches.is_empty(), "Phone with +1 should be detected");
    assert_eq!(matches[0].category, "Phone");
}

#[test]
fn test_iso_date_no_match() {
    let matches = patterns::scan("2023-08-22");
    let ssn_matches: Vec<_> = matches.iter().filter(|m| m.category == "SSN").collect();
    assert!(ssn_matches.is_empty(), "ISO date should not match SSN");
}

#[test]
fn test_cusip_no_match() {
    let matches = patterns::scan("cusip: 12345678");
    assert!(matches.is_empty(), "CUSIP should not trigger PII");
}

#[test]
fn test_dollar_amounts_no_match() {
    let matches = patterns::scan("value: 100000.0");
    assert!(matches.is_empty(), "Dollar amounts should not trigger PII");
}

#[test]
fn test_tickers_no_match() {
    let matches = patterns::scan("VOO BND DGRO SPY");
    assert!(matches.is_empty(), "Tickers should not trigger PII");
}

#[test]
fn test_rebalance_fixture_no_match() {
    let fixture = r#"{"household_id": 101, "accounts": [{"account_id": 45758, "name": "Investment Account", "account_type": "taxable", "holdings": [{"security_id": 1, "ticker": "VOO", "cusip": "12345678", "shares": 150.0, "market_value": 60000.0, "cost_basis": 45000.0, "price": 400.0, "weight": 0.6}, {"security_id": 2, "ticker": "BND", "cusip": "87654321", "shares": 380.0, "market_value": 30000.0, "cost_basis": 29000.0, "price": 78.95, "weight": 0.3}], "target_allocation": [{"ticker": "VOO", "weight": 0.6}, {"ticker": "BND", "weight": 0.3}], "trade_date": "2023-08-22", "inception_date": "2023-01-01", "gains_budget_lt": 5000.0, "tolerance": 0.05, "lot_selection": "L", "avoid_wash_sales": true}]}"#;
    let matches = patterns::scan(fixture);
    assert!(matches.is_empty(), "Rebalance fixture should not trigger PII: {:?}", matches.iter().map(|m| (&m.category, &m.matched_text)).collect::<Vec<_>>());
}

#[test]
fn test_pii_redact() {
    let input = "SSN: 123-45-6789 email: test@example.com";
    let redacted = patterns::redact(input);
    assert!(!redacted.contains("123-45-6789"));
    assert!(!redacted.contains("test@example.com"));
    assert!(redacted.contains("[REDACTED]"));
}
