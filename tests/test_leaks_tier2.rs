use ward::leaks::tier2;

#[test]
fn test_private_key_rsa() {
    let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PkPfcLBBnBMBFOAlwLwHBLFkJQ\nmore_key_data_here_to_make_it_long_enough_for_the_pattern\n-----END RSA PRIVATE KEY-----";
    let matches = tier2::scan(key);
    assert!(!matches.is_empty(), "RSA private key should match");
    assert_eq!(matches[0].category, "Private Key");
}

#[test]
fn test_private_key_openssh() {
    let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----";
    let matches = tier2::scan(key);
    assert!(!matches.is_empty(), "OPENSSH private key should match");
    assert_eq!(matches[0].category, "Private Key");
}

#[test]
fn test_private_key_ec() {
    let key = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIIrYSSNQFaA2Hwf583QmKbyuQ7DCDhQJsKzYVwWkGMFJoAcGBSuBBAAi\noWQDYgAELGzPH6AR9aFiA1KFKREHF2VVvL6IRNg9Fa8fvFkirQ6BNQAB\n-----END EC PRIVATE KEY-----";
    let matches = tier2::scan(key);
    assert!(!matches.is_empty(), "EC private key should match");
    assert_eq!(matches[0].category, "Private Key");
}

#[test]
fn test_jwt_token() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let matches = tier2::scan(jwt);
    assert!(!matches.is_empty(), "JWT should match");
    assert_eq!(matches[0].category, "JWT");
}

#[test]
fn test_postgres_uri() {
    let matches = tier2::scan("postgres://admin:s3cret@db.host:5432/prod");
    assert!(!matches.is_empty(), "Postgres URI should match");
    assert_eq!(matches[0].category, "Connection String");
}

#[test]
fn test_mysql_uri() {
    let matches = tier2::scan("mysql://root:password@localhost/mydb");
    assert!(!matches.is_empty(), "MySQL URI should match");
    assert_eq!(matches[0].category, "Connection String");
}

#[test]
fn test_mongodb_srv_uri() {
    let matches = tier2::scan("mongodb+srv://user:pass@cluster.mongodb.net/db");
    assert!(!matches.is_empty(), "MongoDB+srv URI should match");
    assert_eq!(matches[0].category, "Connection String");
}

#[test]
fn test_redis_uri() {
    let matches = tier2::scan("redis://default:password@cache:6379");
    assert!(!matches.is_empty(), "Redis URI should match");
    assert_eq!(matches[0].category, "Connection String");
}

#[test]
fn test_env_password() {
    let matches = tier2::scan("PASSWORD=hunter2");
    assert!(!matches.is_empty(), "PASSWORD= should match");
    assert_eq!(matches[0].category, "Env Secret");
}

#[test]
fn test_env_client_secret() {
    let matches = tier2::scan("BRIDGEFT_CLIENT_SECRET=abc123secret");
    assert!(!matches.is_empty(), "CLIENT_SECRET= should match");
    assert_eq!(matches[0].category, "Env Secret");
}

#[test]
fn test_env_database_url() {
    let matches = tier2::scan("DATABASE_URL=postgresql://user:pw@host/db");
    assert!(!matches.is_empty(), "DATABASE_URL= should match");
    let categories: Vec<_> = matches.iter().map(|m| m.category).collect();
    assert!(categories.contains(&"Env Secret") || categories.contains(&"Connection String"),
        "Should match as Env Secret or Connection String, got: {:?}", categories);
}

#[test]
fn test_url_path_no_match() {
    let matches = tier2::scan("https://api.example.com/v1/tokens");
    assert!(matches.is_empty(), "URL path should not match");
}

#[test]
fn test_schema_ddl_no_match() {
    let matches = tier2::scan("password VARCHAR(255)");
    assert!(matches.is_empty(), "Schema DDL should not match");
}

#[test]
fn test_placeholder_no_match() {
    let matches = tier2::scan("SECRET=${MY_SECRET}");
    assert!(matches.is_empty(), "Placeholder should not match");
}
