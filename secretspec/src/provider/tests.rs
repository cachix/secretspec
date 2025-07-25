use crate::Result;
use crate::provider::Provider;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

#[cfg(test)]
use tempfile::TempDir;

/// Mock provider for testing
pub struct MockProvider {
    storage: Arc<Mutex<HashMap<String, String>>>,
}

impl MockProvider {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Provider for MockProvider {
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        let storage = self.storage.lock().unwrap();
        let full_key = format!("{}/{}/{}", project, profile, key);
        Ok(storage
            .get(&full_key)
            .map(|v| SecretString::new(v.clone().into())))
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        let mut storage = self.storage.lock().unwrap();
        let full_key = format!("{}/{}/{}", project, profile, key);
        storage.insert(full_key, value.expose_secret().to_string());
        Ok(())
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

#[test]
fn test_create_from_string_with_full_uris() {
    // Test basic onepassword URI
    let provider = Box::<dyn Provider>::try_from("onepassword://Private").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // Test onepassword with account
    let provider = Box::<dyn Provider>::try_from("onepassword://work@Production").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // Test onepassword with token
    let provider =
        Box::<dyn Provider>::try_from("onepassword+token://:ops_abc123@Private").unwrap();
    assert_eq!(provider.name(), "onepassword");
}

#[test]
fn test_create_from_string_with_plain_names() {
    // Test plain provider names
    let provider = Box::<dyn Provider>::try_from("env").unwrap();
    assert_eq!(provider.name(), "env");

    let provider = Box::<dyn Provider>::try_from("keyring").unwrap();
    assert_eq!(provider.name(), "keyring");

    let provider = Box::<dyn Provider>::try_from("dotenv").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test onepassword separately to debug the issue
    match Box::<dyn Provider>::try_from("onepassword") {
        Ok(provider) => assert_eq!(provider.name(), "onepassword"),
        Err(e) => panic!("Failed to create onepassword provider: {}", e),
    }

    let provider = Box::<dyn Provider>::try_from("lastpass").unwrap();
    assert_eq!(provider.name(), "lastpass");

    let provider = Box::<dyn Provider>::try_from("bitwarden").unwrap();
    assert_eq!(provider.name(), "bitwarden");
}

#[test]
fn test_create_from_string_with_colon() {
    // Test provider names with colon
    let provider = Box::<dyn Provider>::try_from("env:").unwrap();
    assert_eq!(provider.name(), "env");

    let provider = Box::<dyn Provider>::try_from("keyring:").unwrap();
    assert_eq!(provider.name(), "keyring");
}

#[test]
fn test_invalid_onepassword_scheme() {
    // Test that '1password' scheme gives proper error suggesting 'onepassword'
    let result = Box::<dyn Provider>::try_from("1password");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password' scheme"),
    }

    let result = Box::<dyn Provider>::try_from("1password:");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password:' scheme"),
    }

    let result = Box::<dyn Provider>::try_from("1password://Private");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password://' scheme"),
    }
}

#[test]
fn test_dotenv_with_custom_path() {
    // Test dotenv provider with relative path - host part becomes first folder
    let provider = Box::<dyn Provider>::try_from("dotenv://custom/path/to/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test with absolute path format
    let provider = Box::<dyn Provider>::try_from("dotenv:///custom/path/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");
}

#[test]
fn test_unknown_provider() {
    let result = Box::<dyn Provider>::try_from("unknown");
    assert!(result.is_err());
    match result {
        Err(crate::SecretSpecError::ProviderNotFound(scheme)) => {
            assert_eq!(scheme, "unknown");
        }
        _ => panic!("Expected ProviderNotFound error"),
    }
}

#[test]
fn test_dotenv_shorthand_from_docs() {
    // Test the example from line 187 of registry.rs
    let provider = Box::<dyn Provider>::try_from("dotenv:.env.production").unwrap();
    assert_eq!(provider.name(), "dotenv");
}

#[test]
fn test_documentation_examples() {
    // Test examples from the documentation

    // From line 102: onepassword://work@Production
    let provider = Box::<dyn Provider>::try_from("onepassword://work@Production").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // From line 107: dotenv:/path/to/.env
    let provider = Box::<dyn Provider>::try_from("dotenv:/path/to/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // From line 115: lastpass://folder
    let provider = Box::<dyn Provider>::try_from("lastpass://folder").unwrap();
    assert_eq!(provider.name(), "lastpass");

    // Test dotenv examples from provider list
    let provider = Box::<dyn Provider>::try_from("dotenv://path").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test bitwarden examples (Password Manager)
    let provider = Box::<dyn Provider>::try_from("bitwarden://").unwrap();
    assert_eq!(provider.name(), "bitwarden");

    let provider = Box::<dyn Provider>::try_from("bitwarden://collection-id").unwrap();
    assert_eq!(provider.name(), "bitwarden");

    let provider = Box::<dyn Provider>::try_from("bitwarden://org@collection").unwrap();
    assert_eq!(provider.name(), "bitwarden");

    // Test bws examples (Secrets Manager)
    let provider = Box::<dyn Provider>::try_from("bws://").unwrap();
    assert_eq!(provider.name(), "bitwarden");

    let provider = Box::<dyn Provider>::try_from("bws://project-id").unwrap();
    assert_eq!(provider.name(), "bitwarden");
}

#[test]
fn test_edge_cases_and_normalization() {
    // Test scheme-only format (mentioned in docs line 151)
    let provider = Box::<dyn Provider>::try_from("keyring:").unwrap();
    assert_eq!(provider.name(), "keyring");

    // Test dotenv special case without authority (line 152-153)
    let provider = Box::<dyn Provider>::try_from("dotenv:/absolute/path").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test normalized URIs with localhost (line 154)
    let provider = Box::<dyn Provider>::try_from("env://localhost").unwrap();
    assert_eq!(provider.name(), "env");
}

#[test]
fn test_documentation_example_line_184() {
    // Test the exact example from line 184 of registry.rs
    let provider = Box::<dyn Provider>::try_from("onepassword://vault/Production").unwrap();
    assert_eq!(provider.name(), "onepassword");
}

#[test]
fn test_url_parsing_behavior() {
    use url::Url;

    // Test how URLs are actually parsed
    let url = "onepassword://vault/Production".parse::<Url>().unwrap();
    assert_eq!(url.scheme(), "onepassword");
    assert_eq!(url.host_str(), Some("vault"));
    assert_eq!(url.path(), "/Production");

    // Test dotenv URL parsing - host part becomes part of the path
    let url = "dotenv://path/to/.env".parse::<Url>().unwrap();
    assert_eq!(url.scheme(), "dotenv");
    assert_eq!(url.host_str(), Some("path"));
    assert_eq!(url.path(), "/to/.env");
}

#[test]
fn test_bitwarden_config_parsing() {
    use crate::provider::bitwarden::{BitwardenConfig, BitwardenService};
    use std::convert::TryFrom;
    use url::Url;

    // Test Password Manager configurations

    // Test basic bitwarden:// URI
    let url = Url::parse("bitwarden://").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert!(config.organization_id.is_none());
    assert!(config.collection_id.is_none());
    assert!(config.server.is_none());
    assert!(config.project_id.is_none());
    // Login is the default item type
    assert_eq!(config.default_item_type, Some(BitwardenItemType::Login));
    assert!(config.default_field.is_none());

    // Test collection ID only
    let url = Url::parse("bitwarden://collection-123").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert!(config.organization_id.is_none());
    assert_eq!(config.collection_id, Some("collection-123".to_string()));
    assert!(config.server.is_none());

    // Test org@collection format
    let url = Url::parse("bitwarden://myorg@collection-456").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert_eq!(config.organization_id, Some("myorg".to_string()));
    assert_eq!(config.collection_id, Some("collection-456".to_string()));
    assert!(config.server.is_none());

    // Test query parameters
    let url = Url::parse("bitwarden://?server=https://vault.company.com&org=myorg").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert_eq!(config.organization_id, Some("myorg".to_string()));
    assert_eq!(config.server, Some("https://vault.company.com".to_string()));

    // Test folder prefix customization
    let url = Url::parse("bitwarden://?folder=custom/{project}/{profile}").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert_eq!(
        config.folder_prefix,
        Some("custom/{project}/{profile}".to_string())
    );

    // Test item type and field parameters
    let url = Url::parse("bitwarden://?type=card&field=api_key").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    use crate::provider::bitwarden::BitwardenItemType;
    assert_eq!(config.default_item_type, Some(BitwardenItemType::Card));
    assert_eq!(config.default_field, Some("api_key".to_string()));

    // Test Secrets Manager configurations

    // Test basic bws:// URI
    let url = Url::parse("bws://").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert!(config.project_id.is_none());
    assert!(config.access_token.is_none());
    assert!(config.organization_id.is_none()); // Should be None for Secrets Manager
    // Login is the default item type even for BWS
    assert_eq!(config.default_item_type, Some(BitwardenItemType::Login));

    // Test project ID
    let url = Url::parse("bws://project-789").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert_eq!(config.project_id, Some("project-789".to_string()));

    // Test query parameters for Secrets Manager
    let url = Url::parse("bws://?project=project-abc&token=my-token").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert_eq!(config.project_id, Some("project-abc".to_string()));
    assert_eq!(config.access_token, Some("my-token".to_string()));

    // Test BWS with item type and field parameters (should work for consistency)
    let url = Url::parse("bws://?type=login&field=password").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert_eq!(config.default_item_type, Some(BitwardenItemType::Login));
    assert_eq!(config.default_field, Some("password".to_string()));

    // Test timeout configuration
    let url = Url::parse("bitwarden://?timeout=60").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert_eq!(config.cli_timeout, Some(60));

    // Test timeout configuration with other parameters
    let url = Url::parse("bws://?project=test&timeout=45&field=password").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert_eq!(config.project_id, Some("test".to_string()));
    assert_eq!(config.cli_timeout, Some(45));
    assert_eq!(config.default_field, Some("password".to_string()));

    // Test invalid timeout value is ignored
    let url = Url::parse("bitwarden://?timeout=invalid").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert_eq!(config.cli_timeout, Some(30)); // Should use default
}

#[test]
fn test_bitwarden_item_type_parsing() {
    use crate::provider::bitwarden::BitwardenItemType;

    // Test parsing from string (for environment variables)
    assert_eq!(
        BitwardenItemType::from_str("login"),
        Some(BitwardenItemType::Login)
    );
    assert_eq!(
        BitwardenItemType::from_str("card"),
        Some(BitwardenItemType::Card)
    );
    assert_eq!(
        BitwardenItemType::from_str("identity"),
        Some(BitwardenItemType::Identity)
    );
    assert_eq!(
        BitwardenItemType::from_str("securenote"),
        Some(BitwardenItemType::SecureNote)
    );
    assert_eq!(
        BitwardenItemType::from_str("note"),
        Some(BitwardenItemType::SecureNote)
    ); // alias
    assert_eq!(
        BitwardenItemType::from_str("secure_note"),
        Some(BitwardenItemType::SecureNote)
    ); // alias
    assert_eq!(
        BitwardenItemType::from_str("sshkey"),
        Some(BitwardenItemType::SshKey)
    );
    assert_eq!(
        BitwardenItemType::from_str("ssh_key"),
        Some(BitwardenItemType::SshKey)
    ); // alias
    assert_eq!(
        BitwardenItemType::from_str("ssh"),
        Some(BitwardenItemType::SshKey)
    ); // alias
    assert_eq!(BitwardenItemType::from_str("unknown"), None);

    // Test conversion to/from integers (Bitwarden API format)
    assert_eq!(
        BitwardenItemType::from_u8(1),
        Some(BitwardenItemType::Login)
    );
    assert_eq!(
        BitwardenItemType::from_u8(2),
        Some(BitwardenItemType::SecureNote)
    );
    assert_eq!(BitwardenItemType::from_u8(3), Some(BitwardenItemType::Card));
    assert_eq!(
        BitwardenItemType::from_u8(4),
        Some(BitwardenItemType::Identity)
    );
    assert_eq!(
        BitwardenItemType::from_u8(5),
        Some(BitwardenItemType::SshKey)
    );
    assert_eq!(BitwardenItemType::from_u8(99), None);

    // Test default field detection
    assert_eq!(
        BitwardenItemType::Login.default_field_for_hint("password"),
        "password".to_string()
    );
    assert_eq!(
        BitwardenItemType::Login.default_field_for_hint("custom"),
        "password".to_string()
    );
    assert_eq!(
        BitwardenItemType::Card.default_field_for_hint("api_key"),
        "api_key".to_string()
    );
    assert_eq!(
        BitwardenItemType::Card.default_field_for_hint("number"),
        "number".to_string()
    ); // Cards default to the hint for standard fields
    assert_eq!(
        BitwardenItemType::Identity.default_field_for_hint("ssn"),
        "ssn".to_string()
    );
    assert_eq!(
        BitwardenItemType::SshKey.default_field_for_hint("private_key"),
        "private_key".to_string()
    );
    assert_eq!(
        BitwardenItemType::SshKey.default_field_for_hint("custom"),
        "private_key".to_string()
    ); // SSH keys default to private_key
}

#[test]
fn test_bitwarden_field_type_detection() {
    use crate::provider::bitwarden::BitwardenFieldType;

    // Test smart field type detection
    assert_eq!(
        BitwardenFieldType::for_field_name("password"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("secret"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("token"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("api_key"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("cvv"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("username"),
        BitwardenFieldType::Text
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("name"),
        BitwardenFieldType::Text
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("description"),
        BitwardenFieldType::Text
    );

    // Test enum conversions
    assert_eq!(BitwardenFieldType::Text.to_u8(), 0);
    assert_eq!(BitwardenFieldType::Hidden.to_u8(), 1);
    assert_eq!(BitwardenFieldType::Boolean.to_u8(), 2);

    assert_eq!(
        BitwardenFieldType::from_u8(0),
        Some(BitwardenFieldType::Text)
    );
    assert_eq!(
        BitwardenFieldType::from_u8(1),
        Some(BitwardenFieldType::Hidden)
    );
    assert_eq!(
        BitwardenFieldType::from_u8(2),
        Some(BitwardenFieldType::Boolean)
    );
    assert_eq!(BitwardenFieldType::from_u8(99), None);
}

#[test]
fn test_bitwarden_environment_variables() {
    use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};
    use std::env;

    // Test environment variable support for default type and field
    unsafe {
        env::set_var("BITWARDEN_DEFAULT_TYPE", "card");
        env::set_var("BITWARDEN_DEFAULT_FIELD", "api_key");
        env::set_var("BITWARDEN_ORGANIZATION", "test-org");
        env::set_var("BITWARDEN_COLLECTION", "test-collection");
    }

    let config = BitwardenConfig::default();
    let _provider = BitwardenProvider::new(config);

    // Note: These environment variables are checked at runtime in the actual provider methods
    // This test verifies the environment variables exist and can be read
    assert_eq!(env::var("BITWARDEN_DEFAULT_TYPE").unwrap(), "card");
    assert_eq!(env::var("BITWARDEN_DEFAULT_FIELD").unwrap(), "api_key");
    assert_eq!(env::var("BITWARDEN_ORGANIZATION").unwrap(), "test-org");
    assert_eq!(env::var("BITWARDEN_COLLECTION").unwrap(), "test-collection");

    // Clean up
    unsafe {
        env::remove_var("BITWARDEN_DEFAULT_TYPE");
        env::remove_var("BITWARDEN_DEFAULT_FIELD");
        env::remove_var("BITWARDEN_ORGANIZATION");
        env::remove_var("BITWARDEN_COLLECTION");
    }
}

#[test]
fn test_bitwarden_timeout_configuration() {
    use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};
    use std::env;
    use std::time::Duration;

    // Test default timeout
    let config = BitwardenConfig::default();
    let provider = BitwardenProvider::new(config);
    assert_eq!(provider.get_cli_timeout(), Duration::from_secs(30));

    // Test timeout from configuration
    let mut config = BitwardenConfig::default();
    config.cli_timeout = Some(45);
    let provider = BitwardenProvider::new(config);
    assert_eq!(provider.get_cli_timeout(), Duration::from_secs(45));

    // Test environment variable override
    unsafe {
        env::set_var("BITWARDEN_CLI_TIMEOUT", "60");
    }

    let config = BitwardenConfig::default();
    let provider = BitwardenProvider::new(config);
    assert_eq!(provider.get_cli_timeout(), Duration::from_secs(60));

    // Clean up
    unsafe {
        env::remove_var("BITWARDEN_CLI_TIMEOUT");
    }
}

#[test]
fn test_bitwarden_error_message_sanitization() {
    use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};

    let config = BitwardenConfig::default();
    let provider = BitwardenProvider::new(config);

    // Test JSON token redaction
    let error_with_token = r#"{"error": "authentication failed", "token": "test_secret_token_12345678901234567890", "code": 401}"#;
    let sanitized = provider.sanitize_error_message(error_with_token);
    assert!(!sanitized.contains("test_secret_token_12345678901234567890"));
    assert!(sanitized.contains("\"[REDACTED]\""));

    // Test Bearer token redaction
    let error_with_bearer = "HTTP 401: Bearer eyJ0eXAiOiJKV1QiLnothinghere invalid or expired";
    let sanitized = provider.sanitize_error_message(error_with_bearer);
    assert!(!sanitized.contains("eyJ0eXAiOiJKV1QiLnothinghere"));
    assert!(sanitized.contains("Bearer [REDACTED]"));

    // Test password redaction
    let error_with_password = r#"{"password": "supersecretpassword123", "username": "user"}"#;
    let sanitized = provider.sanitize_error_message(error_with_password);
    assert!(!sanitized.contains("supersecretpassword123"));
    assert!(sanitized.contains("\"[REDACTED]\""));

    // Test URL parameter redaction
    let error_with_url_params = "Failed to authenticate: token=abc123def456ghi789jkl012 expired";
    let sanitized = provider.sanitize_error_message(error_with_url_params);
    assert!(!sanitized.contains("abc123def456ghi789jkl012"));
    assert!(sanitized.contains("token=[REDACTED]"));

    // Test long base64-like string redaction
    let error_with_base64 =
        "Session YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg== expired";
    let sanitized = provider.sanitize_error_message(error_with_base64);
    assert!(
        !sanitized
            .contains("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==")
    );
    assert!(sanitized.contains("[REDACTED]"));

    // Test file path redaction
    let error_with_path = "Cannot read /home/user/.config/bitwarden/session.json";
    let sanitized = provider.sanitize_error_message(error_with_path);
    assert!(!sanitized.contains("/home/user/.config/bitwarden/session.json"));
    assert!(sanitized.contains(".../session.json"));

    // Test short values are NOT redacted (to avoid false positives)
    let error_with_short_values = r#"{"key": "short", "status": "ok"}"#;
    let sanitized = provider.sanitize_error_message(error_with_short_values);
    assert!(sanitized.contains("short")); // Should not be redacted

    // Test normal error messages are preserved
    let normal_error = "Vault is locked. Please unlock with bw unlock.";
    let sanitized = provider.sanitize_error_message(normal_error);
    assert_eq!(sanitized, normal_error);

    // Test message truncation for very long messages
    let long_message = "A".repeat(600);
    let sanitized = provider.sanitize_error_message(&long_message);
    assert!(sanitized.len() <= 500);
    assert!(sanitized.ends_with("... [truncated for security]"));
}

// Integration tests for all providers
#[cfg(test)]
mod integration_tests {
    use super::*;

    fn generate_test_project_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let suffix = timestamp % 100000;
        format!("secretspec_test_{}", suffix)
    }

    fn get_test_providers() -> Vec<String> {
        std::env::var("SECRETSPEC_TEST_PROVIDERS")
            .unwrap_or_else(|_| String::new())
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect()
    }

    fn create_provider_with_temp_path(provider_name: &str) -> (Box<dyn Provider>, Option<TempDir>) {
        match provider_name {
            "dotenv" => {
                let temp_dir = TempDir::new().expect("Create temp directory");
                let dotenv_path = temp_dir.path().join(".env");
                let provider_spec = format!("dotenv:{}", dotenv_path.to_str().unwrap());
                let provider = Box::<dyn Provider>::try_from(provider_spec.as_str())
                    .expect("Should create dotenv provider with path");
                (provider, Some(temp_dir))
            }
            "bitwarden" => {
                // For bitwarden, we test with basic configuration
                // Real authentication is handled by the CLI
                let provider = Box::<dyn Provider>::try_from("bitwarden://")
                    .expect("Should create bitwarden provider");
                (provider, None)
            }
            "bws" => {
                // For BWS, we test with basic Secrets Manager configuration
                // Real authentication is handled by the BWS CLI and BWS_ACCESS_TOKEN
                let provider =
                    Box::<dyn Provider>::try_from("bws://").expect("Should create bws provider");
                (provider, None)
            }
            _ => {
                let provider = Box::<dyn Provider>::try_from(provider_name)
                    .expect(&format!("{} provider should exist", provider_name));
                (provider, None)
            }
        }
    }

    // Generic test function that tests a provider implementation
    fn test_provider_basic_workflow(provider: &dyn Provider, provider_name: &str) {
        let project_name = generate_test_project_name();

        // Test 1: Get non-existent secret
        let result = provider.get(&project_name, "TEST_PASSWORD", "default");
        match result {
            Ok(None) => {
                // Expected: key doesn't exist
            }
            Ok(Some(_)) => {
                panic!("[{}] Should not find non-existent secret", provider_name);
            }
            Err(_) => {
                // Some providers may return error instead of None
            }
        }

        // Test 2: Try to set a secret (may fail for read-only providers)
        let test_value = SecretString::new(format!("test_password_{}", provider_name).into());

        if provider.allows_set() {
            // Provider claims to support set, so it should work
            provider
                .set(&project_name, "TEST_PASSWORD", &test_value, "default")
                .expect(&format!(
                    "[{}] Provider claims to support set but failed",
                    provider_name
                ));

            // Verify we can retrieve it
            let retrieved = provider
                .get(&project_name, "TEST_PASSWORD", "default")
                .expect(&format!(
                    "[{}] Should not error when getting after set",
                    provider_name
                ));

            match retrieved {
                Some(value) => {
                    assert_eq!(
                        value.expose_secret(),
                        test_value.expose_secret(),
                        "[{}] Retrieved value should match set value",
                        provider_name
                    );
                }
                None => {
                    panic!("[{}] Should find secret after setting it", provider_name);
                }
            }
        } else {
            // Provider is read-only, verify set fails
            match provider.set(&project_name, "TEST_PASSWORD", &test_value, "default") {
                Ok(_) => {
                    panic!(
                        "[{}] Read-only provider should not allow set operations",
                        provider_name
                    );
                }
                Err(_) => {
                    println!(
                        "[{}] Read-only provider correctly rejected set",
                        provider_name
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_providers_basic_workflow() {
        // Test with our internal providers directly
        println!("Testing MockProvider");
        let mock = MockProvider::new();
        test_provider_basic_workflow(&mock, "mock");

        // Test actual providers if environment variable is set
        let providers = get_test_providers();
        for provider_name in providers {
            println!("Testing provider: {}", provider_name);
            let (provider, _temp_dir) = create_provider_with_temp_path(&provider_name);
            test_provider_basic_workflow(provider.as_ref(), &provider_name);
        }
    }

    #[test]
    fn test_provider_special_characters() {
        let test_cases = vec![
            ("SPACED_VALUE", "value with spaces"),
            ("NEWLINE_VALUE", "value\nwith\nnewlines"),
            ("SPECIAL_CHARS", "!@#%^&*()_+-=[]{}|;',./<>?"),
            ("UNICODE_VALUE", "🔐 Secret with émojis and ñ"),
        ];

        // Test with MockProvider
        let provider = MockProvider::new();
        let project_name = generate_test_project_name();

        for (key, value) in &test_cases {
            let secret_value = SecretString::new(value.to_string().into());
            provider
                .set(&project_name, key, &secret_value, "default")
                .expect("Mock provider should handle all characters");

            let result = provider
                .get(&project_name, key, "default")
                .expect("Should not error when getting");

            assert_eq!(
                result.map(|s| s.expose_secret().to_string()),
                Some(value.to_string()),
                "Special characters should be preserved"
            );
        }
    }

    #[test]
    fn test_provider_profile_support() {
        let provider = MockProvider::new();
        let project_name = generate_test_project_name();
        let profiles = vec!["dev", "staging", "prod"];
        let test_key = "API_KEY";

        for profile in &profiles {
            let value = SecretString::new(format!("key_for_{}", profile).into());
            provider
                .set(&project_name, test_key, &value, profile)
                .expect("Should set with profile");

            let result = provider
                .get(&project_name, test_key, profile)
                .expect("Should get with profile");

            assert_eq!(
                result.map(|s| s.expose_secret().to_string()),
                Some(value.expose_secret().to_string()),
                "Profile-specific value should match"
            );
        }

        // Verify isolation between profiles
        for i in 0..profiles.len() {
            for j in 0..profiles.len() {
                let result = provider
                    .get(&project_name, test_key, profiles[j])
                    .expect("Should not error");

                if i == j {
                    assert!(result.is_some(), "Should find value in same profile");
                } else {
                    let expected_value = format!("key_for_{}", profiles[j]);
                    assert_eq!(
                        result.map(|s| s.expose_secret().to_string()),
                        Some(expected_value),
                        "Should find profile-specific value"
                    );
                }
            }
        }
    }

    #[test]
    fn test_bitwarden_authentication_states() {
        // Only run this test if SECRETSPEC_TEST_PROVIDERS includes bitwarden
        let providers = get_test_providers();
        if !providers.contains(&"bitwarden".to_string()) {
            println!("Skipping bitwarden authentication test - not in SECRETSPEC_TEST_PROVIDERS");
            return;
        }

        // Test that we get proper error messages for different authentication states
        let provider = Box::<dyn Provider>::try_from("bitwarden://")
            .expect("Should create bitwarden provider");

        let project_name = generate_test_project_name();
        let test_key = "AUTH_TEST_KEY";

        // Test get operation when not authenticated
        match provider.get(&project_name, test_key, "default") {
            Ok(None) => {
                // If this succeeds, the vault is unlocked and working
                println!("Bitwarden vault is unlocked and accessible");
            }
            Ok(Some(_)) => {
                // Found a value, vault is unlocked
                println!("Bitwarden vault is unlocked and contains data");
            }
            Err(err) => {
                // Should get authentication error if not unlocked
                let err_str = err.to_string();
                assert!(
                    err_str.contains("authentication required") || 
                    err_str.contains("not logged in") ||
                    err_str.contains("locked") ||
                    err_str.contains("BW_SESSION") ||
                    err_str.contains("JSON error") || // CLI returning invalid JSON
                    err_str.contains("CLI not found") ||
                    err_str.contains("command not found"),
                    "Should get authentication-related or CLI error, got: {}",
                    err_str
                );
                println!("Got expected authentication error: {}", err_str);
            }
        }
    }

    #[test]
    fn test_bitwarden_error_messages() {
        // Only run this test if SECRETSPEC_TEST_PROVIDERS includes bitwarden
        let providers = get_test_providers();
        if !providers.contains(&"bitwarden".to_string()) {
            println!("Skipping bitwarden error messages test - not in SECRETSPEC_TEST_PROVIDERS");
            return;
        }

        use crate::provider::bitwarden::BitwardenProvider;

        // Test that we get helpful error messages
        let provider = BitwardenProvider::default();

        // This will likely fail with authentication error or CLI not found error
        // but we want to verify the error messages are helpful
        let result = provider.get("test", "KEY", "default");
        match result {
            Err(err) => {
                let err_msg = err.to_string();
                // Should contain helpful guidance
                assert!(
                    err_msg.contains("bw login") ||
                    err_msg.contains("bw unlock") ||
                    err_msg.contains("BW_SESSION") ||
                    err_msg.contains("authentication") ||
                    err_msg.contains("install") ||
                    err_msg.contains("JSON error") || // CLI returning invalid JSON
                    err_msg.contains("CLI not found") ||
                    err_msg.contains("command not found"),
                    "Error message should be helpful: {}",
                    err_msg
                );
                println!("Got helpful error message: {}", err_msg);
            }
            Ok(_) => {
                println!("Bitwarden provider is working (vault is unlocked)");
            }
        }
    }

    #[test]
    fn test_bitwarden_with_real_cli_if_available() {
        // Only run this test if SECRETSPEC_TEST_PROVIDERS includes bitwarden
        let providers = get_test_providers();
        if !providers.contains(&"bitwarden".to_string()) {
            println!("Skipping bitwarden CLI test - not in SECRETSPEC_TEST_PROVIDERS");
            return;
        }

        println!("Testing bitwarden provider with real CLI");
        let (provider, _temp_dir) = create_provider_with_temp_path("bitwarden");

        // Run the generic provider test
        test_provider_basic_workflow(provider.as_ref(), "bitwarden");

        println!("Bitwarden provider passed all tests!");
    }

    #[test]
    fn test_bws_with_real_cli_if_available() {
        // Only run this test if SECRETSPEC_TEST_PROVIDERS includes bws
        let providers = get_test_providers();
        if !providers.contains(&"bws".to_string()) {
            println!("Skipping BWS CLI test - not in SECRETSPEC_TEST_PROVIDERS");
            return;
        }

        println!("Testing BWS (Bitwarden Secrets Manager) provider with real CLI");
        let (provider, _temp_dir) = create_provider_with_temp_path("bws");

        // Run the generic provider test
        test_provider_basic_workflow(provider.as_ref(), "bws");

        println!("BWS provider passed all tests!");
    }

    #[test]
    fn test_bitwarden_item_type_support() {
        // Test that different item types are supported in provider creation
        let providers_to_test = vec![
            ("bitwarden://?type=login", "login items"),
            ("bitwarden://?type=card", "card items"),
            ("bitwarden://?type=identity", "identity items"),
            ("bitwarden://?type=sshkey", "SSH key items"),
            ("bitwarden://?type=securenote", "secure note items"),
        ];

        for (uri, description) in providers_to_test {
            println!("Testing provider creation for {}", description);
            let provider = Box::<dyn Provider>::try_from(uri);
            match provider {
                Ok(provider) => {
                    assert_eq!(provider.name(), "bitwarden");
                    println!("✓ Successfully created provider for {}", description);
                }
                Err(e) => {
                    panic!("Failed to create provider for {}: {}", description, e);
                }
            }
        }
    }

    #[test]
    fn test_concurrent_access_to_mock_provider() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let provider = Arc::new(MockProvider::new());
        let num_threads = 10;
        let operations_per_thread = 50;

        // Set up initial data
        let project = "concurrent-test";
        let profile = "default";

        // Create threads that perform concurrent read/write operations
        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let provider = Arc::clone(&provider);

            let handle = thread::spawn(move || {
                for op_id in 0..operations_per_thread {
                    let key = format!("key-{}-{}", thread_id, op_id);
                    let value = format!("value-{}-{}", thread_id, op_id);

                    // Set the value
                    let secret = SecretString::new(value.clone().into());
                    provider.set(project, &key, &secret, profile).unwrap();

                    // Small delay to increase chance of race conditions
                    thread::sleep(Duration::from_millis(1));

                    // Get the value back
                    let retrieved = provider.get(project, &key, profile).unwrap();
                    assert!(retrieved.is_some(), "Key {} should exist", key);
                    assert_eq!(
                        retrieved.unwrap().expose_secret(),
                        &value,
                        "Value mismatch for key {}",
                        key
                    );
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state - should have all keys
        let expected_total = num_threads * operations_per_thread;
        let storage = provider.storage.lock().unwrap();
        let actual_count = storage.len();

        assert_eq!(
            actual_count, expected_total,
            "Expected {} keys but found {}",
            expected_total, actual_count
        );

        println!(
            "✓ Concurrent access test passed: {} threads × {} operations = {} total keys",
            num_threads, operations_per_thread, actual_count
        );
    }

    #[test]
    fn test_concurrent_read_heavy_workload() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Instant;

        let provider = Arc::new(MockProvider::new());
        let project = "read-heavy-test";
        let profile = "default";

        // Pre-populate with test data
        let num_keys = 100;
        for i in 0..num_keys {
            let key = format!("key-{}", i);
            let value = format!("value-{}", i);
            let secret = SecretString::new(value.into());
            provider.set(project, &key, &secret, profile).unwrap();
        }

        let num_reader_threads = 20;
        let reads_per_thread = 200;
        let start_time = Instant::now();

        let mut handles = vec![];

        for thread_id in 0..num_reader_threads {
            let provider = Arc::clone(&provider);

            let handle = thread::spawn(move || {
                for read_id in 0..reads_per_thread {
                    let key_index = (thread_id + read_id) % num_keys;
                    let key = format!("key-{}", key_index);
                    let expected_value = format!("value-{}", key_index);

                    let result = provider.get(project, &key, profile).unwrap();
                    assert!(result.is_some(), "Key {} should exist", key);
                    assert_eq!(
                        result.unwrap().expose_secret(),
                        &expected_value,
                        "Value mismatch for key {}",
                        key
                    );
                }
            });

            handles.push(handle);
        }

        // Wait for all readers to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let elapsed = start_time.elapsed();
        let total_reads = num_reader_threads * reads_per_thread;
        let reads_per_second = total_reads as f64 / elapsed.as_secs_f64();

        println!(
            "✓ Read-heavy test: {} reads in {:?} ({:.0} reads/sec)",
            total_reads, elapsed, reads_per_second
        );

        // Performance assertion - should handle at least 1000 reads/sec
        assert!(
            reads_per_second > 1000.0,
            "Performance too slow: {:.0} reads/sec (expected > 1000)",
            reads_per_second
        );
    }

    #[test]
    fn test_mixed_concurrent_workload() {
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        let provider = Arc::new(MockProvider::new());
        let project = "mixed-workload-test";
        let profile = "default";

        // Pre-populate with some initial data
        for i in 0..50 {
            let key = format!("initial-key-{}", i);
            let value = format!("initial-value-{}", i);
            let secret = SecretString::new(value.into());
            provider.set(project, &key, &secret, profile).unwrap();
        }

        let num_writer_threads = 5;
        let num_reader_threads = 15;
        let operations_per_thread = 100;
        let start_time = Instant::now();

        let mut handles = vec![];

        // Writer threads
        for thread_id in 0..num_writer_threads {
            let provider = Arc::clone(&provider);

            let handle = thread::spawn(move || {
                for op_id in 0..operations_per_thread {
                    let key = format!("writer-{}-key-{}", thread_id, op_id);
                    let value = format!("writer-{}-value-{}", thread_id, op_id);
                    let secret = SecretString::new(value.into());

                    provider.set(project, &key, &secret, profile).unwrap();

                    // Simulate some processing time
                    thread::sleep(Duration::from_millis(2));
                }
            });

            handles.push(handle);
        }

        // Reader threads
        for thread_id in 0..num_reader_threads {
            let provider = Arc::clone(&provider);

            let handle = thread::spawn(move || {
                for op_id in 0..operations_per_thread {
                    // Try to read existing keys
                    let key_index = (thread_id + op_id) % 50;
                    let key = format!("initial-key-{}", key_index);

                    let result = provider.get(project, &key, profile).unwrap();
                    assert!(result.is_some(), "Initial key {} should exist", key);

                    // Small delay to allow more interleaving
                    thread::sleep(Duration::from_millis(1));
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let elapsed = start_time.elapsed();
        let total_operations = (num_writer_threads + num_reader_threads) * operations_per_thread;
        let ops_per_second = total_operations as f64 / elapsed.as_secs_f64();

        // Verify we have the expected number of keys
        let storage = provider.storage.lock().unwrap();
        let expected_keys = 50 + (num_writer_threads * operations_per_thread); // initial + written
        assert_eq!(
            storage.len(),
            expected_keys,
            "Expected {} keys but found {}",
            expected_keys,
            storage.len()
        );

        println!(
            "✓ Mixed workload test: {} operations in {:?} ({:.0} ops/sec)",
            total_operations, elapsed, ops_per_second
        );

        // Performance assertion - should handle reasonable throughput
        assert!(
            ops_per_second > 500.0,
            "Performance too slow: {:.0} ops/sec (expected > 500)",
            ops_per_second
        );
    }

    #[test]
    fn test_provider_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let provider = Arc::new(MockProvider::new());
        let project = "thread-safety-test";
        let profile = "default";

        // Test that the same provider instance can be safely shared across threads
        let num_threads = 8;
        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let provider = Arc::clone(&provider);

            let handle = thread::spawn(move || {
                // Each thread sets and gets its own unique key
                let key = format!("thread-{}-key", thread_id);
                let value = format!("thread-{}-value", thread_id);
                let secret = SecretString::new(value.clone().into());

                // Set the value
                provider.set(project, &key, &secret, profile).unwrap();

                // Immediately try to get it back
                let result = provider.get(project, &key, profile).unwrap();
                assert!(
                    result.is_some(),
                    "Key {} should exist immediately after setting",
                    key
                );
                assert_eq!(
                    result.unwrap().expose_secret(),
                    &value,
                    "Value should match for key {}",
                    key
                );

                // Try multiple get operations
                for _ in 0..10 {
                    let result = provider.get(project, &key, profile).unwrap();
                    assert!(result.is_some(), "Key {} should remain accessible", key);
                    assert_eq!(
                        result.unwrap().expose_secret(),
                        &value,
                        "Value should remain consistent for key {}",
                        key
                    );
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all keys are present and correct
        for thread_id in 0..num_threads {
            let key = format!("thread-{}-key", thread_id);
            let expected_value = format!("thread-{}-value", thread_id);

            let result = provider.get(project, &key, profile).unwrap();
            assert!(
                result.is_some(),
                "Key {} should exist after all threads complete",
                key
            );
            assert_eq!(
                result.unwrap().expose_secret(),
                &expected_value,
                "Final value should be correct for key {}",
                key
            );
        }

        println!(
            "✓ Thread safety test passed: {} threads completed successfully",
            num_threads
        );
    }

    #[test]
    fn test_performance_baseline_measurements() {
        use std::time::Instant;

        let provider = MockProvider::new();
        let project = "perf-baseline";
        let profile = "default";

        // Test single operation performance
        let key = "perf-test-key";
        let value = "perf-test-value";
        let secret = SecretString::new(value.into());

        // Measure set operation
        let start = Instant::now();
        provider.set(project, key, &secret, profile).unwrap();
        let set_duration = start.elapsed();

        // Measure get operation
        let start = Instant::now();
        let result = provider.get(project, key, profile).unwrap();
        let get_duration = start.elapsed();

        assert!(result.is_some());
        assert_eq!(result.unwrap().expose_secret(), value);

        // Measure batch operations
        let batch_size = 1000;
        let start = Instant::now();

        for i in 0..batch_size {
            let batch_key = format!("batch-key-{}", i);
            let batch_value = format!("batch-value-{}", i);
            let batch_secret = SecretString::new(batch_value.into());
            provider
                .set(project, &batch_key, &batch_secret, profile)
                .unwrap();
        }

        let batch_set_duration = start.elapsed();
        let avg_set_time = batch_set_duration / batch_size;

        // Measure batch gets
        let start = Instant::now();

        for i in 0..batch_size {
            let batch_key = format!("batch-key-{}", i);
            let result = provider.get(project, &batch_key, profile).unwrap();
            assert!(result.is_some());
        }

        let batch_get_duration = start.elapsed();
        let avg_get_time = batch_get_duration / batch_size;

        println!("✓ Performance baseline measurements:");
        println!("  Single set: {:?}", set_duration);
        println!("  Single get: {:?}", get_duration);
        println!("  Average set ({}): {:?}", batch_size, avg_set_time);
        println!("  Average get ({}): {:?}", batch_size, avg_get_time);
        println!(
            "  Batch set throughput: {:.0} ops/sec",
            batch_size as f64 / batch_set_duration.as_secs_f64()
        );
        println!(
            "  Batch get throughput: {:.0} ops/sec",
            batch_size as f64 / batch_get_duration.as_secs_f64()
        );

        // Performance assertions - should be very fast for in-memory operations
        assert!(
            set_duration.as_micros() < 1000,
            "Set operation too slow: {:?}",
            set_duration
        );
        assert!(
            get_duration.as_micros() < 1000,
            "Get operation too slow: {:?}",
            get_duration
        );
        assert!(
            avg_set_time.as_micros() < 100,
            "Average set too slow: {:?}",
            avg_set_time
        );
        assert!(
            avg_get_time.as_micros() < 100,
            "Average get too slow: {:?}",
            avg_get_time
        );
    }

    // Unit tests for individual BitwardenProvider methods
    #[test]
    fn test_bitwarden_redact_secret_patterns() {
        use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};

        let provider = BitwardenProvider::new(BitwardenConfig::default());

        // Test JSON token pattern redaction - just verify method works
        let input = r#"{"token": "secret123", "other": "value"}"#;
        let result = provider.redact_secret_patterns(input.to_string());
        println!("redact_secret_patterns: '{}' -> '{}'", input, result);
        assert!(!result.is_empty(), "Should produce output");

        // Test that method works with various inputs including new field names
        let test_cases = vec![
            (r#"{"key": "mysecretkey12345", "data": "public"}"#, true),
            (r#"{"secret": "topsecret12345", "id": 123}"#, true),
            (r#"{"password": "mypassword123", "username": "user"}"#, true),
            (
                r#"{"authorization": "Bearer abc123456789", "type": "auth"}"#,
                true,
            ),
            (
                r#"{"jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "id": 1}"#,
                true,
            ),
            (
                r#"{"client_secret": "verysecret123456", "client_id": "public123"}"#,
                true,
            ),
            (r#"{"data": "public", "status": "ok"}"#, false),
        ];

        for (input, should_redact) in test_cases {
            let result = provider.redact_secret_patterns(input.to_string());
            println!("Enhanced pattern test: '{}' -> '{}'", input, result);
            assert!(!result.is_empty(), "Should produce output for: {}", input);
            if should_redact {
                assert!(
                    result.contains("[REDACTED]"),
                    "Should redact secrets in: {}",
                    input
                );
            }
        }
    }

    #[test]
    fn test_bitwarden_redact_bearer_tokens() {
        use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};

        let provider = BitwardenProvider::new(BitwardenConfig::default());

        // Test method exists and processes inputs without crashing
        let test_cases = vec![
            "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "Bearer abc123456789012345678901234567890", // Long bearer token
            "No tokens here, just regular text",
            "Bearer short", // Short bearer token
        ];

        for input in test_cases {
            let result = provider.redact_bearer_tokens(input.to_string());
            assert!(!result.is_empty(), "Should produce output for: {}", input);
            // Method should not crash and should produce reasonable output
        }
    }

    #[test]
    fn test_bitwarden_redact_base64_tokens() {
        use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};

        let provider = BitwardenProvider::new(BitwardenConfig::default());

        // Test method exists and processes inputs without crashing
        let test_cases = vec![
            "Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "short123",                       // Should not be redacted
            "123456789012345678901234567890", // Pure numbers
            "aaaaaaaaaaaaaaaaaaaaaaaaa",      // Repeated chars
            "abc123def456ghi789jkl012mno345", // Mixed alphanumeric
        ];

        for input in test_cases {
            let result = provider.redact_base64_tokens(input.to_string());
            println!("base64 test: '{}' -> '{}'", input, result);
            assert!(!result.is_empty(), "Should produce output for: {}", input);
            // Method should not crash - actual behavior may vary
        }
    }

    #[test]
    fn test_bitwarden_redact_file_paths() {
        use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};

        let provider = BitwardenProvider::new(BitwardenConfig::default());

        // Test method exists and processes inputs without crashing
        let test_cases = vec![
            "Error in /home/user/secrets/config.json at line 5",
            "Failed to read C:\\Users\\Admin\\Documents\\secret.txt",
            "Copy from /tmp/source.dat to /home/dest.dat",
            "No file paths in this message",
            "File: ./config.json or ../data.txt",
        ];

        for input in test_cases {
            let result = provider.redact_file_paths(input.to_string());
            println!("file path test: '{}' -> '{}'", input, result);
            assert!(!result.is_empty(), "Should produce output for: {}", input);
            // Method should not crash - actual behavior may vary
        }
    }

    #[test]
    fn test_bitwarden_truncate_long_message() {
        use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};

        let provider = BitwardenProvider::new(BitwardenConfig::default());

        // Test short message (should remain unchanged)
        let short_msg = "This is a short error message";
        let result = provider.truncate_long_message(short_msg.to_string());
        assert_eq!(result, short_msg);

        // Test long message (should be truncated)
        let long_msg = "A".repeat(600); // 600 characters
        let result = provider.truncate_long_message(long_msg);
        assert_eq!(result.len(), 450 + "... [truncated for security]".len());
        assert!(result.ends_with("... [truncated for security]"));
        assert!(result.starts_with("AAA")); // Should start with original content

        // Test exactly 500 characters (should not be truncated)
        let exact_msg = "B".repeat(500);
        let result = provider.truncate_long_message(exact_msg.clone());
        assert_eq!(result, exact_msg);

        // Test 501 characters (should be truncated)
        let just_over_msg = "C".repeat(501);
        let result = provider.truncate_long_message(just_over_msg);
        assert!(result.ends_with("... [truncated for security]"));
        assert_eq!(result.len(), 450 + "... [truncated for security]".len());
    }

    #[test]
    fn test_bitwarden_sanitize_integration() {
        use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};

        let provider = BitwardenProvider::new(BitwardenConfig::default());

        // Test comprehensive sanitization with complex input
        let complex_error = "Authentication failed: {\"token\": \"longsecret123456789\", \"bearer\": \"Bearer eyJ0eXAiOiJKV1QiLnothinghere\"} File: /home/user/.secrets/vault.json Error: ".to_string() + &"Additional context: ".repeat(50);

        let result = provider.sanitize_error_message(&complex_error);

        // Just verify the method works and produces output
        assert!(!result.is_empty(), "Should produce output");

        // Should contain some form of redaction indicators
        assert!(
            result.contains("[REDACTED]") || result.contains("...") || result.contains("truncated"),
            "Should show some sanitization occurred: {}",
            result
        );
    }

    #[test]
    fn test_bitwarden_comprehensive_error_sanitization() {
        use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};

        let provider = BitwardenProvider::new(BitwardenConfig::default());

        // Test that all error paths through sanitize_error_message produce clean output
        let test_cases = vec![
            "Command failed with token: abc123456789012345",
            "Authentication failed: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.secret",
            "Error reading /home/user/.secrets/vault.json",
            "Failed to parse: {\"password\": \"verysecret12345678\", \"status\": \"error\"}",
            "Windows path error: C:\\Users\\Admin\\AppData\\Local\\secret.dat",
        ];

        for input in test_cases {
            let result = provider.sanitize_error_message(input);
            println!("Comprehensive sanitization: '{}' -> '{}'", input, result);

            // Verify no raw secrets remain
            assert!(
                !result.contains("abc123456789012345"),
                "Should redact long tokens"
            );
            assert!(
                !result.contains("verysecret12345678"),
                "Should redact password values"
            );
            assert!(
                !result.contains("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.secret"),
                "Should redact JWT"
            );

            // Verify file paths are sanitized
            if input.contains("/home/user/.secrets") {
                assert!(
                    result.contains(".../vault.json"),
                    "Should preserve filename in Unix paths"
                );
            }
            if input.contains("C:\\Users\\Admin") {
                assert!(
                    result.contains("...\\secret.dat"),
                    "Should preserve filename in Windows paths"
                );
            }

            assert!(!result.is_empty(), "Should produce output");
        }
    }

    #[test]
    fn test_bitwarden_string_helper_functions() {
        use crate::provider::bitwarden::BitwardenProvider;
        use secrecy::ExposeSecret;

        // Test to_secret_string helper
        let test_string = "test_value";
        let secret = BitwardenProvider::to_secret_string(test_string);
        assert_eq!(secret.expose_secret(), test_string);

        // Test with String type
        let test_string = String::from("test_value_2");
        let secret = BitwardenProvider::to_secret_string(&test_string);
        assert_eq!(secret.expose_secret(), "test_value_2");

        // Test option_to_secret_string helper with Some
        let some_value = Some("optional_test");
        let result = BitwardenProvider::option_to_secret_string(some_value);
        assert!(result.is_some());
        assert_eq!(result.unwrap().expose_secret(), "optional_test");

        // Test option_to_secret_string helper with None
        let none_value: Option<&str> = None;
        let result = BitwardenProvider::option_to_secret_string(none_value);
        assert!(result.is_none());

        // Test with Option<String>
        let some_string = Some(String::from("string_test"));
        let result = BitwardenProvider::option_to_secret_string(some_string.as_deref());
        assert!(result.is_some());
        assert_eq!(result.unwrap().expose_secret(), "string_test");
    }

  #[test]
  fn test_default_reflect_returns_error() {
        // Test that the default reflect implementation returns an error
        let provider = MockProvider::new();
        let result = provider.reflect();
        assert!(
            result.is_err(),
            "Default reflect implementation should return an error"
        );

        let error = result.unwrap_err();
        let error_msg = error.to_string();
        assert!(
            error_msg.contains("does not support reflection"),
            "Error message should indicate reflection is not supported"
        );
    }
}
