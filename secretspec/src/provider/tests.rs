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

    fn uri(&self) -> String {
        "mock://".to_string()
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

    let provider = Box::<dyn Provider>::try_from("pass").unwrap();
    assert_eq!(provider.name(), "pass");
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

    // Test pass examples
    let provider = Box::<dyn Provider>::try_from("pass://").unwrap();
    assert_eq!(provider.name(), "pass");
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
            "pass" => {
                let provider =
                    Box::<dyn Provider>::try_from("pass").expect("Should create pass provider");
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

    #[test]
    fn test_pass_provider_creation() {
        // Test pass provider can be created from various URI formats
        let provider = Box::<dyn Provider>::try_from("pass").unwrap();
        assert_eq!(provider.name(), "pass");
        assert_eq!(provider.uri(), "pass");

        let provider = Box::<dyn Provider>::try_from("pass://").unwrap();
        assert_eq!(provider.name(), "pass");
        assert_eq!(provider.uri(), "pass");
    }

    #[test]
    fn test_pass_provider_allows_set() {
        let provider = Box::<dyn Provider>::try_from("pass").unwrap();
        assert!(
            provider.allows_set(),
            "Pass provider should support write operations"
        );
    }

    #[cfg(feature = "gcsm")]
    #[test]
    fn test_gcsm_provider_creation() {
        // Test GCSM provider can be created from URI format
        let provider = Box::<dyn Provider>::try_from("gcsm://my-project").unwrap();
        assert_eq!(provider.name(), "gcsm");
        assert_eq!(provider.uri(), "gcsm://my-project");
    }

    #[cfg(feature = "gcsm")]
    #[test]
    fn test_gcsm_provider_requires_project_id() {
        // Test that GCSM provider requires a project ID
        let result = Box::<dyn Provider>::try_from("gcsm://");
        assert!(result.is_err(), "GCSM provider should require project ID");

        let result = Box::<dyn Provider>::try_from("gcsm");
        assert!(result.is_err(), "GCSM provider should require project ID");
    }

    #[cfg(feature = "gcsm")]
    #[test]
    fn test_gcsm_provider_validates_project_id_format() {
        // Too short (< 6 chars)
        let result = Box::<dyn Provider>::try_from("gcsm://short");
        assert!(result.is_err(), "Should reject project ID < 6 chars");

        // Must start with lowercase letter
        let result = Box::<dyn Provider>::try_from("gcsm://123456");
        assert!(
            result.is_err(),
            "Should reject project ID starting with number"
        );

        let result = Box::<dyn Provider>::try_from("gcsm://My-Project-123");
        assert!(result.is_err(), "Should reject project ID with uppercase");

        // Cannot end with hyphen
        let result = Box::<dyn Provider>::try_from("gcsm://my-project-");
        assert!(
            result.is_err(),
            "Should reject project ID ending with hyphen"
        );

        // Invalid characters
        let result = Box::<dyn Provider>::try_from("gcsm://my_project");
        assert!(result.is_err(), "Should reject project ID with underscore");

        // Valid project IDs
        let provider = Box::<dyn Provider>::try_from("gcsm://my-project-123").unwrap();
        assert_eq!(provider.name(), "gcsm");

        let provider = Box::<dyn Provider>::try_from("gcsm://project123").unwrap();
        assert_eq!(provider.name(), "gcsm");
    }
}
