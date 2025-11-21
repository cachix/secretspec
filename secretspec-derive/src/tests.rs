#[cfg(test)]
mod tests {
    use crate::capitalize_first;
    use secretspec::Config;

    #[test]
    fn test_capitalize_first() {
        assert_eq!(capitalize_first("development"), "Development");
        assert_eq!(capitalize_first("production"), "Production");
        assert_eq!(capitalize_first("test"), "Test");
        assert_eq!(capitalize_first(""), "");
        assert_eq!(capitalize_first("a"), "A");
    }

    #[test]
    fn test_parse_basic_config() {
        let toml_str = r#"[project]
name = "test"
revision = "1.0"

[profiles.default]
API_KEY = { description = "API key", required = true }
DATABASE_URL = { description = "Database URL", required = false, default = "postgres://localhost" }
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.profiles.len(), 1);
        let default_profile = &config.profiles["default"];
        assert_eq!(default_profile.secrets.len(), 2);

        let api_key = &default_profile.secrets["API_KEY"];
        assert_eq!(api_key.required, Some(true));
        assert!(api_key.default.is_none());

        let db_url = &default_profile.secrets["DATABASE_URL"];
        assert_eq!(db_url.required, Some(false));
        assert_eq!(db_url.default.as_deref(), Some("postgres://localhost"));
    }

    #[test]
    fn test_parse_profile_overrides() {
        let toml_str = r#"
            [profiles.default]
            API_KEY = { description = "API key", required = true }
            
            [profiles.development]
            API_KEY = { description = "API key", required = false, default = "dev-key" }
            
            [profiles.production]
            API_KEY = { description = "API key", required = true }
        "#;

        let config: Config = toml::from_str(&format!(
            r#"[project]
name = "test"
revision = "1.0"
{}"#,
            toml_str
        ))
        .unwrap();
        let api_key = &config.profiles["default"].secrets["API_KEY"];

        assert_eq!(api_key.required, Some(true));
        assert_eq!(config.profiles.len(), 3);

        let dev_api_key = &config.profiles["development"].secrets["API_KEY"];
        assert_eq!(dev_api_key.required, Some(false));
        assert_eq!(dev_api_key.default.as_deref(), Some("dev-key"));

        let prod_api_key = &config.profiles["production"].secrets["API_KEY"];
        assert_eq!(prod_api_key.required, Some(true));
        assert!(prod_api_key.default.is_none());
    }

    #[test]
    fn test_field_type_determination() {
        // Test that a field that's optional in any profile becomes Option<String>
        let toml_str = r#"[project]
name = "test"
revision = "1.0"

[profiles.default]
SOMETIMES_REQUIRED = { description = "Sometimes required secret", required = true }

[profiles.development]
SOMETIMES_REQUIRED = { description = "Sometimes required secret", required = false }
"#;

        let config: Config = toml::from_str(toml_str).unwrap();

        // Simulate the logic from the macro - check if secret is optional across all profiles
        let mut is_ever_optional = false;

        for (_profile_name, profile_config) in &config.profiles {
            if let Some(secret_config) = profile_config.secrets.get("SOMETIMES_REQUIRED") {
                if secret_config.required != Some(true) || secret_config.default.is_some() {
                    is_ever_optional = true;
                    break;
                }
            } else {
                // Secret doesn't exist in this profile, so it's optional
                is_ever_optional = true;
                break;
            }
        }

        assert!(
            is_ever_optional,
            "Field should be optional since it's optional in development"
        );
    }

    #[test]
    fn test_always_required_field() {
        let toml_str = r#"[project]
name = "test"
revision = "1.0"

[profiles.default]
ALWAYS_REQUIRED = { description = "Always required secret", required = true }

[profiles.development]
ALWAYS_REQUIRED = { description = "Always required secret", required = true }

[profiles.production]
ALWAYS_REQUIRED = { description = "Always required secret", required = true }
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let secret_config = &config.profiles["default"].secrets["ALWAYS_REQUIRED"];
        let mut is_ever_optional = false;

        if secret_config.required != Some(true) || secret_config.default.is_some() {
            is_ever_optional = true;
        }

        // Test with the same logic that checks across all profiles
        // (The profile check logic is already above)

        assert!(!is_ever_optional, "Field should never be optional");
    }

    #[test]
    fn test_default_makes_optional() {
        let toml_str = r#"[project]
name = "test"
revision = "1.0"

[profiles.default]
HAS_DEFAULT = { description = "Secret with default", required = true, default = "some-default" }
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let secret_config = &config.profiles["default"].secrets["HAS_DEFAULT"];

        let is_ever_optional =
            secret_config.required != Some(true) || secret_config.default.is_some();
        assert!(
            is_ever_optional,
            "Field with default should be treated as optional"
        );
    }

    // ===== STAGE 1: HELPER FUNCTION TESTS =====

    #[test]
    fn test_is_valid_rust_identifier() {
        use crate::is_valid_rust_identifier;

        // Valid identifiers
        assert!(is_valid_rust_identifier("valid_name"));
        assert!(is_valid_rust_identifier("_valid"));
        assert!(is_valid_rust_identifier("Valid123"));
        assert!(is_valid_rust_identifier("a"));
        assert!(is_valid_rust_identifier("API_KEY"));
        assert!(is_valid_rust_identifier("database_url"));

        // Invalid identifiers
        assert!(!is_valid_rust_identifier(""));
        assert!(!is_valid_rust_identifier("123invalid"));
        assert!(!is_valid_rust_identifier("invalid-name"));
        assert!(!is_valid_rust_identifier("invalid.name"));
        assert!(!is_valid_rust_identifier("invalid name"));
        assert!(!is_valid_rust_identifier("invalid@name"));
        assert!(!is_valid_rust_identifier("invalid#name"));
    }

    #[test]
    fn test_validate_rust_identifiers() {
        use crate::validate_rust_identifiers;
        use secretspec::{Profile, Project, Secret};
        use std::collections::HashMap;

        let mut errors = Vec::new();

        // Test with valid identifiers
        let mut valid_secrets = HashMap::new();
        valid_secrets.insert(
            "API_KEY".to_string(),
            Secret {
                description: Some("API Key".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        valid_secrets.insert(
            "database_url".to_string(),
            Secret {
                description: Some("Database URL".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );

        let mut valid_profiles = HashMap::new();
        valid_profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: valid_secrets,
            },
        );

        let valid_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: valid_profiles,
        };

        validate_rust_identifiers(&valid_config, &mut errors);
        assert!(
            errors.is_empty(),
            "Valid identifiers should not produce errors"
        );

        // Test with invalid identifiers
        let mut invalid_secrets = HashMap::new();
        invalid_secrets.insert(
            "123invalid".to_string(),
            Secret {
                description: Some("Invalid name".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        invalid_secrets.insert(
            "invalid-name".to_string(),
            Secret {
                description: Some("Invalid name".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );

        let mut invalid_profiles = HashMap::new();
        invalid_profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: invalid_secrets,
            },
        );

        let invalid_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: invalid_profiles,
        };

        errors.clear();
        validate_rust_identifiers(&invalid_config, &mut errors);
        assert_eq!(
            errors.len(),
            2,
            "Should have errors for invalid identifiers"
        );
        // Check that errors contain the invalid secret names
        let error_text = errors.join(" ");
        assert!(
            error_text.contains("123invalid"),
            "Errors should mention 123invalid: {:?}",
            errors
        );
        assert!(
            error_text.contains("invalid-name"),
            "Errors should mention invalid-name: {:?}",
            errors
        );
    }

    #[test]
    fn test_validate_rust_keywords() {
        use crate::validate_rust_identifiers;
        use secretspec::{Profile, Project, Secret};
        use std::collections::HashMap;

        let mut errors = Vec::new();

        // Test with Rust keywords
        let mut keyword_secrets = HashMap::new();
        keyword_secrets.insert(
            "fn".to_string(),
            Secret {
                description: Some("Function keyword".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        keyword_secrets.insert(
            "struct".to_string(),
            Secret {
                description: Some("Struct keyword".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        keyword_secrets.insert(
            "async".to_string(),
            Secret {
                description: Some("Async keyword".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );

        let mut keyword_profiles = HashMap::new();
        keyword_profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: keyword_secrets,
            },
        );

        let keyword_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: keyword_profiles,
        };

        validate_rust_identifiers(&keyword_config, &mut errors);
        assert_eq!(errors.len(), 3, "Should have errors for all Rust keywords");
        let error_text = errors.join(" ");
        assert!(
            error_text.contains("fn"),
            "Should contain 'fn' keyword error: {:?}",
            errors
        );
        assert!(
            error_text.contains("struct"),
            "Should contain 'struct' keyword error: {:?}",
            errors
        );
        assert!(
            error_text.contains("async"),
            "Should contain 'async' keyword error: {:?}",
            errors
        );
    }

    #[test]
    fn test_validate_duplicate_field_names() {
        use crate::validate_rust_identifiers;
        use secretspec::{Profile, Project, Secret};
        use std::collections::HashMap;

        let mut errors = Vec::new();

        // Test with case-insensitive duplicates
        let mut duplicate_secrets = HashMap::new();
        duplicate_secrets.insert(
            "API_KEY".to_string(),
            Secret {
                description: Some("API Key upper".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        duplicate_secrets.insert(
            "api_key".to_string(),
            Secret {
                description: Some("API Key lower".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        duplicate_secrets.insert(
            "Api_Key".to_string(),
            Secret {
                description: Some("API Key mixed".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );

        let mut duplicate_profiles = HashMap::new();
        duplicate_profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: duplicate_secrets,
            },
        );

        let duplicate_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: duplicate_profiles,
        };

        validate_rust_identifiers(&duplicate_config, &mut errors);
        // Should have 2 duplicate errors (3 secrets, 2 duplicates)
        let duplicate_errors: Vec<_> = errors
            .iter()
            .filter(|e| e.contains("multiple secrets"))
            .collect();
        assert_eq!(
            duplicate_errors.len(),
            2,
            "Should detect duplicate field names"
        );
    }

    #[test]
    fn test_validate_profile_identifiers() {
        use crate::validate_profile_identifiers;
        use secretspec::{Profile, Project};
        use std::collections::HashMap;

        let mut errors = Vec::new();

        // Test with valid profile names
        let mut valid_profiles = HashMap::new();
        valid_profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: HashMap::new(),
            },
        );
        valid_profiles.insert(
            "development".to_string(),
            Profile {
                defaults: None,
                secrets: HashMap::new(),
            },
        );
        valid_profiles.insert(
            "production".to_string(),
            Profile {
                defaults: None,
                secrets: HashMap::new(),
            },
        );

        let valid_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: valid_profiles,
        };

        validate_profile_identifiers(&valid_config, &mut errors);
        assert!(
            errors.is_empty(),
            "Valid profile names should not produce errors"
        );

        // Test with invalid profile names
        let mut invalid_profiles = HashMap::new();
        invalid_profiles.insert(
            "123invalid".to_string(),
            Profile {
                defaults: None,
                secrets: HashMap::new(),
            },
        );
        invalid_profiles.insert(
            "invalid-name".to_string(),
            Profile {
                defaults: None,
                secrets: HashMap::new(),
            },
        );

        let invalid_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: invalid_profiles,
        };

        errors.clear();
        validate_profile_identifiers(&invalid_config, &mut errors);
        assert_eq!(
            errors.len(),
            2,
            "Should have errors for invalid profile names"
        );
        assert!(errors.iter().any(|e| e.contains("123invalid")));
        assert!(errors.iter().any(|e| e.contains("invalid-name")));
    }

    #[test]
    fn test_field_name_ident() {
        use crate::field_name_ident;

        // Test case conversion
        assert_eq!(field_name_ident("API_KEY").to_string(), "api_key");
        assert_eq!(field_name_ident("DATABASE_URL").to_string(), "database_url");
        assert_eq!(field_name_ident("simple").to_string(), "simple");
        assert_eq!(field_name_ident("Mixed_Case").to_string(), "mixed_case");
    }

    #[test]
    fn test_is_secret_optional() {
        use crate::is_secret_optional;
        use secretspec::Secret;

        // Required without default
        let required_no_default = Secret {
            description: Some("Required".to_string()),
            required: Some(true),
            default: None,
            providers: None,
            as_path: None,
        };
        assert!(!is_secret_optional(&required_no_default));

        // Required with default (should NOT be optional)
        let required_with_default = Secret {
            description: Some("Required with default".to_string()),
            required: Some(true),
            default: Some("default_value".to_string()),
            providers: None,
            as_path: None,
        };
        assert!(!is_secret_optional(&required_with_default));

        // Not required
        let not_required = Secret {
            description: Some("Not required".to_string()),
            required: Some(false),
            default: None,
            providers: None,
            as_path: None,
        };
        assert!(is_secret_optional(&not_required));

        // Not required with default
        let not_required_with_default = Secret {
            description: Some("Not required with default".to_string()),
            required: Some(false),
            default: Some("default_value".to_string()),
            providers: None,
            as_path: None,
        };
        assert!(is_secret_optional(&not_required_with_default));
    }

    #[test]
    fn test_is_field_optional_across_profiles() {
        use crate::is_field_optional_across_profiles;
        use secretspec::{Profile, Project, Secret};
        use std::collections::HashMap;

        // Setup config with multiple profiles
        let mut profiles = HashMap::new();

        // Default profile: API_KEY required, DATABASE_URL optional
        let mut default_secrets = HashMap::new();
        default_secrets.insert(
            "API_KEY".to_string(),
            Secret {
                description: Some("API Key".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        default_secrets.insert(
            "DATABASE_URL".to_string(),
            Secret {
                description: Some("Database URL".to_string()),
                required: Some(false),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: default_secrets,
            },
        );

        // Development profile: API_KEY with default (optional), DATABASE_URL required
        let mut dev_secrets = HashMap::new();
        dev_secrets.insert(
            "API_KEY".to_string(),
            Secret {
                description: Some("API Key".to_string()),
                required: Some(true),
                default: Some("dev-key".to_string()),
                providers: None,
                as_path: None,
            },
        );
        dev_secrets.insert(
            "DATABASE_URL".to_string(),
            Secret {
                description: Some("Database URL".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        // Note: CACHE_URL only exists in development
        dev_secrets.insert(
            "CACHE_URL".to_string(),
            Secret {
                description: Some("Cache URL".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        profiles.insert(
            "development".to_string(),
            Profile {
                defaults: None,
                secrets: dev_secrets,
            },
        );

        let config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles,
        };

        // API_KEY is NOT optional (required in all profiles, default doesn't make it optional)
        assert!(!is_field_optional_across_profiles("API_KEY", &config));

        // DATABASE_URL is optional because it's not required in default
        assert!(is_field_optional_across_profiles("DATABASE_URL", &config));

        // CACHE_URL is optional because it doesn't exist in default profile
        assert!(is_field_optional_across_profiles("CACHE_URL", &config));

        // Test a secret that's always required
        let mut strict_profiles = HashMap::new();
        let mut strict_default = HashMap::new();
        strict_default.insert(
            "ALWAYS_REQUIRED".to_string(),
            Secret {
                description: Some("Always required".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        let mut strict_dev = HashMap::new();
        strict_dev.insert(
            "ALWAYS_REQUIRED".to_string(),
            Secret {
                description: Some("Always required".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        strict_profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: strict_default,
            },
        );
        strict_profiles.insert(
            "development".to_string(),
            Profile {
                defaults: None,
                secrets: strict_dev,
            },
        );

        let strict_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: strict_profiles,
        };

        // ALWAYS_REQUIRED should not be optional
        assert!(!is_field_optional_across_profiles(
            "ALWAYS_REQUIRED",
            &strict_config
        ));
    }

    #[test]
    fn test_analyze_field_types() {
        use crate::analyze_field_types;
        use secretspec::{Profile, Project, Secret};
        use std::collections::HashMap;

        let mut profiles = HashMap::new();

        // Default profile
        let mut default_secrets = HashMap::new();
        default_secrets.insert(
            "REQUIRED_SECRET".to_string(),
            Secret {
                description: Some("Always required".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        default_secrets.insert(
            "OPTIONAL_SECRET".to_string(),
            Secret {
                description: Some("Optional".to_string()),
                required: Some(false),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        default_secrets.insert(
            "DEFAULT_SECRET".to_string(),
            Secret {
                description: Some("Has default".to_string()),
                required: Some(true),
                default: Some("default_value".to_string()),
                providers: None,
                as_path: None,
            },
        );
        profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: default_secrets,
            },
        );

        // Development profile with additional secret
        let mut dev_secrets = HashMap::new();
        dev_secrets.insert(
            "REQUIRED_SECRET".to_string(),
            Secret {
                description: Some("Always required".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        dev_secrets.insert(
            "DEV_ONLY_SECRET".to_string(),
            Secret {
                description: Some("Development only".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        profiles.insert(
            "development".to_string(),
            Profile {
                defaults: None,
                secrets: dev_secrets,
            },
        );

        let config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles,
        };

        let field_info = analyze_field_types(&config);

        // Should have 4 unique secrets across all profiles
        assert_eq!(field_info.len(), 4);

        // REQUIRED_SECRET exists in both profiles and is always required -> String
        let required_field = field_info.get("REQUIRED_SECRET").unwrap();
        assert!(!required_field.is_optional);

        // OPTIONAL_SECRET only exists in default and is optional -> Option<String>
        let optional_field = field_info.get("OPTIONAL_SECRET").unwrap();
        assert!(optional_field.is_optional);

        // DEFAULT_SECRET has default value -> Option<String>
        let default_field = field_info.get("DEFAULT_SECRET").unwrap();
        assert!(default_field.is_optional);

        // DEV_ONLY_SECRET only exists in development -> Option<String>
        let dev_only_field = field_info.get("DEV_ONLY_SECRET").unwrap();
        assert!(dev_only_field.is_optional);
    }

    #[test]
    fn test_field_info_methods() {
        use crate::FieldInfo;
        use quote::quote;

        // Test required field
        let required_field = FieldInfo::new("API_KEY".to_string(), quote! { String }, false, false);

        assert_eq!(required_field.name, "API_KEY");
        assert!(!required_field.is_optional);
        assert_eq!(required_field.field_name().to_string(), "api_key");

        // Test the struct field generation
        let struct_field = required_field.generate_struct_field();
        let expected_struct = quote! { pub api_key: String };
        assert_eq!(struct_field.to_string(), expected_struct.to_string());

        // Test optional field
        let optional_field = FieldInfo::new(
            "DATABASE_URL".to_string(),
            quote! { Option<String> },
            true,
            false,
        );

        assert!(optional_field.is_optional);
        assert_eq!(optional_field.field_name().to_string(), "database_url");

        let optional_struct_field = optional_field.generate_struct_field();
        let expected_optional_struct = quote! { pub database_url: Option<String> };
        assert_eq!(
            optional_struct_field.to_string(),
            expected_optional_struct.to_string()
        );
    }

    #[test]
    fn test_profile_variant_methods() {
        use crate::ProfileVariant;

        let variant = ProfileVariant::new("development".to_string());
        assert_eq!(variant.name, "development");
        assert_eq!(variant.capitalized, "Development");
        assert_eq!(variant.as_ident().to_string(), "Development");

        let default_variant = ProfileVariant::new("default".to_string());
        assert_eq!(default_variant.capitalized, "Default");
        assert_eq!(default_variant.as_ident().to_string(), "Default");

        let prod_variant = ProfileVariant::new("production".to_string());
        assert_eq!(prod_variant.capitalized, "Production");
        assert_eq!(prod_variant.as_ident().to_string(), "Production");
    }

    #[test]
    fn test_get_profile_variants() {
        use crate::get_profile_variants;
        use std::collections::HashSet;

        // Test empty profiles
        let empty_profiles = HashSet::new();
        let variants = get_profile_variants(&empty_profiles);
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0].name, "default");

        // Test with multiple profiles
        let mut profiles = HashSet::new();
        profiles.insert("production".to_string());
        profiles.insert("development".to_string());
        profiles.insert("staging".to_string());
        profiles.insert("default".to_string());

        let variants = get_profile_variants(&profiles);
        assert_eq!(variants.len(), 4);

        // Should be sorted alphabetically
        let names: Vec<&String> = variants.iter().map(|v| &v.name).collect();
        assert_eq!(
            names,
            vec!["default", "development", "production", "staging"]
        );

        // Check capitalization
        assert_eq!(variants[0].capitalized, "Default");
        assert_eq!(variants[1].capitalized, "Development");
        assert_eq!(variants[2].capitalized, "Production");
        assert_eq!(variants[3].capitalized, "Staging");
    }

    #[test]
    fn test_validate_config_for_codegen() {
        use crate::validate_config_for_codegen;
        use secretspec::{Profile, Project, Secret};
        use std::collections::HashMap;

        // Test valid config
        let mut valid_secrets = HashMap::new();
        valid_secrets.insert(
            "API_KEY".to_string(),
            Secret {
                description: Some("API Key".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        valid_secrets.insert(
            "database_url".to_string(),
            Secret {
                description: Some("Database URL".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );

        let mut valid_profiles = HashMap::new();
        valid_profiles.insert(
            "default".to_string(),
            Profile {
                defaults: None,
                secrets: valid_secrets,
            },
        );
        valid_profiles.insert(
            "development".to_string(),
            Profile {
                defaults: None,
                secrets: HashMap::new(),
            },
        );

        let valid_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: valid_profiles,
        };

        let result = validate_config_for_codegen(&valid_config);
        assert!(result.is_ok(), "Valid config should pass validation");

        // Test invalid config
        let mut invalid_secrets = HashMap::new();
        invalid_secrets.insert(
            "123invalid".to_string(),
            Secret {
                description: Some("Invalid name".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );
        invalid_secrets.insert(
            "fn".to_string(),
            Secret {
                description: Some("Rust keyword".to_string()),
                required: Some(true),
                default: None,
                providers: None,
                as_path: None,
            },
        );

        let mut invalid_profiles = HashMap::new();
        invalid_profiles.insert(
            "123invalid-profile".to_string(),
            Profile {
                defaults: None,
                secrets: invalid_secrets,
            },
        );

        let invalid_config = Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: invalid_profiles,
        };

        let result = validate_config_for_codegen(&invalid_config);
        assert!(result.is_err(), "Invalid config should fail validation");
        let errors = result.unwrap_err();
        assert!(!errors.is_empty(), "Should have validation errors");
        let error_text = errors.join(" ");
        assert!(
            error_text.contains("123invalid"),
            "Should contain secret validation errors: {:?}",
            errors
        );
        assert!(
            error_text.contains("fn"),
            "Should contain keyword errors: {:?}",
            errors
        );
    }
}
