// Integration tests that verify the complete macro output

use secretspec_derive::declare_secrets;

mod basic_generation {
    use super::*;

    declare_secrets!("tests/fixtures/basic.toml");

    #[test]
    fn test_struct_fields_exist() {
        // This verifies that the struct has the expected fields
        fn _test_field_types(s: SecretSpec) {
            let _: String = s.api_key;
            let _: String = s.database_url;
            let _: Option<String> = s.optional_secret;
        }
    }
}

mod profile_generation {
    use super::*;

    declare_secrets!("tests/fixtures/profiles.toml");

    #[test]
    fn test_profile_enum_variants() {
        // Verify Profile enum has the expected variants
        let _dev = Profile::Development;
        let _staging = Profile::Staging;
        let _prod = Profile::Production;
    }

    #[test]
    fn test_profile_specific_types() {
        // This verifies the profile-specific enum variants have correct field types
        fn _test_development(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Development {
                    api_key,
                    database_url,
                    redis_url,
                } => {
                    let _: Option<String> = api_key; // Optional in dev
                    let _: String = database_url; // Required but has default
                    let _: Option<String> = redis_url; // Optional
                }
                _ => panic!("Expected Development variant"),
            }
        }

        fn _test_production(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Production {
                    api_key,
                    database_url,
                    redis_url,
                } => {
                    let _: String = api_key; // Required in prod
                    let _: String = database_url; // Required in prod
                    let _: String = redis_url; // Required in prod
                }
                _ => panic!("Expected Production variant"),
            }
        }
    }

    #[test]
    fn test_union_type_fields() {
        // Verify the union struct has Option for fields that are optional in any profile
        fn _test_field_types(s: SecretSpec) {
            let _: Option<String> = s.api_key; // Optional in development
            let _: String = s.database_url; // Has default in dev but still required
            let _: Option<String> = s.redis_url; // Optional by default
        }
    }
}

mod complex_generation {
    use super::*;

    declare_secrets!("tests/fixtures/complex.toml");

    #[test]
    fn test_complex_field_types() {
        fn _test_field_types(s: SecretSpec) {
            let _: String = s.always_required;
            let _: String = s.required_with_default; // Has default but still required
            let _: Option<String> = s.always_optional;
            let _: Option<String> = s.complex_secret; // Optional in dev and test
            let _: Option<String> = s.multi_profile; // Optional in base
        }
    }

    #[test]
    fn test_all_profiles_generated() {
        // Verify all profiles from the TOML are generated
        let _dev = Profile::Development;
        let _staging = Profile::Staging;
        let _prod = Profile::Production;
        let _test = Profile::Test;
    }
}

mod empty_generation {
    use super::*;

    declare_secrets!("tests/fixtures/empty.toml");

    #[test]
    fn test_empty_struct() {
        // Verify the struct is generated even with no secrets
        let _size = std::mem::size_of::<SecretSpec>();

        // The struct should have no fields
        fn _test_no_fields(_s: SecretSpec) {
            // Empty struct
        }
    }
}

mod json_serialization {
    use super::*;
    use serde_json;

    declare_secrets!("tests/fixtures/basic.toml");

    #[test]
    fn test_secret_spec_secrets_json_serialization() {
        use secretspec::Resolved;

        // Create a mock SecretSpec instance
        let spec = SecretSpec {
            api_key: "test_key".to_string(),
            database_url: "postgres://localhost/db".to_string(),
            optional_secret: Some("optional".to_string()),
        };

        let secrets_wrapper = Resolved::new(spec, "dotenv".to_string(), "production".to_string());

        // Test serialization to JSON
        let json = serde_json::to_string(&secrets_wrapper).expect("Failed to serialize Resolved");

        // Verify JSON contains expected fields
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Failed to parse JSON");
        assert_eq!(parsed["provider"], "dotenv");
        assert_eq!(parsed["profile"], "production");
        assert_eq!(parsed["secrets"]["api_key"], "test_key");

        // Test round-trip deserialization
        let deserialized: Resolved<SecretSpec> =
            serde_json::from_str(&json).expect("Failed to deserialize Resolved");
        assert_eq!(deserialized.provider, "dotenv");
        assert_eq!(deserialized.profile, "production");
        assert_eq!(deserialized.secrets.api_key, "test_key");
    }
}

mod profile_inheritance {
    use super::*;

    declare_secrets!("tests/fixtures/profile_inheritance.toml");

    #[test]
    fn test_profile_inheritance_compilation() {
        // This test verifies that the macro successfully processes a TOML file
        // where profiles have partial secret definitions that rely on field-level inheritance

        // Verify all expected profiles are generated
        let _default = Profile::Default;
        let _dev = Profile::Development;
        let _prod = Profile::Production;
        let _staging = Profile::Staging;
    }

    #[test]
    fn test_union_type_with_inheritance() {
        // Verify the union struct has all secrets from all profiles
        fn _test_field_types(s: SecretSpec) {
            let _: Option<String> = s.database_url;
            let _: Option<String> = s.api_key;
            let _: Option<String> = s.log_level;
            let _: Option<String> = s.cache_ttl;
            let _: Option<String> = s.debug_mode;
            let _: Option<String> = s.enable_profiling;
        }
    }

    #[test]
    fn test_profile_specific_with_inheritance() {
        // Test that each profile variant has the expected fields
        fn _test_default(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Default {
                    database_url,
                    api_key,
                    log_level,
                    cache_ttl,
                } => {
                    let _: String = database_url; // Required
                    let _: String = api_key; // Required
                    let _: Option<String> = log_level; // Optional (required=false) with default
                    let _: Option<String> = cache_ttl; // Optional (required=false) with default
                }
                _ => panic!("Expected Default variant"),
            }
        }

        fn _test_development(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Development {
                    database_url,
                    debug_mode,
                } => {
                    let _: Option<String> = database_url; // Override: required=false with default
                    let _: Option<String> = debug_mode; // New field in development (required=false)
                }
                _ => panic!("Expected Development variant"),
            }
        }

        fn _test_production(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Production {
                    database_url,
                    api_key,
                    log_level,
                } => {
                    let _: String = database_url; // Override: required
                    let _: String = api_key; // Override: required
                    let _: Option<String> = log_level; // Override: required=false with different default
                }
                _ => panic!("Expected Production variant"),
            }
        }

        fn _test_staging(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Staging {
                    database_url,
                    log_level,
                    enable_profiling,
                } => {
                    let _: String = database_url; // Override: required
                    let _: Option<String> = log_level; // Override: required=false with different default
                    let _: Option<String> = enable_profiling; // New field in staging (required=false)
                }
                _ => panic!("Expected Staging variant"),
            }
        }
    }

    #[test]
    fn test_builder_works_with_inherited_profiles() {
        // Verify the builder is generated correctly
        let _builder = SecretSpec::builder();

        // Test that we can specify different profiles
        // (We're not actually loading, just verifying the API exists)
        let _ = SecretSpec::builder()
            .with_profile("development")
            .with_provider("dotenv://.env");

        let _ = SecretSpec::builder()
            .with_profile(Profile::Production)
            .with_provider("keyring://");
    }
}
