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
            let _: String = s.optional_secret; // Supplied by its manifest default
        }
    }
}

/// Exercises `.prompt_missing(...)` end to end. Follows the same
/// isolated-child-process shape as `as_path_lifetime` above (rather than
/// mutating this process's current directory), since these tests would
/// otherwise race with every other test in this binary over `cwd`.
mod prompt_missing {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    declare_secrets!("tests/fixtures/basic.toml");

    const CHILD_CASE_VAR: &str = "SECRETSPEC_DERIVE_PROMPT_MISSING_CHILD";

    fn run_in_isolated_project(case: &str, env_file: Option<&str>) -> bool {
        let project = TempDir::new().expect("create isolated project");
        fs::write(
            project.path().join("secretspec.toml"),
            include_str!("fixtures/basic.toml"),
        )
        .expect("write project manifest");
        if let Some(contents) = env_file {
            fs::write(project.path().join(".env"), contents).expect("write dotenv provider");
        }

        Command::new(std::env::current_exe().expect("locate integration test binary"))
            .args([&format!("prompt_missing::{case}"), "--exact", "--nocapture"])
            .current_dir(project.path())
            .env(CHILD_CASE_VAR, "1")
            .env("HOME", project.path())
            .env("XDG_CONFIG_HOME", project.path())
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_PROVIDER")
            .status()
            .expect("run isolated child test")
            .success()
    }

    #[test]
    fn prompt_missing_load_succeeds_when_nothing_is_missing() {
        if std::env::var_os(CHILD_CASE_VAR).is_none() {
            assert!(run_in_isolated_project(
                "prompt_missing_load_succeeds_when_nothing_is_missing",
                Some("API_KEY=key-value\nDATABASE_URL=postgres://localhost/db\n"),
            ));
            return;
        }

        // `.prompt_missing(true)` only changes behavior when a required
        // secret is missing; when every secret already resolves, it must
        // load exactly like the default (`prompt_missing` unset).
        let resolved = SecretSpec::builder()
            .with_provider("dotenv://.env")
            .with_reason("integration test")
            .prompt_missing(true)
            .load()
            .expect("load with prompt_missing(true) and no missing secrets");
        assert_eq!(resolved.secrets.api_key, "key-value");
        assert_eq!(resolved.secrets.database_url, "postgres://localhost/db");
    }

    #[test]
    fn default_fails_fast_on_missing_secret() {
        if std::env::var_os(CHILD_CASE_VAR).is_none() {
            assert!(run_in_isolated_project(
                "default_fails_fast_on_missing_secret",
                None
            ));
            return;
        }

        // Left unset, `prompt_missing` defaults to `false`: a missing
        // required secret still fails fast with `RequiredSecretMissing`,
        // exactly like before `prompt_missing` existed.
        let result = SecretSpec::builder()
            .with_provider("dotenv://.env")
            .with_reason("integration test")
            .load();
        assert!(matches!(
            result,
            Err(secretspec::SecretSpecError::RequiredSecretMissing(_))
        ));
    }

    #[test]
    fn prompt_missing_without_a_terminal_fails_with_required_secret_missing() {
        if std::env::var_os(CHILD_CASE_VAR).is_none() {
            assert!(run_in_isolated_project(
                "prompt_missing_without_a_terminal_fails_with_required_secret_missing",
                None,
            ));
            return;
        }

        // `Secrets::ensure_secrets` only prompts when stdin is a real
        // terminal; the child process's stdin here isn't one (inherited
        // from `cargo test`, itself piped), so `prompt_missing(true)`
        // must degrade to the identical `RequiredSecretMissing` a
        // non-interactive load gives, never hang waiting for input.
        let result = SecretSpec::builder()
            .with_provider("dotenv://.env")
            .with_reason("integration test")
            .prompt_missing(true)
            .load();
        assert!(matches!(
            result,
            Err(secretspec::SecretSpecError::RequiredSecretMissing(_))
        ));
    }
}

/// A constraint violation (an `at_least_one`/`exactly_one` group with no/too
/// many members present) is a validation error with an empty
/// `missing_required` list, so it must keep failing as `ValidationFailed`
/// even with `prompt_missing(true)` — the interactive branch only triggers
/// when `missing_required` is non-empty. Runs in its own isolated project,
/// same as `prompt_missing` above, since `Secrets::load()` finds
/// `secretspec.toml` by walking up from `cwd`.
mod prompt_missing_constraint_violation {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    declare_secrets!("tests/fixtures/constraint_violation.toml");

    const CHILD_CASE_VAR: &str = "SECRETSPEC_DERIVE_PROMPT_MISSING_CONSTRAINT_CHILD";

    #[test]
    fn prompt_missing_does_not_intercept_constraint_violations() {
        if std::env::var_os(CHILD_CASE_VAR).is_none() {
            let project = TempDir::new().expect("create isolated project");
            fs::write(
                project.path().join("secretspec.toml"),
                include_str!("fixtures/constraint_violation.toml"),
            )
            .expect("write project manifest");

            let status = Command::new(std::env::current_exe().expect("locate integration test binary"))
                .args([
                    "prompt_missing_constraint_violation::prompt_missing_does_not_intercept_constraint_violations",
                    "--exact",
                    "--nocapture",
                ])
                .current_dir(project.path())
                .env(CHILD_CASE_VAR, "1")
                .env("HOME", project.path())
                .env("XDG_CONFIG_HOME", project.path())
                .env_remove("SECRETSPEC_PROFILE")
                .env_remove("SECRETSPEC_PROVIDER")
                .status()
                .expect("run isolated child test");
            assert!(status.success());
            return;
        }

        let result = SecretSpec::builder()
            .with_provider("dotenv://.env")
            .with_reason("integration test")
            .prompt_missing(true)
            .load();
        assert!(matches!(
            result,
            Err(secretspec::SecretSpecError::ValidationFailed(_))
        ));
    }
}

/// `load_profile()` threads `prompt_missing` through its own call to
/// `load_internal`, separate from `load()`'s — the "development" profile's
/// defaults satisfy every field, so this only needs to prove that wiring
/// doesn't break a successful `load_profile()`, mirroring
/// `prompt_missing_load_succeeds_when_nothing_is_missing` above for `load()`.
mod prompt_missing_load_profile {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    declare_secrets!("tests/fixtures/profiles.toml");

    const CHILD_CASE_VAR: &str = "SECRETSPEC_DERIVE_PROMPT_MISSING_LOAD_PROFILE_CHILD";

    #[test]
    fn prompt_missing_load_profile_succeeds_when_nothing_is_missing() {
        if std::env::var_os(CHILD_CASE_VAR).is_none() {
            let project = TempDir::new().expect("create isolated project");
            fs::write(
                project.path().join("secretspec.toml"),
                include_str!("fixtures/profiles.toml"),
            )
            .expect("write project manifest");

            let status = Command::new(std::env::current_exe().expect("locate integration test binary"))
                .args([
                    "prompt_missing_load_profile::prompt_missing_load_profile_succeeds_when_nothing_is_missing",
                    "--exact",
                    "--nocapture",
                ])
                .current_dir(project.path())
                .env(CHILD_CASE_VAR, "1")
                .env("HOME", project.path())
                .env("XDG_CONFIG_HOME", project.path())
                .env_remove("SECRETSPEC_PROFILE")
                .env_remove("SECRETSPEC_PROVIDER")
                .status()
                .expect("run isolated child test");
            assert!(status.success());
            return;
        }

        let resolved = SecretSpec::builder()
            .with_provider("dotenv://.env")
            .with_profile("development")
            .with_reason("integration test")
            .prompt_missing(true)
            .load_profile()
            .expect("load_profile with prompt_missing(true) and no missing secrets");
        match resolved.secrets {
            SecretSpecProfile::Development { api_key, .. } => {
                assert_eq!(api_key, "dev-api-key");
            }
            _ => panic!("Expected Development variant"),
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
                    let _: String = api_key; // Supplied by its manifest default
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
            let _: String = s.api_key; // Defaulted in development, required elsewhere
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
            let _: String = s.required_with_default; // Its default guarantees a value
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

mod as_path_lifetime {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    declare_secrets!("tests/fixtures/as_path.toml");

    const CHILD_PROCESS: &str = "SECRETSPEC_DERIVE_AS_PATH_LIFETIME_CHILD";

    #[test]
    fn typed_as_path_lifetime_child() {
        if std::env::var_os(CHILD_PROCESS).is_none() {
            return;
        }

        let resolved =
            SecretSpec::load(Some("dotenv://.env"), None).expect("load the typed as_path secret");
        let path = resolved.secrets.cert_data.clone();

        assert!(
            path.exists(),
            "the generated loader must keep an as_path file alive while Resolved is alive"
        );

        drop(resolved);

        assert!(
            !path.exists(),
            "dropping Resolved must remove its as_path temporary file"
        );
    }

    #[test]
    fn typed_as_path_file_lives_as_long_as_resolved() {
        if std::env::var_os(CHILD_PROCESS).is_some() {
            return;
        }

        let project = TempDir::new().expect("create isolated project");
        fs::write(
            project.path().join("secretspec.toml"),
            include_str!("fixtures/as_path.toml"),
        )
        .expect("write project manifest");
        fs::write(
            project.path().join(".env"),
            "CERT_DATA=certificate-content\n",
        )
        .expect("write dotenv provider");

        let status = Command::new(std::env::current_exe().expect("locate integration test binary"))
            .args([
                "as_path_lifetime::typed_as_path_lifetime_child",
                "--exact",
                "--nocapture",
            ])
            .current_dir(project.path())
            .env(CHILD_PROCESS, "1")
            .env("HOME", project.path())
            .env("XDG_CONFIG_HOME", project.path())
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_PROVIDER")
            .status()
            .expect("run isolated child test");

        assert!(status.success(), "child lifetime assertion failed");
    }
}

mod json_serialization {
    use super::*;

    declare_secrets!("tests/fixtures/basic.toml");

    #[test]
    fn test_secret_spec_secrets_json_serialization() {
        use secretspec::Resolved;

        // Create a mock SecretSpec instance
        let spec = SecretSpec {
            api_key: "test_key".to_string(),
            database_url: "postgres://localhost/db".to_string(),
            optional_secret: "optional".to_string(),
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
            let _: String = s.database_url;
            let _: String = s.api_key;
            let _: String = s.session_secret;
            let _: String = s.cache_ttl;
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
                    session_secret,
                    cache_ttl,
                } => {
                    let _: String = database_url; // Required
                    let _: String = api_key; // Required
                    let _: String = session_secret; // Required
                    let _: String = cache_ttl; // Guaranteed by default
                }
                _ => panic!("Expected Default variant"),
            }
        }

        fn _test_development(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Development {
                    database_url,
                    session_secret,
                    debug_mode,
                    api_key,
                    cache_ttl,
                } => {
                    let _: String = database_url; // Guaranteed by override default
                    let _: String = session_secret; // Guaranteed by development-only default
                    let _: String = debug_mode; // Guaranteed by its default
                    let _: String = api_key; // Inherited from default
                    let _: String = cache_ttl; // Inherited from default
                }
                _ => panic!("Expected Development variant"),
            }
        }

        fn _test_production(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Production {
                    database_url,
                    api_key,
                    session_secret,
                    cache_ttl,
                } => {
                    let _: String = database_url; // Override: required
                    let _: String = api_key; // Override: required
                    let _: String = session_secret; // Override: required
                    let _: String = cache_ttl; // Inherited from default
                }
                _ => panic!("Expected Production variant"),
            }
        }

        fn _test_staging(profile: SecretSpecProfile) {
            match profile {
                SecretSpecProfile::Staging {
                    database_url,
                    session_secret,
                    enable_profiling,
                    api_key,
                    cache_ttl,
                } => {
                    let _: String = database_url; // Override: required
                    let _: String = session_secret; // Override: required
                    let _: String = enable_profiling; // Guaranteed by its default
                    let _: String = api_key; // Inherited from default
                    let _: String = cache_ttl; // Inherited from default
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

        // The builder exposes with_reason so typed SDK callers can satisfy the
        // require_reason policy (default "agents") without relying on the
        // SECRETSPEC_REASON env var. (Not loading; just verifying the API exists.)
        let _ = SecretSpec::builder()
            .with_reason("running database migrations")
            .with_provider("dotenv://.env");

        // Caller context identifies an integration without standing in for a
        // user-supplied reason (0.20+).
        let _ = SecretSpec::builder()
            .with_caller(
                secretspec::CallerContext::new("git")
                    .with_operation("credential_get")
                    .with_resource("github.com"),
            )
            .with_provider("dotenv://.env");

        // `prompt_missing` opts the typed loader into the same
        // prompt-and-store behavior `Secrets::ensure_secrets` gives the
        // untyped `Secrets` API. (Not loading; just verifying the API exists.)
        let _ = SecretSpec::builder()
            .prompt_missing(true)
            .with_provider("dotenv://.env");
    }
}
