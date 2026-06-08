use crate::config::{
    Config, GlobalConfig, GlobalDefaults, ParseError, Profile, Project, RequireReason, Resolved,
    Secret,
};
use crate::error::{Result, SecretSpecError};
use crate::secrets::Secrets;
use crate::validation::{ValidatedSecrets, ValidationErrors};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;
use std::{fs, io};
use tempfile::TempDir;

// Helper function for tests that need to parse from string
fn parse_spec_from_str(content: &str, _base_path: Option<&Path>) -> Result<Config> {
    // Parse the TOML content directly
    let config: Config = toml::from_str(content).map_err(SecretSpecError::Toml)?;

    // Validate the configuration
    if config.project.revision != "1.0" {
        return Err(SecretSpecError::UnsupportedRevision(
            config.project.revision,
        ));
    }

    config.validate().map_err(|e| SecretSpecError::from(e))?;

    Ok(config)
}

// Builder pattern test removed - SecretsBuilder no longer exists

#[test]
fn test_new_with_project_config() {
    let config = Config {
        project: Project {
            name: "test-project".to_string(),
            ..Default::default()
        },
        profiles: HashMap::new(),
        providers: None,
    };

    let spec = Secrets::new(config, None, None, None);

    assert_eq!(spec.config().project.name, "test-project");
}

#[test]
fn test_new_with_custom_configs() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path().join("custom-secretspec.toml");
    let global_path = temp_dir.path().join("custom-global.toml");

    // Create test project config
    let project_config = r#"
[project]
name = "custom-project"
revision = "1.0"

[profiles.default]
API_KEY = { description = "API Key", required = true }
"#;
    fs::write(&project_path, project_config).unwrap();

    // Create test global config
    let global_config = r#"
[defaults]
provider = "keyring"
profile = "development"
"#;
    fs::write(&global_path, global_config).unwrap();

    // Load configs from files
    let config = Config::try_from(project_path.as_path()).unwrap();
    // For tests, we'll parse the global config directly since load_global_config uses a fixed path
    let global_config_content = fs::read_to_string(&global_path).unwrap();
    let global_config: Option<GlobalConfig> = Some(toml::from_str(&global_config_content).unwrap());

    let spec = Secrets::new(config, global_config, None, None);

    assert_eq!(spec.config().project.name, "custom-project");
    assert_eq!(
        spec.global_config()
            .as_ref()
            .unwrap()
            .defaults
            .provider
            .as_ref(),
        Some(&"keyring".to_string())
    );
}

#[test]
fn require_reason_always_blocks_access_without_reason() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path().join("secretspec.toml");
    fs::write(
        &project_path,
        r#"
[project]
name = "policy-project"
revision = "1.0"
require_reason = true

[profiles.default]
"#,
    )
    .unwrap();

    // Build hermetically from the parsed project config rather than via
    // `load_from`, which would build a real audit logger and write to the user's
    // real audit log. This still exercises that `require_reason = true` parses to
    // the Always policy and that the gate is enforced.
    let project_config = Config::try_from(project_path.as_path()).unwrap();
    assert_eq!(
        project_config.project.require_reason,
        Some(RequireReason::Always)
    );
    let build = || {
        let mut spec = Secrets::new(project_config.clone(), None, None, None);
        spec.set_require_reason(RequireReason::Always);
        spec
    };

    // require_reason = true -> any caller (agent or not) is refused without a reason.
    assert!(matches!(
        build().validate(),
        Err(SecretSpecError::ReasonRequired)
    ));

    // With an explicit reason the policy is satisfied: validation proceeds past the
    // gate. It may still fail later for environment reasons (e.g. no provider
    // configured), so assert specifically that it is no longer the reason gate.
    assert!(!matches!(
        build().with_reason("running migrations").validate(),
        Err(SecretSpecError::ReasonRequired)
    ));

    // A blank/whitespace-only reason must NOT satisfy the policy: it carries no
    // audit value, so the gate still refuses access.
    assert!(matches!(
        build().with_reason("   ").validate(),
        Err(SecretSpecError::ReasonRequired)
    ));
}

#[test]
fn require_reason_false_allows_access_without_reason() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path().join("secretspec.toml");
    fs::write(
        &project_path,
        r#"
[project]
name = "open-project"
revision = "1.0"
require_reason = false

[profiles.default]
"#,
    )
    .unwrap();

    // Hermetic build (see the sibling test) — no real audit log is touched.
    let project_config = Config::try_from(project_path.as_path()).unwrap();
    assert_eq!(
        project_config.project.require_reason,
        Some(RequireReason::Never)
    );
    let mut spec = Secrets::new(project_config, None, None, None);
    spec.set_require_reason(RequireReason::Never);

    // require_reason = false -> the reason gate never fires, even under an agent.
    // (validate() may still fail later for environment reasons such as no provider
    // configured, so assert specifically that it is not the ReasonRequired gate.)
    assert!(!matches!(
        spec.validate(),
        Err(SecretSpecError::ReasonRequired)
    ));
}

#[test]
fn test_new_with_default_overrides() {
    let config = Config {
        project: Project {
            name: "test-project".to_string(),
            ..Default::default()
        },
        profiles: HashMap::new(),
        providers: None,
    };

    // Create a global config with specific defaults
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("dotenv".to_string()),
            profile: Some("production".to_string()),
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);

    assert_eq!(spec.config().project.name, "test-project");
}

#[test]
fn test_extends_functionality() {
    // Create temporary directory structure for testing
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create directory structure
    fs::create_dir_all(base_path.join("common")).unwrap();
    fs::create_dir_all(base_path.join("auth")).unwrap();
    fs::create_dir_all(base_path.join("base")).unwrap();

    // Create common config
    let common_config = r#"
[project]
name = "common"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "Database connection string", required = true }
REDIS_URL = { description = "Redis connection URL", required = false, default = "redis://localhost:6379" }

[profiles.development]
DATABASE_URL = { description = "Database connection string", required = false, default = "sqlite:///dev.db" }
REDIS_URL = { description = "Redis connection URL", required = false, default = "redis://localhost:6379" }
"#;
    fs::write(base_path.join("common/secretspec.toml"), common_config).unwrap();

    // Create auth config
    let auth_config = r#"
[project]
name = "auth"
revision = "1.0"

[profiles.default]
JWT_SECRET = { description = "Secret key for JWT token signing", required = true }
OAUTH_CLIENT_ID = { description = "OAuth client ID", required = false }
"#;
    fs::write(base_path.join("auth/secretspec.toml"), auth_config).unwrap();

    // Create base config that extends from common and auth
    let base_config = r#"
[project]
name = "test_project"
revision = "1.0"
extends = ["../common", "../auth"]

[profiles.default]
API_KEY = { description = "API key for external service", required = true }
# This should override the common one
DATABASE_URL = { description = "Override database connection", required = true }

[profiles.development]
API_KEY = { description = "API key for external service", required = false, default = "dev-api-key" }
"#;
    fs::write(base_path.join("base/secretspec.toml"), base_config).unwrap();

    // Parse the config
    let config = Config::try_from(base_path.join("base/secretspec.toml").as_path()).unwrap();

    // Verify the config has merged correctly
    assert_eq!(config.project.name, "test_project");
    assert_eq!(config.project.revision, "1.0");
    assert_eq!(
        config.project.extends,
        Some(vec!["../common".to_string(), "../auth".to_string()])
    );

    // Check that all secrets are present
    let default_profile = config.profiles.get("default").unwrap();
    assert!(default_profile.secrets.contains_key("API_KEY"));
    assert!(default_profile.secrets.contains_key("DATABASE_URL"));
    assert!(default_profile.secrets.contains_key("REDIS_URL"));
    assert!(default_profile.secrets.contains_key("JWT_SECRET"));
    assert!(default_profile.secrets.contains_key("OAUTH_CLIENT_ID"));

    // Check that base config takes precedence (DATABASE_URL should be overridden)
    let database_url_config = default_profile.secrets.get("DATABASE_URL").unwrap();
    assert_eq!(
        database_url_config.description,
        Some("Override database connection".to_string())
    );

    // Check that extended secrets are included
    let redis_config = default_profile.secrets.get("REDIS_URL").unwrap();
    assert_eq!(
        redis_config.description,
        Some("Redis connection URL".to_string())
    );
    assert_eq!(redis_config.required, Some(false));
    assert_eq!(
        redis_config.default,
        Some("redis://localhost:6379".to_string())
    );

    let jwt_config = default_profile.secrets.get("JWT_SECRET").unwrap();
    assert_eq!(
        jwt_config.description,
        Some("Secret key for JWT token signing".to_string())
    );
    assert_eq!(jwt_config.required, Some(true));
}

#[test]
fn test_validation_result_structure() {
    // Test ValidatedSecrets structure
    let valid_result = ValidatedSecrets {
        resolved: Resolved::new(HashMap::new(), "keyring".to_string(), "default".to_string()),
        missing_optional: vec!["optional_secret".to_string()],
        with_defaults: Vec::new(),
        resolution: Vec::new(),
        temp_files: Vec::new(),
    };
    assert_eq!(valid_result.missing_optional.len(), 1);
    assert_eq!(valid_result.with_defaults.len(), 0);

    // Test ValidationErrors structure
    let validation_errors = ValidationErrors::new(
        vec!["required_secret".to_string()],
        vec!["optional_secret".to_string()],
        vec![],
        "keyring".to_string(),
        "default".to_string(),
    );
    assert!(validation_errors.has_errors());
    assert_eq!(validation_errors.missing_required.len(), 1);
}

#[test]
fn test_resolution_report_provenance() {
    use crate::report::ResolutionStatus;

    let temp_dir = TempDir::new().unwrap();
    // Only DATABASE_URL is present in the backend; everything else exercises a
    // different resolution arm (default, missing-optional, missing-required).
    let env_path = temp_dir.path().join(".env");
    fs::write(&env_path, "DATABASE_URL=postgres://localhost/db\n").unwrap();

    let secret = |required: bool, default: Option<&str>| Secret {
        description: Some("test".to_string()),
        required: Some(required),
        default: default.map(String::from),
        ..Default::default()
    };

    let mut secrets = HashMap::new();
    secrets.insert("DATABASE_URL".to_string(), secret(true, None));
    secrets.insert("LOG_LEVEL".to_string(), secret(false, Some("info")));
    secrets.insert("SENTRY_DSN".to_string(), secret(false, None));
    secrets.insert("STRIPE_KEY".to_string(), secret(true, None));

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "report-test".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    let provider = format!("dotenv://{}", env_path.display());
    let spec = Secrets::new(config, None, Some(provider), None);

    // A required secret (STRIPE_KEY) is missing, so validation reports an error,
    // but the report still describes every declared secret.
    let report = match spec.validate().unwrap() {
        Ok(validated) => validated.report(),
        Err(errors) => errors.report(),
    };

    assert_eq!(report.schema_version, 1);
    assert_eq!(report.profile, "default");
    assert!(!report.all_required_present());

    // Entries are sorted by name for deterministic output.
    let names: Vec<&str> = report.secrets.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["DATABASE_URL", "LOG_LEVEL", "SENTRY_DSN", "STRIPE_KEY"]
    );

    let by_name = |name: &str| {
        report
            .secrets
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("missing entry {name}"))
    };

    let db = by_name("DATABASE_URL");
    assert_eq!(db.status, ResolutionStatus::Resolved);
    assert!(db.required);
    assert!(db.source_provider.is_some(), "provider hit is attributed");
    assert!(!db.default_applied);
    assert!(!db.generated);

    let log = by_name("LOG_LEVEL");
    assert_eq!(log.status, ResolutionStatus::Resolved);
    assert!(log.default_applied);
    assert!(log.source_provider.is_none(), "a default has no provider");

    let sentry = by_name("SENTRY_DSN");
    assert_eq!(sentry.status, ResolutionStatus::MissingOptional);
    assert!(!sentry.required);

    let stripe = by_name("STRIPE_KEY");
    assert_eq!(stripe.status, ResolutionStatus::MissingRequired);
    assert!(stripe.required);
}

fn resolve_test_config(secrets: HashMap<String, Secret>) -> Config {
    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );
    Config {
        project: Project {
            name: "resolve-test".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    }
}

#[test]
fn test_resolve_carries_values_and_provenance() {
    use crate::resolve::ResolvedSource;

    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env");
    fs::write(&env_path, "DATABASE_URL=postgres://localhost/db\n").unwrap();

    let secret = |required: bool, default: Option<&str>| Secret {
        description: Some("test".to_string()),
        required: Some(required),
        default: default.map(String::from),
        ..Default::default()
    };

    let mut secrets = HashMap::new();
    secrets.insert("DATABASE_URL".to_string(), secret(true, None));
    secrets.insert("LOG_LEVEL".to_string(), secret(false, Some("info")));
    secrets.insert("SENTRY_DSN".to_string(), secret(false, None));

    let provider = format!("dotenv://{}", env_path.display());
    let spec = Secrets::new(resolve_test_config(secrets), None, Some(provider), None);

    let response = spec.resolve().unwrap();
    assert_eq!(response.schema_version, 1);
    assert_eq!(response.profile, "default");
    assert!(response.is_ok());
    assert_eq!(response.missing_optional, vec!["SENTRY_DSN".to_string()]);

    // Provider value is exposed with provenance.
    let db = &response.secrets["DATABASE_URL"];
    assert_eq!(db.value.as_deref(), Some("postgres://localhost/db"));
    assert!(db.path.is_none());
    assert!(!db.as_path);
    assert_eq!(db.source, ResolvedSource::Provider);
    assert!(db.source_provider.is_some());

    // Default value is exposed and attributed to the default source.
    let log = &response.secrets["LOG_LEVEL"];
    assert_eq!(log.value.as_deref(), Some("info"));
    assert_eq!(log.source, ResolvedSource::Default);
    assert!(log.source_provider.is_none());

    // Optional-missing does not appear in secrets.
    assert!(!response.secrets.contains_key("SENTRY_DSN"));

    // without_values strips values but keeps structure.
    let stripped = response.without_values();
    assert!(stripped.secrets["DATABASE_URL"].value.is_none());
    assert_eq!(
        stripped.secrets["DATABASE_URL"].source,
        ResolvedSource::Provider
    );
}

#[test]
fn test_resolve_missing_required_is_empty_with_error_list() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env");
    fs::write(&env_path, "").unwrap();

    let mut secrets = HashMap::new();
    secrets.insert(
        "STRIPE_KEY".to_string(),
        Secret {
            description: Some("stripe".to_string()),
            required: Some(true),
            ..Default::default()
        },
    );

    let provider = format!("dotenv://{}", env_path.display());
    let spec = Secrets::new(resolve_test_config(secrets), None, Some(provider), None);

    let response = spec.resolve().unwrap();
    assert!(!response.is_ok());
    assert_eq!(response.missing_required, vec!["STRIPE_KEY".to_string()]);
    // A failed resolution returns no values, mirroring the derive crate's load().
    assert!(response.secrets.is_empty());
}

#[test]
fn test_resolve_as_path_returns_persisted_path() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env");
    fs::write(&env_path, "TLS_CERT=----cert-bytes----\n").unwrap();

    let mut secrets = HashMap::new();
    secrets.insert(
        "TLS_CERT".to_string(),
        Secret {
            description: Some("cert".to_string()),
            required: Some(true),
            as_path: Some(true),
            ..Default::default()
        },
    );

    let provider = format!("dotenv://{}", env_path.display());
    let spec = Secrets::new(resolve_test_config(secrets), None, Some(provider), None);

    let response = spec.resolve().unwrap();
    let cert = &response.secrets["TLS_CERT"];
    assert!(cert.as_path);
    assert!(cert.value.is_none());
    let path = cert.path.as_deref().expect("as_path yields a path");
    // The temp file is persisted, so the path is readable after resolve returns.
    let contents = fs::read_to_string(path).unwrap();
    assert_eq!(contents, "----cert-bytes----");
    fs::remove_file(path).ok();
}

#[test]
fn test_secretspec_new() {
    let config = Config {
        project: Project {
            name: "test".to_string(),
            ..Default::default()
        },
        profiles: HashMap::new(),
        providers: None,
    };

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: Some("dev".to_string()),
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config.clone(), Some(global_config.clone()), None, None);
    assert_eq!(spec.config().project.name, "test");
    assert!(spec.global_config().is_some());
    assert_eq!(
        spec.global_config().as_ref().unwrap().defaults.provider,
        Some("keyring".to_string())
    );

    let spec_without_global = Secrets::new(config, None, None, None);
    assert!(spec_without_global.global_config().is_none());
}

#[test]
fn test_resolve_profile() {
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: Some("development".to_string()),
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles: HashMap::new(),
            providers: None,
        },
        Some(global_config),
        None,
        None,
    );

    // Test with explicit profile
    assert_eq!(spec.resolve_profile_name(Some("production")), "production");

    // Test with global config default
    assert_eq!(spec.resolve_profile_name(None), "development");

    // Test without global config
    let spec_no_global = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles: HashMap::new(),
            providers: None,
        },
        None,
        None,
        None,
    );
    assert_eq!(spec_no_global.resolve_profile_name(None), "default");
}

#[test]
fn test_resolve_secret_config() {
    let mut default_secrets = HashMap::new();
    default_secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key".to_string()),
            required: Some(true),
            default: None,
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );
    default_secrets.insert(
        "DATABASE_URL".to_string(),
        Secret {
            description: Some("Database URL".to_string()),
            required: Some(false),
            default: Some("sqlite:///default.db".to_string()),
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    let mut dev_secrets = HashMap::new();
    dev_secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("Dev API Key".to_string()),
            required: Some(false),
            default: Some("dev-key".to_string()),
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets: default_secrets,
        },
    );
    profiles.insert(
        "development".to_string(),
        Profile {
            defaults: None,
            secrets: dev_secrets,
        },
    );

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles,
            providers: None,
        },
        None,
        None,
        None,
    );

    // Test profile-specific secret
    let secret_config = spec
        .resolve_secret_config("API_KEY", Some("development"))
        .unwrap();
    assert_eq!(secret_config.required, Some(false));
    assert_eq!(secret_config.default, Some("dev-key".to_string()));

    // Test fallback to default profile
    let secret_config = spec
        .resolve_secret_config("DATABASE_URL", Some("development"))
        .unwrap();
    assert_eq!(secret_config.required, Some(false));
    assert_eq!(
        secret_config.default,
        Some("sqlite:///default.db".to_string())
    );

    // Test nonexistent secret
    assert!(
        spec.resolve_secret_config("NONEXISTENT", Some("development"))
            .is_none()
    );
}

#[test]
fn test_get_provider_error_cases() {
    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles: HashMap::new(),
            providers: None,
        },
        None,
        None,
        None,
    );

    // Test with no provider configured
    let result = spec.get_provider(None);
    assert!(matches!(result, Err(SecretSpecError::NoProviderConfigured)));
}

#[test]
fn test_get_provider_with_global_config() {
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles: HashMap::new(),
            providers: None,
        },
        Some(global_config),
        None,
        None,
    );

    // Should not error with global config
    let result = spec.get_provider(None);
    assert!(result.is_ok());
}

#[test]
fn test_project_config_from_path_error_handling() {
    let temp_dir = TempDir::new().unwrap();
    let invalid_toml = temp_dir.path().join("invalid.toml");
    fs::write(&invalid_toml, "[invalid toml content").unwrap();

    let result = Config::try_from(invalid_toml.as_path()).map_err(Into::<SecretSpecError>::into);
    assert!(matches!(result, Err(SecretSpecError::Toml(_))));

    // Test nonexistent file
    let nonexistent = temp_dir.path().join("nonexistent.toml");
    let result = Config::try_from(nonexistent.as_path()).map_err(Into::<SecretSpecError>::into);
    assert!(matches!(result, Err(SecretSpecError::NoManifest)));
}

#[test]
fn test_parse_spec_from_str() {
    let valid_toml = r#"
[project]
name = "test"
revision = "1.0"

[profiles.default]
API_KEY = { description = "API Key", required = true }
"#;

    let result = parse_spec_from_str(valid_toml, None);
    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.project.name, "test");

    // Test invalid TOML
    let invalid_toml = "[invalid";
    let result = parse_spec_from_str(invalid_toml, None);
    assert!(matches!(result, Err(SecretSpecError::Toml(_))));
}

#[test]
fn test_extends_with_real_world_example() {
    // Test a real-world scenario with multiple extends and profile overrides
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create directory structure
    fs::create_dir_all(base_path.join("common")).unwrap();
    fs::create_dir_all(base_path.join("auth")).unwrap();
    fs::create_dir_all(base_path.join("base")).unwrap();

    // Create common config with database and cache settings
    let common_config = r#"
[project]
name = "common"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "Main database connection string", required = true }
REDIS_URL = { description = "Redis cache connection", required = false, default = "redis://localhost:6379" }

[profiles.development]
DATABASE_URL = { description = "Development database", required = false, default = "sqlite:///dev.db" }
REDIS_URL = { description = "Redis cache connection", required = false, default = "redis://localhost:6379" }

[profiles.production]
DATABASE_URL = { description = "Production database", required = true }
REDIS_URL = { description = "Redis cache connection", required = true }
"#;
    fs::write(base_path.join("common/secretspec.toml"), common_config).unwrap();

    // Create auth config with authentication settings
    let auth_config = r#"
[project]
name = "auth"
revision = "1.0"

[profiles.default]
JWT_SECRET = { description = "Secret for JWT signing", required = true }
OAUTH_CLIENT_ID = { description = "OAuth client identifier", required = false }
OAUTH_CLIENT_SECRET = { description = "OAuth client secret", required = false }

[profiles.production]
JWT_SECRET = { description = "Secret for JWT signing", required = true }
OAUTH_CLIENT_ID = { description = "OAuth client identifier", required = true }
OAUTH_CLIENT_SECRET = { description = "OAuth client secret", required = true }
"#;
    fs::write(base_path.join("auth/secretspec.toml"), auth_config).unwrap();

    // Create base config that extends from both common and auth
    let base_config = r#"
[project]
name = "my_app"
revision = "1.0"
extends = ["../common", "../auth"]

[profiles.default]
API_KEY = { description = "External API key", required = true }
# Override the database description from common
DATABASE_URL = { description = "Custom database for my app", required = true }

[profiles.development]
API_KEY = { description = "External API key", required = false, default = "dev-key-123" }

[profiles.production]
API_KEY = { description = "External API key", required = true }
MONITORING_TOKEN = { description = "Token for monitoring service", required = true }
"#;
    fs::write(base_path.join("base/secretspec.toml"), base_config).unwrap();

    // Parse the config
    let config = Config::try_from(base_path.join("base/secretspec.toml").as_path()).unwrap();

    // Verify project info
    assert_eq!(config.project.name, "my_app");
    assert_eq!(config.project.revision, "1.0");
    assert_eq!(
        config.project.extends,
        Some(vec!["../common".to_string(), "../auth".to_string()])
    );

    // Verify default profile has all merged secrets
    let default_profile = config.profiles.get("default").unwrap();
    assert_eq!(default_profile.secrets.len(), 6); // API_KEY, DATABASE_URL, REDIS_URL, JWT_SECRET, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET

    // Verify base config overrides common config
    let database_url = default_profile.secrets.get("DATABASE_URL").unwrap();
    assert_eq!(
        database_url.description,
        Some("Custom database for my app".to_string())
    );
    assert_eq!(database_url.required, Some(true));

    // Verify inherited secrets from common
    let redis_url = default_profile.secrets.get("REDIS_URL").unwrap();
    assert_eq!(
        redis_url.description,
        Some("Redis cache connection".to_string())
    );
    assert_eq!(redis_url.required, Some(false));
    assert_eq!(
        redis_url.default,
        Some("redis://localhost:6379".to_string())
    );

    // Verify inherited secrets from auth
    let jwt_secret = default_profile.secrets.get("JWT_SECRET").unwrap();
    assert_eq!(
        jwt_secret.description,
        Some("Secret for JWT signing".to_string())
    );
    assert_eq!(jwt_secret.required, Some(true));

    // Verify development profile
    let dev_profile = config.profiles.get("development").unwrap();
    let dev_api_key = dev_profile.secrets.get("API_KEY").unwrap();
    assert_eq!(dev_api_key.required, Some(false));
    assert_eq!(dev_api_key.default, Some("dev-key-123".to_string()));

    let dev_database_url = dev_profile.secrets.get("DATABASE_URL").unwrap();
    assert_eq!(
        dev_database_url.description,
        Some("Development database".to_string())
    );
    assert_eq!(dev_database_url.required, Some(false));
    assert_eq!(
        dev_database_url.default,
        Some("sqlite:///dev.db".to_string())
    );

    // Verify production profile has all required secrets
    let prod_profile = config.profiles.get("production").unwrap();
    assert_eq!(
        prod_profile.secrets.get("API_KEY").unwrap().required,
        Some(true)
    );
    assert_eq!(
        prod_profile.secrets.get("DATABASE_URL").unwrap().required,
        Some(true)
    );
    assert_eq!(
        prod_profile.secrets.get("REDIS_URL").unwrap().required,
        Some(true)
    );
    assert_eq!(
        prod_profile.secrets.get("JWT_SECRET").unwrap().required,
        Some(true)
    );
    assert_eq!(
        prod_profile
            .secrets
            .get("OAUTH_CLIENT_ID")
            .unwrap()
            .required,
        Some(true)
    );
    assert_eq!(
        prod_profile
            .secrets
            .get("OAUTH_CLIENT_SECRET")
            .unwrap()
            .required,
        Some(true)
    );
    assert_eq!(
        prod_profile
            .secrets
            .get("MONITORING_TOKEN")
            .unwrap()
            .required,
        Some(true)
    );
}

#[test]
fn test_extends_with_direct_circular_dependency() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create directory structure
    fs::create_dir_all(base_path.join("a")).unwrap();
    fs::create_dir_all(base_path.join("b")).unwrap();

    // Create config A that extends B
    let config_a = r#"
[project]
name = "config_a"
revision = "1.0"
extends = ["../b"]

[profiles.default]
SECRET_A = { description = "Secret A", required = true }
"#;
    fs::write(base_path.join("a/secretspec.toml"), config_a).unwrap();

    // Create config B that extends A (circular dependency)
    let config_b = r#"
[project]
name = "config_b"
revision = "1.0"
extends = ["../a"]

[profiles.default]
SECRET_B = { description = "Secret B", required = true }
"#;
    fs::write(base_path.join("b/secretspec.toml"), config_b).unwrap();

    // Parse should fail with circular dependency error
    let result = Config::try_from(base_path.join("a/secretspec.toml").as_path());
    assert!(result.is_err());
    match result {
        Err(ParseError::CircularDependency(msg)) => {
            assert!(msg.contains("circular dependency"));
        }
        _ => panic!("Expected CircularDependency error"),
    }
}

#[test]
fn test_extends_with_indirect_circular_dependency() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create directory structure
    fs::create_dir_all(base_path.join("a")).unwrap();
    fs::create_dir_all(base_path.join("b")).unwrap();
    fs::create_dir_all(base_path.join("c")).unwrap();

    // Create config A that extends B
    let config_a = r#"
[project]
name = "config_a"
revision = "1.0"
extends = ["../b"]

[profiles.default]
SECRET_A = { description = "Secret A", required = true }
"#;
    fs::write(base_path.join("a/secretspec.toml"), config_a).unwrap();

    // Create config B that extends C
    let config_b = r#"
[project]
name = "config_b"
revision = "1.0"
extends = ["../c"]

[profiles.default]
SECRET_B = { description = "Secret B", required = true }
"#;
    fs::write(base_path.join("b/secretspec.toml"), config_b).unwrap();

    // Create config C that extends A (circular dependency through chain)
    let config_c = r#"
[project]
name = "config_c"
revision = "1.0"
extends = ["../a"]

[profiles.default]
SECRET_C = { description = "Secret C", required = true }
"#;
    fs::write(base_path.join("c/secretspec.toml"), config_c).unwrap();

    // Parse should fail with circular dependency error
    let result = Config::try_from(base_path.join("a/secretspec.toml").as_path());
    assert!(result.is_err());
    match result {
        Err(ParseError::CircularDependency(msg)) => {
            assert!(msg.contains("circular dependency"));
        }
        _ => panic!("Expected CircularDependency error"),
    }
}

#[test]
fn test_nested_extends() {
    // Test A extends B, B extends C scenario
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create directory structure
    fs::create_dir_all(base_path.join("a")).unwrap();
    fs::create_dir_all(base_path.join("b")).unwrap();
    fs::create_dir_all(base_path.join("c")).unwrap();

    // Create config C (base config)
    let config_c = r#"
[project]
name = "config_c"
revision = "1.0"

[profiles.default]
SECRET_C = { description = "Secret C from base", required = true }
COMMON_SECRET = { description = "Common secret from C", required = true }

[profiles.production]
SECRET_C = { description = "Secret C for production", required = true }
"#;
    fs::write(base_path.join("c/secretspec.toml"), config_c).unwrap();

    // Create config B that extends C
    let config_b = r#"
[project]
name = "config_b"
revision = "1.0"
extends = ["../c"]

[profiles.default]
SECRET_B = { description = "Secret B", required = true }
COMMON_SECRET = { description = "Common secret overridden by B", required = false, default = "default-b" }

[profiles.staging]
SECRET_B = { description = "Secret B for staging", required = true }
"#;
    fs::write(base_path.join("b/secretspec.toml"), config_b).unwrap();

    // Create config A that extends B (which extends C)
    let config_a = r#"
[project]
name = "config_a"
revision = "1.0"
extends = ["../b"]

[profiles.default]
SECRET_A = { description = "Secret A", required = true }

[profiles.staging]
SECRET_A = { description = "Secret A for staging", required = false, default = "staging-a" }
"#;
    fs::write(base_path.join("a/secretspec.toml"), config_a).unwrap();

    // Parse config A
    let config = Config::try_from(base_path.join("a/secretspec.toml").as_path()).unwrap();

    // Verify project info
    assert_eq!(config.project.name, "config_a");

    // Verify default profile has all secrets from A, B, and C
    let default_profile = config.profiles.get("default").unwrap();
    assert_eq!(default_profile.secrets.len(), 4); // SECRET_A, SECRET_B, SECRET_C, COMMON_SECRET

    // Verify secrets are inherited correctly
    assert!(default_profile.secrets.contains_key("SECRET_A"));
    assert!(default_profile.secrets.contains_key("SECRET_B"));
    assert!(default_profile.secrets.contains_key("SECRET_C"));
    assert!(default_profile.secrets.contains_key("COMMON_SECRET"));

    // Verify B's override of COMMON_SECRET takes precedence over C's
    let common_secret = default_profile.secrets.get("COMMON_SECRET").unwrap();
    assert_eq!(
        common_secret.description,
        Some("Common secret overridden by B".to_string())
    );
    assert_eq!(common_secret.required, Some(false));
    assert_eq!(common_secret.default, Some("default-b".to_string()));

    // Verify staging profile exists from both A and B
    let staging_profile = config.profiles.get("staging").unwrap();
    assert!(staging_profile.secrets.contains_key("SECRET_A"));
    assert!(staging_profile.secrets.contains_key("SECRET_B"));

    // Verify production profile exists only from C
    let prod_profile = config.profiles.get("production").unwrap();
    assert!(prod_profile.secrets.contains_key("SECRET_C"));
    assert!(!prod_profile.secrets.contains_key("SECRET_A")); // A doesn't define production
    assert!(!prod_profile.secrets.contains_key("SECRET_B")); // B doesn't define production
}

#[test]
fn test_extends_with_path_resolution_edge_cases() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create complex directory structure
    fs::create_dir_all(base_path.join("project/src")).unwrap();
    fs::create_dir_all(base_path.join("shared/common")).unwrap();
    fs::create_dir_all(base_path.join("shared/auth")).unwrap();

    // Create common config
    let common_config = r#"
[project]
name = "common"
revision = "1.0"

[profiles.default]
COMMON_SECRET = { description = "Common secret", required = true }
"#;
    fs::write(
        base_path.join("shared/common/secretspec.toml"),
        common_config,
    )
    .unwrap();

    // Create auth config
    let auth_config = r#"
[project]
name = "auth"
revision = "1.0"

[profiles.default]
AUTH_SECRET = { description = "Auth secret", required = true }
"#;
    fs::write(base_path.join("shared/auth/secretspec.toml"), auth_config).unwrap();

    // Test 1: Relative path with ../..
    let config_relative = r#"
[project]
name = "project"
revision = "1.0"
extends = ["../../shared/common", "../../shared/auth"]

[profiles.default]
PROJECT_SECRET = { description = "Project secret", required = true }
"#;
    fs::write(
        base_path.join("project/src/secretspec.toml"),
        config_relative,
    )
    .unwrap();

    let config = Config::try_from(base_path.join("project/src/secretspec.toml").as_path()).unwrap();
    let default_profile = config.profiles.get("default").unwrap();
    assert_eq!(default_profile.secrets.len(), 3);
    assert!(default_profile.secrets.contains_key("COMMON_SECRET"));
    assert!(default_profile.secrets.contains_key("AUTH_SECRET"));
    assert!(default_profile.secrets.contains_key("PROJECT_SECRET"));

    // Test 2: Path with ./ prefix
    let config_dot_slash = r#"
[project]
name = "project2"
revision = "1.0"
extends = ["./../../shared/common"]

[profiles.default]
PROJECT2_SECRET = { description = "Project2 secret", required = true }
"#;
    fs::write(
        base_path.join("project/src/secretspec2.toml"),
        config_dot_slash,
    )
    .unwrap();

    let config2 =
        Config::try_from(base_path.join("project/src/secretspec2.toml").as_path()).unwrap();
    let default_profile2 = config2.profiles.get("default").unwrap();
    assert_eq!(default_profile2.secrets.len(), 2);
    assert!(default_profile2.secrets.contains_key("COMMON_SECRET"));
    assert!(default_profile2.secrets.contains_key("PROJECT2_SECRET"));

    // Test 3: Path with spaces (if supported by the OS)
    let dir_with_spaces = base_path.join("dir with spaces");
    if fs::create_dir_all(&dir_with_spaces).is_ok() {
        let config_spaces = r#"
[project]
name = "spaces"
revision = "1.0"

[profiles.default]
SPACE_SECRET = { description = "Secret in dir with spaces", required = true }
"#;
        fs::write(dir_with_spaces.join("secretspec.toml"), config_spaces).unwrap();

        let config_extends_spaces = r#"
[project]
name = "project3"
revision = "1.0"
extends = ["../dir with spaces"]

[profiles.default]
PROJECT3_SECRET = { description = "Project3 secret", required = true }
"#;
        fs::write(
            base_path.join("project/secretspec3.toml"),
            config_extends_spaces,
        )
        .unwrap();

        let config3 =
            Config::try_from(base_path.join("project/secretspec3.toml").as_path()).unwrap();
        let default_profile3 = config3.profiles.get("default").unwrap();
        assert_eq!(default_profile3.secrets.len(), 2);
        assert!(default_profile3.secrets.contains_key("SPACE_SECRET"));
        assert!(default_profile3.secrets.contains_key("PROJECT3_SECRET"));
    }
}

#[test]
fn test_empty_extends_array() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create config with empty extends array
    let config_empty_extends = r#"
[project]
name = "project"
revision = "1.0"
extends = []

[profiles.default]
SECRET_A = { description = "Secret A", required = true }

[profiles.production]
SECRET_B = { description = "Secret B", required = false, default = "prod-b" }
"#;
    fs::write(base_path.join("secretspec.toml"), config_empty_extends).unwrap();

    // Parse should succeed with empty extends
    let config = Config::try_from(base_path.join("secretspec.toml").as_path()).unwrap();

    // Verify config is parsed correctly
    assert_eq!(config.project.name, "project");
    assert_eq!(config.project.extends, Some(vec![]));

    // Verify profiles and secrets are intact
    let default_profile = config.profiles.get("default").unwrap();
    assert_eq!(default_profile.secrets.len(), 1);
    assert!(default_profile.secrets.contains_key("SECRET_A"));

    let prod_profile = config.profiles.get("production").unwrap();
    assert_eq!(prod_profile.secrets.len(), 1);
    assert!(prod_profile.secrets.contains_key("SECRET_B"));
}

#[test]
fn test_extends_with_file_path() {
    // Test that extends works with full file paths (ending in .toml)
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create shared directory with a custom-named config file
    fs::create_dir_all(base_path.join("shared")).unwrap();
    fs::create_dir_all(base_path.join("backend")).unwrap();

    // Create shared config with a custom filename
    let shared_config = r#"
[project]
name = "shared"
revision = "1.0"

[profiles.default]
SHARED_SECRET = { description = "A shared secret", required = true }
"#;
    fs::write(base_path.join("shared/secretspec.toml"), shared_config).unwrap();

    // Create backend config that extends using full file path
    let backend_config = r#"
[project]
name = "backend"
revision = "1.0"
extends = ["../shared/secretspec.toml"]

[profiles.default]
BACKEND_SECRET = { description = "Backend specific secret", required = true }
"#;
    fs::write(base_path.join("backend/secretspec.toml"), backend_config).unwrap();

    // Parse should succeed with file path extends
    let config = Config::try_from(base_path.join("backend/secretspec.toml").as_path()).unwrap();

    // Verify config merged correctly
    assert_eq!(config.project.name, "backend");
    assert_eq!(
        config.project.extends,
        Some(vec!["../shared/secretspec.toml".to_string()])
    );

    // Verify secrets from both configs are present
    let default_profile = config.profiles.get("default").unwrap();
    assert!(default_profile.secrets.contains_key("BACKEND_SECRET"));
    assert!(default_profile.secrets.contains_key("SHARED_SECRET"));
}

#[test]
fn test_self_extension() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Test 1: Config that tries to extend itself with "."
    let config_self_dot = r#"
[project]
name = "self_extend"
revision = "1.0"
extends = ["."]

[profiles.default]
SECRET_A = { description = "Secret A", required = true }
"#;
    fs::write(base_path.join("secretspec.toml"), config_self_dot).unwrap();

    // This should fail with circular dependency
    let result = Config::try_from(base_path.join("secretspec.toml").as_path());
    assert!(result.is_err());
    match result {
        Err(ParseError::CircularDependency(msg)) => {
            assert!(msg.contains("circular dependency"));
        }
        _ => panic!("Expected CircularDependency error for self-extension"),
    }

    // Test 2: Config in subdirectory that tries to extend its parent which extends it back
    fs::create_dir_all(base_path.join("subdir")).unwrap();

    let parent_config = r#"
[project]
name = "parent"
revision = "1.0"
extends = ["./subdir"]

[profiles.default]
PARENT_SECRET = { description = "Parent secret", required = true }
"#;
    fs::write(base_path.join("secretspec.toml"), parent_config).unwrap();

    let child_config = r#"
[project]
name = "child"
revision = "1.0"
extends = [".."]

[profiles.default]
CHILD_SECRET = { description = "Child secret", required = true }
"#;
    fs::write(base_path.join("subdir/secretspec.toml"), child_config).unwrap();

    // This should also fail with circular dependency
    let result2 = Config::try_from(base_path.join("secretspec.toml").as_path());
    assert!(result2.is_err());
    match result2 {
        Err(ParseError::CircularDependency(msg)) => {
            assert!(msg.contains("circular dependency"));
        }
        _ => panic!("Expected CircularDependency error for parent-child circular reference"),
    }
}

#[test]
fn test_property_overrides() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create directory structure
    fs::create_dir_all(base_path.join("base")).unwrap();
    fs::create_dir_all(base_path.join("override")).unwrap();

    // Create base config with various secret properties
    let base_config = r#"
[project]
name = "base"
revision = "1.0"

[profiles.default]
SECRET_A = { description = "Original description A", required = true }
SECRET_B = { description = "Original description B", required = true, default = "original-b" }
SECRET_C = { description = "Original description C", required = false }
SECRET_D = { description = "Original description D", required = false, default = "original-d" }
"#;
    fs::write(base_path.join("base/secretspec.toml"), base_config).unwrap();

    // Create override config that selectively overrides properties
    let override_config = r#"
[project]
name = "override"
revision = "1.0"
extends = ["../base"]

[profiles.default]
# Override just description
SECRET_A = { description = "New description A", required = true }
# Override just required flag
SECRET_B = { description = "Original description B", required = false, default = "original-b" }
# Override just default value
SECRET_C = { description = "Original description C", required = false, default = "new-c" }
# Override multiple properties
SECRET_D = { description = "New description D", required = true }
# Add new secret
SECRET_E = { description = "New secret E", required = true }
"#;
    fs::write(base_path.join("override/secretspec.toml"), override_config).unwrap();

    // Parse the override config
    let config = Config::try_from(base_path.join("override/secretspec.toml").as_path()).unwrap();
    let default_profile = config.profiles.get("default").unwrap();

    // Verify SECRET_A: only description changed
    let secret_a = default_profile.secrets.get("SECRET_A").unwrap();
    assert_eq!(secret_a.description, Some("New description A".to_string()));
    assert_eq!(secret_a.required, Some(true));
    assert_eq!(secret_a.default, None);

    // Verify SECRET_B: only required flag changed
    let secret_b = default_profile.secrets.get("SECRET_B").unwrap();
    assert_eq!(
        secret_b.description,
        Some("Original description B".to_string())
    );
    assert_eq!(secret_b.required, Some(false)); // Changed from true to false
    assert_eq!(secret_b.default, Some("original-b".to_string()));

    // Verify SECRET_C: only default value added
    let secret_c = default_profile.secrets.get("SECRET_C").unwrap();
    assert_eq!(
        secret_c.description,
        Some("Original description C".to_string())
    );
    assert_eq!(secret_c.required, Some(false));
    assert_eq!(secret_c.default, Some("new-c".to_string()));

    // Verify SECRET_D: multiple properties changed
    let secret_d = default_profile.secrets.get("SECRET_D").unwrap();
    assert_eq!(secret_d.description, Some("New description D".to_string()));
    assert_eq!(secret_d.required, Some(true)); // Changed from false to true
    assert_eq!(secret_d.default, None); // Removed default

    // Verify SECRET_E: new secret added
    let secret_e = default_profile.secrets.get("SECRET_E").unwrap();
    assert_eq!(secret_e.description, Some("New secret E".to_string()));
    assert_eq!(secret_e.required, Some(true));
    assert_eq!(secret_e.default, None);
}

#[test]
fn test_extends_with_missing_file() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create base config with non-existent extend path
    let base_config = r#"
[project]
name = "test_project"
revision = "1.0"
extends = ["../nonexistent"]

[profiles.default]
API_KEY = { description = "API key for external service", required = true }
"#;
    fs::write(base_path.join("secretspec.toml"), base_config).unwrap();

    // Parse should fail with missing file error
    let result = Config::try_from(base_path.join("secretspec.toml").as_path());
    assert!(result.is_err());
    match result {
        Err(ParseError::ExtendedConfigNotFound(path)) => {
            assert!(path.contains("nonexistent"));
        }
        _ => panic!("Expected ExtendedConfigNotFound error for missing file"),
    }
}

#[test]
fn test_extends_with_invalid_inputs() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Test 1: Extend to a file instead of directory
    let some_file = base_path.join("notadir.txt");
    fs::write(&some_file, "not a directory").unwrap();

    let config_extend_file = r#"
[project]
name = "test"
revision = "1.0"
extends = ["./notadir.txt"]

[profiles.default]
SECRET_A = { description = "Secret A", required = true }
"#;
    fs::write(base_path.join("secretspec.toml"), config_extend_file).unwrap();

    let result = Config::try_from(base_path.join("secretspec.toml").as_path());
    assert!(result.is_err());
    match result {
        Err(ParseError::ExtendedConfigNotFound(path)) => {
            assert!(path.contains("notadir.txt"));
        }
        _ => panic!("Expected ExtendedConfigNotFound error for extending to file"),
    }

    // Test 2: Extend with empty string
    let config_empty_string = r#"
[project]
name = "test2"
revision = "1.0"
extends = [""]

[profiles.default]
SECRET_B = { description = "Secret B", required = true }
"#;
    fs::write(base_path.join("secretspec2.toml"), config_empty_string).unwrap();

    let result2 = Config::try_from(base_path.join("secretspec2.toml").as_path());
    assert!(result2.is_err());

    // Test 3: Extend to non-existent directory
    let config_no_dir = r#"
[project]
name = "test3"
revision = "1.0"
extends = ["./does_not_exist"]

[profiles.default]
SECRET_C = { description = "Secret C", required = true }
"#;
    fs::write(base_path.join("secretspec3.toml"), config_no_dir).unwrap();

    let result3 = Config::try_from(base_path.join("secretspec3.toml").as_path());
    assert!(result3.is_err());
    match result3 {
        Err(ParseError::ExtendedConfigNotFound(path)) => {
            assert!(path.contains("does_not_exist"));
        }
        _ => panic!("Expected ExtendedConfigNotFound error for non-existent directory"),
    }
}

#[test]
fn test_extends_with_different_revisions() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create directory
    fs::create_dir_all(base_path.join("old")).unwrap();

    // Create config with unsupported revision
    let old_config = r#"
[project]
name = "old"
revision = "0.9"

[profiles.default]
OLD_SECRET = { description = "Old secret", required = true }
"#;
    fs::write(base_path.join("old/secretspec.toml"), old_config).unwrap();

    // Create config that tries to extend the old revision
    let new_config = r#"
[project]
name = "new"
revision = "1.0"
extends = ["./old"]

[profiles.default]
NEW_SECRET = { description = "New secret", required = true }
"#;
    fs::write(base_path.join("secretspec.toml"), new_config).unwrap();

    // This should fail with unsupported revision error
    let result = Config::try_from(base_path.join("secretspec.toml").as_path());
    assert!(result.is_err());
    match result {
        Err(ParseError::UnsupportedRevision(rev)) => {
            assert_eq!(rev, "0.9");
        }
        _ => panic!("Expected UnsupportedRevision error"),
    }
}

#[test]
fn test_set_with_undefined_secret() {
    let project_config = Config {
        project: Project {
            name: "test_project".to_string(),
            ..Default::default()
        },
        profiles: {
            let mut profiles = HashMap::new();
            let mut secrets = HashMap::new();
            secrets.insert(
                "DEFINED_SECRET".to_string(),
                Secret {
                    description: Some("A defined secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            profiles.insert(
                "default".to_string(),
                Profile {
                    defaults: None,
                    secrets,
                },
            );
            profiles
        },
        providers: None,
    };

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("env".to_string()),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(project_config, Some(global_config), None, None);

    // Test setting an undefined secret - env provider is read-only,
    // but we should get the SecretNotFound error before the provider error
    let result = spec.set("UNDEFINED_SECRET", Some("test_value".to_string()));

    assert!(result.is_err());
    match result {
        Err(SecretSpecError::SecretNotFound(msg)) => {
            assert!(msg.contains("UNDEFINED_SECRET"));
            assert!(msg.contains("not defined in profile"));
            assert!(msg.contains("DEFINED_SECRET"));
        }
        _ => panic!("Expected SecretNotFound error"),
    }
}

#[test]
fn test_set_with_defined_secret() {
    use std::env;
    use tempfile::TempDir;

    // Serialize against other current-directory-mutating tests (the current
    // directory is process-global and shared across test threads).
    let _cwd = crate::secrets::lock_cwd();

    // Create a temporary directory for dotenv file
    let temp_dir = TempDir::new().unwrap();
    let original_dir = env::current_dir().unwrap();
    env::set_current_dir(&temp_dir).unwrap();

    let project_config = Config {
        project: Project {
            name: "test_project".to_string(),
            ..Default::default()
        },
        profiles: {
            let mut profiles = HashMap::new();
            let mut secrets = HashMap::new();
            secrets.insert(
                "DEFINED_SECRET".to_string(),
                Secret {
                    description: Some("A defined secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            profiles.insert(
                "default".to_string(),
                Profile {
                    defaults: None,
                    secrets,
                },
            );
            profiles
        },
        providers: None,
    };

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("dotenv".to_string()),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(project_config, Some(global_config), None, None);

    // This should succeed with dotenv provider
    let result = spec.set("DEFINED_SECRET", Some("test_value".to_string()));

    // Restore original directory
    env::set_current_dir(original_dir).unwrap();

    // The set operation should succeed for a defined secret
    assert!(result.is_ok(), "Setting a defined secret should succeed");
}

#[test]
fn test_set_with_readonly_provider() {
    let project_config = Config {
        project: Project {
            name: "test_project".to_string(),
            ..Default::default()
        },
        profiles: {
            let mut profiles = HashMap::new();
            let mut secrets = HashMap::new();
            secrets.insert(
                "DEFINED_SECRET".to_string(),
                Secret {
                    description: Some("A defined secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            profiles.insert(
                "default".to_string(),
                Profile {
                    defaults: None,
                    secrets,
                },
            );
            profiles
        },
        providers: None,
    };

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("env".to_string()),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(project_config, Some(global_config), None, None);

    // Test setting a defined secret with env provider (which is read-only)
    let result = spec.set("DEFINED_SECRET", Some("test_value".to_string()));

    assert!(result.is_err());
    match result {
        Err(SecretSpecError::ProviderOperationFailed(msg)) => {
            assert!(msg.contains("read-only"));
        }
        _ => panic!("Expected ProviderOperationFailed error for read-only provider"),
    }
}

#[test]
fn test_import_between_dotenv_files() {
    // Create temporary directory for testing
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    // Create project config
    let project_config = Config {
        project: Project {
            name: "test_import_project".to_string(),
            ..Default::default()
        },
        profiles: {
            let mut profiles = HashMap::new();
            let mut secrets = HashMap::new();

            // Add test secrets
            secrets.insert(
                "SECRET_ONE".to_string(),
                Secret {
                    description: Some("First test secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            secrets.insert(
                "SECRET_TWO".to_string(),
                Secret {
                    description: Some("Second test secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            secrets.insert(
                "SECRET_THREE".to_string(),
                Secret {
                    description: Some("Third test secret".to_string()),
                    required: Some(false),
                    default: Some("default_value".to_string()),
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            secrets.insert(
                "SECRET_FOUR".to_string(),
                Secret {
                    description: Some("Fourth test secret (not in source)".to_string()),
                    required: Some(false),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );

            profiles.insert(
                "default".to_string(),
                Profile {
                    defaults: None,
                    secrets,
                },
            );
            profiles
        },
        providers: None,
    };

    // Create source .env file
    let source_env_path = project_path.join(".env.source");
    fs::write(
        &source_env_path,
        "SECRET_ONE=value_one_from_source\nSECRET_TWO=value_two_from_source\n",
    )
    .unwrap();

    // Create target .env file with existing value
    let target_env_path = project_path.join(".env.target");
    fs::write(&target_env_path, "SECRET_TWO=existing_value_in_target\n").unwrap();

    // Create global config with target dotenv as default provider
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", target_env_path.display())),
            profile: Some("default".to_string()),
            providers: None,
        },
        audit: None,
    };

    // Create SecretSpec instance
    let spec = Secrets::new(project_config, Some(global_config), None, None);

    // Import from source dotenv to target dotenv
    let from_provider = format!("dotenv://{}", source_env_path.display());
    let result = spec.import(&from_provider);
    assert!(result.is_ok(), "Import should succeed: {:?}", result);

    // Verify using dotenvy that the values are correct
    let vars: HashMap<String, String> = {
        let mut result = HashMap::new();
        let env_vars = dotenvy::from_path_iter(&target_env_path).unwrap();
        for item in env_vars {
            let (k, v) = item.unwrap();
            result.insert(k, v);
        }
        result
    };

    // SECRET_ONE should be imported
    assert_eq!(
        vars.get("SECRET_ONE"),
        Some(&"value_one_from_source".to_string()),
        "SECRET_ONE should be imported from source"
    );

    // SECRET_TWO should NOT be overwritten (already exists)
    assert_eq!(
        vars.get("SECRET_TWO"),
        Some(&"existing_value_in_target".to_string()),
        "SECRET_TWO should not be overwritten"
    );

    // SECRET_THREE and SECRET_FOUR should not be in the file
    assert!(
        vars.get("SECRET_THREE").is_none(),
        "SECRET_THREE should not be imported (not in source)"
    );
    assert!(
        vars.get("SECRET_FOUR").is_none(),
        "SECRET_FOUR should not be imported (not in source)"
    );
}

#[test]
fn test_import_edge_cases() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    // Create project config
    let project_config = Config {
        project: Project {
            name: "test_edge_cases".to_string(),
            ..Default::default()
        },
        profiles: {
            let mut profiles = HashMap::new();
            let mut secrets = HashMap::new();

            secrets.insert(
                "EMPTY_VALUE".to_string(),
                Secret {
                    description: Some("Secret with empty value".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            secrets.insert(
                "SPECIAL_CHARS".to_string(),
                Secret {
                    description: Some("Secret with special characters".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            secrets.insert(
                "MULTILINE".to_string(),
                Secret {
                    description: Some("Secret with multiline value".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );

            profiles.insert(
                "default".to_string(),
                Profile {
                    defaults: None,
                    secrets,
                },
            );
            profiles
        },
        providers: None,
    };

    // Create source .env file with edge case values
    let source_env_path = project_path.join(".env.edge");
    fs::write(
        &source_env_path,
        concat!(
            "EMPTY_VALUE=\n",
            "SPECIAL_CHARS=\"value with spaces and special chars!\"\n",
            "MULTILINE=single_line_value_no_spaces\n"
        ),
    )
    .unwrap();

    let target_env_path = project_path.join(".env.target");
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", target_env_path.display())),
            profile: Some("default".to_string()),
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(project_config, Some(global_config), None, None);

    // Import from source to target
    let from_provider = format!("dotenv://{}", source_env_path.display());
    let result = spec.import(&from_provider);
    assert!(
        result.is_ok(),
        "Import should handle edge cases: {:?}",
        result
    );

    // Verify using dotenvy that the values are correct
    let vars: HashMap<String, String> = {
        let mut result = HashMap::new();
        let env_vars = dotenvy::from_path_iter(&target_env_path).unwrap();
        for item in env_vars {
            let (k, v) = item.unwrap();
            result.insert(k, v);
        }
        result
    };

    // Empty value should be imported
    assert_eq!(
        vars.get("EMPTY_VALUE"),
        Some(&"".to_string()),
        "Empty value should be imported"
    );

    // Special characters should be preserved
    assert_eq!(
        vars.get("SPECIAL_CHARS"),
        Some(&"value with spaces and special chars!".to_string()),
        "Special characters should be preserved"
    );

    // Multiline value should be imported
    assert_eq!(
        vars.get("MULTILINE"),
        Some(&"single_line_value_no_spaces".to_string()),
        "Value should be imported"
    );
}

#[test]
fn test_profiles_inherit_from_default() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path().join("secretspec.toml");

    // Create a secretspec.toml with default and development profiles
    // where development has same secret with different description and default
    let config_content = r#"
[project]
name = "test-no-merge"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "Default database connection", required = true, default = "postgres://localhost/default" }
API_KEY = { description = "API key for services", required = true }
CACHE_TTL = { description = "Cache time to live", required = false, default = "3600" }

[profiles.development]
DATABASE_URL = { description = "Dev database connection", required = true, default = "postgres://localhost/dev" }
API_KEY = { description = "Dev API key", required = true }
# Note: CACHE_TTL is NOT defined in development profile
"#;
    fs::write(&project_path, config_content).unwrap();

    // Load the config
    let config = Config::try_from(project_path.as_path()).unwrap();

    // Create a global config with env provider
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("env".to_string()),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config.clone(), Some(global_config.clone()), None, None);

    // Test that profiles are completely independent

    // 1. Check default profile
    let secret_config = spec
        .resolve_secret_config("DATABASE_URL", Some("default"))
        .expect("DATABASE_URL should exist in default");
    assert_eq!(secret_config.required, Some(true));
    assert_eq!(
        secret_config.default,
        Some("postgres://localhost/default".to_string())
    );

    // 2. Check development profile - should have its own description and default
    let secret_config = spec
        .resolve_secret_config("DATABASE_URL", Some("development"))
        .expect("DATABASE_URL should exist in development");
    assert_eq!(secret_config.required, Some(true));
    assert_eq!(
        secret_config.default,
        Some("postgres://localhost/dev".to_string())
    );

    // 3. Check that CACHE_TTL exists in default and IS inherited by development
    // This proves profiles inherit from default
    assert!(
        spec.resolve_secret_config("CACHE_TTL", Some("default"))
            .is_some()
    );
    assert!(
        spec.resolve_secret_config("CACHE_TTL", Some("development"))
            .is_some(),
        "CACHE_TTL should be inherited from default profile"
    );

    // 4. Verify through validation that development profile DOES see CACHE_TTL
    // Create separate instances for each profile validation
    let spec_default = Secrets::new(
        config.clone(),
        Some(global_config.clone()),
        None,
        Some("default".to_string()),
    );
    let default_validation_result = spec_default.validate().unwrap();

    let spec_dev = Secrets::new(
        config,
        Some(global_config),
        None,
        Some("development".to_string()),
    );
    let dev_validation_result = spec_dev.validate().unwrap();

    // Both should be errors since we're using env provider with no env vars set
    let default_errors = default_validation_result
        .err()
        .expect("Should have validation errors");
    let dev_errors = dev_validation_result
        .err()
        .expect("Should have validation errors");

    // Default profile should know about 3 secrets
    assert_eq!(
        default_errors.missing_required.len()
            + default_errors.missing_optional.len()
            + default_errors.with_defaults.len(),
        3
    );

    // Development profile should now know about 3 secrets (2 defined + 1 inherited)
    assert_eq!(
        dev_errors.missing_required.len()
            + dev_errors.missing_optional.len()
            + dev_errors.with_defaults.len(),
        3,
        "Development should see 3 secrets: DATABASE_URL, API_KEY, and inherited CACHE_TTL"
    );
}

#[test]
fn test_import_with_profiles() {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    // Create project config with multiple profiles
    let project_config = Config {
        project: Project {
            name: "test_profiles".to_string(),
            ..Default::default()
        },
        profiles: {
            let mut profiles = HashMap::new();

            // Development profile
            let mut dev_secrets = HashMap::new();
            dev_secrets.insert(
                "DEV_SECRET".to_string(),
                Secret {
                    description: Some("Development secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            dev_secrets.insert(
                "SHARED_SECRET".to_string(),
                Secret {
                    description: Some("Shared secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            profiles.insert(
                "development".to_string(),
                Profile {
                    defaults: None,
                    secrets: dev_secrets,
                },
            );

            // Production profile
            let mut prod_secrets = HashMap::new();
            prod_secrets.insert(
                "PROD_SECRET".to_string(),
                Secret {
                    description: Some("Production secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            prod_secrets.insert(
                "SHARED_SECRET".to_string(),
                Secret {
                    description: Some("Shared secret".to_string()),
                    required: Some(true),
                    default: None,
                    providers: None,
                    as_path: None,
                    ..Default::default()
                },
            );
            profiles.insert(
                "production".to_string(),
                Profile {
                    defaults: None,
                    secrets: prod_secrets,
                },
            );

            profiles
        },
        providers: None,
    };

    // Create source .env file with all secrets
    let source_env_path = project_path.join(".env.all");
    fs::write(
        &source_env_path,
        concat!(
            "DEV_SECRET=dev_value\n",
            "PROD_SECRET=prod_value\n",
            "SHARED_SECRET=shared_value\n"
        ),
    )
    .unwrap();

    let target_env_path = project_path.join(".env.dev");
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", target_env_path.display())),
            profile: Some("development".to_string()),
            providers: None, // Use development profile
        },
        audit: None,
    };

    let spec = Secrets::new(project_config, Some(global_config), None, None);

    // Import should only import secrets from the active profile (development)
    let from_provider = format!("dotenv://{}", source_env_path.display());
    let result = spec.import(&from_provider);
    assert!(result.is_ok());

    // Verify using dotenvy
    let vars: HashMap<String, String> = {
        let mut result = HashMap::new();
        let env_vars = dotenvy::from_path_iter(&target_env_path).unwrap();
        for item in env_vars {
            let (k, v) = item.unwrap();
            result.insert(k, v);
        }
        result
    };

    // Only DEV_SECRET and SHARED_SECRET should be imported (not PROD_SECRET)
    assert_eq!(
        vars.get("DEV_SECRET"),
        Some(&"dev_value".to_string()),
        "Development secret should be imported"
    );
    assert_eq!(
        vars.get("SHARED_SECRET"),
        Some(&"shared_value".to_string()),
        "Shared secret should be imported for development profile"
    );
    assert!(
        vars.get("PROD_SECRET").is_none(),
        "Production secret should not be imported when using development profile"
    );
}

#[test]
fn test_run_with_empty_command() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "").unwrap();

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles: HashMap::new(),
            providers: None,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
            audit: None,
        }),
        None,
        None,
    );

    let result = spec.run(vec![]);
    assert!(result.is_err());

    match result {
        Err(SecretSpecError::Io(e)) => {
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            assert!(e.to_string().contains("No command specified"));
        }
        _ => panic!("Expected IO InvalidInput error"),
    }
}

#[test]
fn test_run_with_missing_required_secrets() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    // Create empty .env file so required secret is missing
    fs::write(&env_file, "").unwrap();

    let mut secrets = HashMap::new();
    secrets.insert(
        "REQUIRED_SECRET".to_string(),
        Secret {
            description: Some("A required secret".to_string()),
            required: Some(true),
            default: None,
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles,
            providers: None,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
            audit: None,
        }),
        None,
        None,
    );

    let result = spec.run(vec!["echo".to_string(), "hello".to_string()]);
    assert!(result.is_err());

    match result {
        Err(SecretSpecError::RequiredSecretMissing(msg)) => {
            assert!(msg.contains("REQUIRED_SECRET"));
        }
        _ => panic!("Expected RequiredSecretMissing error"),
    }
}

#[test]
fn test_get_existing_secret() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "TEST_SECRET=test_value\n").unwrap();

    let mut secrets = HashMap::new();
    secrets.insert(
        "TEST_SECRET".to_string(),
        Secret {
            description: Some("Test secret".to_string()),
            required: Some(true),
            default: None,
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles,
            providers: None,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
            audit: None,
        }),
        None,
        None,
    );

    let result = spec.get("TEST_SECRET");
    assert!(result.is_ok(), "Failed to get secret: {:?}", result);
}

#[test]
fn test_get_secret_with_default() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    // Create empty .env file so dotenv provider works but returns no value
    fs::write(&env_file, "").unwrap();

    let mut secrets = HashMap::new();
    secrets.insert(
        "SECRET_WITH_DEFAULT".to_string(),
        Secret {
            description: Some("Secret with default value".to_string()),
            required: Some(false),
            default: Some("default_value".to_string()),
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles,
            providers: None,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
            audit: None,
        }),
        None,
        None,
    );

    let result = spec.get("SECRET_WITH_DEFAULT");
    assert!(result.is_ok());
}

#[test]
fn test_get_nonexistent_secret() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "EXISTING_SECRET=exists\n").unwrap();

    let mut secrets = HashMap::new();
    secrets.insert(
        "EXISTING_SECRET".to_string(),
        Secret {
            description: Some("Existing secret".to_string()),
            required: Some(true),
            default: None,
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles,
            providers: None,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
            audit: None,
        }),
        None,
        None,
    );

    let result = spec.get("NONEXISTENT_SECRET");
    assert!(result.is_err());

    match result {
        Err(SecretSpecError::SecretNotFound(msg)) => {
            assert!(msg.contains("NONEXISTENT_SECRET"));
        }
        _ => panic!("Expected SecretNotFound error"),
    }
}

#[test]
fn test_import_dotenv_profile_issue_36() {
    // Reproduces the exact bug reported in GitHub issue #36
    // https://github.com/cachix/secretspec/issues/36

    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path();

    // Load project config from fixture that matches the bug report exactly
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture_path = Path::new(manifest_dir).join("src/fixtures/issue_36_secretspec.toml");

    let project_config =
        Config::try_from(fixture_path.as_path()).expect("Should load fixture config");

    // Create the .env file with only JWT_SECRET (matching the actual bug scenario)
    // The bug is that other secrets with defaults show as "not found in source"
    // instead of using their defaults from the development profile
    let source_env_path = project_path.join(".env");
    fs::write(&source_env_path, "JWT_SECRET=super-secret-jwt-token\n").unwrap();

    // Create target .env for import (using mock provider for testing)
    let target_env_path = project_path.join(".env.target");

    // Create global config with development profile and mock provider as target
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", target_env_path.display())),
            profile: Some("development".to_string()),
            providers: None, // Using development profile as per bug report
        },
        audit: None,
    };

    // Create SecretSpec instance
    let spec = Secrets::new(project_config, Some(global_config), None, None);

    // Import from source dotenv (this should reproduce the bug)
    let from_provider = format!("dotenv://{}", source_env_path.display());

    println!("=== Testing Issue #36 Bug Reproduction ===");
    println!("Source .env file: {}", source_env_path.display());
    println!("Target provider: dotenv://{}", target_env_path.display());
    println!("Profile: development");
    println!("Source .env contents:");
    println!("{}", fs::read_to_string(&source_env_path).unwrap());

    let result = spec.import(&from_provider);

    // The bug report shows that this results in "0 imported, 0 already exists, 7 not found in source"
    // This test should initially fail, helping us identify the root cause

    match result {
        Ok(_) => {
            // Check what was actually imported by reading the target file
            if target_env_path.exists() {
                let target_contents = fs::read_to_string(&target_env_path).unwrap();
                println!("Target file after import:");
                println!("{}", target_contents);

                // The real bug: JWT_SECRET should be imported from .env
                assert!(
                    target_contents.contains("JWT_SECRET=\"super-secret-jwt-token\""),
                    "JWT_SECRET should have been imported from source .env"
                );

                // The import should NOT import defaults - those stay as defaults
                // The bug is that JWT_SECRET (which exists in .env but is only defined in [profiles.default])
                // is not being imported because the import only looks at the active profile

                // JWT_SECRET should be imported since it exists in source .env
                // Other variables should NOT be in the target file since they have defaults and aren't in source
                assert!(
                    !target_contents.contains("MONGODB_HOST"),
                    "MONGODB_HOST should not be in target - it has a default and isn't in source"
                );
                assert!(
                    !target_contents.contains("MONGODB_PORT"),
                    "MONGODB_PORT should not be in target - it has a default and isn't in source"
                );
            } else {
                // The bug might also be that no file is created if only some secrets are imported
                println!("Target file was not created - this might be part of the bug");

                // At minimum, JWT_SECRET should be importable, so a file should be created
                panic!("Target file should have been created after importing JWT_SECRET");
            }
        }
        Err(e) => {
            panic!("Import should not fail: {:?}", e);
        }
    }

    println!("=== Issue #36 test completed ===");
}

#[test]
fn test_per_secret_provider_configuration() {
    // Test that secrets can specify their own providers
    let mut secrets = HashMap::new();

    // Secret with specific provider
    secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key from shared provider".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["shared".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    // Secret without provider (uses default)
    secrets.insert(
        "DATABASE_URL".to_string(),
        Secret {
            description: Some("Database URL from default provider".to_string()),
            required: Some(true),
            default: None,
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "test_per_secret_provider".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    // Create global config with provider aliases
    let mut providers_map = HashMap::new();
    providers_map.insert("shared".to_string(), "keyring://".to_string());

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("env".to_string()),
            profile: None,
            providers: Some(providers_map),
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);

    // Verify API_KEY has providers configured
    let api_key_config = spec
        .resolve_secret_config("API_KEY", Some("default"))
        .unwrap();
    assert_eq!(api_key_config.providers, Some(vec!["shared".to_string()]));

    // Verify DATABASE_URL has no providers (uses default)
    let db_config = spec
        .resolve_secret_config("DATABASE_URL", Some("default"))
        .unwrap();
    assert_eq!(db_config.providers, None);
}

#[test]
fn test_provider_alias_resolution() {
    let mut providers_map = HashMap::new();
    providers_map.insert("dev".to_string(), "dotenv://.env.development".to_string());
    providers_map.insert(
        "prod".to_string(),
        "onepassword://vault/Production".to_string(),
    );

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: None,
            providers: Some(providers_map),
        },
        audit: None,
    };

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles: HashMap::new(),
            providers: None,
        },
        Some(global_config),
        None,
        None,
    );

    // Test resolving dev alias
    let dev_uris = spec
        .resolve_provider_aliases(Some(&["dev".to_string()]))
        .expect("Should resolve dev alias");
    assert_eq!(
        dev_uris,
        Some(vec!["dotenv://.env.development".to_string()])
    );

    // Test resolving prod alias
    let prod_uris = spec
        .resolve_provider_aliases(Some(&["prod".to_string()]))
        .expect("Should resolve prod alias");
    assert_eq!(
        prod_uris,
        Some(vec!["onepassword://vault/Production".to_string()])
    );

    // Test resolving multiple aliases in order
    let multi_uris = spec
        .resolve_provider_aliases(Some(&["dev".to_string(), "prod".to_string()]))
        .expect("Should resolve multiple aliases");
    assert_eq!(
        multi_uris,
        Some(vec![
            "dotenv://.env.development".to_string(),
            "onepassword://vault/Production".to_string(),
        ])
    );

    // Test with no aliases
    let no_uris = spec
        .resolve_provider_aliases(None)
        .expect("Should handle no aliases");
    assert_eq!(no_uris, None);
}

#[test]
fn test_provider_alias_not_found() {
    let mut providers_map = HashMap::new();
    providers_map.insert("existing".to_string(), "dotenv://.env".to_string());

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: None,
            providers: Some(providers_map),
        },
        audit: None,
    };

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles: HashMap::new(),
            providers: None,
        },
        Some(global_config),
        None,
        None,
    );

    // Test resolving non-existent alias
    let result = spec.resolve_provider_aliases(Some(&["nonexistent".to_string()]));
    assert!(result.is_err());
    match result {
        Err(SecretSpecError::ProviderNotFound(msg)) => {
            assert!(msg.contains("nonexistent"));
        }
        _ => panic!("Expected ProviderNotFound error"),
    }
}

#[test]
fn test_per_secret_provider_with_fallback_chain() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    let keyring_file = temp_dir.path().join(".env.keyring");

    // Primary provider has DATABASE_URL
    fs::write(&env_file, "DATABASE_URL=postgres://localhost\n").unwrap();

    // Fallback provider has API_KEY
    fs::write(&keyring_file, "API_KEY=secret-key\n").unwrap();

    let mut secrets = HashMap::new();

    // Try env first, then keyring
    secrets.insert(
        "DATABASE_URL".to_string(),
        Secret {
            description: Some("Database URL".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["primary".to_string(), "fallback".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    // Try fallback first
    secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["fallback".to_string(), "primary".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "test_fallback".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    let mut providers_map = HashMap::new();
    providers_map.insert(
        "primary".to_string(),
        format!("dotenv://{}", env_file.display()),
    );
    providers_map.insert(
        "fallback".to_string(),
        format!("dotenv://{}", keyring_file.display()),
    );

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: None,
            profile: None,
            providers: Some(providers_map),
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);

    // Verify DATABASE_URL config has providers in correct order
    let db_config = spec
        .resolve_secret_config("DATABASE_URL", Some("default"))
        .unwrap();
    assert_eq!(
        db_config.providers,
        Some(vec!["primary".to_string(), "fallback".to_string()])
    );

    // Verify API_KEY config has providers in reverse order
    let api_config = spec
        .resolve_secret_config("API_KEY", Some("default"))
        .unwrap();
    assert_eq!(
        api_config.providers,
        Some(vec!["fallback".to_string(), "primary".to_string()])
    );
}

#[test]
fn test_get_secret_with_fallback_chain() {
    let temp_dir = TempDir::new().unwrap();
    let primary_file = temp_dir.path().join(".env.primary");
    let fallback_file = temp_dir.path().join(".env.fallback");

    // Primary provider doesn't have API_KEY, but has DATABASE_URL
    fs::write(&primary_file, "DATABASE_URL=postgres://localhost\n").unwrap();

    // Fallback provider has API_KEY
    fs::write(&fallback_file, "API_KEY=secret-key\n").unwrap();

    let mut secrets = HashMap::new();

    // API_KEY tries primary first, then fallback (should get from fallback)
    secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key from fallback".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["primary".to_string(), "fallback".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    // DATABASE_URL tries primary first (has it)
    secrets.insert(
        "DATABASE_URL".to_string(),
        Secret {
            description: Some("Database URL from primary".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["primary".to_string(), "fallback".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "test_fallback_integration".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    let mut providers_map = HashMap::new();
    providers_map.insert(
        "primary".to_string(),
        format!("dotenv://{}", primary_file.display()),
    );
    providers_map.insert(
        "fallback".to_string(),
        format!("dotenv://{}", fallback_file.display()),
    );

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()), // Default fallback provider
            profile: None,
            providers: Some(providers_map),
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);

    // Validate should find both secrets using fallback chain
    match spec.validate().unwrap() {
        Ok(valid) => {
            // Both secrets should be found
            assert!(valid.resolved.secrets.contains_key("API_KEY"));
            assert!(valid.resolved.secrets.contains_key("DATABASE_URL"));

            // API_KEY should have come from fallback
            let api_key = valid.resolved.secrets.get("API_KEY").unwrap();
            assert_eq!(api_key.expose_secret(), "secret-key");

            // DATABASE_URL should have come from primary
            let db_url = valid.resolved.secrets.get("DATABASE_URL").unwrap();
            assert_eq!(db_url.expose_secret(), "postgres://localhost");
        }
        Err(e) => panic!("Validation should succeed: {:?}", e),
    }
}

/// When the primary provider in a chain errors (e.g. authentication failure),
/// validation should fall back to the next provider rather than propagating
/// the error. Simulated here by pointing the primary dotenv at a directory,
/// which causes `from_path_iter` to fail on read.
#[test]
fn test_validate_falls_back_on_primary_provider_error() {
    let temp_dir = TempDir::new().unwrap();
    let primary_dir = temp_dir.path().join("broken");
    fs::create_dir(&primary_dir).unwrap();
    let fallback_file = temp_dir.path().join(".env.fallback");
    fs::write(&fallback_file, "API_KEY=from-fallback\n").unwrap();

    let mut secrets = HashMap::new();
    secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["primary".to_string(), "fallback".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "test_error_fallback".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    let mut providers_map = HashMap::new();
    providers_map.insert(
        "primary".to_string(),
        format!("dotenv://{}", primary_dir.display()),
    );
    providers_map.insert(
        "fallback".to_string(),
        format!("dotenv://{}", fallback_file.display()),
    );

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: None,
            providers: Some(providers_map),
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);

    match spec
        .validate()
        .expect("validate should not propagate primary failure")
    {
        Ok(valid) => {
            let api_key = valid.resolved.secrets.get("API_KEY").unwrap();
            assert_eq!(api_key.expose_secret(), "from-fallback");
        }
        Err(e) => panic!("Expected fallback to succeed, got: {:?}", e),
    }
}

/// When every provider in the chain errors, the last error should surface
/// rather than masking the failure as a missing secret.
#[test]
fn test_validate_surfaces_error_when_all_providers_fail() {
    let temp_dir = TempDir::new().unwrap();
    let broken_a = temp_dir.path().join("broken-a");
    let broken_b = temp_dir.path().join("broken-b");
    fs::create_dir(&broken_a).unwrap();
    fs::create_dir(&broken_b).unwrap();

    let mut secrets = HashMap::new();
    secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["a".to_string(), "b".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "test_all_fail".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    let mut providers_map = HashMap::new();
    providers_map.insert("a".to_string(), format!("dotenv://{}", broken_a.display()));
    providers_map.insert("b".to_string(), format!("dotenv://{}", broken_b.display()));

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: None,
            providers: Some(providers_map),
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);

    let result = spec.validate();
    assert!(
        result.is_err(),
        "Expected error when every provider in the chain fails"
    );
}

#[test]
fn test_validate_with_per_secret_providers() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    let keyring_file = temp_dir.path().join(".env.keyring");

    // Env provider has API_KEY
    fs::write(&env_file, "API_KEY=from-env\n").unwrap();

    // Keyring provider has DATABASE_URL
    fs::write(&keyring_file, "DATABASE_URL=from-keyring\n").unwrap();

    let mut secrets = HashMap::new();

    // API_KEY from env provider
    secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["env_provider".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    // DATABASE_URL from keyring provider
    secrets.insert(
        "DATABASE_URL".to_string(),
        Secret {
            description: Some("Database URL".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["keyring_provider".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    // Optional secret without specific provider (uses default)
    secrets.insert(
        "OPTIONAL_CONFIG".to_string(),
        Secret {
            description: Some("Optional configuration".to_string()),
            required: Some(false),
            default: Some("default-config".to_string()),
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "test_multi_provider".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    let mut providers_map = HashMap::new();
    providers_map.insert(
        "env_provider".to_string(),
        format!("dotenv://{}", env_file.display()),
    );
    providers_map.insert(
        "keyring_provider".to_string(),
        format!("dotenv://{}", keyring_file.display()),
    );

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("env".to_string()),
            profile: None,
            providers: Some(providers_map),
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);

    match spec.validate().unwrap() {
        Ok(valid) => {
            // All secrets should be resolved
            assert_eq!(valid.resolved.secrets.len(), 3);

            // Verify each secret came from correct provider
            assert_eq!(
                valid
                    .resolved
                    .secrets
                    .get("API_KEY")
                    .unwrap()
                    .expose_secret(),
                "from-env"
            );
            assert_eq!(
                valid
                    .resolved
                    .secrets
                    .get("DATABASE_URL")
                    .unwrap()
                    .expose_secret(),
                "from-keyring"
            );
            assert_eq!(
                valid
                    .resolved
                    .secrets
                    .get("OPTIONAL_CONFIG")
                    .unwrap()
                    .expose_secret(),
                "default-config"
            );

            // No missing required secrets
            assert!(valid.missing_optional.is_empty());
        }
        Err(e) => panic!("Validation should succeed: {:?}", e),
    }
}

#[test]
fn test_secret_config_merges_providers_from_default() {
    let mut default_secrets = HashMap::new();
    default_secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key from default".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["shared".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    let mut current_secrets = HashMap::new();
    // Override API_KEY in current profile without specifying providers
    // Should inherit from default profile
    current_secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API Key from current".to_string()),
            required: Some(true),
            default: None,
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );

    // Add new secret only in current profile
    current_secrets.insert(
        "DATABASE_URL".to_string(),
        Secret {
            description: Some("Database URL".to_string()),
            required: Some(true),
            default: None,
            providers: Some(vec!["prod".to_string()]),
            as_path: None,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets: default_secrets,
        },
    );
    profiles.insert(
        "production".to_string(),
        Profile {
            defaults: None,
            secrets: current_secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "test_merge".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    let spec = Secrets::new(config, None, None, None);

    // When resolving API_KEY from production profile, should inherit providers from default
    let api_key_config = spec
        .resolve_secret_config("API_KEY", Some("production"))
        .unwrap();
    assert_eq!(
        api_key_config.providers,
        Some(vec!["shared".to_string()]),
        "API_KEY should inherit providers from default profile"
    );

    // Database URL should have its own providers
    let db_config = spec
        .resolve_secret_config("DATABASE_URL", Some("production"))
        .unwrap();
    assert_eq!(
        db_config.providers,
        Some(vec!["prod".to_string()]),
        "DATABASE_URL should use its own providers"
    );
}

#[test]
fn test_profile_defaults_from_toml() {
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.path().join("secretspec.toml");

    let toml_content = r#"[project]
name = "test"
revision = "1.0"

[profiles.production.defaults]
providers = ["prod_vault", "keyring"]

[profiles.production]
DATABASE_URL = { description = "Production DB" }
API_KEY = { description = "API key" }
SECRET_KEY = { description = "Secret key", providers = ["env"] }

[profiles.development.defaults]
required = false
default = "dev-default"

[profiles.development]
DATABASE_URL = { description = "Dev DB" }
API_KEY = { description = "Dev API key" }
SPECIAL_SECRET = { description = "Special secret", required = true }
"#;

    fs::write(&config_file, toml_content).unwrap();

    let config = Config::try_from(config_file.as_path()).unwrap();
    let spec = Secrets::new(config, None, None, None);

    // Test production profile provider defaults
    let db_prod = spec
        .resolve_secret_config("DATABASE_URL", Some("production"))
        .unwrap();
    assert_eq!(
        db_prod.providers,
        Some(vec!["prod_vault".to_string(), "keyring".to_string()]),
        "DATABASE_URL should inherit production profile defaults"
    );

    let api_prod = spec
        .resolve_secret_config("API_KEY", Some("production"))
        .unwrap();
    assert_eq!(
        api_prod.providers,
        Some(vec!["prod_vault".to_string(), "keyring".to_string()]),
        "API_KEY should inherit production profile defaults"
    );

    let secret_prod = spec
        .resolve_secret_config("SECRET_KEY", Some("production"))
        .unwrap();
    assert_eq!(
        secret_prod.providers,
        Some(vec!["env".to_string()]),
        "SECRET_KEY should override with its own providers"
    );

    // Test development profile required and default values
    let db_dev = spec
        .resolve_secret_config("DATABASE_URL", Some("development"))
        .unwrap();
    assert_eq!(
        db_dev.required,
        Some(false),
        "DATABASE_URL should inherit required=false from dev defaults"
    );
    assert_eq!(
        db_dev.default,
        Some("dev-default".to_string()),
        "DATABASE_URL should inherit default value from dev defaults"
    );

    let api_dev = spec
        .resolve_secret_config("API_KEY", Some("development"))
        .unwrap();
    assert_eq!(api_dev.required, Some(false));
    assert_eq!(api_dev.default, Some("dev-default".to_string()));

    let special_dev = spec
        .resolve_secret_config("SPECIAL_SECRET", Some("development"))
        .unwrap();
    assert_eq!(
        special_dev.required,
        Some(true),
        "SPECIAL_SECRET should override required setting"
    );
    assert_eq!(
        special_dev.default,
        Some("dev-default".to_string()),
        "SPECIAL_SECRET should still inherit default value"
    );
}

#[test]
fn test_cli_provider_alias_operations() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().join(".config");
    fs::create_dir(&config_dir).unwrap();

    // Create a temporary config file
    let config_path = config_dir.join("secretspec_config.toml");

    // Write initial config
    let initial_config = r#"
[defaults]
provider = "keyring"

[providers]
"#;
    fs::write(&config_path, initial_config).unwrap();

    // Parse the config
    let mut config: GlobalConfig = toml::from_str(initial_config).unwrap();

    // Simulate adding a provider alias
    if config.defaults.providers.is_none() {
        config.defaults.providers = Some(HashMap::new());
    }
    if let Some(providers) = &mut config.defaults.providers {
        providers.insert(
            "shared".to_string(),
            "onepassword://vault/Shared".to_string(),
        );
        providers.insert(
            "prod".to_string(),
            "onepassword://vault/Production".to_string(),
        );
    }

    // Verify providers were added
    assert_eq!(config.defaults.providers.as_ref().unwrap().len(), 2);
    assert_eq!(
        config.defaults.providers.as_ref().unwrap().get("shared"),
        Some(&"onepassword://vault/Shared".to_string())
    );

    // Simulate removing a provider alias
    if let Some(providers) = &mut config.defaults.providers {
        providers.remove("prod");
    }
    assert_eq!(config.defaults.providers.as_ref().unwrap().len(), 1);

    // Simulate listing provider aliases
    let aliases: Vec<_> = config
        .defaults
        .providers
        .as_ref()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert_eq!(aliases.len(), 1);
    assert_eq!(aliases[0].0, "shared");
}

#[test]
fn test_as_path_secrets() {
    use secrecy::ExposeSecret;
    use std::fs;

    let temp_dir = TempDir::new().unwrap();
    let secret_value = "my-secret-certificate-content";

    // Create a dotenv file with a secret
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, format!("CERT_DATA={}", secret_value)).unwrap();
    fs::write(
        &env_file,
        format!("CERT_DATA={}\nREGULAR_SECRET=not-a-path", secret_value),
    )
    .unwrap();

    // Create config with as_path secret
    let config_file = temp_dir.path().join("secretspec.toml");
    let toml_content = r#"[project]
name = "test-as-path"
revision = "1.0"

[profiles.default]
CERT_DATA = { description = "Certificate data", as_path = true }
REGULAR_SECRET = { description = "Regular secret", as_path = false }
"#;
    fs::write(&config_file, toml_content).unwrap();

    // Load and validate
    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);
    let validated = spec.validate().unwrap().unwrap();

    // Check that CERT_DATA contains a path
    let cert_path_str = validated
        .resolved
        .secrets
        .get("CERT_DATA")
        .unwrap()
        .expose_secret();
    let cert_path = std::path::PathBuf::from(cert_path_str);

    // Verify the temp file exists and contains the secret
    assert!(cert_path.exists(), "Temporary file should exist");
    let file_content = fs::read_to_string(&cert_path).unwrap();
    assert_eq!(
        file_content, secret_value,
        "Temporary file should contain the secret value"
    );

    // Check that REGULAR_SECRET contains the actual value (not a path)
    let regular_secret = validated
        .resolved
        .secrets
        .get("REGULAR_SECRET")
        .unwrap()
        .expose_secret();
    assert_eq!(regular_secret, "not-a-path");

    // Check that temp_files vector is not empty
    assert!(
        !validated.temp_files.is_empty(),
        "temp_files should contain the temporary file"
    );

    // Drop validated to trigger cleanup
    drop(validated);

    // Verify the temp file is cleaned up
    assert!(
        !cert_path.exists(),
        "Temporary file should be cleaned up after drop"
    );
}

#[test]
fn test_as_path_secrets_keep_temp_files() {
    use secrecy::ExposeSecret;
    use std::fs;

    let temp_dir = TempDir::new().unwrap();
    let secret_value = "certificate-data-to-keep";

    // Create a dotenv file with a secret
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, format!("CERT_DATA={}", secret_value)).unwrap();

    // Create config with as_path secret
    let config_file = temp_dir.path().join("secretspec.toml");
    let toml_content = r#"[project]
name = "test-keep-files"
revision = "1.0"

[profiles.default]
CERT_DATA = { description = "Certificate data", as_path = true }
"#;
    fs::write(&config_file, toml_content).unwrap();

    // Load and validate
    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);
    let mut validated = spec.validate().unwrap().unwrap();

    // Get the cert path before keeping files
    let cert_path_str = validated
        .resolved
        .secrets
        .get("CERT_DATA")
        .unwrap()
        .expose_secret();
    let cert_path = std::path::PathBuf::from(cert_path_str);

    // Verify the temp file exists
    assert!(cert_path.exists(), "Temporary file should exist");

    // Keep the temp files (persist them)
    let kept_paths = validated.keep_temp_files().unwrap();
    assert_eq!(kept_paths.len(), 1, "Should have kept one temp file");

    // Drop validated
    drop(validated);

    // Verify the temp file still exists after drop (because we kept it)
    assert!(
        cert_path.exists(),
        "Temporary file should still exist after keep_temp_files()"
    );

    // Verify the content
    let file_content = fs::read_to_string(&cert_path).unwrap();
    assert_eq!(file_content, secret_value);

    // Clean up manually
    fs::remove_file(&cert_path).unwrap();
}

#[cfg(unix)]
#[test]
fn test_run_cleans_up_as_path_temp_files() {
    use std::fs;

    let temp_dir = TempDir::new().unwrap();
    let secret_value = "secret-cert-content";

    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, format!("CERT_DATA={}", secret_value)).unwrap();

    let config_file = temp_dir.path().join("secretspec.toml");
    fs::write(
        &config_file,
        r#"[project]
name = "test-run-cleanup"
revision = "1.0"

[profiles.default]
CERT_DATA = { description = "Certificate data", as_path = true }
"#,
    )
    .unwrap();

    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };
    let spec = Secrets::new(config, Some(global_config), None, None);

    // Have the child write the path it received back to disk so the parent
    // can inspect it after run_command returns.
    let captured_path_file = temp_dir.path().join("captured-path");
    let exit_code = spec
        .run_command(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "printf '%s' \"$CERT_DATA\" > {}",
                captured_path_file.display()
            ),
        ])
        .unwrap();
    assert_eq!(exit_code, 0);

    let captured_path = fs::read_to_string(&captured_path_file).unwrap();
    assert!(
        !captured_path.is_empty(),
        "child should have observed the temp file path via $CERT_DATA"
    );
    assert!(
        !std::path::Path::new(&captured_path).exists(),
        "as_path temp file at {} should be removed once `run` returns",
        captured_path
    );
}

// ========== Secret generation tests ==========

#[test]
fn test_config_parse_generate_bool() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
DB_PASSWORD = { description = "Database password", type = "password", generate = true }
"#;
    let config = parse_spec_from_str(toml_content, None).unwrap();
    let profile = config.profiles.get("default").unwrap();
    let secret = profile.secrets.get("DB_PASSWORD").unwrap();
    assert_eq!(secret.secret_type.as_deref(), Some("password"));
    assert!(matches!(
        secret.generate,
        Some(crate::config::GenerateConfig::Bool(true))
    ));
}

#[test]
fn test_config_parse_generate_options() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
API_TOKEN = { description = "API token", type = "hex", generate = { bytes = 32 } }
"#;
    let config = parse_spec_from_str(toml_content, None).unwrap();
    let profile = config.profiles.get("default").unwrap();
    let secret = profile.secrets.get("API_TOKEN").unwrap();
    assert_eq!(secret.secret_type.as_deref(), Some("hex"));
    match &secret.generate {
        Some(crate::config::GenerateConfig::Options(opts)) => {
            assert_eq!(opts.bytes, Some(32));
        }
        other => panic!("Expected Options, got {:?}", other),
    }
}

#[test]
fn test_config_parse_generate_command() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
MONGO_KEY = { description = "MongoDB keyfile", type = "command", generate = { command = "echo test" } }
"#;
    let config = parse_spec_from_str(toml_content, None).unwrap();
    let profile = config.profiles.get("default").unwrap();
    let secret = profile.secrets.get("MONGO_KEY").unwrap();
    assert_eq!(secret.secret_type.as_deref(), Some("command"));
    match &secret.generate {
        Some(crate::config::GenerateConfig::Options(opts)) => {
            assert_eq!(opts.command.as_deref(), Some("echo test"));
        }
        other => panic!("Expected Options, got {:?}", other),
    }
}

#[test]
fn test_config_type_without_generate_is_valid() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
STATIC_SECRET = { description = "Manually managed", type = "password" }
"#;
    let config = parse_spec_from_str(toml_content, None).unwrap();
    let profile = config.profiles.get("default").unwrap();
    let secret = profile.secrets.get("STATIC_SECRET").unwrap();
    assert_eq!(secret.secret_type.as_deref(), Some("password"));
    assert!(secret.generate.is_none());
}

#[test]
fn test_config_generate_without_type_is_error() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
BAD_SECRET = { description = "Missing type", generate = true }
"#;
    let result = parse_spec_from_str(toml_content, None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("requires 'type'"),
        "Expected error about missing type, got: {}",
        err_msg
    );
}

#[test]
fn test_config_generate_false_without_type_is_valid() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
MANUAL_SECRET = { description = "No gen", generate = false }
"#;
    let config = parse_spec_from_str(toml_content, None).unwrap();
    let profile = config.profiles.get("default").unwrap();
    let secret = profile.secrets.get("MANUAL_SECRET").unwrap();
    assert!(matches!(
        secret.generate,
        Some(crate::config::GenerateConfig::Bool(false))
    ));
}

#[test]
fn test_config_generate_and_default_is_error() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
CONFLICT = { description = "Both", type = "password", generate = true, default = "foo" }
"#;
    let result = parse_spec_from_str(toml_content, None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("cannot both be set"),
        "Expected conflict error, got: {}",
        err_msg
    );
}

#[test]
fn test_config_command_type_generate_bool_is_error() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
CMD_SECRET = { description = "Cmd", type = "command", generate = true }
"#;
    let result = parse_spec_from_str(toml_content, None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("command"),
        "Expected command requirement error, got: {}",
        err_msg
    );
}

#[test]
fn test_config_unknown_type_is_error() {
    let toml_content = r#"
[project]
name = "test-gen"
revision = "1.0"

[profiles.default]
BAD_TYPE = { description = "Unknown type", type = "rsa_key", generate = true }
"#;
    let result = parse_spec_from_str(toml_content, None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown secret type"),
        "Expected unknown type error, got: {}",
        err_msg
    );
}

#[test]
fn test_validate_generates_missing_secret() {
    use secrecy::ExposeSecret;

    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "").unwrap();

    let config_file = temp_dir.path().join("secretspec.toml");
    let toml_content = r#"[project]
name = "test-gen-validate"
revision = "1.0"

[profiles.default]
DB_PASSWORD = { description = "Database password", type = "password", generate = true }
"#;
    fs::write(&config_file, toml_content).unwrap();

    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);
    let result = spec.validate().unwrap();
    let validated = result.unwrap();

    // The secret should have been generated
    let value = validated.resolved.secrets.get("DB_PASSWORD").unwrap();
    let s = value.expose_secret();
    assert_eq!(s.len(), 32, "Default password length should be 32");
    assert!(
        s.chars().all(|c| c.is_alphanumeric()),
        "Default password should be alphanumeric"
    );
}

#[test]
fn test_validate_does_not_regenerate_existing_secret() {
    use secrecy::ExposeSecret;

    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "DB_PASSWORD=existing_value").unwrap();

    let config_file = temp_dir.path().join("secretspec.toml");
    let toml_content = r#"[project]
name = "test-gen-existing"
revision = "1.0"

[profiles.default]
DB_PASSWORD = { description = "Database password", type = "password", generate = true }
"#;
    fs::write(&config_file, toml_content).unwrap();

    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);
    let result = spec.validate().unwrap();
    let validated = result.unwrap();

    let value = validated
        .resolved
        .secrets
        .get("DB_PASSWORD")
        .unwrap()
        .expose_secret();
    assert_eq!(
        value, "existing_value",
        "Existing secret should not be regenerated"
    );
}

#[test]
fn test_validate_idempotent_generation() {
    use secrecy::ExposeSecret;

    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "").unwrap();

    let config_file = temp_dir.path().join("secretspec.toml");
    let toml_content = r#"[project]
name = "test-gen-idempotent"
revision = "1.0"

[profiles.default]
DB_PASSWORD = { description = "Database password", type = "password", generate = true }
"#;
    fs::write(&config_file, toml_content).unwrap();

    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config.clone(), Some(global_config.clone()), None, None);

    // First validate generates the secret
    let result1 = spec.validate().unwrap().unwrap();
    let v1 = result1
        .resolved
        .secrets
        .get("DB_PASSWORD")
        .unwrap()
        .expose_secret()
        .to_string();

    // Second validate should find the previously generated secret
    let spec2 = Secrets::new(config, Some(global_config), None, None);
    let result2 = spec2.validate().unwrap().unwrap();
    let v2 = result2
        .resolved
        .secrets
        .get("DB_PASSWORD")
        .unwrap()
        .expose_secret()
        .to_string();

    assert_eq!(v1, v2, "Second validate should return same generated value");
}

#[test]
fn test_validate_multiple_generate_types() {
    use secrecy::ExposeSecret;

    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "").unwrap();

    let config_file = temp_dir.path().join("secretspec.toml");
    let toml_content = r#"[project]
name = "test-gen-multi"
revision = "1.0"

[profiles.default]
DB_PASSWORD = { description = "Password", type = "password", generate = true }
API_TOKEN = { description = "Token", type = "hex", generate = { bytes = 16 } }
SESSION_KEY = { description = "Session", type = "base64", generate = { bytes = 24 } }
REQUEST_ID = { description = "ID", type = "uuid", generate = true }
"#;
    fs::write(&config_file, toml_content).unwrap();

    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);
    let validated = spec.validate().unwrap().unwrap();

    // All secrets should be present
    assert!(validated.resolved.secrets.contains_key("DB_PASSWORD"));
    assert!(validated.resolved.secrets.contains_key("API_TOKEN"));
    assert!(validated.resolved.secrets.contains_key("SESSION_KEY"));
    assert!(validated.resolved.secrets.contains_key("REQUEST_ID"));

    // Verify types
    let pw = validated
        .resolved
        .secrets
        .get("DB_PASSWORD")
        .unwrap()
        .expose_secret();
    assert_eq!(pw.len(), 32);

    let hex = validated
        .resolved
        .secrets
        .get("API_TOKEN")
        .unwrap()
        .expose_secret();
    assert_eq!(hex.len(), 32); // 16 bytes = 32 hex chars

    let uuid = validated
        .resolved
        .secrets
        .get("REQUEST_ID")
        .unwrap()
        .expose_secret();
    assert_eq!(uuid.len(), 36);
    assert!(uuid.contains('-'));
}

#[test]
fn test_validate_generate_with_profile() {
    use secrecy::ExposeSecret;

    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "").unwrap();

    let config_file = temp_dir.path().join("secretspec.toml");
    let toml_content = r#"[project]
name = "test-gen-profile"
revision = "1.0"

[profiles.default]
SHARED_KEY = { description = "Shared", type = "password", generate = true }

[profiles.production]
PROD_KEY = { description = "Production key", type = "hex", generate = { bytes = 32 } }
"#;
    fs::write(&config_file, toml_content).unwrap();

    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(
        config,
        Some(global_config),
        None,
        Some("production".to_string()),
    );
    let validated = spec.validate().unwrap().unwrap();

    // Both secrets should be generated
    assert!(validated.resolved.secrets.contains_key("SHARED_KEY"));
    assert!(validated.resolved.secrets.contains_key("PROD_KEY"));

    let hex = validated
        .resolved
        .secrets
        .get("PROD_KEY")
        .unwrap()
        .expose_secret();
    assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
}

#[test]
fn test_resolve_secret_config_merges_type_and_generate() {
    let mut profiles = HashMap::new();
    let mut default_secrets = HashMap::new();
    default_secrets.insert(
        "DB_PASSWORD".to_string(),
        Secret {
            description: Some("Database password".to_string()),
            required: None,
            default: None,
            providers: None,
            as_path: None,
            secret_type: Some("password".to_string()),
            generate: Some(crate::config::GenerateConfig::Bool(true)),
        },
    );
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets: default_secrets,
        },
    );

    let mut prod_secrets = HashMap::new();
    prod_secrets.insert(
        "DB_PASSWORD".to_string(),
        Secret {
            description: Some("Prod DB password".to_string()),
            required: Some(true),
            default: None,
            providers: None,
            as_path: None,
            ..Default::default()
        },
    );
    profiles.insert(
        "production".to_string(),
        Profile {
            defaults: None,
            secrets: prod_secrets,
        },
    );

    let config = Config {
        project: Project {
            name: "test".to_string(),
            ..Default::default()
        },
        profiles,
        providers: None,
    };

    let spec = Secrets::new(config, None, Some("production".to_string()), None);
    let resolved = spec
        .resolve_secret_config("DB_PASSWORD", Some("production"))
        .unwrap();

    // type and generate should be inherited from default
    assert_eq!(resolved.secret_type.as_deref(), Some("password"));
    assert!(resolved.generate.is_some());
    // description should come from production
    assert_eq!(resolved.description.as_deref(), Some("Prod DB password"));
}

/// Builds a project + global config matching the scenario in
/// https://github.com/cachix/secretspec/issues/81: profile defaults declare a
/// `providers = ["personal", "team"]` chain whose aliases resolve to dotenv files,
/// and the secret has no per-secret `providers` override.
fn build_chain_scenario(
    temp_dir: &TempDir,
) -> (Config, GlobalConfig, std::path::PathBuf, std::path::PathBuf) {
    let personal_path = temp_dir.path().join(".env.personal");
    let team_path = temp_dir.path().join(".env.team");
    fs::write(&personal_path, "").unwrap();
    fs::write(&team_path, "").unwrap();

    let config = Config {
        project: Project {
            name: "test_project".to_string(),
            ..Default::default()
        },
        profiles: {
            let mut profiles = HashMap::new();
            let mut secrets = HashMap::new();
            secrets.insert(
                "MY_SECRET".to_string(),
                Secret {
                    description: Some("test secret".to_string()),
                    required: Some(true),
                    ..Default::default()
                },
            );
            profiles.insert(
                "development".to_string(),
                Profile {
                    defaults: Some(crate::config::ProfileDefaults {
                        required: None,
                        default: None,
                        providers: Some(vec!["personal".to_string(), "team".to_string()]),
                    }),
                    secrets,
                },
            );
            profiles
        },
        providers: None,
    };

    let mut providers_map = HashMap::new();
    providers_map.insert(
        "personal".to_string(),
        format!("dotenv://{}", personal_path.display()),
    );
    providers_map.insert(
        "team".to_string(),
        format!("dotenv://{}", team_path.display()),
    );
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: Some("development".to_string()),
            providers: Some(providers_map),
        },
        audit: None,
    };

    (config, global_config, personal_path, team_path)
}

fn read_env_var(path: &std::path::Path, key: &str) -> Option<String> {
    dotenvy::from_path_iter(path)
        .ok()?
        .filter_map(|res| res.ok())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

/// Regression test for issue #81: `set --provider <alias>` must override the
/// per-secret/profile providers chain, writing only to the chosen provider.
#[test]
fn test_set_provider_override_wins_over_chain() {
    let temp_dir = TempDir::new().unwrap();
    let (config, global_config, personal_path, team_path) = build_chain_scenario(&temp_dir);

    // Builder-set provider mirrors `--provider team` from the CLI. Use the alias
    // name; the override resolver must look it up in the global providers map.
    let spec = Secrets::new(config, Some(global_config), Some("team".to_string()), None);
    spec.set("MY_SECRET", Some("override_value".to_string()))
        .expect("set should succeed");

    assert_eq!(
        read_env_var(&team_path, "MY_SECRET").as_deref(),
        Some("override_value"),
        "secret should be written to the overridden provider"
    );
    assert!(
        read_env_var(&personal_path, "MY_SECRET").is_none(),
        "secret must not leak into the first-in-chain provider when overridden"
    );
}

/// Without an override, `set` still writes to the first provider in the chain
/// (the documented convention). This guards against the override fix accidentally
/// shifting the no-flag default.
#[test]
fn test_set_without_override_uses_chain_first() {
    let temp_dir = TempDir::new().unwrap();
    let (config, global_config, personal_path, team_path) = build_chain_scenario(&temp_dir);

    let spec = Secrets::new(config, Some(global_config), None, None);
    spec.set("MY_SECRET", Some("chain_value".to_string()))
        .expect("set should succeed");

    assert_eq!(
        read_env_var(&personal_path, "MY_SECRET").as_deref(),
        Some("chain_value"),
        "without override, set writes to the first alias in the chain"
    );
    assert!(
        read_env_var(&team_path, "MY_SECRET").is_none(),
        "team provider must remain untouched"
    );
}

/// `get` with an explicit override must read only from that provider, never
/// falling back through the chain.
#[test]
fn test_resolve_read_provider_uris_override_skips_chain() {
    let temp_dir = TempDir::new().unwrap();
    let (config, global_config, _, team_path) = build_chain_scenario(&temp_dir);

    let spec = Secrets::new(config, Some(global_config), Some("team".to_string()), None);
    let secret_config = spec.resolve_secret_config("MY_SECRET", None).unwrap();
    let uris = spec
        .resolve_read_provider_uris(&secret_config, None)
        .expect("override resolution should succeed")
        .expect("override should produce a URI list");

    assert_eq!(
        uris.len(),
        1,
        "override must collapse the chain to a single URI"
    );
    assert_eq!(uris[0], format!("dotenv://{}", team_path.display()));
}

/// Strip ANSI escape sequences so summary assertions don't depend on whether
/// the `colored` crate decides to emit them (TTY detection differs between
/// local runs and CI).
fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'm' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Regression for https://github.com/cachix/secretspec/issues/72: when every
/// optional secret is set, the summary line keeps its previous two-segment
/// form so we don't churn output for the common case.
#[test]
fn test_format_summary_omits_optional_when_none_missing() {
    let line = Secrets::format_summary(5, 0, 0);
    assert_eq!(strip_ansi(&line), "Summary: 5 found, 0 missing");
}

/// Regression for https://github.com/cachix/secretspec/issues/72: missing
/// optional secrets must surface in the summary as a third segment rather
/// than being silently absorbed into "found".
#[test]
fn test_format_summary_appends_optional_when_some_missing() {
    let line = Secrets::format_summary(4, 0, 1);
    assert_eq!(strip_ansi(&line), "Summary: 4 found, 0 missing, 1 optional");

    let mixed = Secrets::format_summary(2, 3, 4);
    assert_eq!(
        strip_ansi(&mixed),
        "Summary: 2 found, 3 missing, 4 optional"
    );
}

/// End-to-end check for https://github.com/cachix/secretspec/issues/72:
/// an optional secret that has no value in the backing provider must land in
/// `missing_optional` instead of being treated as found. The display layer
/// relies on this — without it, `secretspec check` would still print a green
/// checkmark for optional-but-unset secrets and undercount them in the
/// summary, which was the original user-visible bug.
#[test]
fn test_validate_marks_unset_optional_secret_as_missing_optional() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "REQUIRED_PRESENT=value\n").unwrap();

    let config_file = temp_dir.path().join("secretspec.toml");
    let toml_content = r#"[project]
name = "issue72"
revision = "1.0"

[profiles.default]
REQUIRED_PRESENT = { description = "required, present" }
OPTIONAL_MISSING = { description = "optional, not set", required = false }
"#;
    fs::write(&config_file, toml_content).unwrap();

    let config = Config::try_from(config_file.as_path()).unwrap();
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some(format!("dotenv://{}", env_file.display())),
            profile: None,
            providers: None,
        },
        audit: None,
    };

    let spec = Secrets::new(config, Some(global_config), None, None);
    let validated = spec
        .validate()
        .unwrap()
        .expect("no required secrets are missing, so validation should succeed");

    assert!(
        validated.resolved.secrets.contains_key("REQUIRED_PRESENT"),
        "required secret should be resolved"
    );
    assert!(
        !validated.resolved.secrets.contains_key("OPTIONAL_MISSING"),
        "unset optional secret must not appear in resolved secrets"
    );
    assert_eq!(
        validated.missing_optional,
        vec!["OPTIONAL_MISSING".to_string()],
        "unset optional secret must be reported in missing_optional"
    );
}

fn aliases_map(aliases: &[(&str, &str)]) -> HashMap<String, String> {
    aliases
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn config_with_project_aliases(aliases: &[(&str, &str)]) -> Config {
    Config {
        project: Project {
            name: "alias-test".to_string(),
            ..Default::default()
        },
        profiles: HashMap::new(),
        providers: Some(aliases_map(aliases)),
    }
}

fn global_config_with_aliases(aliases: &[(&str, &str)]) -> GlobalConfig {
    GlobalConfig {
        defaults: GlobalDefaults {
            provider: None,
            profile: None,
            providers: Some(aliases_map(aliases)),
        },
        audit: None,
    }
}

fn config_with_project_alias_secret(
    alias: &str,
    uri: &str,
    secret_providers: Option<Vec<String>>,
) -> Config {
    let mut secrets = HashMap::new();
    secrets.insert(
        "API_KEY".to_string(),
        Secret {
            description: Some("API key".to_string()),
            required: Some(true),
            providers: secret_providers,
            ..Default::default()
        },
    );

    let mut profiles = HashMap::new();
    profiles.insert(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    );

    Config {
        project: Project {
            name: "alias-validation".to_string(),
            ..Default::default()
        },
        profiles,
        providers: Some(aliases_map(&[(alias, uri)])),
    }
}

#[test]
fn test_project_providers_resolve_without_global_config() {
    let config = config_with_project_aliases(&[("op_infra", "onepassword://Infra")]);
    let spec = Secrets::new(config, None, None, None);

    let resolved = spec
        .resolve_provider_aliases(Some(&["op_infra".to_string()]))
        .expect("project alias should resolve")
        .expect("resolved list should be present");

    assert_eq!(resolved, vec!["onepassword://Infra".to_string()]);
}

#[test]
fn test_project_providers_take_precedence_over_global() {
    let config = config_with_project_aliases(&[("shared", "dotenv://.env.team")]);
    let global = global_config_with_aliases(&[("shared", "dotenv://.env.user")]);
    let spec = Secrets::new(config, Some(global), None, None);

    let resolved = spec
        .resolve_provider_aliases(Some(&["shared".to_string()]))
        .expect("alias should resolve")
        .expect("resolved list should be present");

    assert_eq!(
        resolved,
        vec!["dotenv://.env.team".to_string()],
        "project alias must win on conflict with global"
    );
}

#[test]
fn test_unknown_alias_error_lists_both_sources() {
    let config = config_with_project_aliases(&[("project_only", "dotenv://.env.team")]);
    let global = global_config_with_aliases(&[("global_only", "dotenv://.env.user")]);
    let spec = Secrets::new(config, Some(global), None, None);

    let err = spec
        .resolve_provider_aliases(Some(&["does_not_exist".to_string()]))
        .expect_err("missing alias must error");

    let msg = err.to_string();
    assert!(
        msg.contains("project_only") && msg.contains("global_only"),
        "error should list aliases from both project and global config, got: {}",
        msg
    );
}

#[test]
fn test_extends_carries_project_providers() {
    let temp_dir = TempDir::new().unwrap();
    let base = temp_dir.path();
    fs::create_dir_all(base.join("shared")).unwrap();
    fs::create_dir_all(base.join("app")).unwrap();

    fs::write(
        base.join("shared/secretspec.toml"),
        r#"
[project]
name = "shared"
revision = "1.0"

[providers]
op_infra = "onepassword://Shared"
op_overridden = "onepassword://OldVault"

[profiles.default]
SHARED_SECRET = { description = "Shared", required = true }
"#,
    )
    .unwrap();

    fs::write(
        base.join("app/secretspec.toml"),
        r#"
[project]
name = "app"
revision = "1.0"
extends = ["../shared"]

[providers]
op_overridden = "onepassword://NewVault"

[profiles.default]
APP_SECRET = { description = "App", required = true }
"#,
    )
    .unwrap();

    let config = Config::try_from(base.join("app/secretspec.toml").as_path()).unwrap();
    let providers = config
        .providers
        .as_ref()
        .expect("merged config should carry [providers]");

    assert_eq!(
        providers.get("op_infra").map(String::as_str),
        Some("onepassword://Shared"),
        "alias defined only in extended config should be inherited"
    );
    assert_eq!(
        providers.get("op_overridden").map(String::as_str),
        Some("onepassword://NewVault"),
        "alias defined in both should resolve to the current (extending) config's value"
    );
}

#[test]
fn test_provider_override_expands_project_alias() {
    let config = config_with_project_aliases(&[("op_infra", "onepassword://Infra")]);
    let spec = Secrets::new(config, None, None, Some("default".to_string()));
    // builder-style override (mirrors `--provider <alias>`)
    let mut spec = spec;
    spec.set_provider("op_infra");

    let resolved = spec
        .resolve_provider_override(None)
        .expect("override should resolve to a URI");

    assert_eq!(resolved, "onepassword://Infra");
}

#[test]
fn test_global_alias_still_resolves_when_project_providers_present() {
    // Project map defines `local`; we look up `team`, which only exists in
    // global. Walks past the project source into the global one.
    let config = config_with_project_aliases(&[("local", "dotenv://.env.local")]);
    let global = global_config_with_aliases(&[("team", "onepassword://Team")]);
    let spec = Secrets::new(config, Some(global), None, None);

    let resolved = spec
        .resolve_provider_aliases(Some(&["team".to_string()]))
        .expect("global alias should resolve when project map exists but doesn't define it")
        .expect("resolved list should be present");

    assert_eq!(resolved, vec!["onepassword://Team".to_string()]);
}

#[test]
fn test_fallback_chain_resolves_aliases_from_mixed_sources() {
    // Chain mixes a project-only alias and a global-only alias; order in the
    // chain is preserved and each is resolved from whichever source defines it.
    let config = config_with_project_aliases(&[("project_vault", "onepassword://Team")]);
    let global = global_config_with_aliases(&[("user_dotenv", "dotenv://.env.user")]);
    let spec = Secrets::new(config, Some(global), None, None);

    let resolved = spec
        .resolve_provider_aliases(Some(&[
            "project_vault".to_string(),
            "user_dotenv".to_string(),
        ]))
        .expect("mixed-source chain should resolve")
        .expect("resolved list should be present");

    assert_eq!(
        resolved,
        vec![
            "onepassword://Team".to_string(),
            "dotenv://.env.user".to_string(),
        ],
        "chain order must be preserved across sources"
    );
}

#[test]
fn test_provider_override_resolves_global_alias_when_project_providers_present() {
    // `--provider <alias>` path must consult the same source order as the
    // per-secret chain; a global-only alias resolves even when a project
    // providers map is set.
    let config = config_with_project_aliases(&[("local", "dotenv://.env.local")]);
    let global = global_config_with_aliases(&[("team", "onepassword://Team")]);
    let mut spec = Secrets::new(config, Some(global), None, None);
    spec.set_provider("team");

    let resolved = spec
        .resolve_provider_override(None)
        .expect("override should resolve to a URI");

    assert_eq!(resolved, "onepassword://Team");
}

#[test]
fn test_validate_project_provider_chain_without_global_default() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env.project");
    fs::write(&env_file, "API_KEY=from-project\n").unwrap();
    let uri = format!("dotenv://{}", env_file.display());

    let config = config_with_project_alias_secret(
        "project_env",
        &uri,
        Some(vec!["project_env".to_string()]),
    );
    let spec = Secrets::new(config, None, None, None);

    let validated = spec
        .validate()
        .expect("project provider alias should not require a global provider")
        .expect("secret should resolve from project provider alias");

    assert_eq!(
        validated
            .resolved
            .secrets
            .get("API_KEY")
            .unwrap()
            .expose_secret(),
        "from-project"
    );
    assert_eq!(
        validated.resolved.provider, uri,
        "validation metadata should report the resolved project provider URI"
    );
}

#[test]
fn test_validate_provider_override_project_alias_without_global_default() {
    let temp_dir = TempDir::new().unwrap();
    let env_file = temp_dir.path().join(".env.override");
    fs::write(&env_file, "API_KEY=from-override\n").unwrap();
    let uri = format!("dotenv://{}", env_file.display());

    let config = config_with_project_alias_secret("project_env", &uri, None);
    let mut spec = Secrets::new(config, None, None, None);
    spec.set_provider("project_env");

    let validated = spec
        .validate()
        .expect("override alias should not be reparsed as a provider scheme")
        .expect("secret should resolve from explicit project alias");

    assert_eq!(
        validated
            .resolved
            .secrets
            .get("API_KEY")
            .unwrap()
            .expose_secret(),
        "from-override"
    );
    assert_eq!(
        validated.resolved.provider, uri,
        "validation metadata should report the resolved override URI"
    );
}

/// Builds a Secrets backed by a dotenv provider over a temp `.env` file.
///
/// The caller must keep `temp_dir` alive for as long as the returned Secrets
/// is used, since the `.env` file lives inside it.
fn dotenv_spec(
    env_contents: &str,
    profiles: HashMap<String, Profile>,
    temp_dir: &TempDir,
) -> Secrets {
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, env_contents).unwrap();
    Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                ..Default::default()
            },
            profiles,
            providers: None,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
            audit: None,
        }),
        None,
        None,
    )
}

fn required_secret_profile(name: &str) -> HashMap<String, Profile> {
    let mut secrets = HashMap::new();
    secrets.insert(
        name.to_string(),
        Secret {
            description: Some("A required secret".to_string()),
            required: Some(true),
            ..Default::default()
        },
    );
    HashMap::from([(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    )])
}

#[test]
fn test_check_returns_ok_when_required_present() {
    let temp_dir = TempDir::new().unwrap();
    let spec = dotenv_spec(
        "REQUIRED=value\n",
        required_secret_profile("REQUIRED"),
        &temp_dir,
    );

    let validated = spec.check(true).expect("check should succeed");
    assert!(validated.resolved.secrets.contains_key("REQUIRED"));
}

#[test]
fn test_check_no_prompt_errors_when_required_missing() {
    let temp_dir = TempDir::new().unwrap();
    // Empty .env -> the required secret is missing.
    let spec = dotenv_spec("", required_secret_profile("REQUIRED"), &temp_dir);

    assert!(
        matches!(
            spec.check(true),
            Err(SecretSpecError::RequiredSecretMissing(_))
        ),
        "expected RequiredSecretMissing when a required secret is absent"
    );
}

#[test]
fn test_run_command_returns_child_exit_code() {
    let temp_dir = TempDir::new().unwrap();
    // An empty (but present) default profile -> ensure_secrets passes and the
    // child's exit code is propagated verbatim.
    let empty_default = HashMap::from([(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets: HashMap::new(),
        },
    )]);
    let spec = dotenv_spec("", empty_default, &temp_dir);

    assert_eq!(
        spec.run_command(vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 3".to_string()
        ])
        .unwrap(),
        3
    );
    assert_eq!(spec.run_command(vec!["true".to_string()]).unwrap(), 0);
    assert_eq!(spec.run_command(vec!["false".to_string()]).unwrap(), 1);
}

/// The audit `action`s emitted by an operation, in order.
fn audit_actions(lines: &std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> Vec<String> {
    lines
        .lock()
        .unwrap()
        .iter()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["action"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[test]
fn audit_check_emits_single_check_event() {
    let temp_dir = TempDir::new().unwrap();
    let mut spec = dotenv_spec(
        "REQUIRED=value\n",
        required_secret_profile("REQUIRED"),
        &temp_dir,
    );
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    spec.check(true).expect("check should succeed");

    // Exactly one `check` event — not the 2-3 that the repeated internal
    // re-validations used to produce.
    assert_eq!(audit_actions(&lines), vec!["check"]);
}

#[test]
fn audit_run_emits_run_not_check() {
    let temp_dir = TempDir::new().unwrap();
    // Present required secret -> resolution succeeds and the command runs.
    let mut spec = dotenv_spec(
        "REQUIRED=value\n",
        required_secret_profile("REQUIRED"),
        &temp_dir,
    );
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    spec.run_command(vec!["true".to_string()]).unwrap();

    // `run` records itself as a single `run` event; the internal read it performs
    // through `ensure_secrets` must not also be logged as a `check`.
    assert_eq!(audit_actions(&lines), vec!["run"]);

    // A successfully launched command is `started`, not `found`.
    let event: serde_json::Value = serde_json::from_str(&lines.lock().unwrap()[0]).unwrap();
    assert_eq!(event["outcome"], "started");
}

/// The full audit events emitted by an operation, parsed in order.
fn audit_events(lines: &std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> Vec<serde_json::Value> {
    lines
        .lock()
        .unwrap()
        .iter()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .collect()
}

/// A `default`-only profile: one optional secret carrying a fallback value, so a
/// `get` with no stored value resolves to the default.
fn defaulted_secret_profile(name: &str, default: &str) -> HashMap<String, Profile> {
    let mut secrets = HashMap::new();
    secrets.insert(
        name.to_string(),
        Secret {
            description: Some("with default".to_string()),
            required: Some(false),
            default: Some(default.to_string()),
            ..Default::default()
        },
    );
    HashMap::from([(
        "default".to_string(),
        Profile {
            defaults: None,
            secrets,
        },
    )])
}

#[test]
fn audit_get_present_records_found_without_value() {
    let temp_dir = TempDir::new().unwrap();
    let mut spec = dotenv_spec(
        "REQUIRED=hunter2\n",
        required_secret_profile("REQUIRED"),
        &temp_dir,
    );
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    spec.get("REQUIRED").unwrap();

    let events = audit_events(&lines);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "get");
    assert_eq!(events[0]["outcome"], "found");
    assert_eq!(events[0]["key"], "REQUIRED");
    assert!(events[0]["provider"].as_str().unwrap().contains("dotenv"));
    // The retrieved value never reaches the log.
    assert!(!lines.lock().unwrap()[0].contains("hunter2"));
}

#[test]
fn audit_get_missing_records_missing() {
    let temp_dir = TempDir::new().unwrap();
    // Empty .env -> a required secret with no default is missing.
    let mut spec = dotenv_spec("", required_secret_profile("REQUIRED"), &temp_dir);
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    assert!(matches!(
        spec.get("REQUIRED"),
        Err(SecretSpecError::SecretNotFound(_))
    ));

    let events = audit_events(&lines);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "get");
    // A missing read is recorded as `missing` even though `get` then errors.
    assert_eq!(events[0]["outcome"], "missing");
    assert_eq!(events[0]["key"], "REQUIRED");
}

#[test]
fn audit_get_default_records_default() {
    let temp_dir = TempDir::new().unwrap();
    // No stored value -> the configured default is served.
    let mut spec = dotenv_spec(
        "",
        defaulted_secret_profile("OPTIONAL", "fallback"),
        &temp_dir,
    );
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    spec.get("OPTIONAL").unwrap();

    let events = audit_events(&lines);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "get");
    assert_eq!(events[0]["outcome"], "default");
    assert_eq!(events[0]["key"], "OPTIONAL");
}

#[test]
fn audit_get_undefined_records_error() {
    let temp_dir = TempDir::new().unwrap();
    let mut spec = dotenv_spec("", required_secret_profile("REQUIRED"), &temp_dir);
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    assert!(matches!(
        spec.get("UNDEFINED"),
        Err(SecretSpecError::SecretNotFound(_))
    ));

    let events = audit_events(&lines);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "get");
    assert_eq!(events[0]["outcome"], "error");
    assert_eq!(events[0]["error_kind"], "secret_not_found");
    // No provider can be attributed to an undefined secret.
    assert!(events[0].get("provider").is_none());
}

#[test]
fn audit_set_records_written_without_value() {
    let temp_dir = TempDir::new().unwrap();
    let mut spec = dotenv_spec("", required_secret_profile("REQUIRED"), &temp_dir);
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    spec.set("REQUIRED", Some("secret_value".to_string()))
        .unwrap();

    let events = audit_events(&lines);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "set");
    assert_eq!(events[0]["outcome"], "written");
    assert_eq!(events[0]["key"], "REQUIRED");
    assert!(events[0]["provider"].as_str().unwrap().contains("dotenv"));
    // The stored value is never logged.
    assert!(!lines.lock().unwrap()[0].contains("secret_value"));
}

#[test]
fn audit_set_undefined_records_error() {
    let temp_dir = TempDir::new().unwrap();
    let mut spec = dotenv_spec("", required_secret_profile("REQUIRED"), &temp_dir);
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    assert!(matches!(
        spec.set("UNDEFINED", Some("v".to_string())),
        Err(SecretSpecError::SecretNotFound(_))
    ));

    let events = audit_events(&lines);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "set");
    assert_eq!(events[0]["outcome"], "error");
    assert_eq!(events[0]["error_kind"], "secret_not_found");
}

#[test]
fn audit_set_readonly_provider_records_error() {
    let project_config = Config {
        project: Project {
            name: "test".to_string(),
            ..Default::default()
        },
        profiles: required_secret_profile("REQUIRED"),
        providers: None,
    };
    // `env` is read-only, so a `set` is rejected and recorded as an error.
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("env".to_string()),
            profile: None,
            providers: None,
        },
        audit: None,
    };
    let mut spec = Secrets::new(project_config, Some(global_config), None, None);
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    assert!(matches!(
        spec.set("REQUIRED", Some("v".to_string())),
        Err(SecretSpecError::ProviderOperationFailed(_))
    ));

    let events = audit_events(&lines);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "set");
    assert_eq!(events[0]["outcome"], "error");
    assert_eq!(events[0]["error_kind"], "provider_operation_failed");
}

#[test]
fn audit_policy_denied_still_records_blocked_attempt() {
    let temp_dir = TempDir::new().unwrap();
    let mut spec = dotenv_spec(
        "REQUIRED=value\n",
        required_secret_profile("REQUIRED"),
        &temp_dir,
    );
    // require_reason = Always with no reason supplied -> every access is denied.
    spec.set_require_reason(RequireReason::Always);
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    assert!(matches!(
        spec.get("REQUIRED"),
        Err(SecretSpecError::ReasonRequired)
    ));

    // A blocked access still leaves an audit trace.
    let events = audit_events(&lines);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "get");
    assert_eq!(events[0]["outcome"], "error");
    assert_eq!(events[0]["error_kind"], "reason_required");
    assert_eq!(events[0]["key"], "REQUIRED");
}

#[test]
fn audit_import_records_keys_and_per_secret_writes() {
    let temp_dir = TempDir::new().unwrap();
    // Target provider (the spec default) starts empty.
    let mut spec = dotenv_spec("", required_secret_profile("REQUIRED"), &temp_dir);
    // Source provider holds the secret to copy.
    let source = temp_dir.path().join("source.env");
    fs::write(&source, "REQUIRED=from_source\n").unwrap();
    let (logger, lines) = crate::audit::test_support::collecting_logger();
    spec.set_audit_for_test(logger);

    spec.import(&format!("dotenv://{}", source.display()))
        .unwrap();

    let events = audit_events(&lines);
    let actions: Vec<&str> = events
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    // Each copied secret is recorded as a `set`, then one bulk `import` event.
    assert_eq!(actions, vec!["set", "import"]);

    let set = &events[0];
    assert_eq!(set["outcome"], "written");
    assert_eq!(set["key"], "REQUIRED");

    let import = &events[1];
    assert_eq!(import["outcome"], "written");
    assert_eq!(import["keys"][0], "REQUIRED");
    // The copied value is never logged.
    assert!(
        !lines
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("from_source"))
    );
}

#[test]
fn test_resolve_profile_unknown_returns_invalid_profile() {
    let temp_dir = TempDir::new().unwrap();
    let spec = dotenv_spec("", required_secret_profile("REQUIRED"), &temp_dir);

    let result = spec.resolve_profile(Some("nonexistent"));
    match result {
        Err(SecretSpecError::InvalidProfile(msg)) => {
            assert!(msg.contains("nonexistent"));
            assert!(msg.contains("Available profiles"));
        }
        other => panic!("expected InvalidProfile, got {other:?}"),
    }
}
