use crate::config::{
    Config, GlobalConfig, GlobalDefaults, ParseError, Profile, Project, Resolved, Secret,
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
            revision: "1.0".to_string(),
            extends: None,
        },
        profiles: HashMap::new(),
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
fn test_new_with_default_overrides() {
    let config = Config {
        project: Project {
            name: "test-project".to_string(),
            revision: "1.0".to_string(),
            extends: None,
        },
        profiles: HashMap::new(),
    };

    // Create a global config with specific defaults
    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("dotenv".to_string()),
            profile: Some("production".to_string()),
            providers: None,
        },
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
fn test_secretspec_new() {
    let config = Config {
        project: Project {
            name: "test".to_string(),
            revision: "1.0".to_string(),
            extends: None,
        },
        profiles: HashMap::new(),
    };

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("keyring".to_string()),
            profile: Some("dev".to_string()),
            providers: None,
        },
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
    };

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: HashMap::new(),
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
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: HashMap::new(),
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
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles,
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
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: HashMap::new(),
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
    };

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: HashMap::new(),
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
            revision: "1.0".to_string(),
            extends: None,
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
    };

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("env".to_string()),
            profile: None,
            providers: None,
        },
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

    // Create a temporary directory for dotenv file
    let temp_dir = TempDir::new().unwrap();
    let original_dir = env::current_dir().unwrap();
    env::set_current_dir(&temp_dir).unwrap();

    let project_config = Config {
        project: Project {
            name: "test_project".to_string(),
            revision: "1.0".to_string(),
            extends: None,
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
    };

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("dotenv".to_string()),
            profile: None,
            providers: None,
        },
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
            revision: "1.0".to_string(),
            extends: None,
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
    };

    let global_config = GlobalConfig {
        defaults: GlobalDefaults {
            provider: Some("env".to_string()),
            profile: None,
            providers: None,
        },
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
            revision: "1.0".to_string(),
            extends: None,
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
            revision: "1.0".to_string(),
            extends: None,
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
            revision: "1.0".to_string(),
            extends: None,
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
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: HashMap::new(),
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
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
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
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
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
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
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
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
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles,
        },
        Some(GlobalConfig {
            defaults: GlobalDefaults {
                provider: Some(format!("dotenv://{}", env_file.display())),
                profile: None,
                providers: None,
            },
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
            revision: "1.0".to_string(),
            extends: None,
        },
        profiles,
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
    };

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: HashMap::new(),
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
    };

    let spec = Secrets::new(
        Config {
            project: Project {
                name: "test".to_string(),
                revision: "1.0".to_string(),
                extends: None,
            },
            profiles: HashMap::new(),
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
            revision: "1.0".to_string(),
            extends: None,
        },
        profiles,
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
            revision: "1.0".to_string(),
            extends: None,
        },
        profiles,
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
            revision: "1.0".to_string(),
            extends: None,
        },
        profiles,
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
            revision: "1.0".to_string(),
            extends: None,
        },
        profiles,
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
