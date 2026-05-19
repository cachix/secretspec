use secretspec::{
    Config, ProviderConfig, ProviderRef, ProviderRefDetail, SecretRequest,
};
use std::fs;
use tempfile::TempDir;

fn write_and_parse(toml_content: &str) -> Config {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("secretspec.toml");
    fs::write(&path, toml_content).unwrap();
    Config::try_from(path.as_path()).unwrap()
}

// ── Example 1: Basic provider-relative lookup with sections/fields ────────

#[test]
fn example_1_basic_provider_relative_lookup() {
    let toml = r#"
[project]
name = "myapp"
revision = "1.0"

[providers]
op-dev = "onepassword://Development"

[profiles.default]
GITHUB_TOKEN = { description = "GitHub PAT", providers = [{ provider = "op-dev", path = ["GitHub"], key = "token" }] }
GITHUB_USER  = { description = "GitHub username", providers = [{ provider = "op-dev", path = ["GitHub"], key = "user" }] }
DATABASE_URL = { description = "DB connection", providers = [{ provider = "op-dev", path = ["Database"], key = "url" }] }
"#;
    let config = write_and_parse(toml);

    // Providers map contains op-dev as a bare alias
    let providers = config.providers.as_ref().unwrap();
    let op_dev = providers.get("op-dev").unwrap();
    assert!(
        matches!(op_dev, ProviderConfig::Alias(s) if s == "onepassword://Development"),
        "expected Alias, got {:?}", op_dev
    );

    // Default profile secrets
    let def = config.profiles.get("default").unwrap();

    let gh_token = def.secrets.get("GITHUB_TOKEN").unwrap();
    let token_providers = gh_token.providers.as_ref().unwrap();
    assert_eq!(token_providers.len(), 1);
    match &token_providers[0] {
        ProviderRef::Detail(d) => {
            assert_eq!(d.provider, "op-dev");
            assert_eq!(d.path.as_ref(), Some(&vec!["GitHub".to_string()]));
            assert_eq!(d.key.as_deref(), Some("token"));
        }
        other => panic!("expected Detail, got {:?}", other),
    }

    let gh_user = def.secrets.get("GITHUB_USER").unwrap();
    let providers = gh_user.providers.as_ref().unwrap();
    match &providers[0] {
        ProviderRef::Detail(d) => {
            assert_eq!(d.provider, "op-dev");
            assert_eq!(d.path.as_ref(), Some(&vec!["GitHub".to_string()]));
            assert_eq!(d.key.as_deref(), Some("user"));
        }
        other => panic!("expected Detail, got {:?}", other),
    }

    let db_url = def.secrets.get("DATABASE_URL").unwrap();
    let providers = db_url.providers.as_ref().unwrap();
    match &providers[0] {
        ProviderRef::Detail(d) => {
            assert_eq!(d.provider, "op-dev");
            assert_eq!(d.path.as_ref(), Some(&vec!["Database".to_string()]));
            assert_eq!(d.key.as_deref(), Some("url"));
        }
        other => panic!("expected Detail, got {:?}", other),
    }

    // SecretRequest from ref
    let req = SecretRequest::from_provider_ref(&providers[0]);
    assert_eq!(req.path, Some(vec!["Database".to_string()]));
    assert_eq!(req.key, Some("url".to_string()));
}

// ── Example 10: Full CI setup ─────────────────────────────────────────────

#[test]
fn example_10_full_ci_setup_with_structured_provider() {
    let config = write_and_parse(r#"
[project]
name = "ci-pipeline"
revision = "1.0"

[providers]
keyring = "keyring://"
env     = "env://"

[providers.ci-env]
uri = "onepassword+env+token://abc123def456"
[[providers.ci-env.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"

[profiles.default]
OP_SERVICE_ACCOUNT_TOKEN = { description = "1Password CI service account token", required = true, providers = ["keyring", "env"] }
DEPLOY_KEY    = { description = "Deploy key", providers = ["ci-env"] }
SLACK_WEBHOOK = { description = "Slack webhook URL", providers = ["ci-env"] }
NPM_TOKEN     = { description = "NPM publish token", providers = ["ci-env"] }
"#);

    assert_eq!(config.project.name, "ci-pipeline");

    let providers = config.providers.as_ref().unwrap();
    assert!(
        matches!(providers.get("keyring"), Some(ProviderConfig::Alias(s)) if s == "keyring://")
    );
    assert!(
        matches!(providers.get("env"), Some(ProviderConfig::Alias(s)) if s == "env://")
    );

    match providers.get("ci-env").unwrap() {
        ProviderConfig::Structured(s) => {
            assert_eq!(s.uri, "onepassword+env+token://abc123def456");
            assert_eq!(s.depends_on[0].secret, "OP_SERVICE_ACCOUNT_TOKEN");
        }
        other => panic!("expected Structured, got {:?}", other),
    }

    let def = config.profiles.get("default").unwrap();
    assert!(def.secrets.contains_key("OP_SERVICE_ACCOUNT_TOKEN"));
    assert!(def.secrets.contains_key("DEPLOY_KEY"));
    assert!(def.secrets.contains_key("SLACK_WEBHOOK"));
    assert!(def.secrets.contains_key("NPM_TOKEN"));

    let token = def.secrets.get("OP_SERVICE_ACCOUNT_TOKEN").unwrap();
    assert_eq!(token.required, Some(true));
    let token_providers = token.providers.as_ref().unwrap();
    assert_eq!(token_providers.len(), 2);
    assert!(matches!(&token_providers[0], ProviderRef::Alias(s) if s == "keyring"));
    assert!(matches!(&token_providers[1], ProviderRef::Alias(s) if s == "env"));

    for secret_name in &["DEPLOY_KEY", "SLACK_WEBHOOK", "NPM_TOKEN"] {
        let secret = def.secrets.get(*secret_name).unwrap();
        let p = secret.providers.as_ref().unwrap();
        assert_eq!(p.len(), 1, "{secret_name} should have 1 provider");
        assert!(matches!(&p[0], ProviderRef::Alias(s) if s == "ci-env"));
    }
}

// ── Quick-check all remaining examples parse without errors ───────────────

#[test]
fn all_examples_parse() {
    // Example 2
    write_and_parse(r#"
[project]
name = "myapp"
revision = "1.0"
[providers]
op-prod = "onepassword://Production"
keyring = "keyring://"
[profiles.production]
API_KEY = { description = "External API key", providers = [{ provider = "op-prod", path = ["APIs"], key = "stripe" }, "keyring"] }
"#);

    // Example 3
    write_and_parse(r#"
[project]
name = "myapp"
revision = "1.0"
[providers]
keyring = "keyring://"
[providers.op-prod]
uri = "onepassword://Production"
[[providers.op-prod.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"
[profiles.default]
OP_SERVICE_ACCOUNT_TOKEN = { description = "1Password token", required = true, providers = ["keyring"] }
[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["op-prod"] }
API_KEY      = { description = "Prod API key", providers = ["op-prod"] }
"#);

    // Example 4
    write_and_parse(r#"
[project]
name = "myapp"
revision = "1.0"
[providers]
op-dev = "onepassword://Development"
op-prod = "onepassword://Production"
[profiles.default]
DATABASE_URL = { description = "Dev DB", providers = ["op-dev"] }
[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["op-prod"] }
"#);

    // Example 6
    write_and_parse(r#"
[project]
name = "myapp"
revision = "1.0"
[providers]
dev-env = "onepassword+env://work@blgexucrwfr2dtsxe2q4uu7dp4"
ci-env  = "onepassword+env+token://ops_abc123def456@xyz789"
[profiles.default]
DATABASE_URL = { description = "Dev DB", providers = ["dev-env"] }
[profiles.ci]
DATABASE_URL = { description = "CI DB", providers = ["ci-env"] }
API_KEY      = { description = "CI API key", providers = ["ci-env"] }
"#);

    // Example 7
    write_and_parse(r#"
[project]
name = "myapp"
revision = "1.0"
[providers]
op-items = "onepassword://Development"
env-vars = "onepassword+env://blgexucrwfr2dtsxe2q4uu7dp4"
[profiles.default]
GITHUB_TOKEN = { description = "GitHub token", providers = [{ provider = "op-items", path = ["GitHub"], key = "token" }] }
PORT        = { description = "Server port", providers = ["env-vars"] }
LOG_LEVEL   = { description = "Log level", providers = ["env-vars"] }
NODE_ENV    = { description = "Node env", providers = ["env-vars", "env"] }
"#);

    // Example 8
    write_and_parse(r#"
[project]
name = "myapp"
revision = "1.0"
[providers]
op-prod = "onepassword://Production"
[profiles.default]
GOOGLE_APPLICATION_CREDENTIALS = { description = "GCP SA JSON", providers = [{ provider = "op-prod", path = ["Google"] }] }
"#);

    // Example 9
    write_and_parse(r#"
[project]
name = "myapp"
revision = "1.0"
[providers.op-multi]
uri = "onepassword://Team"
[[providers.op-multi.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"
[[providers.op-multi.depends_on]]
secret = "SOME_API_KEY"
[profiles.default]
OP_SERVICE_ACCOUNT_TOKEN = { description = "OP token", providers = ["keyring"] }
SOME_API_KEY = { description = "API key", providers = ["env"] }
"#);
}

// ── Example 5: Cross-project shared config with inheritance ────────────────

#[test]
fn example_5_cross_project_shared_config() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    let shared_dir = base.join("team-shared");
    fs::create_dir_all(&shared_dir).unwrap();
    fs::write(shared_dir.join("secretspec.toml"), r#"
[project]
name = "team-shared"
revision = "1.0"
[providers]
op-core  = "onepassword://Core"
op-prod  = "onepassword://Production"
keyring  = "keyring://"
env      = "env://"
[profiles]
"#).unwrap();

    let myapp_dir = base.join("myapp");
    fs::create_dir_all(&myapp_dir).unwrap();
    fs::write(myapp_dir.join("secretspec.toml"), r#"
[project]
name = "myapp"
revision = "1.0"
extends = ["../team-shared"]
[profiles.default]
DATABASE_URL = { description = "Dev DB", providers = ["op-core", "keyring"] }
"#).unwrap();

    let config = Config::try_from(myapp_dir.join("secretspec.toml").as_path()).unwrap();
    assert_eq!(config.project.name, "myapp");
    assert_eq!(config.project.extends, Some(vec!["../team-shared".to_string()]));

    let providers = config.providers.as_ref().unwrap();
    assert!(providers.contains_key("op-core"));
    assert!(providers.contains_key("op-prod"));
    assert!(providers.contains_key("keyring"));
    assert!(providers.contains_key("env"));
}

// ── Serde roundtrip for ProviderRef ───────────────────────────────────────┐

#[test]
fn provider_ref_serde_roundtrip() {
    // Alias
    let json = r#""keyring""#;
    let r: ProviderRef = serde_json::from_str(json).unwrap();
    assert!(matches!(&r, ProviderRef::Alias(s) if s == "keyring"));
    let serialized = serde_json::to_string(&r).unwrap();
    assert_eq!(serialized, json);

    // Detail with path and key
    let json = r#"{"provider":"op-dev","path":["GitHub"],"key":"token"}"#;
    let r: ProviderRef = serde_json::from_str(json).unwrap();
    let serialized = serde_json::to_string(&r).unwrap();
    match &r {
        ProviderRef::Detail(d) => {
            assert_eq!(d.provider, "op-dev");
            assert_eq!(d.path.as_ref(), Some(&vec!["GitHub".to_string()]));
            assert_eq!(d.key.as_deref(), Some("token"));
        }
        _ => panic!("expected Detail"),
    }
    assert_eq!(serialized, json);

    // Detail with path only
    let json = r#"{"provider":"op-dev","path":["Google"]}"#;
    let r: ProviderRef = serde_json::from_str(json).unwrap();
    match &r {
        ProviderRef::Detail(d) => {
            assert_eq!(d.provider, "op-dev");
            assert_eq!(d.path.as_ref(), Some(&vec!["Google".to_string()]));
            assert!(d.key.is_none());
        }
        _ => panic!("expected Detail"),
    }

    // Detail with key only
    let json = r#"{"provider":"op-dev","key":"token"}"#;
    let r: ProviderRef = serde_json::from_str(json).unwrap();
    match &r {
        ProviderRef::Detail(d) => {
            assert_eq!(d.provider, "op-dev");
            assert!(d.path.is_none());
            assert_eq!(d.key.as_deref(), Some("token"));
        }
        _ => panic!("expected Detail"),
    }

    // Detail with provider only
    let json = r#"{"provider":"op-dev"}"#;
    let r: ProviderRef = serde_json::from_str(json).unwrap();
    match &r {
        ProviderRef::Detail(d) => {
            assert_eq!(d.provider, "op-dev");
            assert!(d.path.is_none());
            assert!(d.key.is_none());
        }
        _ => panic!("expected Detail"),
    }
}

// ── Serde roundtrip for ProviderConfig ───────────────────────────────────┐

#[test]
fn provider_config_serde_roundtrip() {
    // Alias
    let json = r#""keyring://""#;
    let pc: ProviderConfig = serde_json::from_str(json).unwrap();
    assert!(matches!(&pc, ProviderConfig::Alias(s) if s == "keyring://"));
    assert_eq!(serde_json::to_string(&pc).unwrap(), json);

    // Structured with requires
    let json = r#"{"uri":"onepassword://Prod","depends_on":[{"secret":"SECRET_NAME"}]}"#;
    let pc: ProviderConfig = serde_json::from_str(json).unwrap();
    let serialized = serde_json::to_string(&pc).unwrap();
    match &pc {
        ProviderConfig::Structured(s) => {
            assert_eq!(s.uri, "onepassword://Prod");
            assert_eq!(s.depends_on[0].secret, "SECRET_NAME");
        }
        _ => panic!("expected Structured"),
    }
    assert!(serialized.contains("onepassword://Prod"));
    assert!(serialized.contains("SECRET_NAME"));

    // Structured without requires
    let json = r#"{"uri":"onepassword://Prod"}"#;
    let pc: ProviderConfig = serde_json::from_str(json).unwrap();
    match &pc {
        ProviderConfig::Structured(s) => {
            assert_eq!(s.uri, "onepassword://Prod");
            assert!(s.depends_on.is_empty());
        }
        _ => panic!("expected Structured"),
    }
}

// ── SecretRequest construction ───────────────────────────────────────

#[test]
fn secret_request_from_provider_ref_key_defaults() {
    let detail = ProviderRef::Detail(ProviderRefDetail {
        provider: "op-dev".into(),
        path: Some(vec!["GitHub".into()]),
        key: None,
    });
    let req = SecretRequest::from_provider_ref(&detail);
    assert_eq!(req.path, Some(vec!["GitHub".into()]));
    assert_eq!(req.key, None);

    let detail = ProviderRef::Detail(ProviderRefDetail {
        provider: "op-dev".into(),
        path: Some(vec!["APIs".into()]),
        key: Some("stripe".into()),
    });
    let req = SecretRequest::from_provider_ref(&detail);
    assert_eq!(req.path, Some(vec!["APIs".into()]));
    assert_eq!(req.key, Some("stripe".into()));

    // Alias produces empty request
    let alias = ProviderRef::Alias("keyring".into());
    let req = SecretRequest::from_provider_ref(&alias);
    assert_eq!(req.path, None);
    assert_eq!(req.key, None);
}

#[test]
fn secret_request_serde_roundtrip() {
    let req = SecretRequest { path: Some(vec!["X".into()]), key: Some("Y".into()) };
    let json = serde_json::to_string(&req).unwrap();
    let back: SecretRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.path, Some(vec!["X".into()]));
    assert_eq!(back.key, Some("Y".into()));

    let empty = SecretRequest { path: None, key: None };
    let json = serde_json::to_string(&empty).unwrap();
    let back: SecretRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, SecretRequest { path: None, key: None });
}

// ── Backward compat: old-style providers still parse ─────────────────────┐

#[test]
fn old_style_string_providers_still_parse() {
    let config = write_and_parse(r#"
[project]
name = "old-project"
revision = "1.0"
[profiles.default]
API_KEY = { description = "API Key", required = true, providers = ["keyring", "dotenv"] }
"#);
    let def = config.profiles.get("default").unwrap();
    let providers = def.secrets.get("API_KEY").unwrap().providers.as_ref().unwrap();
    assert_eq!(providers.len(), 2);
    assert!(matches!(&providers[0], ProviderRef::Alias(s) if s == "keyring"));
    assert!(matches!(&providers[1], ProviderRef::Alias(s) if s == "dotenv"));
}

#[test]
fn old_style_providers_table_still_parses() {
    let config = write_and_parse(r#"
[project]
name = "old-project"
revision = "1.0"
[providers]
keyring = "keyring://"
dotenv  = "dotenv://.env.local"
[profiles.default]
API_KEY = { description = "API Key", required = true }
"#);
    let providers = config.providers.as_ref().unwrap();
    assert!(matches!(providers.get("keyring"), Some(ProviderConfig::Alias(s)) if s == "keyring://"));
    assert!(matches!(providers.get("dotenv"), Some(ProviderConfig::Alias(s)) if s == "dotenv://.env.local"));
}

#[test]
fn mixed_providers_table_aliases_and_structured() {
    let config = write_and_parse(r#"
[project]
name = "mixed"
revision = "1.0"
[providers]
keyring = "keyring://"
env     = "env://"
[providers.op-prod]
uri = "onepassword://Production"
[[providers.op-prod.depends_on]]
secret = "OP_TOKEN"
[profiles.default]
DATABASE_URL = { description = "DB", providers = ["op-prod", "keyring"] }
"#);
    let providers = config.providers.as_ref().unwrap();
    assert_eq!(providers.len(), 3);
    assert!(matches!(providers.get("keyring"), Some(ProviderConfig::Alias(s)) if s == "keyring://"));
    assert!(matches!(providers.get("env"), Some(ProviderConfig::Alias(s)) if s == "env://"));
    match providers.get("op-prod").unwrap() {
        ProviderConfig::Structured(s) => {
            assert_eq!(s.uri, "onepassword://Production");
            assert_eq!(s.depends_on[0].secret, "OP_TOKEN");
        }
        _ => panic!("expected Structured"),
    }
}
