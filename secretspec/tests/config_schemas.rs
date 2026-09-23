// The schemas are produced by `secretspec schema`, so these tests exercise the
// generated output directly. The copies the documentation site publishes are
// compared against it when the tests run inside the repository.
#![cfg(feature = "cli")]

use secretspec::__private::Config;
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;

/// Runs `secretspec schema --config KIND` and returns its stdout.
fn generate(kind: &str) -> String {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .current_dir(directory.path())
        .args(["schema", "--config", kind])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn schema(name: &str) -> Value {
    let kind = match name {
        "secretspec" => "project",
        "config" => "global",
        _ => panic!("unknown schema {name}"),
    };
    serde_json::from_str(&generate(kind)).unwrap()
}

fn validate(schema: &Value, document: &Value) {
    let validator = jsonschema::validator_for(schema).unwrap();
    let errors: Vec<_> = validator
        .iter_errors(document)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn config_schemas_cover_project_syntax() {
    let document = r#"
[project]
name = "schema-test"
revision = "1.0"
extends = []
require_reason = "agents"
[defaults]
providers = ["local"]
[providers]
local = "dotenv://.env"
vault = { uri = "vault://secret", credentials = { token = "env" }, ref = { item = "{project}/{key}" } }
inline = { uri = "vault://secret", cache = { provider = "local", max_age = "1h" } }
cached = { fallback = ["vault"], cache = { provider = "local", max_age = "30m" } }
credential = { uri = "vault://secret", credentials = { token = { provider = "local", ref = { item = "token" } } } }
[profiles.default.defaults]
required = false
providers = ["local"]
[profiles.default]
TOKEN = { description = "API token", required = true, type = "password", generate = { length = 32, charset = "ascii" }, prompt = false }
FALLBACK = { default = "local" }
COMPOSED = { composed = "${TOKEN}" }
GROUP = { required = { at_least_one = "auth", exactly_one = ["login"] } }
FILE = { as_path = true, encoding = "base64", ref = { item = "file", field = "value", vault = "prod", section = "keys", version = "1" } }
EXTRACTED = { refs = { vault = { item = "data" } }, extract = { format = "json", pointer = "/token" } }
PGP = { type = "openpgp_private_key", generate = { user_id = "Test <test@example.com>", algorithm = "rsa", bits = 3072, capabilities = ["sign"] } }
SSH = { type = "ssh_private_key", generate = { comment = "test" } }
[profiles.production.defaults]
inherit = false
default = "production"
[profiles.production]
TOKEN = { generate = true, type = "hex" }
[scopes.api]
secrets = ["TOKEN"]
"#;
    // Exercise the actual TOML deserializer as well as the editor schema.
    let _: Config = toml::from_str(document).unwrap();
    let value: Value = toml::from_str(document).unwrap();
    validate(&schema("secretspec"), &value);
}

#[test]
fn config_schemas_cover_user_syntax_and_share_provider_definitions() {
    let project = schema("secretspec");
    let user = schema("config");
    for name in [
        "NativeAddress",
        "NativeAddressTemplate",
        "ProviderCache",
        "CredentialSource",
        "ProviderAlias",
    ] {
        assert!(project["definitions"][name].is_object(), "missing {name}");
        assert_eq!(user["definitions"][name], project["definitions"][name]);
    }
    validate(&user, &json!({}));
    validate(
        &user,
        &json!({
            "defaults": {"profile": "production", "provider": "local", "providers": {
                "local": "dotenv://.env",
                "vault": {"uri": "vault://secret", "credentials": {"token": "env"}}
            }},
            "audit": {"enabled": false, "path": "~/audit.log", "max_size_bytes": 1024}
        }),
    );
}

#[test]
fn config_schemas_cli_matches_published_files_without_loading_configuration() {
    // `cargo package` always adds Cargo.toml.orig. The documentation site's
    // copies exist only in the repository checkout, not in the published crate.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let in_repository = !manifest_dir.join("Cargo.toml.orig").exists();
    let directory = tempfile::tempdir().unwrap();
    // Neither a broken nearby manifest nor an explicit nonexistent path should
    // matter when exporting the configuration format itself.
    std::fs::write(directory.path().join("secretspec.toml"), "not valid TOML").unwrap();
    for (kind, filename) in [("project", "secretspec"), ("global", "config")] {
        let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
            .current_dir(directory.path())
            .args(["--file", "missing.toml", "schema", "--config", kind])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let generated = String::from_utf8(output.stdout).unwrap();
        assert_eq!(generated, generate(kind));
        if in_repository {
            let path = manifest_dir
                .join("../docs/public/schema")
                .join(format!("{filename}.schema.json"));
            assert_eq!(
                generated,
                std::fs::read_to_string(path).unwrap(),
                "regenerate with secretspec schema --config {kind} --output docs/public/schema/{filename}.schema.json"
            );
        }

        let path = directory.path().join(format!("{filename}.json"));
        let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
            .current_dir(directory.path())
            .args(["schema", "--config", kind, "--output"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read_to_string(path).unwrap(), generated);
    }

    for args in [
        vec!["schema", "--config", "project", "--profile", "default"],
        vec!["schema", "--config", "invalid"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
            .current_dir(directory.path())
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn config_schemas_reject_invalid_shapes_and_typos() {
    let project_schema = schema("secretspec");
    let validator = jsonschema::validator_for(&project_schema).unwrap();
    let base = json!({"project": {"name": "test", "revision": "1.0"}, "profiles": {"default": {}}});
    validate(&project_schema, &base);
    for secret in [
        json!("not a table"),
        json!({"requred": true}),
        json!({"required": "yes"}),
        json!({"required": {}}),
        json!({"required": {"exactly_one": 1}}),
        json!({"encoding": "rot13"}),
        json!({"encoding": null}),
        json!({"ref": "vault://item"}),
        json!({"ref": {"field": "password"}}),
        json!({"ref": {"item": "a"}, "refs": {"local": {"item": "b"}}}),
        json!({"extract": {"format": "xml", "pointer": "/a"}}),
        json!({"generate": {"length": "32"}}),
        json!({"generate": {"algorithm": "unknown"}}),
    ] {
        let mut document = base.clone();
        document["profiles"]["default"]["TOKEN"] = secret;
        assert!(!validator.is_valid(&document), "{document}");
    }
    for document in [
        json!({"project": {"name": "test", "revision": "1.0"}, "profiles": {}}),
        json!({"project": {"name": "test"}, "profiles": {"default": {}}}),
        json!({"project": {"name": "test", "revision": "1.0"}, "profiles": {"default": {"defaults": {"required": "yes"}}}}),
    ] {
        assert!(!validator.is_valid(&document), "{document}");
    }
    for provider in [
        json!({"uri": "env://", "fallback": ["local"]}),
        json!({"fallback": ["local"]}),
        json!({"fallback": [], "cache": {"provider": "local", "max_age": "1h"}}),
        json!({"uri": "env://", "ref": {"item": "a"}, "cache": {"provider": "local", "max_age": "1h"}}),
    ] {
        let mut document = base.clone();
        document["providers"] = json!({"invalid": provider});
        assert!(!validator.is_valid(&document), "{document}");
    }
    let user_schema = schema("config");
    let user = jsonschema::validator_for(&user_schema).unwrap();
    for document in [
        base,
        json!({"defaults": {"profiles": "default"}}),
        json!({"audit": {"enabled": "false"}}),
        json!({"audit": {"max_size_bytes": -1}}),
    ] {
        assert!(!user.is_valid(&document), "{document}");
    }
}
