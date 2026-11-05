#![cfg(feature = "cli")]

use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("secretspec.toml"),
        r#"
[project]
name = "computed-config"
revision = "1.0"
require_reason = true

[profiles.default]
API_KEY = { description = "Never fetched", default = "secret-value-sentinel" }

[profiles.production]

[scopes]
api = { secrets = ["API_KEY"] }

[providers]
shared = "env://"
project_only = "dotenv://.env"
"#,
    )
    .unwrap();
    dir
}

fn command(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("APPDATA", dir.join("config"))
        .env("LOCALAPPDATA", dir.join("state"));
    for name in ["FILE", "PROFILE", "PROVIDER", "SCOPE", "REASON"] {
        cmd.env_remove(format!("SECRETSPEC_{name}"));
    }
    cmd
}

fn global(dir: &Path) {
    let path = dir.join(if cfg!(windows) {
        "config/secretspec/config"
    } else {
        "config/secretspec"
    });
    fs::create_dir_all(&path).unwrap();
    fs::write(
        path.join("config.toml"),
        r#"
[defaults]
profile = "production"
provider = "shared"

[defaults.providers]
shared = "dotenv://global.env"
global_only = "env://"
"#,
    )
    .unwrap();
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-value-sentinel"));
}

#[test]
fn computed_show_uses_defaults_without_accessing_secrets_or_creating_audit_state() {
    let dir = project();
    let output = command(dir.path())
        .args(["config", "show", "--json"])
        .output()
        .unwrap();
    success(&output);
    let report = report(&output);
    assert_eq!(
        report["profile"],
        json!({"value": "default", "source": "default"})
    );
    assert_eq!(report["provider"]["value"], Value::Null);
    assert_eq!(report["scope"]["value"], Value::Null);
    assert_eq!(report["reason"]["value"], Value::Null);
    assert_eq!(report["manifest"]["source"], "discovery");
    assert!(!dir.path().join("state").exists());
    assert!(!dir.path().join("config").exists());
}

#[test]
fn merges_global_defaults_and_aliases_with_project_aliases_winning() {
    let dir = project();
    global(dir.path());
    let output = command(dir.path())
        .args(["config", "show", "--json"])
        .output()
        .unwrap();
    success(&output);
    let report = report(&output);
    assert_eq!(report["profile"]["value"], "production");
    assert!(
        report["profile"]["source"]
            .as_str()
            .unwrap()
            .contains("[defaults.profile]")
    );
    assert_eq!(report["provider"]["value"], "shared");
    assert_eq!(report["provider_is_override"], false);
    let aliases = &report["provider_aliases"];
    assert_eq!(aliases["shared"]["value"], "env://");
    assert!(
        aliases["shared"]["source"]
            .as_str()
            .unwrap()
            .contains("[providers]")
    );
    assert_eq!(aliases["global_only"]["value"], "env://");
    assert!(
        aliases["global_only"]["source"]
            .as_str()
            .unwrap()
            .contains("[defaults.providers]")
    );
    assert_eq!(aliases["project_only"]["value"], "dotenv://.env");
}

#[test]
fn attributes_all_five_environment_overrides_and_exposes_discovery_disagreement() {
    let dir = project();
    let outer = project();
    let selected = outer.path().join("secretspec.toml");
    let output = command(dir.path())
        .args(["config", "show", "--json"])
        .env("SECRETSPEC_FILE", &selected)
        .env("SECRETSPEC_PROFILE", "production")
        .env(
            "SECRETSPEC_PROVIDER",
            "provider-that-must-not-be-constructed://",
        )
        .env("SECRETSPEC_SCOPE", "api")
        .env("SECRETSPEC_REASON", "  editor session  ")
        .output()
        .unwrap();
    success(&output);
    let report = report(&output);
    for (field, env) in [
        ("manifest", "FILE"),
        ("profile", "PROFILE"),
        ("provider", "PROVIDER"),
        ("scope", "SCOPE"),
        ("reason", "REASON"),
    ] {
        assert_eq!(report[field]["source"], format!("SECRETSPEC_{env}"));
    }
    assert_eq!(report["manifest"]["value"], selected.to_str().unwrap());
    assert!(
        same_file::is_same_file(
            report["discovered_manifest"].as_str().unwrap(),
            dir.path().join("secretspec.toml"),
        )
        .unwrap()
    );
    assert_eq!(report["reason"]["value"], "editor session");
    assert_eq!(report["provider_is_override"], true);
}

#[test]
fn explicit_flags_win_over_environment_and_blank_scope_and_reason_clear_them() {
    let dir = project();
    let output = command(dir.path())
        .args([
            "--file",
            dir.path().join("secretspec.toml").to_str().unwrap(),
            "config",
            "show",
            "--json",
            "--profile",
            "default",
            "--provider",
            "env",
            "--scope",
            "",
            "--reason",
            "",
        ])
        .env("SECRETSPEC_FILE", "/missing/manifest.toml")
        .env("SECRETSPEC_PROFILE", "undefined-profile")
        .env("SECRETSPEC_PROVIDER", "wrong-provider")
        .env("SECRETSPEC_SCOPE", "undefined-scope")
        .env("SECRETSPEC_REASON", "wrong reason")
        .output()
        .unwrap();
    success(&output);
    let report = report(&output);
    for (field, flag) in [
        ("manifest", "file"),
        ("profile", "profile"),
        ("provider", "provider"),
        ("scope", "scope"),
        ("reason", "reason"),
    ] {
        assert_eq!(report[field]["source"], format!("--{flag}"));
    }
    assert_eq!(report["profile"]["value"], "default");
    assert_eq!(report["provider"]["value"], "env");
    assert_eq!(report["scope"]["value"], Value::Null);
    assert_eq!(report["reason"]["value"], Value::Null);
}

#[test]
fn ignored_blank_provider_and_profile_flags_retain_ambient_provenance() {
    let dir = project();
    let output = command(dir.path())
        .args([
            "config",
            "show",
            "--json",
            "--profile",
            " ",
            "--provider",
            "",
        ])
        .env("SECRETSPEC_PROFILE", "production")
        .env("SECRETSPEC_PROVIDER", "env")
        .output()
        .unwrap();
    success(&output);
    let report = report(&output);
    assert_eq!(
        report["profile"],
        json!({"value": "production", "source": "SECRETSPEC_PROFILE"})
    );
    assert_eq!(
        report["provider"],
        json!({"value": "env", "source": "SECRETSPEC_PROVIDER"})
    );
}

#[test]
fn invalid_profile_and_scope_still_print_the_computed_selection() {
    for (field, env) in [
        ("profile", "SECRETSPEC_PROFILE"),
        ("scope", "SECRETSPEC_SCOPE"),
    ] {
        let dir = project();
        let output = command(dir.path())
            .args(["config", "show", "--json"])
            .env(env, "undefined-selection")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let report = report(&output);
        assert_eq!(
            report[field],
            json!({"value": "undefined-selection", "source": env})
        );
        assert!(
            report["errors"][0]
                .as_str()
                .unwrap()
                .contains("undefined-selection")
        );
    }
}

#[test]
fn text_and_json_redact_provider_credentials_and_never_print_secret_defaults() {
    let dir = project();
    let manifest = dir.path().join("secretspec.toml");
    let mut source = fs::read_to_string(&manifest).unwrap();
    source.push_str(
        "credential_uri = 'vault://user:credential-sentinel@host?token=query-sentinel'\n",
    );
    fs::write(&manifest, source).unwrap();
    for args in [vec!["config", "show"], vec!["config", "show", "--json"]] {
        let output = command(dir.path())
            .args(args)
            .env(
                "SECRETSPEC_PROVIDER",
                "vault://user:credential-sentinel@host?token=query-sentinel",
            )
            .output()
            .unwrap();
        success(&output);
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("vault://host"), "{text}");
        assert!(!text.contains("credential-sentinel"), "{text}");
        assert!(!text.contains("query-sentinel"), "{text}");
    }
}

#[test]
fn global_show_keeps_its_saved_configuration_view_without_a_project() {
    let dir = tempfile::tempdir().unwrap();
    global(dir.path());
    let output = command(dir.path())
        .args(["config", "global", "show"])
        .output()
        .unwrap();
    success(&output);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Profile:  production"), "{text}");
    assert!(text.contains("shared = dotenv://global.env"), "{text}");
    assert!(!text.contains("Manifest:"), "{text}");
}
