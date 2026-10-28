//! Check the spawned environment using this test binary as a portable child.
#![cfg(feature = "cli")]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const OVERRIDES: [&str; 5] = [
    "SECRETSPEC_FILE",
    "SECRETSPEC_PROFILE",
    "SECRETSPEC_PROVIDER",
    "SECRETSPEC_SCOPE",
    "SECRETSPEC_REASON",
];

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("secretspec.toml"),
        r#"[project]
name = "outer-project"
revision = "1.0"
require_reason = true

[profiles.default]
VISIBLE = { description = "Injected secret", default = "default-value", providers = ["null"] }
HIDDEN = { description = "Scope-excluded secret", default = "hidden-value", providers = ["null"] }

[profiles.production]
VISIBLE = { default = "production-value" }

[scopes]
api = { secrets = ["VISIBLE"] }
"#,
    )
    .unwrap();
    dir
}

fn command(project: &Path) -> Command {
    let manifest = project.join("secretspec.toml");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    cmd.arg("run")
        .current_dir(project)
        .env("HOME", project)
        .env("XDG_CONFIG_HOME", project.join("config"))
        .env("XDG_STATE_HOME", project.join("state"))
        .env("APPDATA", project.join("config"))
        .env("LOCALAPPDATA", project.join("state"))
        .env("SECRETSPEC_FILE", &manifest)
        .env("SECRETSPEC_PROFILE", "production")
        .env("SECRETSPEC_PROVIDER", "null")
        .env("SECRETSPEC_SCOPE", "api")
        .env("SECRETSPEC_REASON", "outer-reason")
        .env("SECRETSPEC_UNRELATED", "passthrough")
        .env("APPLICATION_SETTING", "preserved")
        .env("HIDDEN", "inherited-hidden-value")
        .env("EXPECTED_MANIFEST", manifest)
        .env("EXPECTED_PROFILE", "production");
    cmd
}

fn probe(cmd: &mut Command, mode: &str) -> Output {
    cmd.env("CONFIG_ENV_PROBE", mode)
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "environment_child", "--ignored", "--nocapture"])
        .output()
        .unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "child failed with {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[ignore = "helper executed by secretspec run"]
fn environment_child() {
    let mode = std::env::var("CONFIG_ENV_PROBE").unwrap();
    if mode.starts_with("clear") {
        for key in OVERRIDES {
            assert!(std::env::var_os(key).is_none(), "{key} reached the child");
        }
    } else {
        for (key, expected) in [
            (
                "SECRETSPEC_FILE",
                std::env::var("EXPECTED_MANIFEST").unwrap(),
            ),
            (
                "SECRETSPEC_PROFILE",
                std::env::var("EXPECTED_PROFILE").unwrap(),
            ),
            ("SECRETSPEC_PROVIDER", "null".into()),
            ("SECRETSPEC_SCOPE", "api".into()),
            ("SECRETSPEC_REASON", "outer-reason".into()),
        ] {
            assert_eq!(std::env::var(key).unwrap(), expected, "{key}");
        }
    }
    assert_eq!(std::env::var("VISIBLE").unwrap(), "production-value");
    assert_eq!(
        std::env::var("SECRETSPEC_UNRELATED").unwrap(),
        "passthrough"
    );
    assert_eq!(std::env::var("APPLICATION_SETTING").unwrap(), "preserved");
    if mode == "clear-collisions" {
        assert_eq!(std::env::var("HIDDEN").unwrap(), "hidden-value");
    } else {
        assert!(std::env::var_os("HIDDEN").is_none());
    }
    #[cfg(unix)]
    if mode == "clear-non-utf8" {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            std::env::var_os("NON_UTF8_SETTING").unwrap().into_vec(),
            b"fo\x80"
        );
    }
}

#[test]
fn default_inherits_configuration_and_still_filters_scope_exclusions() {
    let project = project();
    success(&probe(&mut command(project.path()), "inherit"));
}

#[test]
fn explicit_inherit_preserves_ambient_values_instead_of_exporting_cli_overrides() {
    let project = project();
    let mut cmd = command(project.path());
    cmd.args(["--config-env=inherit", "--profile", "production"])
        .env("SECRETSPEC_PROFILE", "default")
        .env("EXPECTED_PROFILE", "default");
    success(&probe(&mut cmd, "inherit"));
}

#[test]
fn clear_removes_all_five_overrides_but_keeps_injected_secrets_and_other_environment() {
    let project = project();
    let mut cmd = command(project.path());
    cmd.args(["--config-env", "clear"]);
    success(&probe(&mut cmd, "clear"));
}

#[test]
fn clear_does_not_bypass_the_outer_access_reason_requirement() {
    let project = project();
    let mut cmd = command(project.path());
    cmd.arg("--config-env=clear")
        .env_remove("SECRETSPEC_REASON");
    let output = probe(&mut cmd, "clear");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("reason"));
}

#[test]
fn unknown_configuration_policy_is_rejected() {
    let project = project();
    let mut cmd = command(project.path());
    cmd.arg("--config-env=unknown");
    let output = probe(&mut cmd, "clear");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value"));
}

#[test]
fn clear_also_removes_overrides_declared_as_application_secrets() {
    let project = project();
    let manifest = project.path().join("secretspec.toml");
    let declarations = OVERRIDES.iter().map(|key| format!(
        "{key} = {{ description = 'Reserved override', default = 'overlaid-value', providers = ['null'] }}\n"
    )).collect::<String>();
    let source = fs::read_to_string(&manifest).unwrap().replace(
        "[profiles.production]\n",
        &format!("[profiles.production]\n{declarations}"),
    );
    fs::write(&manifest, source).unwrap();
    let audit_path = project.path().join("audit.jsonl");
    let config_dir = project.path().join(if cfg!(windows) {
        "config/secretspec/config"
    } else {
        "config/secretspec"
    });
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        toml::to_string(&serde_json::json!({"audit": {"path": audit_path}})).unwrap(),
    )
    .unwrap();
    let mut cmd = command(project.path());
    cmd.args(["--config-env=clear", "--scope", ""]);
    success(&probe(&mut cmd, "clear-collisions"));
    let events = fs::read_to_string(audit_path).unwrap();
    let run_event = events
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["action"] == "run")
        .unwrap();
    assert_eq!(run_event["keys"], serde_json::json!(["HIDDEN", "VISIBLE"]));
}

#[test]
fn nested_invocations_discover_their_own_project_only_when_configuration_is_cleared() {
    let outer = project();
    let inner = tempfile::tempdir().unwrap();
    fs::write(
        inner.path().join("secretspec.toml"),
        r#"[project]
name = "inner-project"
revision = "1.0"
require_reason = false
[profiles.default]
INNER_VALUE = { description = "Inner value", default = "inner-project-value", providers = ["null"] }
"#,
    )
    .unwrap();
    for (mode, expected_key) in [("inherit", "VISIBLE"), ("clear", "INNER_VALUE")] {
        let output = command(outer.path())
            .current_dir(inner.path())
            .arg(format!("--config-env={mode}"))
            .arg("--")
            .arg(env!("CARGO_BIN_EXE_secretspec"))
            .args(["export", "--format", "json"])
            .output()
            .unwrap();
        success(&output);
        let values: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            values.as_object().unwrap().keys().collect::<Vec<_>>(),
            [expected_key]
        );
    }
}

#[cfg(unix)]
#[test]
fn clear_preserves_unrelated_non_utf8_environment() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let project = project();
    let mut cmd = command(project.path());
    cmd.arg("--config-env=clear")
        .env("NON_UTF8_SETTING", OsString::from_vec(b"fo\x80".to_vec()));
    success(&probe(&mut cmd, "clear-non-utf8"));
}
