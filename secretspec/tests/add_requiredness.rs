#![cfg(feature = "cli")]

use std::fs;
use std::path::Path;
use std::process::Command;

const SECRET_NAME: &str = "SECRETSPEC_ADD_REQUIREDNESS_TOKEN";

fn command(project: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .current_dir(project)
        .env("HOME", project)
        .env("XDG_CONFIG_HOME", project.join("config"))
        .env("APPDATA", project.join("config"))
        .env("XDG_STATE_HOME", project.join("state"))
        .env("LOCALAPPDATA", project.join("state"))
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .env_remove(SECRET_NAME);
    command
}

#[test]
fn add_requiredness_overrides_profile_defaults_and_controls_check() {
    for default_required in [false, true] {
        for (flag, required) in [
            (None, None),
            (Some("--optional"), Some(false)),
            (Some("--required"), Some(true)),
        ] {
            let project = tempfile::tempdir().unwrap();
            let manifest = project.path().join("secretspec.toml");
            fs::write(
                &manifest,
                format!(
                    r#"[project]
name = "add-requiredness"
revision = "1.0"
require_reason = false

[profiles.default]
BASELINE = {{ description = "Baseline secret", default = "present" }}

[profiles.production]
defaults = {{ required = {default_required} }}
PROFILE_BASELINE = {{ description = "Profile baseline", default = "present" }}
"#
                ),
            )
            .unwrap();

            let mut add = command(project.path());
            add.args(["add", SECRET_NAME, "-d", "Test token", "-P", "production"]);
            if let Some(flag) = flag {
                add.arg(flag);
            }
            let output = add.output().unwrap();
            assert!(
                output.status.success(),
                "default {default_required}, flag {flag:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let config: toml::Value =
                toml::from_str(&fs::read_to_string(&manifest).unwrap()).unwrap();
            assert_eq!(
                config["profiles"]["production"][SECRET_NAME]
                    .get("required")
                    .and_then(toml::Value::as_bool),
                required
            );
            assert!(config["profiles"]["default"].get(SECRET_NAME).is_none());

            let output = command(project.path())
                .args([
                    "check",
                    "--no-prompt",
                    "--provider",
                    "env://",
                    "-P",
                    "production",
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(i32::from(required.unwrap_or(default_required))),
                "default {default_required}, flag {flag:?}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
