#![cfg(feature = "cli")]

use std::fs;
use std::process::Command;

#[test]
fn unknown_secret_fields_warn_without_rejecting_the_manifest_or_printing_values() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path();
    let manifest = path.join("secretspec.toml");
    let header = r#"[project]
name = "config-warnings"
revision = "1.0"
require_reason = false

[profiles.default]
REPO_PATH = { description = "Repository path", default = "c:/ws/my-repo", providers = ["null"] }
"#;
    for (declaration, expected_value, warns) in [
        (
            r#"TEMP_HOME = { description = "Temporary home", default = "fallback", compose = "${REPO_PATH}/.tmp", metadata = { nested = ["private-sentinel", 42] }, providers = ["null"] }"#,
            "fallback",
            true,
        ),
        (
            r#"TEMP_HOME = { description = "Temporary home", composed = "${REPO_PATH}/.tmp" }"#,
            "c:/ws/my-repo/.tmp",
            false,
        ),
    ] {
        fs::write(&manifest, format!("{header}{declaration}\n")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
            .args(["--file", manifest.to_str().unwrap(), "export"])
            .current_dir(path)
            .env("HOME", path)
            .env("XDG_CONFIG_HOME", path.join("config"))
            .env("XDG_STATE_HOME", path.join("state"))
            .env("APPDATA", path.join("config"))
            .env("LOCALAPPDATA", path.join("state"))
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_SCOPE")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stderr}");
        assert!(
            stdout.contains(&format!("TEMP_HOME='{expected_value}'")),
            "{stdout}"
        );
        assert!(!stderr.contains("private-sentinel"), "{stderr}");
        assert!(!stderr.contains("${REPO_PATH}"), "{stderr}");
        if warns {
            assert!(
                stderr.contains("ignoring unknown secret field `compose`"),
                "{stderr}"
            );
            assert!(stderr.contains("Did you mean `composed`?"), "{stderr}");
            assert!(
                stderr.contains("ignoring unknown secret field `metadata`"),
                "{stderr}"
            );
            for warning in stderr
                .lines()
                .filter(|line| line.contains("unknown secret field"))
            {
                assert!(
                    warning
                        .contains("This field may be supported in a newer version of SecretSpec."),
                    "{warning}"
                );
            }
            assert!(!stdout.contains("warning:"), "{stdout}");
        } else {
            assert!(!stderr.contains("unknown secret field"), "{stderr}");
        }
    }
}
