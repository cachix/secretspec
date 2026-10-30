#![cfg(feature = "cli")]

use std::fs;
use std::process::Command;

#[test]
fn undeclared_secret_diagnostics_are_not_wrapped_twice() {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("secretspec.toml"),
        r#"[project]
name = "undeclared-test"
revision = "1.0"
require_reason = false

[profiles.default]
DECLARED = { description = "A declared secret" }
"#,
    )
    .unwrap();

    for args in [
        vec!["set", "UNDECLARED", "value", "--provider", "dotenv://.env"],
        vec!["delete", "UNDECLARED", "--provider", "dotenv://.env"],
        vec!["cache", "clear", "UNDECLARED"],
        vec!["get", "UNDECLARED", "--provider", "dotenv://.env"],
        vec!["get", "DECLARED", "--provider", "dotenv://.env"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
            .args(&args)
            .current_dir(project.path())
            .env("HOME", project.path())
            .env("XDG_CONFIG_HOME", project.path().join("config"))
            .env("APPDATA", project.path().join("config"))
            .env("XDG_STATE_HOME", project.path().join("state"))
            .env("LOCALAPPDATA", project.path().join("state"))
            .env("NO_COLOR", "1")
            .env_remove("SECRETSPEC_FILE")
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_SCOPE")
            .env_remove("SECRETSPEC_REASON")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        // Ignore diagnostic borders and line wrapping while checking the full
        // message actually rendered by the CLI.
        let message = stderr
            .split_whitespace()
            .filter(|word| !matches!(*word, "×" | "│" | "╰─▶"))
            .collect::<Vec<_>>()
            .join(" ");
        let expected = if args[0] == "get" {
            format!("Secret '{}' not found", args[1])
        } else {
            "Secret 'UNDECLARED' is not defined in profile 'default'. Available secrets: DECLARED"
                .to_string()
        };
        assert!(message.contains(&expected), "{args:?}: {stderr}");
        assert!(!message.contains("Secret 'Secret '"), "{stderr}");
        assert!(!project.path().join(".env").exists());
    }
}
