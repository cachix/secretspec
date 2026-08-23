use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SECRET_NAME: &str = "SECRETSPEC_CHECK_STREAM_DATABASE_URL";

fn config_home(project: &Path) -> PathBuf {
    project.join("config")
}

fn run_check(project: &Path, present: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .args([
            "--file",
            project.join("secretspec.toml").to_str().unwrap(),
            "check",
            "--no-prompt",
            "--provider",
            "env",
        ])
        .current_dir(project)
        .env("HOME", project)
        .env("XDG_CONFIG_HOME", config_home(project))
        .env("XDG_STATE_HOME", project.join("state"))
        .env("APPDATA", config_home(project))
        .env("LOCALAPPDATA", project.join("state"))
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .env_remove(SECRET_NAME);

    if present {
        command.env(SECRET_NAME, "postgres://localhost/example");
    }

    command.output().expect("run secretspec check")
}

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("secretspec.toml"),
        format!(
            r#"[project]
name = "stream-test"
revision = "1.0"
require_reason = false

[profiles.default]
{SECRET_NAME} = {{ description = "database URL" }}
"#
        ),
    )
    .unwrap();
    project
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn passing_check_writes_the_report_to_stdout() {
    let project = project();
    let output = run_check(project.path(), true);

    assert!(
        output.status.success(),
        "check failed with {}:\n{}",
        output.status,
        stderr(&output)
    );
    assert!(stdout(&output).contains("Checking secrets in stream-test"));
    assert!(stdout(&output).contains(SECRET_NAME));
    assert!(stdout(&output).contains("Summary:"));
    assert!(!stderr(&output).contains("Checking secrets in stream-test"));
    assert!(!stderr(&output).contains("Summary:"));
}

#[test]
fn failing_check_keeps_the_report_separate_from_diagnostics() {
    let project = project();
    let output = run_check(project.path(), false);

    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains(SECRET_NAME));
    assert!(stdout(&output).contains("Summary:"));
    assert!(!stderr(&output).contains("Summary:"));
    assert!(stderr(&output).contains("Failed to check secrets"));
}
