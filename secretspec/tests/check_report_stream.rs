use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SECRET_NAME: &str = "SECRETSPEC_CHECK_STREAM_DATABASE_URL";

fn config_home(project: &Path) -> PathBuf {
    project.join("config")
}

fn run_check(project: &Path, present: bool) -> Output {
    run(project, present, &["check", "--no-prompt"])
}

fn run(project: &Path, present: bool, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .args(["--file", project.join("secretspec.toml").to_str().unwrap()])
        .args(args)
        .args(["--provider", "env"])
        .current_dir(project)
        .env("TMPDIR", temp_dir(project))
        .env("TMP", temp_dir(project))
        .env("TEMP", temp_dir(project))
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

fn temp_dir(project: &Path) -> PathBuf {
    project.join("tmp")
}

fn project() -> tempfile::TempDir {
    project_with(false)
}

fn project_with(as_path: bool) -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    fs::create_dir(temp_dir(project.path())).unwrap();
    fs::write(
        project.path().join("secretspec.toml"),
        format!(
            r#"[project]
name = "stream-test"
revision = "1.0"
require_reason = false

[profiles.default]
{SECRET_NAME} = {{ description = "database URL", as_path = {as_path} }}
"#
        ),
    )
    .unwrap();
    project
}

fn temp_files(project: &Path) -> Vec<PathBuf> {
    fs::read_dir(temp_dir(project))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
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

#[test]
fn get_keeps_the_as_path_file_it_prints() {
    let project = project_with(true);
    let output = run(project.path(), true, &["get", SECRET_NAME]);

    assert!(output.status.success(), "{}", stderr(&output));
    let printed = PathBuf::from(stdout(&output).trim());
    assert_eq!(temp_files(project.path()), vec![printed.clone()]);
    assert_eq!(
        fs::read_to_string(printed).unwrap(),
        "postgres://localhost/example"
    );
}

#[test]
fn check_leaves_no_as_path_files_behind() {
    let project = project_with(true);
    let output = run_check(project.path(), true);

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(temp_files(project.path()), Vec::<PathBuf>::new());
}
