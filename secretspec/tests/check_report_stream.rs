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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if args.first() == Some(&"get") {
        command = Command::new("sh");
        command.args([
            "-c",
            r#"path=$("$@") || exit; printf '%s\n' "$path"; cat "$path""#,
            "sh",
            env!("CARGO_BIN_EXE_secretspec"),
        ]);
    }
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_keeps_the_as_path_file_it_prints() {
    let project = project_with(true);
    let output = run(project.path(), true, &["get", SECRET_NAME]);

    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = stdout(&output);
    let (printed, value) = stdout.split_once('\n').unwrap();
    let printed = PathBuf::from(printed);
    assert!(temp_files(project.path()).is_empty());
    assert_eq!(value, "postgres://localhost/example");
    let metadata = project
        .path()
        .join("Library/Application Support/file-lease");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while (printed.exists()
        || fs::read_dir(&metadata).is_ok_and(|mut entries| entries.next().is_some()))
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!printed.exists());
    assert!(fs::read_dir(metadata).map_or(true, |mut entries| entries.next().is_none()));
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn check_leaves_no_as_path_files_behind() {
    let project = project_with(true);
    let output = run_check(project.path(), true);

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(temp_files(project.path()), Vec::<PathBuf>::new());
}

#[test]
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unsupported_file_delivery_never_falls_back_to_temporary_files() {
    let project = project_with(true);
    let output = run_check(project.path(), true);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("requires Linux or macOS"));
    assert!(temp_files(project.path()).is_empty());
}
