//! `check` must write its report to stdout, not stderr.
//!
//! The report is the output the user asked for, so `secretspec check | grep
//! ...` has to see it. It previously went to stderr in its entirety, which
//! made every pipeline silently observe an empty report while the text
//! appeared on the terminal anyway.
//!
//! These assert the stream split rather than the wording: the report on
//! stdout, diagnostics and the failure message on stderr, and the exit codes
//! unchanged in both directions.
//!
//! One of them guards the hazard that moving to stdout introduced: a reader
//! that closes the pipe early (`check | head -1`) makes the next write fail
//! with EPIPE, and Rust's `println!` *panics* on that. Writing through a sink
//! turns it into an ordinary error instead.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const MANIFEST: &str = r#"
[project]
name = "stream-demo"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "app database", required = true }
SENTRY_DSN = { description = "error reporting", required = false }
"#;

fn config_home(project: &Path) -> PathBuf {
    project.join("config")
}

/// Run `check` against a dotenv file inside the project directory.
fn run_check(project: &Path, dotenv: &str) -> Output {
    let env_path = project.join(dotenv);
    Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .args([
            "--file",
            project.join("secretspec.toml").to_str().unwrap(),
            "--reason",
            "checking the report stream",
            "check",
            "--no-prompt",
            "--provider",
            &format!("dotenv://{}", env_path.display()),
        ])
        .current_dir(project)
        // Keep the subprocess hermetic: no user aliases, defaults, profile, or
        // audit path may influence the check under test.
        .env("HOME", project)
        .env("XDG_CONFIG_HOME", config_home(project))
        .env("XDG_STATE_HOME", project.join("state"))
        // Windows ignores the XDG variables: there the config and audit
        // directories come from APPDATA and the cache from LOCALAPPDATA.
        .env("APPDATA", config_home(project))
        .env("LOCALAPPDATA", project.join("state"))
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .output()
        .expect("run secretspec check")
}

fn project_with(dotenv_name: &str, dotenv_body: &str) -> TempDir {
    let dir = TempDir::new().expect("temp project");
    fs::write(dir.path().join("secretspec.toml"), MANIFEST).unwrap();
    fs::write(dir.path().join(dotenv_name), dotenv_body).unwrap();
    dir
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_passing_check_writes_its_whole_report_to_stdout() {
    let project = project_with(".env", "DATABASE_URL=postgres://localhost/demo\n");
    let output = run_check(project.path(), ".env");

    assert!(
        output.status.success(),
        "check should succeed, got {}:\n{}",
        output.status,
        stderr(&output)
    );

    let out = stdout(&output);
    assert!(
        out.contains("Checking secrets in stream-demo"),
        "header missing from stdout:\n{out}"
    );
    assert!(
        out.contains("DATABASE_URL"),
        "per-secret line missing from stdout:\n{out}"
    );
    assert!(
        out.contains("Summary:"),
        "summary missing from stdout:\n{out}"
    );

    // The whole point: a pipeline reading stdout sees the report, and nothing
    // of it is duplicated onto stderr.
    let err = stderr(&output);
    assert!(
        !err.contains("Checking secrets in"),
        "report leaked onto stderr:\n{err}"
    );
    assert!(
        !err.contains("Summary:"),
        "summary leaked onto stderr:\n{err}"
    );
}

#[test]
fn a_failing_check_reports_on_stdout_but_errors_on_stderr() {
    // An empty store leaves the required secret unset.
    let project = project_with("empty.env", "");
    let output = run_check(project.path(), "empty.env");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a missing required secret must still exit 1"
    );

    let out = stdout(&output);
    assert!(
        out.contains("DATABASE_URL"),
        "the report belongs on stdout even when the check fails:\n{out}"
    );
    assert!(
        out.contains("Summary:"),
        "summary missing from stdout:\n{out}"
    );

    // The failure message itself is a diagnostic and stays on stderr, so the
    // two streams remain distinguishable.
    let err = stderr(&output);
    assert!(
        err.contains("DATABASE_URL"),
        "the error naming the missing secret belongs on stderr:\n{err}"
    );
    assert!(
        !err.contains("Summary:"),
        "the report's summary must not appear on stderr:\n{err}"
    );
}

// Unix-only: this drives a real `sh` pipeline with `head`, and EPIPE is the
// Unix mechanism under test. The other two tests in this file are portable and
// do run on the Windows leg.
#[cfg(unix)]
#[test]
fn a_reader_that_closes_the_pipe_early_does_not_panic() {
    // Moving the report to stdout put it on a stream a reader can close early.
    // `println!` panics on EPIPE ("failed printing to stdout: Broken pipe"),
    // exiting 101 — so before the sink was introduced, the very pipeline this
    // change exists to enable would abort the process partway through the
    // report. Worse for the downstream broker: a panic unwinds past the audit
    // bookkeeping, stranding an operation that has an attempt event and no
    // terminal one.
    //
    // Driven through `sh` because the hazard is the shell pipeline itself: the
    // reader must exit while the writer still has lines to emit.
    let project = project_with(".env", "DATABASE_URL=postgres://localhost/demo\n");
    let env_path = project.path().join(".env");

    let script = format!(
        "{bin} --file {manifest} --reason 'closing the pipe early' \
         check --no-prompt --provider 'dotenv://{env}' | head -1",
        bin = shell_quote(env!("CARGO_BIN_EXE_secretspec")),
        manifest = shell_quote(project.path().join("secretspec.toml").to_str().unwrap()),
        env = shell_quote(env_path.to_str().unwrap()),
    );

    let output = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .current_dir(project.path())
        .env("HOME", project.path())
        .env("XDG_CONFIG_HOME", config_home(project.path()))
        .env("XDG_STATE_HOME", project.path().join("state"))
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .output()
        .expect("run the pipeline");

    let err = stderr(&output);
    assert!(
        !err.contains("panicked"),
        "check panicked on a closed pipe:\n{err}"
    );
    assert!(
        !err.contains("failed printing to stdout"),
        "check hit the `println!` EPIPE panic:\n{err}"
    );

    // `head` consumed the first line, so the pipeline itself succeeded.
    assert!(
        stdout(&output).contains("Checking secrets in stream-demo"),
        "the reader should still have received the first line: {:?}",
        stdout(&output)
    );
}

#[cfg(unix)]
/// Single-quote a path for `sh -c`. The temp paths here never contain quotes,
/// but constructing a shell command without escaping is a habit worth not
/// forming.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
