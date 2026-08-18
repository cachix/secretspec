//! A closed output pipe should terminate the CLI quietly, the way any other
//! Unix tool does — `secretspec export | head` must not report an error.
//!
//! Rust's runtime ignores `SIGPIPE`, so without an explicit reset the write
//! returns `EPIPE` instead: `export` surfaces it as `IO error: Broken pipe`
//! and `check --json` panics out of `println!`.

#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

/// `SIGPIPE`. Hardcoded so the test needs no `libc` dev-dependency.
const SIGPIPE: i32 = 13;

/// Output big enough that the child keeps writing after the ~64KiB pipe
/// buffer fills — otherwise everything fits and the pipe never breaks.
/// `check --json` emits roughly 200 bytes per secret regardless of value
/// size, so the count is what has to carry that path over the threshold.
const SECRET_COUNT: usize = 500;
const SECRET_LEN: usize = 200;

/// Runs `secretspec <args>`, reads a few bytes, then closes the pipe.
fn run_with_closed_stdout(args: &[&str]) -> std::process::Output {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("secretspec.toml");

    let mut config = String::from(
        r#"[project]
name = "sigpipe-test"
revision = "1.0"
require_reason = false

[providers]
env = "env://"

[profiles.default]
"#,
    );
    for i in 0..SECRET_COUNT {
        config.push_str(&format!(
            "SECRET_{i} = {{ description = \"secret {i}\", providers = [\"env\"] }}\n"
        ));
    }
    fs::write(&config_path, config).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .args(["--file", config_path.to_str().unwrap()])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for i in 0..SECRET_COUNT {
        command.env(format!("SECRET_{i}"), "v".repeat(SECRET_LEN));
    }

    let mut child = command.spawn().unwrap();

    // Consume a little, then drop the read end. The child's next write to a
    // pipe with no reader is what raises SIGPIPE.
    let mut stdout = child.stdout.take().unwrap();
    let mut head = [0u8; 16];
    stdout.read_exact(&mut head).unwrap();
    drop(stdout);

    child.wait_with_output().unwrap()
}

#[test]
fn export_dies_on_sigpipe_instead_of_reporting_a_broken_pipe() {
    let output = run_with_closed_stdout(&["export", "--provider", "env", "--format", "dotenv"]);

    assert_eq!(
        output.status.signal(),
        Some(SIGPIPE),
        "expected termination by SIGPIPE, got {}:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "a closed pipe should be silent, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_json_dies_on_sigpipe_instead_of_panicking() {
    let output = run_with_closed_stdout(&["check", "--provider", "env", "--json"]);

    assert_eq!(
        output.status.signal(),
        Some(SIGPIPE),
        "expected termination by SIGPIPE, got {}:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "a closed pipe should be silent, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
