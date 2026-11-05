//! End-to-end redaction through the CLI, using this test binary as the child.
#![cfg(feature = "cli")]

use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn project(declarations: &str) -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("secretspec.toml"),
        format!(
            r#"
[project]
name = "redaction-test"
revision = "1.0"
require_reason = false
[providers]
env = "env://"
[profiles.default]
{declarations}
"#
        ),
    )
    .unwrap();
    project
}

fn command(project: &tempfile::TempDir, mode: &str) -> Command {
    command_for(project, mode, "run")
}

fn command_for(project: &tempfile::TempDir, mode: &str, subcommand: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .args([
            "--file",
            project.path().join("secretspec.toml").to_str().unwrap(),
            subcommand,
        ])
        .current_dir(project.path())
        .env("HOME", project.path())
        .env("XDG_CONFIG_HOME", project.path().join("config"))
        .env("XDG_STATE_HOME", project.path().join("state"))
        .env("APPDATA", project.path().join("config"))
        .env("LOCALAPPDATA", project.path().join("state"))
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .env("REDACTION_CHILD", mode);
    command
}

fn child(command: &mut Command) -> &mut Command {
    command
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "output_child", "--ignored", "--nocapture"])
}

#[test]
#[ignore = "helper executed by secretspec run"]
fn output_child() {
    let mode = std::env::var("REDACTION_CHILD").unwrap();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    match mode.as_str() {
        "streams" => {
            let value = std::env::var("TOKEN").unwrap();
            for _ in 0..10000 {
                out.write_all(b"out:").unwrap();
                for byte in value.bytes() {
                    out.write_all(&[byte]).unwrap();
                }
                out.write_all(b"\n").unwrap();
                err.write_all(format!("err:{value}\n").as_bytes()).unwrap();
            }
            out.write_all(value.as_bytes()).unwrap();
            err.write_all(value.as_bytes()).unwrap();
            out.flush().unwrap();
            err.flush().unwrap();
            std::process::exit(23);
        }
        "file" => {
            let path = std::env::var("TOKEN").unwrap();
            fs::write("materialized-path", &path).unwrap();
            let value = fs::read(path).unwrap();
            out.write_all(b"before:").unwrap();
            out.write_all(&value).unwrap();
            out.write_all(b":after\xff").unwrap();
        }
        "prompt" => {
            out.write_all(b"Prompt: ").unwrap();
            out.flush().unwrap();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            assert_eq!(line, "answer\n");
            out.write_all(std::env::var("TOKEN").unwrap().as_bytes())
                .unwrap();
        }
        "derived" => {
            assert!(std::env::var_os("TOKEN").is_none());
            let url = std::env::var("URL").unwrap();
            let fragment = url
                .strip_prefix("prefix:")
                .unwrap()
                .strip_suffix(":suffix")
                .unwrap();
            write!(out, "{url}\nfragment:{fragment}").unwrap();
        }
        "background" => {
            // The direct child must exit with a live descendant for this test.
            #[allow(clippy::zombie_processes)]
            let descendant = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "output_child", "--ignored", "--nocapture"])
                .env("REDACTION_CHILD", "sleep")
                .spawn()
                .unwrap();
            fs::write("descendant-pid", descendant.id().to_string()).unwrap();
        }
        "sleep" => std::thread::sleep(std::time::Duration::from_secs(3)),
        "mixed" => {
            write!(
                out,
                "first:{} second:{}",
                std::env::var("TOKEN").unwrap(),
                std::env::var("PROTECTED").unwrap()
            )
            .unwrap();
        }
        "value" => out
            .write_all(std::env::var("TOKEN").unwrap().as_bytes())
            .unwrap(),
        _ => panic!("unknown child mode"),
    }
    out.flush().unwrap();
    std::process::exit(0);
}

#[test]
fn filters_both_streams_by_default_under_load_and_preserves_exit_code() {
    let project = project(r#"TOKEN = { description = "token", providers = ["env"] }"#);
    let output = child(command(&project, "streams").env("TOKEN", "synthetic-token"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    let out = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(!out.contains("synthetic-token"));
    assert!(!err.contains("synthetic-token"));
    assert_eq!(out.matches("[REDACTED]").count(), 10001);
    assert_eq!(err.matches("[REDACTED]").count(), 10001);
    assert!(out.ends_with("[REDACTED]"));
    assert!(err.ends_with("[REDACTED]"));
}

#[test]
fn masks_decoded_binary_file_contents_and_removes_temporary_file() {
    let project = project(
        r#"TOKEN = { description = "file", providers = ["env"], encoding = "hex", as_path = true }"#,
    );
    let output = child(command(&project, "file").env("TOKEN", "ff0061"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.ends_with(b"before:[REDACTED]:after\xff"));
    let path = fs::read_to_string(project.path().join("materialized-path")).unwrap();
    assert!(!std::path::Path::new(&path).exists());
}

#[test]
fn inherited_secrets_are_also_masked() {
    let project = project(
        r#"TOKEN = { description = "token", providers = ["env"] }
[profiles.other]
TOKEN = { description = "Override description" }"#,
    );
    let output = child(
        command(&project, "value")
            .args(["--profile", "other"])
            .env("TOKEN", "synthetic-token"),
    )
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.ends_with(b"[REDACTED]"));
}

#[test]
fn masks_hidden_dependency_in_scoped_composition() {
    let project = project(
        r#"TOKEN = { description = "token", providers = ["env"] }
URL = { description = "URL", composed = "prefix:${TOKEN}:suffix" }
[scopes.api]
secrets = ["URL"]"#,
    );
    let output = child(
        command(&project, "derived")
            .args(["--scope", "api"])
            .env("TOKEN", "synthetic-token"),
    )
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.ends_with(b"[REDACTED]\nfragment:[REDACTED]"));
}

#[test]
fn safe_prompt_is_delivered_before_child_reads_inherited_stdin() {
    let project = project(r#"TOKEN = { description = "token", providers = ["env"] }"#);
    let mut process = child(command(&project, "prompt").env("TOKEN", "synthetic-token"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = process.stdout.take().unwrap();
    // Bound this handshake so a buffering regression cannot hang the test suite.
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut prefix = Vec::new();
        let mut byte = [0];
        while !prefix.ends_with(b"Prompt: ") {
            stdout.read_exact(&mut byte).unwrap();
            prefix.push(byte[0]);
        }
        tx.send(()).unwrap();
        let mut rest = Vec::new();
        stdout.read_to_end(&mut rest).unwrap();
        rest
    });
    if rx.recv_timeout(std::time::Duration::from_secs(10)).is_err() {
        let _ = process.kill();
        let _ = process.wait();
        panic!("prompt was buffered");
    }
    process
        .stdin
        .take()
        .unwrap()
        .write_all(b"answer\n")
        .unwrap();
    assert!(process.wait().unwrap().success());
    assert_eq!(reader.join().unwrap(), b"[REDACTED]");
}

#[test]
fn defaults_are_masked_but_export_still_returns_the_value() {
    let project = project(
        r#"TOKEN = { description = "token", providers = ["null"], default = "synthetic-token" }"#,
    );
    let output = child(&mut command(&project, "value")).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.ends_with(b"[REDACTED]"));
    let exported = command_for(&project, "unused", "export")
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(exported.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&exported.stdout).unwrap()["TOKEN"],
        "synthetic-token"
    );
}

#[test]
fn oversized_values_fail_before_starting_the_child() {
    let declaration = format!(
        r#"TOKEN = {{ description = "token", providers = ["null"], default = "{}" }}"#,
        "a".repeat(65537)
    );
    let project = project(&declaration);
    let output = child(&mut command(&project, "file")).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("64 KiB"));
    assert!(!project.path().join("materialized-path").exists());
}

#[test]
fn descendants_cannot_hold_output_pipes_open_indefinitely() {
    let project = project(r#"TOKEN = { description = "token", providers = ["env"] }"#);
    let output = child(command(&project, "background").env("TOKEN", "synthetic-token"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("timed out draining"));
}

#[test]
fn a_closed_output_consumer_stops_the_child_without_raw_fallback() {
    let project = project(r#"TOKEN = { description = "token", providers = ["env"] }"#);
    let mut process = child(command(&project, "streams").env("TOKEN", "synthetic-token"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(process.stdout.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = process.try_wait().unwrap() {
            assert!(!status.success());
            return;
        }
        if std::time::Instant::now() >= deadline {
            let _ = process.kill();
            let _ = process.wait();
            panic!("filter failure did not stop the child");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn all_declared_values_are_masked() {
    let project = project(
        r#"TOKEN = { description = "first", providers = ["env"] }
PROTECTED = { description = "second", providers = ["env"] }"#,
    );
    for protected in ["protected-token", "visible-token"] {
        let output = child(
            command(&project, "mixed")
                .env("TOKEN", "visible-token")
                .env("PROTECTED", protected),
        )
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output
                .stdout
                .ends_with(b"first:[REDACTED] second:[REDACTED]")
        );
    }
}
