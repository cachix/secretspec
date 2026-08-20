//! Unix process-supervision behavior for `secretspec run`.

#![cfg(unix)]

use std::fs;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(10);

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("secretspec.toml"),
        r#"[project]
name = "run-signals-test"
revision = "1.0"
require_reason = false

[providers]
env = "env://"

[profiles.default]
UNUSED = { description = "unused optional value", required = false, providers = ["env"] }
"#,
    )
    .unwrap();
    project
}

fn command(project: &tempfile::TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .args([
            "--file",
            project.path().join("secretspec.toml").to_str().unwrap(),
            "run",
            "--",
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
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn wait_until_started(child: &mut Child, ready: &std::path::Path) {
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if ready.exists() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("secretspec exited before its child was ready: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGKILL);
    }
    let _ = child.wait();
    panic!("timed out waiting for the child command to start");
}

#[test]
fn forwards_termination_signals_to_the_child() {
    for (name, signal) in [
        ("TERM", libc::SIGTERM),
        ("INT", libc::SIGINT),
        ("HUP", libc::SIGHUP),
    ] {
        let project = project();
        let ready = project.path().join(format!("ready-{name}"));
        let received = project.path().join(format!("received-{name}"));
        let script = format!("trap ': > \"$2\"; exit 0' {name}; : > \"$1\"; while :; do :; done");
        let mut child = command(&project)
            .args([
                "sh",
                "-c",
                &script,
                "sh",
                ready.to_str().unwrap(),
                received.to_str().unwrap(),
            ])
            .spawn()
            .unwrap();

        wait_until_started(&mut child, &ready);
        assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, signal) }, 0);

        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "forwarding {name} failed with {}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            received.exists(),
            "the child did not receive forwarded SIG{name}"
        );
    }
}

#[test]
fn maps_child_signal_deaths_to_conventional_exit_codes() {
    for (name, expected) in [("TERM", 143), ("KILL", 137)] {
        let project = project();
        let output = command(&project)
            .args(["sh", "-c", &format!("kill -{name} $$")])
            .output()
            .unwrap();

        assert_eq!(
            output.status.code(),
            Some(expected),
            "child killed by SIG{name} produced {}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
