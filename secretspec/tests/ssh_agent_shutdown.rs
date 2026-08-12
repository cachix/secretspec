#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TEST_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----"#;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn stderr(child: &mut Child) -> String {
    let mut output = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        stderr.read_to_string(&mut output).unwrap();
    }
    output
}

#[test]
fn sigterm_stops_the_agent_and_removes_its_socket() {
    foreground_agent_stops_on("TERM", 143);
}

#[test]
fn sighup_stops_the_agent_and_removes_its_socket() {
    // A closed terminal must run the socket guard like any other shutdown;
    // without a handler the default disposition would kill the agent outright
    // and leave a socket that refuses the next start.
    foreground_agent_stops_on("HUP", 129);
}

/// Signal a foreground agent and assert it reports the signal in its exit code
/// (the `128 + signal` convention command mode already uses) and takes its
/// socket with it.
fn foreground_agent_stops_on(signal: &str, expected_code: i32) {
    let project = tempfile::tempdir().unwrap();
    fs::set_permissions(project.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = project.path().join("secretspec.toml");
    let socket = project.path().join("agent.sock");
    fs::write(
        &config,
        r#"[project]
name = "ssh-agent-signal-test"
revision = "1.0"
require_reason = false

[profiles.default]
DEPLOY_KEY = { description = "Deployment key", type = "ssh_private_key" }
"#,
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .args([
            "--file",
            config.to_str().unwrap(),
            "ssh-agent",
            "--provider",
            "env://",
            "--socket",
            socket.to_str().unwrap(),
        ])
        .current_dir(project.path())
        .env("DEPLOY_KEY", TEST_KEY)
        .env("HOME", project.path())
        .env("XDG_CONFIG_HOME", project.path().join("config"))
        .env("XDG_STATE_HOME", project.path().join("state"))
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start secretspec SSH agent");
    let mut child = ChildGuard(child);

    let startup_deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "SSH agent exited during startup with {status}:\n{}",
                stderr(&mut child.0)
            );
        }
        assert!(
            Instant::now() < startup_deadline,
            "timed out waiting for the SSH-agent socket"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let signal_status = Command::new("kill")
        .args([&format!("-{signal}"), &child.0.id().to_string()])
        .status()
        .expect("signal secretspec SSH agent");
    assert!(signal_status.success(), "kill failed with {signal_status}");

    let shutdown_deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < shutdown_deadline,
            "SSH agent did not stop after SIG{signal}"
        );
        thread::sleep(Duration::from_millis(10));
    };

    assert_eq!(
        status.code(),
        Some(expected_code),
        "unexpected SSH-agent status {status}:\n{}",
        stderr(&mut child.0)
    );
    assert!(!socket.exists(), "SSH-agent socket was not removed");
}

#[test]
fn command_mode_strips_key_env_forwards_sigterm_and_cleans_up() {
    let project = tempfile::tempdir().unwrap();
    fs::set_permissions(project.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = project.path().join("secretspec.toml");
    let socket = project.path().join("agent.sock");
    let command_pid = project.path().join("command.pid");
    fs::write(
        &config,
        r#"[project]
name = "ssh-agent-command-test"
revision = "1.0"
require_reason = false

[profiles.default]
DEPLOY_KEY = { description = "Deployment key", type = "ssh_private_key" }
"#,
    )
    .unwrap();

    let script = r#"
test -z "${DEPLOY_KEY+x}" || exit 97
test "$SSH_AUTH_SOCK" = "$2" || exit 98
printf '%s' "$$" > "$1"
trap 'exit 0' INT TERM
while :; do sleep 1; done
"#;
    let child = Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .args([
            "--file",
            config.to_str().unwrap(),
            "ssh-agent",
            "--provider",
            "env://",
            "--socket",
            socket.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            script,
            "sh",
            command_pid.to_str().unwrap(),
            socket.to_str().unwrap(),
        ])
        .current_dir(project.path())
        .env("DEPLOY_KEY", TEST_KEY)
        .env("HOME", project.path())
        .env("XDG_CONFIG_HOME", project.path().join("config"))
        .env("XDG_STATE_HOME", project.path().join("state"))
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start command-backed SecretSpec SSH agent");
    let mut child = ChildGuard(child);

    let startup_deadline = Instant::now() + Duration::from_secs(10);
    while !command_pid.exists() {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "command-backed SSH agent exited during startup with {status}:\n{}",
                stderr(&mut child.0)
            );
        }
        assert!(
            Instant::now() < startup_deadline,
            "timed out waiting for the wrapped command"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "SSH-agent socket was not created");
    let command_pid = fs::read_to_string(&command_pid).unwrap();

    let signal_status = Command::new("kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()
        .expect("send SIGTERM to command-backed SSH agent");
    assert!(signal_status.success(), "kill failed with {signal_status}");

    let shutdown_deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < shutdown_deadline,
            "command-backed SSH agent did not stop after SIGTERM"
        );
        thread::sleep(Duration::from_millis(10));
    };

    assert_eq!(
        status.code(),
        Some(143),
        "unexpected SSH-agent status {status}:\n{}",
        stderr(&mut child.0)
    );
    assert!(!socket.exists(), "SSH-agent socket was not removed");
    let command_alive = Command::new("kill")
        .args(["-0", command_pid.trim()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(!command_alive, "wrapped command was left running");
}
