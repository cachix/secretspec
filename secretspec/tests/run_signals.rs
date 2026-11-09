//! Unix process-supervision behavior for `secretspec run`.

#![cfg(unix)]

use std::fs;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(10);

fn project(redacted: bool) -> tempfile::TempDir {
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
    if redacted {
        use std::io::Write;
        let mut manifest = fs::OpenOptions::new()
            .append(true)
            .open(project.path().join("secretspec.toml"))
            .unwrap();
        writeln!(manifest, "TOKEN = {{ description = \"token\", providers = [\"env\"], default = \"synthetic-signal-token\" }}").unwrap();
    }
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

fn wait_for_output(mut child: Child) -> Output {
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    panic!("timed out waiting for command shutdown: {output:?}");
}

#[test]
fn finishes_after_a_successful_child_exit() {
    for redacted in [false, true] {
        let project = project(redacted);
        let child = command(&project)
            .args(["sh", "-c", "exit 0"])
            .spawn()
            .unwrap();
        let output = wait_for_output(child);
        assert!(output.status.success(), "{output:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn finishes_when_socket_wakeups_are_denied() {
    use std::os::unix::process::CommandExt;

    for redacted in [false, true] {
        let project = project(redacted);
        let mut command = command(&project);
        // Reproduce a restrictive sandbox even when CI itself permits socket
        // wake-ups. Only the spawned process receives this additional filter.
        // SAFETY: the post-fork callback only builds stack data and invokes
        // prctl; it neither allocates nor acquires locks.
        unsafe {
            command.pre_exec(|| {
                let mut filter = [
                    libc::sock_filter {
                        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                        jt: 0,
                        jf: 0,
                        k: 0, // seccomp_data.nr
                    },
                    libc::sock_filter {
                        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 1,
                        k: libc::SYS_sendto as u32,
                    },
                    libc::sock_filter {
                        code: (libc::BPF_RET | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                    },
                    libc::sock_filter {
                        code: (libc::BPF_RET | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ALLOW,
                    },
                ];
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_mut_ptr(),
                };
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1
                    || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.args(["sh", "-c", "exit 0"]).spawn().unwrap();
        let output = wait_for_output(child);
        assert!(output.status.success(), "{output:?}");
    }
}

#[test]
fn forwards_termination_signals_to_the_child() {
    for redacted in [false, true] {
        for (name, signal) in [
            ("TERM", libc::SIGTERM),
            ("INT", libc::SIGINT),
            ("HUP", libc::SIGHUP),
        ] {
            let project = project(redacted);
            let ready = project.path().join(format!("ready-{name}"));
            let received = project.path().join(format!("received-{name}"));
            let script =
                format!("trap ': > \"$2\"; exit 0' {name}; : > \"$1\"; while :; do :; done");
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

            let output = wait_for_output(child);
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
}

#[test]
fn maps_child_signal_deaths_to_conventional_exit_codes() {
    for redacted in [false, true] {
        for (name, expected) in [("TERM", 143), ("KILL", 137)] {
            let project = project(redacted);
            let child = command(&project)
                .args(["sh", "-c", &format!("kill -{name} $$")])
                .spawn()
                .unwrap();
            let output = wait_for_output(child);

            assert_eq!(
                output.status.code(),
                Some(expected),
                "child killed by SIG{name} produced {}:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
