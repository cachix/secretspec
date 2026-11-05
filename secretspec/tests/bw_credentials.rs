#![cfg(all(unix, feature = "bw", feature = "cli"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn project(directory: &Path, credentials: bool) {
    let shim = directory.join("bw");
    fs::write(&shim, include_str!("fixtures/bw-shim.sh")).unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(directory.join("expected-session"), "stored-session").unwrap();
    fs::write(
        directory.join(".env.credentials"),
        "session=stored-session\n",
    )
    .unwrap();
    fs::write(
        directory.join("items.json"),
        r#"[{"id":"item-1","name":"secretspec/bw-credentials/default/TOKEN","type":1,"login":{"password":"application-secret"}}]"#,
    )
    .unwrap();
    let provider = if credentials {
        r#"{ uri = "bw://", credentials = { session = "dotenv:.env.credentials" } }"#
    } else {
        r#""bw://""#
    };
    fs::write(
        directory.join("secretspec.toml"),
        format!(
            r#"[project]
name = "bw-credentials"
revision = "1.0"
require_reason = false

[providers]
bitwarden = {provider}

[profiles.default]
TOKEN = {{ description = "Application token", providers = ["bitwarden"] }}
"#
        ),
    )
    .unwrap();
}

fn cli(directory: &Path) -> Command {
    let path = std::env::join_paths(std::iter::once(directory.to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .current_dir(directory)
        .args(["--file", "secretspec.toml"])
        .env("PATH", path)
        .env("HOME", directory)
        .env("XDG_CONFIG_HOME", directory.join("config"))
        .env("XDG_STATE_HOME", directory.join("state"))
        .env("BITWARDENCLI_APPDATA_DIR", directory.join("appdata"));
    for name in [
        "BW_SESSION",
        "SECRETSPEC_PROVIDER",
        "SECRETSPEC_PROFILE",
        "SECRETSPEC_SCOPE",
        "SECRETSPEC_REASON",
        "BITWARDEN_ORGANIZATION",
        "BITWARDEN_COLLECTION",
        "BITWARDEN_DEFAULT_TYPE",
        "BITWARDEN_DEFAULT_FIELD",
    ] {
        command.env_remove(name);
    }
    command
}

#[test]
fn configured_session_is_only_passed_to_bitwarden() {
    let temp = tempfile::tempdir().unwrap();
    project(temp.path(), true);
    for ambient in [None, Some("ambient-session")] {
        let result = temp.path().join("application-result");
        let _ = fs::remove_file(&result);
        let mut command = cli(temp.path());
        if let Some(session) = ambient {
            command.env("BW_SESSION", session);
        }
        // Inspect a running application, then terminate its process group so
        // the test does not depend on the supervisor's shutdown behavior.
        let mut child = command
            .args([
                "run", "--", "sh", "-c",
                "if test \"$TOKEN\" = application-secret && test \"${BW_SESSION-unset}\" = \"$1\"; then printf success; else printf failure; fi > \"$2\"; exec sleep 30",
                "sh", ambient.unwrap_or("unset"), result.to_str().unwrap(),
            ])
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while fs::read(&result).unwrap_or_default().is_empty() && Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Only this test's child and its descendants belong to this group.
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        let output = child.wait_with_output().unwrap();
        assert!(
            result.exists(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(result).unwrap(), b"success");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("stored-session"));
    }
}

#[test]
fn session_environment_still_works_without_credentials() {
    let temp = tempfile::tempdir().unwrap();
    project(temp.path(), false);
    let output = cli(temp.path())
        .env("BW_SESSION", "stored-session")
        .args(["get", "TOKEN"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"application-secret");
}

#[test]
fn missing_or_empty_configured_session_never_uses_environment() {
    for contents in ["", "session=\n"] {
        let temp = tempfile::tempdir().unwrap();
        project(temp.path(), true);
        fs::write(temp.path().join(".env.credentials"), contents).unwrap();
        let output = cli(temp.path())
            .env("BW_SESSION", "stored-session")
            .args(["get", "TOKEN"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!temp.path().join("invocations.log").exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("stored-session"));
    }
}
