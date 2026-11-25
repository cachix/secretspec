#![cfg(all(unix, feature = "cli", feature = "bws"))]
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

struct Fixture {
    directory: tempfile::TempDir,
}
impl Fixture {
    fn new(mode: &str, attempts: Option<u32>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::write(
            root.join("secretspec.toml"),
            r#"
[project]
name = "retry-test"
revision = "1.0"
require_reason = false
[profiles.default]
API_KEY = { description = "API key" }
SECOND_KEY = { description = "second key" }
"#,
        )
        .unwrap();
        fs::create_dir_all(root.join("config/secretspec")).unwrap();
        let policy = attempts
            .map(|attempts| format!("[defaults.retry]\nmax_attempts = {attempts}\n"))
            .unwrap_or_default();
        fs::write(
            root.join("config/secretspec/config.toml"),
            format!("[audit]\nenabled = false\n{policy}"),
        )
        .unwrap();
        fs::write(root.join("mode"), mode).unwrap();
        let executable = root.join("bws");
        fs::write(&executable, r#"#!/bin/sh
count=0
if test -f "$RETRY_FIXTURE/count"; then read count < "$RETRY_FIXTURE/count"; fi
count=$((count + 1))
echo "$count" > "$RETRY_FIXTURE/count"
read mode < "$RETRY_FIXTURE/mode"
case "$mode" in
  auth) echo 'authentication failed (401 Unauthorized)' >&2; exit 1;;
  json) echo 'not json'; exit 0;;
  persistent) echo "[503 Service Unavailable] connection timeout $BWS_ACCESS_TOKEN" >&2; exit 1;;
  recover) if test "$count" -lt 3; then echo '[503 Service Unavailable] connection timeout' >&2; exit 1; fi;;
esac
echo '[{"id":"first","key":"API_KEY","value":"first-value"},{"id":"second","key":"SECOND_KEY","value":"second-value"}]'
"#).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        Self { directory }
    }
    fn run(&self) -> Output {
        let root = self.directory.path();
        Command::new(env!("CARGO_BIN_EXE_secretspec"))
            .current_dir(root)
            .env("HOME", root).env("XDG_CONFIG_HOME", root.join("config"))
            .env("SECRETSPEC_BWS_CLI_PATH", root.join("bws"))
            .env("BWS_ACCESS_TOKEN", "credential-must-not-leak")
            .env("RETRY_FIXTURE", root)
            .env_remove("SECRETSPEC_PROVIDER").env_remove("SECRETSPEC_PROFILE").env_remove("SECRETSPEC_SCOPE")
            .args(["run", "--provider", "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c", "--", "sh", "-c",
                "test \"$API_KEY\" = first-value && test \"$SECOND_KEY\" = second-value && echo launched >> launched"])
            .output().unwrap()
    }
    fn attempts(&self) -> u32 {
        fs::read_to_string(self.directory.path().join("count"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }
}
#[test]
fn bws_transient_listing_resolves_the_entire_profile_and_launches_once() {
    let fixture = Fixture::new("recover", None);
    let output = fixture.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fixture.attempts(), 3);
    assert_eq!(
        fs::read_to_string(fixture.directory.path().join("launched")).unwrap(),
        "launched\n"
    );
}
#[test]
fn bws_persistent_failure_exhausts_budget_and_redacts_credentials() {
    let fixture = Fixture::new("persistent", None);
    let output = fixture.run();
    assert!(!output.status.success());
    assert_eq!(fixture.attempts(), 3);
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("503"), "{diagnostic}");
    assert!(!diagnostic.contains("credential-must-not-leak"));
    assert!(!fixture.directory.path().join("launched").exists());
}
#[test]
fn permanent_failures_and_disabled_retries_make_one_attempt() {
    for (mode, attempts) in [("auth", None), ("json", None), ("persistent", Some(1))] {
        let fixture = Fixture::new(mode, attempts);
        assert!(!fixture.run().status.success());
        assert_eq!(fixture.attempts(), 1, "{mode}");
        assert!(
            !Path::new(fixture.directory.path())
                .join("launched")
                .exists()
        );
    }
}
