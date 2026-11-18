#![cfg(all(feature = "cli", feature = "sqlite"))]

//! `secretspec verify-history` (0.22+) against the sqlite provider.
//!
//! The failure reasons are covered by the provider's unit tests, which can open
//! the ledger directly; these tests cover the command's two answers — "this
//! provider keeps no verifiable history" and a verified chain — plus the JSON
//! shape a script reads.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn manifest() -> String {
    r#"[project]
name = "verify-history"
revision = "1.0"

[providers]
audited = "sqlite:./secrets.db?history=true"
plain = "sqlite:./plain.db"

[profiles.default]
TOKEN = { description = "never read", providers = ["audited"] }
"#
    .to_string()
}

fn command(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("APPDATA", dir.join("config"))
        .env("LOCALAPPDATA", dir.join("state"));
    for name in ["FILE", "PROFILE", "PROVIDER", "SCOPE", "REASON"] {
        cmd.env_remove(format!("SECRETSPEC_{name}"));
    }
    cmd
}

fn run(dir: &Path, args: &[&str]) -> Output {
    command(dir).args(args).output().unwrap()
}

fn setup() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("secretspec.toml"), manifest()).unwrap();
    dir
}

#[test]
fn provider_without_a_ledger_reports_nothing_to_verify() {
    let dir = setup();

    let output = run(
        dir.path(),
        &["verify-history", "--provider", "sqlite:./plain.db"],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("keeps no verifiable history"),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_written_ledger_verifies_and_reports_its_head() {
    let dir = setup();

    let set = run(
        dir.path(),
        &["set", "TOKEN", "s3cr3t", "--provider", "audited"],
    );
    assert!(
        set.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );

    let output = run(dir.path(), &["verify-history", "--provider", "audited"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("verified 1 entries (head "),
        "stdout: {stdout}"
    );
    assert!(stdout.ends_with(")\n"), "stdout: {stdout}");

    // The JSON report is value-free and names the same head.
    let json = run(
        dir.path(),
        &["verify-history", "--provider", "audited", "--json"],
    );
    assert!(json.status.success());
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["provider"], "sqlite");
    // The alias is expanded verbatim, so the store the command audited is the
    // one the write went to; the query string that turns history on survives.
    assert!(
        report["uri"]
            .as_str()
            .unwrap()
            .ends_with("secrets.db?history=true"),
        "report: {report}"
    );
    assert_eq!(report["verifiable"], true);
    assert_eq!(report["ok"], true);
    assert_eq!(report["history"]["entries"], 1);
    assert_eq!(report["history"]["schema_version"], 2);
    assert!(report["history"]["failure"].is_null());
    let head = report["history"]["head_hash"].as_str().unwrap();
    assert!(stdout.contains(head), "head {head} not in {stdout}");
    assert!(
        !String::from_utf8_lossy(&json.stdout).contains("s3cr3t"),
        "the report must not carry a secret value"
    );
}

#[test]
fn json_reports_a_provider_without_a_ledger() {
    let dir = setup();

    let output = run(
        dir.path(),
        &[
            "verify-history",
            "--provider",
            "sqlite:./plain.db",
            "--json",
        ],
    );
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["uri"].as_str().unwrap().ends_with("plain.db"),
        "report: {report}"
    );
    assert_eq!(report["verifiable"], false);
    assert_eq!(report["ok"], true);
    assert!(report.get("history").is_none());
}
