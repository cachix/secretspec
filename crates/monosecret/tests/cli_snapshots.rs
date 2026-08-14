//! Snapshot tests for the `monosecret` CLI using `insta-cmd`.
//!
//! These tests run the compiled `monosecret` binary and snapshot stdout, stderr,
//! and exit code. Dynamic values (temp directory paths) are redacted with filters
//! so snapshots are stable across machines.
//!
//! To review pending snapshot changes:
//!   devenv shell snapshot:review
//! To accept all pending snapshots without review:
//!   devenv shell snapshot:accept

use std::fs;
use std::process::Command;

use insta_cmd::assert_cmd_snapshot;

fn bin() -> &'static str {
	env!("CARGO_BIN_EXE_monosecret")
}

/// A deterministic per-test HOME so `assert_cmd_snapshot!`'s `env:` section
/// (which insta filters do not touch) is stable across machines and runs.
/// The directory is wiped first so the audit-log first-run note always prints.
fn test_home(name: &str) -> std::path::PathBuf {
	let home = std::path::PathBuf::from(format!("/tmp/monosecret-cli-snapshots-{name}"));
	let _ = std::fs::remove_dir_all(&home);
	home
}

/// Returns a set of insta filters that redact dynamic temp directory paths so
/// snapshots are portable across machines.
fn snapshot_settings() -> insta::Settings {
	let mut settings = insta::Settings::clone_current();
	// macOS temp dirs: /private/var/folders/xx/xxxx/T/...
	settings.add_filter(r"/private/var/folders/\S+", "[TMPDIR]");
	settings.add_filter(r"/var/folders/\S+", "[TMPDIR]");
	// Linux temp dirs: /tmp/xxx...
	settings.add_filter(r"/tmp/\S+", "[TMPDIR]");
	settings.add_filter(r"/home/runner/work/_temp/\S+", "[TMPDIR]");
	// Windows temp dirs (paths are forward-slash normalised in test configs).
	settings.add_filter(r"[A-Z]:/Users/\S+/AppData/Local/Temp/\S+", "[TMPDIR]");
	settings.add_filter(r"[A-Z]:/a/_temp/\S+", "[TMPDIR]");
	// The audit first-run note is platform-dependent (prints on Unix where
	// HOME is honoured, absent on Windows where etcetera uses USERPROFILE).
	settings.add_filter(r"note: \S+ is now recording \S+ access to \S+[^\n]*\n", "");
	// Strip .exe suffix on Windows so binary names match Unix snapshots.
	settings.add_filter(r"monosecret\.exe", "monosecret");
	// dotenv:// URIs containing redacted temp paths.
	settings.add_filter(r"dotenv://\[TMPDIR\].*", "dotenv://[TMPDIR]...");
	settings
}

/// Convert backslashes to forward slashes so Windows paths interpolated into
/// TOML double-quoted strings are not interpreted as escape sequences.
fn forward_slashes(p: &std::path::Path) -> String {
	p.display().to_string().replace('\\', "/")
}

fn write_config(dir: &std::path::Path, toml: &str) {
	fs::write(dir.join("monosecret.toml"), toml).unwrap();
}

/// Snapshot `monosecret --help` — verifies the top-level help text is stable.
#[test]
fn help_output() {
	let mut cmd = Command::new(bin());
	cmd.arg("--help");
	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

#[test]
fn schema_and_check_json_are_value_free() {
	let dir = tempfile::tempdir().unwrap();
	write_config(
		dir.path(),
		r#"
[project]
name = "demo"
revision = "1.0"

[profiles.default]
TOKEN = { description = "token", required = true }
OPTIONAL = { description = "optional", required = false }
"#,
	);
	let env_path = dir.path().join("values.env");
	fs::write(&env_path, "TOKEN=super-secret-value\n").unwrap();

	let schema = Command::new(bin())
		.args([
			"--file",
			dir.path().join("monosecret.toml").to_str().unwrap(),
			"schema",
		])
		.output()
		.unwrap();
	assert!(schema.status.success());
	let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).unwrap();
	assert_eq!(
		schema.get("title").and_then(serde_json::Value::as_str),
		Some("Monosecret")
	);

	let report = Command::new(bin())
		.args([
			"--file",
			dir.path().join("monosecret.toml").to_str().unwrap(),
			"check",
			"--json",
			"--provider",
			&format!("dotenv:{}", env_path.display()),
		])
		.env("HOME", dir.path())
		.output()
		.unwrap();
	assert!(
		report.status.success(),
		"{}",
		String::from_utf8_lossy(&report.stderr)
	);
	let report_text = String::from_utf8(report.stdout).unwrap();
	assert!(!report_text.contains("super-secret-value"));
	let report: serde_json::Value = serde_json::from_str(&report_text).unwrap();
	let entries = report
		.get("secrets")
		.and_then(serde_json::Value::as_array)
		.expect("report secrets array");
	assert_eq!(
		entries
			.first()
			.and_then(|entry| entry.get("name"))
			.and_then(serde_json::Value::as_str),
		Some("OPTIONAL")
	);
	assert_eq!(
		entries
			.get(1)
			.and_then(|entry| entry.get("name"))
			.and_then(serde_json::Value::as_str),
		Some("TOKEN")
	);
}

/// Snapshot `monosecret manifest --format json` — verifies the secret-value-free
/// manifest output is stable.
#[test]
fn manifest_json() {
	let dir = tempfile::tempdir().unwrap();
	write_config(
		dir.path(),
		r#"
[project]
name = "demo"
revision = "1.0"

[providers]
local = "dotenv://.env"

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string", required = true }
API_TOKEN = { description = "API authentication token", required = true, generate = true, type = "password" }
OPTIONAL = { description = "Optional config", required = false, default = "not-a-secret" }
"#,
	);

	let mut cmd = Command::new(bin());
	cmd.env("HOME", test_home("manifest-json"))
		.current_dir(dir.path())
		.args(["manifest", "--format", "json"]);
	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

/// Snapshot `monosecret env --shell dotenv` — verifies dotenv output format.
#[test]
fn env_dotenv() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"DATABASE_URL=postgres://localhost\nAPI_TOKEN=secret\n",
	)
	.unwrap();

	write_config(
		dir.path(),
		&format!(
			r#"
[project]
name = "demo"
revision = "1.0"

[providers]
local = "dotenv://{}"

[profiles.default]
DATABASE_URL = {{ description = "Database URL", required = true, providers = ["local"] }}
API_TOKEN = {{ description = "API token", required = true, providers = ["local"] }}
"#,
			forward_slashes(&dotenv)
		),
	);

	let mut cmd = Command::new(bin());
	cmd.env("HOME", test_home("env-dotenv"));
	cmd.current_dir(dir.path()).args([
		"--reason",
		"test",
		"env",
		"--shell",
		"dotenv",
		"--provider",
		"local",
	]);
	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

/// Snapshot `monosecret env --shell bash` — verifies bash export format.
#[test]
fn env_bash() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"DATABASE_URL=postgres://localhost\nAPI_TOKEN=secret\n",
	)
	.unwrap();

	write_config(
		dir.path(),
		&format!(
			r#"
[project]
name = "demo"
revision = "1.0"

[providers]
local = "dotenv://{}"

[profiles.default]
DATABASE_URL = {{ description = "Database URL", required = true, providers = ["local"] }}
API_TOKEN = {{ description = "API token", required = true, providers = ["local"] }}
"#,
			forward_slashes(&dotenv)
		),
	);

	let mut cmd = Command::new(bin());
	cmd.env("HOME", test_home("env-bash"));
	cmd.current_dir(dir.path()).args([
		"--reason",
		"test",
		"env",
		"--shell",
		"bash",
		"--provider",
		"local",
	]);
	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

/// Snapshot `monosecret check --no-prompt` with all required secrets present —
/// verifies the check summary output.
#[test]
fn check_all_present() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(
		&dotenv,
		"DATABASE_URL=postgres://localhost\nAPI_TOKEN=secret\n",
	)
	.unwrap();

	write_config(
		dir.path(),
		&format!(
			r#"
[project]
name = "demo"
revision = "1.0"

[providers]
local = "dotenv://{}"

[profiles.default]
DATABASE_URL = {{ description = "Database URL", required = true, providers = ["local"] }}
API_TOKEN = {{ description = "API token", required = true, providers = ["local"] }}
"#,
			forward_slashes(&dotenv)
		),
	);

	let mut cmd = Command::new(bin());
	cmd.env("HOME", test_home("check-all-present"));
	cmd.current_dir(dir.path()).args([
		"--reason",
		"test",
		"check",
		"--no-prompt",
		"--provider",
		"local",
	]);
	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

/// Snapshot `monosecret check --no-prompt` with a missing required secret —
/// verifies the error output and non-zero exit code.
#[test]
fn check_missing_required() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "").unwrap();

	write_config(
		dir.path(),
		&format!(
			r#"
[project]
name = "demo"
revision = "1.0"

[providers]
local = "dotenv://{}"

[profiles.default]
API_TOKEN = {{ description = "API token", required = true, providers = ["local"] }}
"#,
			forward_slashes(&dotenv)
		),
	);

	let mut cmd = Command::new(bin());
	cmd.env("HOME", test_home("check-missing-required"));
	cmd.current_dir(dir.path()).args([
		"--reason",
		"test",
		"check",
		"--no-prompt",
		"--provider",
		"local",
	]);
	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

/// Snapshot `monosecret get` for a secret with a value in the provider.
#[test]
fn get_secret_value() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "API_TOKEN=my-secret-token\n").unwrap();

	write_config(
		dir.path(),
		&format!(
			r#"
[project]
name = "demo"
revision = "1.0"

[providers]
local = "dotenv://{}"

[profiles.default]
API_TOKEN = {{ description = "API token", required = true, providers = ["local"] }}
"#,
			forward_slashes(&dotenv)
		),
	);

	let mut cmd = Command::new(bin());
	cmd.env("HOME", test_home("get-secret-value"));
	cmd.current_dir(dir.path()).args([
		"--reason",
		"test",
		"get",
		"API_TOKEN",
		"--provider",
		"local",
	]);
	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

/// Snapshot `monosecret get` for a missing secret that has a default value.
#[test]
fn get_secret_with_default() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "").unwrap();

	write_config(
		dir.path(),
		&format!(
			r#"
[project]
name = "demo"
revision = "1.0"

[providers]
local = "dotenv://{}"

[profiles.default]
DATABASE_URL = {{ description = "Database URL", required = false, default = "postgres://localhost/dev", providers = ["local"] }}
"#,
			forward_slashes(&dotenv)
		),
	);

	let mut cmd = Command::new(bin());
	cmd.env("HOME", test_home("get-secret-with-default"));
	cmd.current_dir(dir.path()).args([
		"--reason",
		"test",
		"get",
		"DATABASE_URL",
		"--provider",
		"local",
	]);
	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}
