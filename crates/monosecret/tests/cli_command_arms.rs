//! Integration tests that exercise CLI command arms (`set`, `get`, `env`,
//! `audit`) through the compiled `monosecret` binary, covering the `load_secrets`
//! + command dispatch lines in `cli/mod.rs` that were missing patch coverage.

use std::fs;
use std::process::Command;

use insta_cmd::assert_cmd_snapshot;

fn bin() -> &'static str {
	env!("CARGO_BIN_EXE_monosecret")
}

fn snapshot_settings() -> insta::Settings {
	let mut settings = insta::Settings::clone_current();
	settings.add_filter(r"/private/var/folders/\S+", "[TMPDIR]");
	settings.add_filter(r"/var/folders/\S+", "[TMPDIR]");
	settings.add_filter(r"/tmp/\S+", "[TMPDIR]");
	settings
}

fn base_config(dotenv_path: &str) -> String {
	format!(
		r#"
[project]
name = "cli-arms"
revision = "1.0"

[providers]
local = "dotenv://{dotenv_path}"

[profiles.default]
API_KEY = {{ description = "API key", required = true, providers = ["local"] }}
OPTIONAL = {{ description = "Optional", required = false, default = "fallback", providers = ["local"] }}
"#
	)
}

#[test]
fn set_command_writes_secret_to_provider() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "").unwrap();
	fs::write(
		dir.path().join("monosecret.toml"),
		base_config(&dotenv.display().to_string()),
	)
	.unwrap();

	let mut cmd = Command::new(bin());
	cmd.current_dir(dir.path()).args([
		"-f",
		"monosecret.toml",
		"--reason",
		"test",
		"set",
		"API_KEY",
		"secret-value",
		"--provider",
		"local",
	]);

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
	insta::assert_snapshot!(fs::read_to_string(&dotenv).unwrap());
}

#[test]
fn get_command_retrieves_secret_from_provider() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "API_KEY=retrieved-value\n").unwrap();
	fs::write(
		dir.path().join("monosecret.toml"),
		base_config(&dotenv.display().to_string()),
	)
	.unwrap();

	let mut cmd = Command::new(bin());
	cmd.current_dir(dir.path()).args([
		"-f",
		"monosecret.toml",
		"--reason",
		"test",
		"get",
		"API_KEY",
		"--provider",
		"local",
	]);

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

#[test]
fn env_command_emits_dotenv_to_output_file() {
	let dir = tempfile::tempdir().unwrap();
	let dotenv = dir.path().join(".env");
	fs::write(&dotenv, "API_KEY=env-value\n").unwrap();
	fs::write(
		dir.path().join("monosecret.toml"),
		base_config(&dotenv.display().to_string()),
	)
	.unwrap();

	let output_file = dir.path().join("env.out");
	let mut cmd = Command::new(bin());
	cmd.current_dir(dir.path()).args([
		"-f",
		"monosecret.toml",
		"--reason",
		"test",
		"env",
		"--shell",
		"dotenv",
		"--provider",
		"local",
		"--output",
		output_file.to_str().unwrap(),
	]);

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
	insta::assert_snapshot!(fs::read_to_string(&output_file).unwrap());
}

#[test]
fn audit_command_reads_log_with_filters() {
	let dir = tempfile::tempdir().unwrap();

	// Set up a global config pointing at a temp audit log.
	let audit_log = dir.path().join("audit.jsonl");
	fs::write(
		&audit_log,
		concat!(
			r#"{"action":"get","project":"demo","key":"A","outcome":"found","ts":"2026-01-01T00:00:00Z","profile":"default"}"#,
			"\n",
			r#"{"action":"set","project":"other","key":"B","outcome":"written","ts":"2026-01-02T00:00:00Z","profile":"default"}"#,
			"\n",
			r#"{"action":"get","project":"demo","key":"C","outcome":"found","ts":"2026-01-03T00:00:00Z","profile":"default"}"#,
			"\n",
		),
	)
	.unwrap();

	let xdg_config_home = dir.path().join(".config");
	let config_dir = xdg_config_home.join("monosecret");
	fs::create_dir_all(&config_dir).unwrap();
	fs::write(
		config_dir.join("config.toml"),
		format!(
			r#"[audit]
path = "{}"
"#,
			audit_log.display()
		),
	)
	.unwrap();

	let mut cmd = Command::new(bin());
	cmd.env("HOME", dir.path())
		.env("XDG_CONFIG_HOME", xdg_config_home)
		.args([
			"audit",
			"--project",
			"demo",
			"--action",
			"get",
			"--tail",
			"1",
			"--json",
		]);

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}
