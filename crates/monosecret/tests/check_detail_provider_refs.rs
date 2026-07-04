use std::fmt::Write as _;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::process::Output;

use insta_cmd::assert_cmd_snapshot;
use tempfile::TempDir;

fn snapshot_settings() -> insta::Settings {
	let mut settings = temp_path_snapshot_settings();
	settings.add_filter(r"dotenv://\[TMPDIR\].*", "dotenv://[TMPDIR]...");
	settings
}

fn temp_path_snapshot_settings() -> insta::Settings {
	let mut settings = insta::Settings::clone_current();
	settings.add_filter(
		r"/private/var/folders/[^[:space:]:]+/\.tmp[^/[:space:]:]+",
		"[TMPDIR]",
	);
	settings.add_filter(
		r"/var/folders/[^[:space:]:]+/\.tmp[^/[:space:]:]+",
		"[TMPDIR]",
	);
	settings.add_filter(r"/tmp/\.tmp[^/[:space:]:]+", "[TMPDIR]");
	settings.add_filter(r"/home/runner/work/_temp/\.tmp[^/[:space:]:]+", "[TMPDIR]");
	settings
}

fn normalized_command_snapshot(output: &Output) -> String {
	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	let stderr = sorted_secret_debug_lines(&stderr);
	let exit_code = output
		.status
		.code()
		.map_or_else(|| "<signal>".to_string(), |code| code.to_string());

	let mut snapshot = String::new();
	let _ = writeln!(&mut snapshot, "success: {}", output.status.success());
	let _ = writeln!(&mut snapshot, "exit_code: {exit_code}");
	append_snapshot_section(&mut snapshot, "stdout", &stdout);
	append_snapshot_section(&mut snapshot, "stderr", &stderr);
	snapshot
}

fn sorted_secret_debug_lines(stderr: &str) -> String {
	let mut normalized = Vec::new();
	let mut debug_lines = Vec::new();

	for line in stderr.lines() {
		if line.starts_with("DEBUG monosecret::secrets:") {
			debug_lines.push(line.to_string());
			continue;
		}

		flush_sorted_debug_lines(&mut normalized, &mut debug_lines);
		normalized.push(line.to_string());
	}

	flush_sorted_debug_lines(&mut normalized, &mut debug_lines);

	let mut stderr = normalized.join("\n");
	if !stderr.is_empty() {
		stderr.push('\n');
	}
	stderr
}

fn flush_sorted_debug_lines(output: &mut Vec<String>, debug_lines: &mut Vec<String>) {
	debug_lines.sort();
	output.append(debug_lines);
}

fn append_snapshot_section(snapshot: &mut String, name: &str, contents: &str) {
	let _ = writeln!(snapshot, "----- {name} -----");
	snapshot.push_str(contents);
	if !contents.ends_with('\n') {
		snapshot.push('\n');
	}
}

#[test]
fn check_resolves_required_object_form_provider_refs_with_key_hints() {
	let temp_dir = TempDir::new().expect("create temp test directory");
	let env_file = temp_dir.path().join("provider.env");
	let monosecret_file = temp_dir.path().join("monosecret.toml");
	let xdg_config_home = temp_dir.path().join("xdg-config");
	let monosecret_config_dir = xdg_config_home.join("monosecret");

	fs::create_dir_all(&monosecret_config_dir).expect("create monosecret config directory");
	fs::write(
		monosecret_config_dir.join("config.toml"),
		r#"
[defaults]
provider = "keyring"
profile = "default"
"#,
	)
	.expect("write isolated user config");

	let mut env_content = String::new();
	let mut profile_content = String::new();
	for index in 1..=15 {
		let _ = writeln!(&mut env_content, "STORED_SECRET_{index}=value-{index}");
		let _ = writeln!(
			&mut profile_content,
			"SECRET_{index} = {{ description = \"Required secret {index}\", required = true, providers = [{{ provider = \"detail_env\", path = [\"Important Details\", \"Company Details\"], key = \"STORED_SECRET_{index}\" }}] }}"
		);
	}

	fs::write(&env_file, env_content).expect("write dotenv provider data");
	fs::write(
		&monosecret_file,
		format!(
			r#"
[project]
name = "object-provider-check-regression"
revision = "1.0"

[providers]
detail_env = "dotenv://{}"

[profiles.default]
{}
"#,
			env_file.display(),
			profile_content
		),
	)
	.expect("write monosecret config");

	let mut cmd = Command::new(env!("CARGO_BIN_EXE_monosecret"));
	cmd.arg("-f")
		.arg(&monosecret_file)
		.arg("check")
		.arg("--no-prompt")
		.env("RUST_LOG", "verbose")
		.env("XDG_CONFIG_HOME", &xdg_config_home)
		.env("HOME", temp_dir.path())
		.env("NO_COLOR", "1")
		.env_remove("MONOSECRET_PROVIDER")
		.env_remove("MONOSECRET_PROFILE");

	let output = cmd.output().expect("run monosecret check");
	let snapshot = normalized_command_snapshot(&output);
	temp_path_snapshot_settings().bind(|| {
		insta::assert_snapshot!(snapshot);
	});
}

#[test]
#[cfg(unix)]
fn onepassword_auth_failures_are_error_logs() {
	let temp_dir = TempDir::new().expect("create temp test directory");
	let op = temp_dir.path().join("op");
	let monosecret_file = temp_dir.path().join("monosecret.toml");

	fs::write(
		&op,
		r"#!/usr/bin/env sh
printf '%s\n' 'not currently signed in' >&2
exit 1
",
	)
	.expect("write fake op command");
	let mut permissions = fs::metadata(&op)
		.expect("stat fake op command")
		.permissions();
	permissions.set_mode(0o755);
	fs::set_permissions(&op, permissions).expect("make fake op executable");

	fs::write(
        &monosecret_file,
        r#"
[project]
name = "onepassword-error-log-test"
revision = "1.0"

[providers]
op = "onepassword://Development"

[profiles.default]
TOKEN = { description = "Token", required = true, providers = [{ provider = "op", path = ["dotfiles", "auth"], key = "TOKEN" }] }
"#,
    )
    .expect("write monosecret config");

	let path = format!(
		"{}:{}",
		temp_dir.path().display(),
		std::env::var("PATH").unwrap_or_default()
	);
	let mut cmd = Command::new(env!("CARGO_BIN_EXE_monosecret"));
	cmd.arg("-f")
		.arg(&monosecret_file)
		.arg("check")
		.arg("--no-prompt")
		.env("PATH", path)
		.env("RUST_LOG", "verbose")
		.env("HOME", temp_dir.path())
		.env("NO_COLOR", "1")
		.env_remove("OP_SERVICE_ACCOUNT_TOKEN")
		.env_remove("MONOSECRET_PROVIDER")
		.env_remove("MONOSECRET_PROFILE");

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

#[test]
#[cfg(unix)]
fn onepassword_lookup_failures_are_warning_logs() {
	let temp_dir = TempDir::new().expect("create temp test directory");
	let op = temp_dir.path().join("op");
	let monosecret_file = temp_dir.path().join("monosecret.toml");

	fs::write(
		&op,
		r#"#!/usr/bin/env sh
printf '%s\n' "item isn't in vault" >&2
exit 1
"#,
	)
	.expect("write fake op command");
	let mut permissions = fs::metadata(&op)
		.expect("stat fake op command")
		.permissions();
	permissions.set_mode(0o755);
	fs::set_permissions(&op, permissions).expect("make fake op executable");

	fs::write(
        &monosecret_file,
        r#"
[project]
name = "onepassword-warning-log-test"
revision = "1.0"

[providers]
op = "onepassword://Development"

[profiles.default]
TOKEN = { description = "Token", required = true, providers = [{ provider = "op", path = ["dotfiles", "auth"], key = "TOKEN" }] }
"#,
    )
    .expect("write monosecret config");

	let path = format!(
		"{}:{}",
		temp_dir.path().display(),
		std::env::var("PATH").unwrap_or_default()
	);
	let mut cmd = Command::new(env!("CARGO_BIN_EXE_monosecret"));
	cmd.arg("-f")
		.arg(&monosecret_file)
		.arg("check")
		.arg("--no-prompt")
		.env("PATH", path)
		.env("RUST_LOG", "verbose")
		.env("HOME", temp_dir.path())
		.env("NO_COLOR", "1")
		.env_remove("OP_SERVICE_ACCOUNT_TOKEN")
		.env_remove("MONOSECRET_PROVIDER")
		.env_remove("MONOSECRET_PROFILE");

	snapshot_settings().bind(|| {
		assert_cmd_snapshot!(cmd);
	});
}

#[test]
fn lightweight_logging_honors_verbosity_and_rust_log_filters() {
	let temp_dir = TempDir::new().expect("create temp test directory");
	let monosecret_file = temp_dir.path().join("monosecret.toml");
	fs::write(
		&monosecret_file,
		r#"
[project]
name = "lightweight-logging-test"
revision = "1.0"

[providers]
env = "env://"

[profiles.default]
TOKEN = { description = "Token", required = true, providers = ["env"] }
"#,
	)
	.expect("write monosecret config");

	let cases = [
		(vec!["-v"], None, true),
		(Vec::new(), Some("monosecret=debug"), true),
		(Vec::new(), Some("quiet"), false),
		(Vec::new(), None, false),
	];

	for (verbosity_args, rust_log, should_log_debug) in cases {
		let mut command = Command::new(env!("CARGO_BIN_EXE_monosecret"));
		command.arg("-f").arg(&monosecret_file);
		for arg in verbosity_args {
			command.arg(arg);
		}
		command
			.arg("check")
			.arg("--no-prompt")
			.env("HOME", temp_dir.path())
			.env("NO_COLOR", "1")
			.env("TOKEN", "value")
			.env_remove("MONOSECRET_PROVIDER")
			.env_remove("MONOSECRET_PROFILE");

		match rust_log {
			Some(value) => {
				command.env("RUST_LOG", value);
			}
			None => {
				command.env_remove("RUST_LOG");
			}
		}

		let output = command.output().expect("run monosecret check");
		let stderr = String::from_utf8_lossy(&output.stderr);
		assert!(
			output.status.success(),
			"check should succeed\nstderr:\n{stderr}"
		);
		assert_eq!(
			stderr.contains("resolved provider reference"),
			should_log_debug,
			"debug provider logs should match filter expectation\nstderr:\n{stderr}"
		);
	}
}

#[test]
fn verbose_filter_inputs_are_accepted_by_cli() {
	let temp_dir = TempDir::new().expect("create temp test directory");
	let monosecret_file = temp_dir.path().join("monosecret.toml");
	let empty_provider_file = temp_dir.path().join("empty.env");
	let broken_provider_dir = temp_dir.path().join("broken-provider");
	fs::write(&empty_provider_file, "").expect("write empty provider file");
	fs::create_dir_all(&broken_provider_dir).expect("create broken provider directory");
	fs::write(
		&monosecret_file,
		format!(
			r#"
[project]
name = "verbose-filter-tests"
revision = "1.0"

[providers]
empty = "dotenv://{}"
broken = "dotenv://{}"
env = "env://"

[profiles.default]
TOKEN = {{ description = "Token", required = true, providers = ["empty", "broken", "env"] }}
"#,
			empty_provider_file.display(),
			broken_provider_dir.display()
		),
	)
	.expect("write monosecret config");

	let cases = [
		(vec!["-v"], None),
		(vec!["-vv"], None),
		(vec!["--verbose"], None),
		(vec!["--verbose", "--verbose"], None),
		(Vec::new(), Some("quiet")),
		(Vec::new(), Some("debug")),
	];

	for (verbosity_args, rust_log) in cases {
		let mut command = Command::new(env!("CARGO_BIN_EXE_monosecret"));
		command.arg("-f").arg(&monosecret_file);
		for arg in verbosity_args {
			command.arg(arg);
		}
		command
			.arg("check")
			.arg("--no-prompt")
			.env("HOME", temp_dir.path())
			.env("NO_COLOR", "1")
			.env("TOKEN", "value")
			.env_remove("MONOSECRET_PROVIDER")
			.env_remove("MONOSECRET_PROFILE");

		match rust_log {
			Some(value) => {
				command.env("RUST_LOG", value);
			}
			None => {
				command.env_remove("RUST_LOG");
			}
		}

		let output = command.output().expect("run monosecret check");
		assert!(
			output.status.success(),
			"check should accept verbosity/filter input\nstdout:\n{}\nstderr:\n{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
	}
}
