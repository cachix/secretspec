#[cfg(unix)]
#[test]
fn run_preserves_non_utf8_environment_variables() {
	use std::ffi::OsString;
	use std::fs;
	use std::os::unix::ffi::OsStringExt;
	use std::process::Command;

	let temp_dir = tempfile::tempdir().unwrap();
	let config_path = temp_dir.path().join("monosecret.toml");
	let output_path = temp_dir.path().join("inherited-env");
	fs::write(
		&config_path,
		r#"[project]
name = "non-utf8-env-test"
revision = "1.0"
require_reason = false

[providers]
env = "env://"

[profiles.default]
FIXTURE_SECRET = { description = "Test fixture secret", providers = ["env"] }
"#,
	)
	.unwrap();

	let output = Command::new(env!("CARGO_BIN_EXE_monosecret"))
		.args([
			"--file",
			config_path.to_str().unwrap(),
			"run",
			"--",
			"sh",
			"-c",
			"printf '%s' \"$MONOSECRET_TEST_NON_UTF8\" > \"$1\"",
			"sh",
			output_path.to_str().unwrap(),
		])
		.env(
			"MONOSECRET_TEST_NON_UTF8",
			OsString::from_vec(vec![0x66, 0x6f, 0x80]),
		)
		.env("FIXTURE_SECRET", "present")
		.output()
		.unwrap();

	assert!(
		output.status.success(),
		"monosecret run failed with {}:\n{}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(fs::read(output_path).unwrap(), b"fo\x80");
}
