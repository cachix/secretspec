use std::fs;
use std::process::Command;

#[test]
fn manifest_command_emits_secret_value_free_json() {
	let dir = tempfile::tempdir().expect("tempdir");
	fs::write(
		dir.path().join("monosecret.toml"),
		r#"
[project]
name = "demo"
revision = "1.0"

[providers]
private = "op+token://vault/item"

[profiles.default]
TOKEN = { description = "Token", required = true }
OPTIONAL = { description = "Optional", required = false, default = "not-a-secret-for-manifest" }
"#,
	)
	.expect("write manifest");

	let output = Command::new(env!("CARGO_BIN_EXE_monosecret"))
		.current_dir(dir.path())
		.args(["manifest", "--format", "json"])
		.output()
		.expect("run monosecret manifest");

	assert!(
		output.status.success(),
		"stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
	assert!(!stdout.contains("op+token"));
	assert!(!stdout.contains("not-a-secret-for-manifest"));
	let manifest: serde_json::Value = serde_json::from_str(&stdout).expect("manifest json");
	insta::assert_json_snapshot!(manifest);
}
