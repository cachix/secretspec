use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

fn manifest(project: &str, store: &std::path::Path) -> String {
    let store_uri = toml::Value::String(format!("file:{}", store.display())).to_string();
    format!(
        r#"[project]
name = "{project}"
revision = "1.0"
require_reason = false

[providers]
store = {store_uri}

[profiles.default]
BINARY = {{ description = "binary", providers = ["store"], as_path = true }}
"#,
    )
}

fn command(home: &std::path::Path, config: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .args(["--file", config.to_str().unwrap(), "set", "BINARY"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("APPDATA", home.join("config"))
        .env("LOCALAPPDATA", home.join("state"))
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON");
    command
}

#[test]
fn from_file_preserves_exact_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("secretspec.toml");
    let store = temp.path().join("store");
    let input = temp.path().join("secret.bin");
    let expected = [0x00, 0xff, 0x80, 0x0a];
    fs::write(&config, manifest("cli-file-input", &store)).unwrap();
    fs::write(&input, expected).unwrap();

    let output = command(temp.path(), &config)
        .args(["--from-file", input.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(store.join("cli-file-input/default/BINARY")).unwrap(),
        expected
    );
}

#[test]
fn from_stdin_preserves_exact_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("secretspec.toml");
    let store = temp.path().join("store");
    let expected = [0x00, 0xff, 0x80, 0x0a];
    fs::write(&config, manifest("cli-stdin-input", &store)).unwrap();

    let mut child = command(temp.path(), &config)
        .args(["--from-file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&expected).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(store.join("cli-stdin-input/default/BINARY")).unwrap(),
        expected
    );
}

#[test]
fn empty_file_input_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("secretspec.toml");
    let store = temp.path().join("store");
    let input = temp.path().join("empty.bin");
    fs::write(&config, manifest("cli-empty-input", &store)).unwrap();
    fs::write(&input, []).unwrap();

    let output = command(temp.path(), &config)
        .args(["--from-file", input.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be empty"));
    assert!(!store.join("cli-empty-input/default/BINARY").exists());
}

#[test]
fn positional_value_conflicts_with_from_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .args(["set", "BINARY", "text", "--from-file", "secret.bin"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}
