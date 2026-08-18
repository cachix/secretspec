use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    codex_home: PathBuf,
    manifest: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        let codex_home = root.join("codex");
        fs::create_dir(&codex_home).unwrap();
        let config = codex_home.join("config.toml");
        fs::write(
            &config,
            r#"# preserve this comment
model = "gpt-5.4"
model_provider = "existing"

[model_providers.existing]
name = "Existing provider"
base_url = "https://existing.example/v1"
wire_api = "responses"
env_key = "EXISTING_API_KEY"

[mcp_servers.example]
command = "example-mcp"
"#,
        )
        .unwrap();
        let manifest = root.join("secretspec.toml");
        fs::write(
            &manifest,
            r#"
[project]
name = "codex-helper"
revision = "1.0"
require_reason = false

[profiles.default]
OPENAI_TOKEN = { description = "OpenAI API key", default = "fixture-custom-key", providers = ["null"] }
"#,
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            codex_home,
            manifest,
            config,
        }
    }

    fn command_for(&self, codex_home: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
        command
            .current_dir(&self.root)
            .env("CODEX_HOME", codex_home)
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("APPDATA", self.root.join("config"))
            .env("LOCALAPPDATA", self.root.join("state"))
            .env_remove("SECRETSPEC_FILE")
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_REASON");
        command
    }

    fn command(&self) -> Command {
        self.command_for(&self.codex_home)
    }

    fn configure(&self, provider: &str) -> Output {
        self.command()
            .args([
                "codex",
                "configure",
                "--yes",
                "--provider",
                provider,
                "--model",
                "gpt-5.4",
            ])
            .output()
            .unwrap()
    }

    fn custom_configure(&self) -> Output {
        self.command()
            .arg("--file")
            .arg(&self.manifest)
            .args([
                "--reason",
                "Use Codex API key",
                "codex",
                "configure",
                "--yes",
                "--token-secret",
                "OPENAI_TOKEN",
                "--profile",
                "default",
                "--provider",
                "null",
            ])
            .output()
            .unwrap()
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("config/secretspec/codex.json")
    }

    fn state(&self) -> Value {
        serde_json::from_slice(&fs::read(self.state_path()).unwrap()).unwrap()
    }

    fn configuration_id(&self) -> String {
        self.state()["configs"][0]["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn credential(&self) -> Output {
        self.command()
            .args([
                "codex",
                "credential",
                "--configuration",
                &self.configuration_id(),
            ])
            .output()
            .unwrap()
    }
}

fn parse_toml(path: &Path) -> toml::Value {
    toml::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn command_with_stdin(mut command: Command, args: &[&str], input: &[u8]) -> Output {
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_success(context: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{context} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn find_named(root: &Path, name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().is_some_and(|file| file == name) {
            return Some(path);
        }
        if path.is_dir()
            && let Some(found) = find_named(&path, name)
        {
            return Some(found);
        }
    }
    None
}

#[test]
fn configure_and_unconfigure_preserve_unrelated_codex_configuration() {
    let fixture = Fixture::new();
    let output = fixture.configure("null");
    assert_success("Codex configure", &output);
    let configured = parse_toml(&fixture.config);
    let provider = configured["model_provider"].as_str().unwrap();
    assert!(provider.starts_with("secretspec-"));
    assert_eq!(configured["model"].as_str(), Some("gpt-5.4"));
    assert_eq!(
        configured["model_providers"]["existing"]["base_url"].as_str(),
        Some("https://existing.example/v1")
    );
    assert_eq!(
        configured["mcp_servers"]["example"]["command"].as_str(),
        Some("example-mcp")
    );
    assert!(
        fs::read_to_string(&fixture.config)
            .unwrap()
            .contains("# preserve this comment")
    );
    assert_eq!(
        fixture.state()["configs"][0]["previous_model_provider"],
        "existing"
    );
    assert!(fixture.state()["configs"][0]["managed_model"].is_null());

    let output = fixture
        .command()
        .args(["codex", "unconfigure", "--yes"])
        .output()
        .unwrap();
    assert_success("Codex unconfigure", &output);
    let restored = parse_toml(&fixture.config);
    assert_eq!(restored["model_provider"].as_str(), Some("existing"));
    assert_eq!(restored["model_providers"].as_table().unwrap().len(), 1);
    assert_eq!(restored["model"].as_str(), Some("gpt-5.4"));
    assert!(
        fs::read_to_string(&fixture.config)
            .unwrap()
            .contains("# preserve this comment")
    );
    assert_eq!(fixture.state()["configs"][0]["configured"], false);
}

#[test]
fn embedded_login_credential_and_logout_reuse_the_configured_provider() {
    let fixture = Fixture::new();
    let store = fixture.root.join("codex.env");
    let provider = format!("dotenv://{}", store.display());
    assert_success("Codex configure", &fixture.configure(&provider));
    let output = command_with_stdin(
        fixture.command(),
        &["codex", "login"],
        b"fixture-codex-key\n",
    );
    assert_success("Codex login", &output);
    let output = fixture.credential();
    assert_success("Codex credential", &output);
    assert_eq!(output.stdout, b"fixture-codex-key\n");

    let output = fixture
        .command()
        .args(["codex", "logout"])
        .output()
        .unwrap();
    assert_success("Codex logout", &output);
    let output = fixture.credential();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("API key is not stored"));
}

#[test]
fn custom_manifest_resolves_and_lifecycle_commands_reject_it() {
    let fixture = Fixture::new();
    assert_success("custom Codex configure", &fixture.custom_configure());
    let output = fixture.credential();
    assert_success("custom Codex credential", &output);
    assert_eq!(output.stdout, b"fixture-custom-key\n");
    assert_eq!(fixture.state()["configs"][0]["source"]["kind"], "manifest");

    for action in ["login", "logout"] {
        let output = fixture.command().args(["codex", action]).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("custom manifest"));
    }
}

#[test]
fn configure_requires_confirmation() {
    let fixture = Fixture::new();
    let original = fs::read(&fixture.config).unwrap();
    let output = fixture
        .command()
        .args(["codex", "configure"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pass --yes"));
    assert_eq!(fs::read(&fixture.config).unwrap(), original);
    assert!(!fixture.state_path().exists());
}

#[test]
fn unconfigure_refuses_an_edited_owned_provider() {
    let fixture = Fixture::new();
    assert_success("Codex configure", &fixture.configure("null"));
    let state = fixture.state();
    let provider = state["configs"][0]["model_provider"].as_str().unwrap();
    let mut config = fs::read_to_string(&fixture.config).unwrap();
    config = config.replace(
        "command = \"secretspec\"",
        "command = \"different-command\"",
    );
    fs::write(&fixture.config, config).unwrap();

    let output = fixture
        .command()
        .args(["codex", "unconfigure", "--yes"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("changed outside") && stderr.contains("SecretSpec"),
        "{output:?}"
    );
    assert!(
        parse_toml(&fixture.config)["model_providers"]
            .get(provider)
            .is_some()
    );
}

#[test]
fn unconfigure_refuses_an_edited_model_provider_selection() {
    let fixture = Fixture::new();
    assert_success("Codex configure", &fixture.configure("null"));
    let mut config = fs::read_to_string(&fixture.config).unwrap();
    let provider = fixture.state()["configs"][0]["model_provider"]
        .as_str()
        .unwrap()
        .to_string();
    config = config.replace(
        &format!("model_provider = \"{provider}\""),
        "model_provider = \"existing\"",
    );
    fs::write(&fixture.config, config).unwrap();

    let output = fixture
        .command()
        .args(["codex", "unconfigure", "--yes"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("changed outside") && stderr.contains("SecretSpec"),
        "{output:?}"
    );
}

#[test]
fn generated_structured_token_command_executes() {
    let fixture = Fixture::new();
    assert_success("custom Codex configure", &fixture.custom_configure());
    let config = parse_toml(&fixture.config);
    let provider = config["model_provider"].as_str().unwrap();
    let auth = &config["model_providers"][provider]["auth"];
    assert_eq!(auth["command"].as_str(), Some("secretspec"));
    let args = auth["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    let output = fixture.command().args(args).output().unwrap();
    assert_success("Codex token command", &output);
    assert_eq!(output.stdout, b"fixture-custom-key\n");
}

#[test]
fn codex_homes_have_isolated_embedded_credentials() {
    let fixture = Fixture::new();
    let second_home = fixture.root.join("second-codex");
    fs::create_dir(&second_home).unwrap();
    let store = fixture.root.join("codex.env");
    let provider = format!("dotenv://{}", store.display());
    assert_success("first Codex configure", &fixture.configure(&provider));
    let output = command_with_stdin(fixture.command(), &["codex", "login"], b"first-key\n");
    assert_success("first Codex login", &output);

    let output = fixture
        .command_for(&second_home)
        .args([
            "codex",
            "configure",
            "--yes",
            "--provider",
            &provider,
            "--model",
            "gpt-5.4",
        ])
        .output()
        .unwrap();
    assert_success("second Codex configure", &output);
    let output = command_with_stdin(
        fixture.command_for(&second_home),
        &["codex", "login"],
        b"second-key\n",
    );
    assert_success("second Codex login", &output);

    let state = fixture.state();
    assert_eq!(state["configs"].as_array().unwrap().len(), 2);
    for (home, expected) in [
        (&fixture.codex_home, b"first-key\n".as_slice()),
        (&second_home, b"second-key\n".as_slice()),
    ] {
        let config = parse_toml(&home.join("config.toml"));
        let provider = config["model_provider"].as_str().unwrap();
        let args = config["model_providers"][provider]["auth"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        let output = fixture.command_for(home).args(args).output().unwrap();
        assert_success("isolated Codex credential", &output);
        assert_eq!(output.stdout, expected);
    }
}

#[test]
fn logout_remains_available_after_unconfigure() {
    let fixture = Fixture::new();
    let store = fixture.root.join("codex.env");
    let provider = format!("dotenv://{}", store.display());
    assert_success("Codex configure", &fixture.configure(&provider));
    let output = command_with_stdin(fixture.command(), &["codex", "login"], b"stored-key\n");
    assert_success("Codex login", &output);
    let configuration = fixture.configuration_id();
    let output = fixture
        .command()
        .args(["codex", "unconfigure", "--yes"])
        .output()
        .unwrap();
    assert_success("Codex unconfigure", &output);
    let output = fixture
        .command()
        .args(["codex", "credential", "--configuration", &configuration])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not active"));
    let output = fixture
        .command()
        .args(["codex", "logout"])
        .output()
        .unwrap();
    assert_success("Codex logout after unconfigure", &output);
}

#[test]
fn configured_gateway_is_used_for_identity_and_audit_context() {
    let fixture = Fixture::new();
    let store = fixture.root.join("codex.env");
    let provider = format!("dotenv://{}", store.display());
    let output = fixture
        .command()
        .args([
            "codex",
            "configure",
            "--yes",
            "--provider",
            &provider,
            "--base-url",
            "https://gateway.example.com/openai/v1/",
        ])
        .output()
        .unwrap();
    assert_success("gateway Codex configure", &output);
    let output = command_with_stdin(fixture.command(), &["codex", "login"], b"gateway-key\n");
    assert_success("gateway Codex login", &output);
    assert_success("gateway Codex credential", &fixture.credential());
    let state = fixture.state();
    assert_eq!(
        state["configs"][0]["base_url"],
        "https://gateway.example.com/openai/v1"
    );
    assert_eq!(state["configs"][0]["resource"], "gateway.example.com");
    let audit = fs::read_to_string(find_named(&fixture.root, "audit.log").unwrap()).unwrap();
    assert!(audit.contains("\"operation\":\"credential_login\""));
    assert!(audit.contains("\"operation\":\"credential_get\""));
    assert!(audit.contains("\"resource\":\"gateway.example.com\""));
}

#[test]
fn repeated_configuration_is_idempotent() {
    let fixture = Fixture::new();
    assert_success("first Codex configure", &fixture.configure("null"));
    let config = fs::read(&fixture.config).unwrap();
    let state = fs::read(fixture.state_path()).unwrap();
    let output = fixture.configure("null");
    assert_success("second Codex configure", &output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("already configured"));
    assert_eq!(fs::read(&fixture.config).unwrap(), config);
    assert_eq!(fs::read(fixture.state_path()).unwrap(), state);
}

#[test]
fn insecure_remote_base_url_is_rejected() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "codex",
            "configure",
            "--yes",
            "--base-url",
            "http://gateway.example.com/v1",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must use HTTPS"));
}

#[test]
fn ambient_provider_is_not_persisted() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env("SECRETSPEC_PROVIDER", "null")
        .args(["codex", "configure", "--yes"])
        .output()
        .unwrap();
    assert_success("ambient-provider Codex configure", &output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("was not recorded"));
    assert!(fixture.state()["configs"][0]["provider"].is_null());
}

#[test]
fn managed_state_rejects_relative_config_paths() {
    let fixture = Fixture::new();
    assert_success("Codex configure", &fixture.configure("null"));
    let mut state = fixture.state();
    state["configs"][0]["config"] = Value::String("relative/config.toml".to_string());
    fs::write(
        fixture.state_path(),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
    let output = fixture
        .command()
        .args(["codex", "unconfigure", "--yes"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid Codex integration entry"));
}

#[cfg(unix)]
#[test]
fn symlinked_config_is_preserved() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let target = fixture.root.join("actual-codex-config.toml");
    fs::rename(&fixture.config, &target).unwrap();
    symlink(&target, &fixture.config).unwrap();
    assert_success("symlinked Codex configure", &fixture.configure("null"));
    assert!(
        fs::symlink_metadata(&fixture.config)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let output = fixture
        .command()
        .args(["codex", "unconfigure", "--yes"])
        .output()
        .unwrap();
    assert_success("symlinked Codex unconfigure", &output);
    assert!(
        fs::symlink_metadata(&fixture.config)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn new_config_and_state_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    fs::remove_file(&fixture.config).unwrap();
    assert_success("Codex configure", &fixture.configure("null"));
    assert_eq!(
        fs::metadata(&fixture.config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(fixture.state_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        parse_toml(&fixture.config)["model"].as_str(),
        Some("gpt-5.4")
    );
    assert_eq!(fixture.state()["configs"][0]["managed_model"], "gpt-5.4");
    let output = fixture
        .command()
        .args(["codex", "unconfigure", "--yes"])
        .output()
        .unwrap();
    assert_success("Codex unconfigure", &output);
    assert!(parse_toml(&fixture.config).get("model").is_none());
}

#[test]
fn new_config_requires_an_explicit_model() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.config).unwrap();
    let output = fixture
        .command()
        .args(["codex", "configure", "--yes"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pass --model"));
    assert!(!fixture.config.exists());
    assert!(!fixture.state_path().exists());
}

#[test]
fn managed_model_changes_fail_closed() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.config).unwrap();
    assert_success("Codex configure", &fixture.configure("null"));
    let config = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace("model = \"gpt-5.4\"", "model = \"gpt-5.6\"");
    fs::write(&fixture.config, config).unwrap();
    let output = fixture
        .command()
        .args(["codex", "unconfigure", "--yes"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("model") && stderr.contains("changed outside"));
}

#[test]
fn managed_root_keys_preserve_an_existing_table_only_config() {
    let fixture = Fixture::new();
    fs::write(&fixture.config, "[features]\nshell_tool = true\n").unwrap();
    assert_success("Codex configure", &fixture.configure("null"));
    let config = parse_toml(&fixture.config);
    assert_eq!(config["model"].as_str(), Some("gpt-5.4"));
    assert_eq!(config["features"]["shell_tool"].as_bool(), Some(true));
}
