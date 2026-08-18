use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    manifest: PathBuf,
    settings: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        let home = root.join("home");
        let project = root.join("project");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&project).unwrap();
        let output = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .output()
            .unwrap();
        assert!(output.status.success());
        let manifest = project.join("secretspec.toml");
        fs::write(
            &manifest,
            r#"
[project]
name = "claude-helper"
revision = "1.0"
require_reason = false

[profiles.default]
CLAUDE_TOKEN = { description = "Claude token", default = "fixture-claude-token", providers = ["null"] }
"#,
        )
        .unwrap();
        let settings = project.join(".claude/settings.local.json");
        fs::create_dir(settings.parent().unwrap()).unwrap();
        fs::write(
            &settings,
            r#"{
  "permissions": {"allow": ["Bash(cargo test:*)"]},
  "env": {"ANTHROPIC_BASE_URL": "https://gateway.example.com"}
}
"#,
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            home,
            project,
            manifest,
            settings,
        }
    }

    fn command_in(&self, directory: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
        command
            .current_dir(directory)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("APPDATA", self.root.join("config"))
            .env("LOCALAPPDATA", self.root.join("state"))
            .env_remove("SECRETSPEC_FILE")
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_REASON")
            .env_remove("CLAUDE_CONFIG_DIR");
        command
    }

    fn command(&self) -> Command {
        self.command_in(&self.project)
    }

    fn custom_configure(&self) -> Output {
        self.command()
            .arg("--file")
            .arg(&self.manifest)
            .args([
                "--reason",
                "Use gateway credential",
                "claude",
                "configure",
                "--token-secret",
                "CLAUDE_TOKEN",
                "--profile",
                "default",
                "--provider",
                "null",
                "--resource",
                "gateway.example.com",
            ])
            .output()
            .unwrap()
    }

    fn embedded_configure(&self, provider: &str) -> Output {
        self.command()
            .args(["claude", "configure", "--provider", provider])
            .output()
            .unwrap()
    }

    fn helper_id_at(&self, settings: &Path) -> String {
        let settings = read_json(settings);
        settings["apiKeyHelper"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .to_string()
    }

    fn helper_id(&self) -> String {
        self.helper_id_at(&self.settings)
    }

    fn credential(&self) -> Output {
        self.command()
            .args(["claude", "credential", "--configuration", &self.helper_id()])
            .output()
            .unwrap()
    }

    fn state(&self) -> Value {
        read_json(&self.root.join("config/secretspec/claude-code.json"))
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
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

#[test]
fn custom_manifest_configure_resolve_and_unconfigure_preserve_settings() {
    let fixture = Fixture::new();
    let original = read_json(&fixture.settings);

    let output = fixture.custom_configure();
    assert_success("Claude configure", &output);
    let configured = read_json(&fixture.settings);
    assert_eq!(configured["permissions"], original["permissions"]);
    assert_eq!(configured["env"], original["env"]);
    assert!(
        configured["apiKeyHelper"]
            .as_str()
            .unwrap()
            .starts_with("secretspec claude credential --configuration ")
    );
    let state = fixture.state();
    assert_eq!(state["settings"][0]["provider"], "null");
    assert_eq!(state["settings"][0]["reason"], "Use gateway credential");
    assert_eq!(state["settings"][0]["resource"], "gateway.example.com");
    assert_eq!(state["settings"][0]["source"]["kind"], "manifest");

    let output = fixture.credential();
    assert_success("Claude credential", &output);
    assert_eq!(output.stdout, b"fixture-claude-token\n");

    let output = fixture
        .command()
        .args(["claude", "unconfigure"])
        .output()
        .unwrap();
    assert_success("Claude unconfigure", &output);
    assert_eq!(read_json(&fixture.settings), original);
    assert_eq!(fixture.state()["settings"][0]["configured"], false);
}

#[test]
fn embedded_login_credential_and_logout_use_the_configured_provider() {
    let fixture = Fixture::new();
    let store = fixture.root.join("claude.env");
    let provider = format!("dotenv://{}", store.display());

    let output = fixture.embedded_configure(&provider);
    assert_success("embedded Claude configure", &output);
    let output = command_with_stdin(
        fixture.command(),
        &[
            "--reason",
            "Store Claude Code credential",
            "claude",
            "login",
            "--provider",
            &provider,
        ],
        b"fixture-embedded-token\n",
    );
    assert_success("embedded Claude login", &output);
    let output = fixture.credential();
    assert_success("embedded Claude credential", &output);
    assert_eq!(output.stdout, b"fixture-embedded-token\n");

    let output = fixture
        .command()
        .args([
            "--reason",
            "Remove Claude Code credential",
            "claude",
            "logout",
            "--provider",
            &provider,
        ])
        .output()
        .unwrap();
    assert_success("embedded Claude logout", &output);
    let output = fixture.credential();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Claude Code API credential is not stored")
    );
}

#[test]
fn configure_refuses_to_replace_an_unmanaged_helper() {
    let fixture = Fixture::new();
    let mut settings = read_json(&fixture.settings);
    settings["apiKeyHelper"] = Value::String("other-helper".to_string());
    fs::write(
        &fixture.settings,
        serde_json::to_vec_pretty(&settings).unwrap(),
    )
    .unwrap();

    let output = fixture.custom_configure();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not") && stderr.contains("managed by SecretSpec"),
        "stderr:\n{stderr}"
    );
    assert_eq!(read_json(&fixture.settings)["apiKeyHelper"], "other-helper");
}

#[test]
fn unconfigure_refuses_to_remove_an_edited_managed_helper() {
    let fixture = Fixture::new();
    assert_success("Claude configure", &fixture.custom_configure());
    let mut settings = read_json(&fixture.settings);
    settings["apiKeyHelper"] = Value::String("edited-helper".to_string());
    fs::write(
        &fixture.settings,
        serde_json::to_vec_pretty(&settings).unwrap(),
    )
    .unwrap();

    let output = fixture
        .command()
        .args(["claude", "unconfigure"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("changed") && stderr.contains("outside SecretSpec"),
        "stderr:\n{stderr}"
    );
    assert_eq!(fixture.state()["settings"].as_array().unwrap().len(), 1);
    assert_eq!(
        read_json(&fixture.settings)["apiKeyHelper"],
        "edited-helper"
    );
}

#[test]
fn unconfigure_recovers_when_the_managed_helper_is_already_absent() {
    let fixture = Fixture::new();
    assert_success("Claude configure", &fixture.custom_configure());
    let mut settings = read_json(&fixture.settings);
    settings.as_object_mut().unwrap().remove("apiKeyHelper");
    fs::write(
        &fixture.settings,
        serde_json::to_vec_pretty(&settings).unwrap(),
    )
    .unwrap();

    let output = fixture
        .command()
        .args(["claude", "unconfigure"])
        .output()
        .unwrap();
    assert_success("stale-state Claude unconfigure", &output);
    assert_eq!(fixture.state()["settings"][0]["configured"], false);
}

#[test]
fn ambient_provider_is_not_saved_as_durable_helper_configuration() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env("SECRETSPEC_PROVIDER", "null")
        .args(["claude", "configure"])
        .output()
        .unwrap();
    assert_success("ambient-provider Claude configure", &output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("was not recorded"));
    assert!(fixture.state()["settings"][0]["provider"].is_null());
}

#[test]
fn global_configuration_requires_confirmation_and_supports_yes() {
    let fixture = Fixture::new();
    let global_settings = fixture.home.join(".claude/settings.json");

    let output = fixture
        .command()
        .args(["claude", "configure", "--global"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pass --yes"));

    let output = fixture
        .command()
        .args(["claude", "configure", "--global", "--yes"])
        .output()
        .unwrap();
    assert_success("global Claude configure", &output);
    assert!(read_json(&global_settings)["apiKeyHelper"].is_string());

    let output = fixture
        .command()
        .args(["claude", "unconfigure", "--global", "--yes"])
        .output()
        .unwrap();
    assert_success("global Claude unconfigure", &output);
    assert!(read_json(&global_settings).get("apiKeyHelper").is_none());
}

#[test]
fn project_configuration_uses_the_repository_root_from_a_subdirectory() {
    let fixture = Fixture::new();
    let subdirectory = fixture.project.join("nested/directory");
    fs::create_dir_all(&subdirectory).unwrap();

    let output = fixture
        .command_in(&subdirectory)
        .args(["claude", "configure"])
        .output()
        .unwrap();
    assert_success("subdirectory Claude configure", &output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("out of version control"));
    assert!(read_json(&fixture.settings)["apiKeyHelper"].is_string());
    assert!(!subdirectory.join(".claude/settings.local.json").exists());
}

#[test]
fn linked_worktree_configuration_uses_the_main_checkout_root() {
    let fixture = Fixture::new();
    let output = Command::new("git")
        .args(["add", "secretspec.toml"])
        .current_dir(&fixture.project)
        .output()
        .unwrap();
    assert_success("git add", &output);
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=SecretSpec Test",
            "-c",
            "user.email=test@secretspec.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ])
        .current_dir(&fixture.project)
        .output()
        .unwrap();
    assert_success("git commit", &output);
    let linked = fixture.root.join("linked");
    let output = Command::new("git")
        .args(["worktree", "add", "--detach", linked.to_str().unwrap()])
        .current_dir(&fixture.project)
        .output()
        .unwrap();
    assert_success("git worktree add", &output);

    let output = fixture
        .command_in(&linked)
        .args(["claude", "configure"])
        .output()
        .unwrap();
    assert_success("linked-worktree Claude configure", &output);
    assert!(read_json(&fixture.settings)["apiKeyHelper"].is_string());
    assert!(!linked.join(".claude/settings.local.json").exists());
}

#[test]
fn global_configuration_honors_claude_config_dir() {
    let fixture = Fixture::new();
    let claude_config = fixture.root.join("claude-work");

    let output = fixture
        .command()
        .env("CLAUDE_CONFIG_DIR", &claude_config)
        .args(["claude", "configure", "--global", "--yes"])
        .output()
        .unwrap();
    assert_success("custom-config-dir Claude configure", &output);
    assert!(read_json(&claude_config.join("settings.json"))["apiKeyHelper"].is_string());
    assert!(!fixture.home.join(".claude/settings.json").exists());
}

#[test]
fn embedded_credentials_are_isolated_by_settings_scope() {
    let fixture = Fixture::new();
    let second = fixture.root.join("second-project");
    fs::create_dir(&second).unwrap();
    let output = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&second)
        .output()
        .unwrap();
    assert_success("second git init", &output);
    let second_settings = second.join(".claude/settings.local.json");
    let store = fixture.root.join("claude.env");
    let provider = format!("dotenv://{}", store.display());

    let output = fixture.embedded_configure(&provider);
    assert_success("first Claude configure", &output);
    let output = command_with_stdin(
        fixture.command(),
        &["claude", "login"],
        b"first-project-token\n",
    );
    assert_success("first Claude login", &output);

    let output = fixture
        .command_in(&second)
        .args(["claude", "configure", "--provider", &provider])
        .output()
        .unwrap();
    assert_success("second Claude configure", &output);
    let output = command_with_stdin(
        fixture.command_in(&second),
        &["claude", "login"],
        b"second-project-token\n",
    );
    assert_success("second Claude login", &output);

    let first = fixture
        .command()
        .args([
            "claude",
            "credential",
            "--configuration",
            &fixture.helper_id(),
        ])
        .output()
        .unwrap();
    assert_success("first Claude credential", &first);
    let second_value = fixture
        .command_in(&second)
        .args([
            "claude",
            "credential",
            "--configuration",
            &fixture.helper_id_at(&second_settings),
        ])
        .output()
        .unwrap();
    assert_success("second Claude credential", &second_value);
    assert_eq!(first.stdout, b"first-project-token\n");
    assert_eq!(second_value.stdout, b"second-project-token\n");
}

#[test]
fn logout_remains_available_after_unconfigure() {
    let fixture = Fixture::new();
    let store = fixture.root.join("claude.env");
    let provider = format!("dotenv://{}", store.display());
    assert_success("Claude configure", &fixture.embedded_configure(&provider));
    let output = command_with_stdin(fixture.command(), &["claude", "login"], b"stored-token\n");
    assert_success("Claude login", &output);
    let configuration = fixture.helper_id();
    let output = fixture
        .command()
        .args(["claude", "unconfigure"])
        .output()
        .unwrap();
    assert_success("Claude unconfigure", &output);
    let output = fixture
        .command()
        .args(["claude", "credential", "--configuration", &configuration])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not active"));
    let output = fixture
        .command()
        .args(["claude", "logout"])
        .output()
        .unwrap();
    assert_success("Claude logout after unconfigure", &output);
}

#[test]
fn managed_state_rejects_relative_settings_paths() {
    let fixture = Fixture::new();
    assert_success("Claude configure", &fixture.embedded_configure("null"));
    let state_path = fixture.root.join("config/secretspec/claude-code.json");
    let mut state = read_json(&state_path);
    state["settings"][0]["settings"] = Value::String("relative/settings.json".to_string());
    fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let output = fixture
        .command()
        .args(["claude", "unconfigure"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must be absolute"));
}

#[test]
fn repeated_configuration_is_idempotent() {
    let fixture = Fixture::new();
    let first = fixture.embedded_configure("null");
    assert_success("first Claude configure", &first);
    let state = fixture.state();
    let second = fixture.embedded_configure("null");
    assert_success("second Claude configure", &second);
    assert!(String::from_utf8_lossy(&second.stdout).contains("already configured"));
    assert_eq!(fixture.state(), state);
    assert_eq!(state["settings"].as_array().unwrap().len(), 1);
}

#[test]
fn configured_resource_is_used_for_lifecycle_and_get_audit_context() {
    let fixture = Fixture::new();
    let store = fixture.root.join("claude.env");
    let provider = format!("dotenv://{}", store.display());
    let output = fixture
        .command()
        .args([
            "claude",
            "configure",
            "--provider",
            &provider,
            "--resource",
            "gateway.example.com",
        ])
        .output()
        .unwrap();
    assert_success("gateway Claude configure", &output);
    let output = command_with_stdin(fixture.command(), &["claude", "login"], b"gateway-token\n");
    assert_success("gateway Claude login", &output);
    assert_success("gateway Claude credential", &fixture.credential());

    let audit = find_named(&fixture.root, "audit.log").unwrap();
    let audit = fs::read_to_string(audit).unwrap();
    assert!(audit.contains("\"operation\":\"credential_login\""));
    assert!(audit.contains("\"operation\":\"credential_get\""));
    assert!(audit.contains("\"resource\":\"gateway.example.com\""));
}

#[cfg(unix)]
#[test]
fn configuration_preserves_a_symlinked_settings_file() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let target = fixture.root.join("actual-settings.json");
    fs::rename(&fixture.settings, &target).unwrap();
    symlink(&target, &fixture.settings).unwrap();

    assert_success(
        "symlinked Claude configure",
        &fixture.embedded_configure("null"),
    );
    assert!(
        fs::symlink_metadata(&fixture.settings)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(read_json(&target)["apiKeyHelper"].is_string());
    let output = fixture
        .command()
        .args(["claude", "unconfigure"])
        .output()
        .unwrap();
    assert_success("symlinked Claude unconfigure", &output);
    assert!(
        fs::symlink_metadata(&fixture.settings)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn new_state_and_settings_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    fs::remove_file(&fixture.settings).unwrap();
    assert_success("Claude configure", &fixture.embedded_configure("null"));
    let state = fixture.root.join("config/secretspec/claude-code.json");
    assert_eq!(
        fs::metadata(&fixture.settings)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(state).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn generated_helper_runs_through_the_system_shell() {
    let fixture = Fixture::new();
    assert_success("Claude configure", &fixture.custom_configure());
    let helper = read_json(&fixture.settings)["apiKeyHelper"]
        .as_str()
        .unwrap()
        .to_string();
    let binary = Path::new(env!("CARGO_BIN_EXE_secretspec"));
    let mut path = vec![binary.parent().unwrap().to_path_buf()];
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let output = Command::new("sh")
        .args(["-c", &helper])
        .current_dir(&fixture.project)
        .env("PATH", std::env::join_paths(path).unwrap())
        .env("HOME", &fixture.home)
        .env("USERPROFILE", &fixture.home)
        .env("XDG_CONFIG_HOME", fixture.root.join("config"))
        .env("XDG_STATE_HOME", fixture.root.join("state"))
        .env("APPDATA", fixture.root.join("config"))
        .env("LOCALAPPDATA", fixture.root.join("state"))
        .env_remove("SECRETSPEC_FILE")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_REASON")
        .output()
        .unwrap();
    assert_success("Claude shell helper", &output);
    assert_eq!(output.stdout, b"fixture-claude-token\n");
}
