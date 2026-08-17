use serde_json::Value;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    manifest: PathBuf,
    docker_config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        let manifest = root.join("secretspec.toml");
        fs::write(
            &manifest,
            r#"
[project]
name = "docker-helper"
revision = "1.0"
require_reason = false

[profiles.default]
DOCKER_USERNAME = { description = "Docker username", default = "registry-user", providers = ["null"] }
DOCKER_TOKEN = { description = "Docker token", default = "token=value", providers = ["null"] }
"#,
        )
        .unwrap();
        let docker_directory = root.join("docker");
        fs::create_dir(&docker_directory).unwrap();
        let docker_config = docker_directory.join("config.json");
        fs::write(
            &docker_config,
            r#"{
  "auths": {"example.com": {"auth": "encoded"}},
  "credsStore": "desktop",
  "credHelpers": {"existing.example.com": "pass"},
  "plugins": {"debug": {"hooks": "exec"}}
}
"#,
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            manifest,
            docker_config,
        }
    }

    fn apply_environment(&self, command: &mut Command) {
        command
            .current_dir(&self.root)
            .env("HOME", &self.root)
            .env("USERPROFILE", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("APPDATA", self.root.join("config"))
            .env("LOCALAPPDATA", self.root.join("state"))
            .env("DOCKER_CONFIG", self.root.join("docker"))
            .env_remove("SECRETSPEC_FILE")
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_REASON");
    }

    fn secretspec(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
        command.arg("--file").arg(&self.manifest);
        self.apply_environment(&mut command);
        command
    }

    fn embedded_secretspec(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
        self.apply_environment(&mut command);
        command
    }

    fn helper(&self, operation: &str, input: &[u8]) -> Output {
        self.helper_with_docker_config(operation, input, &self.root.join("docker"))
    }

    fn helper_with_docker_config(
        &self,
        operation: &str,
        input: &[u8],
        docker_config: &Path,
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_docker-credential-secretspec"));
        command
            .arg(operation)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.apply_environment(&mut command);
        command.env("DOCKER_CONFIG", docker_config);
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn configure(&self, registry: &str) -> Output {
        self.secretspec()
            .args([
                "docker",
                "configure",
                "--registry",
                registry,
                "--token-secret",
                "DOCKER_TOKEN",
                "--username-secret",
                "DOCKER_USERNAME",
                "--provider",
                "null",
                "--yes",
            ])
            .output()
            .unwrap()
    }
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

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn find_named(root: &Path, name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.file_name().is_some_and(|file_name| file_name == name) {
            return Some(path);
        }
        if path.is_dir()
            && let Some(path) = find_named(&path, name)
        {
            return Some(path);
        }
    }
    None
}

#[test]
fn configure_get_and_unconfigure_preserve_docker_configuration() {
    let fixture = Fixture::new();
    let original = read_json(&fixture.docker_config);

    let output = fixture.configure("ghcr.io");
    assert_success("docker configure", &output);
    let configured = read_json(&fixture.docker_config);
    assert_eq!(configured["credHelpers"]["ghcr.io"], "secretspec");
    assert_eq!(configured["credHelpers"]["existing.example.com"], "pass");
    assert_eq!(configured["credsStore"], original["credsStore"]);
    assert_eq!(configured["auths"], original["auths"]);
    assert_eq!(configured["plugins"], original["plugins"]);

    let output = fixture.helper("get", b"ghcr.io\n");
    assert_success("docker credential get", &output);
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["Username"], "registry-user");
    assert_eq!(response["Secret"], "token=value");

    let output = fixture
        .secretspec()
        .args(["docker", "unconfigure", "--registry", "ghcr.io", "--yes"])
        .output()
        .unwrap();
    assert_success("docker unconfigure", &output);
    assert_eq!(read_json(&fixture.docker_config), original);

    let output = fixture.helper("get", b"ghcr.io\n");
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "credentials not found in native keychain"
    );
}

#[test]
fn embedded_credentials_are_isolated_by_docker_configuration() {
    let fixture = Fixture::new();
    let alternate_docker = fixture.root.join("alternate-docker");
    fs::create_dir(&alternate_docker).unwrap();
    fs::write(alternate_docker.join("config.json"), "{}\n").unwrap();
    let store = fixture.root.join("multi-config.env");
    let provider = format!("dotenv://{}", store.display());

    let output = fixture
        .embedded_secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "work-user",
            "--provider",
            &provider,
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("work Docker configure", &output);
    let output = command_with_stdin(
        fixture.embedded_secretspec(),
        &["docker", "login", "ghcr.io", "--provider", &provider],
        b"work-token\n",
    );
    assert_success("work Docker login", &output);

    let mut alternate = fixture.embedded_secretspec();
    alternate.env("DOCKER_CONFIG", &alternate_docker);
    let output = alternate
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "personal-user",
            "--provider",
            &provider,
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("personal Docker configure", &output);
    let mut alternate = fixture.embedded_secretspec();
    alternate.env("DOCKER_CONFIG", &alternate_docker);
    let output = command_with_stdin(
        alternate,
        &["docker", "login", "ghcr.io", "--provider", &provider],
        b"personal-token\n",
    );
    assert_success("personal Docker login", &output);

    let work = fixture.helper("get", b"ghcr.io\n");
    assert_success("work Docker get", &work);
    let work: Value = serde_json::from_slice(&work.stdout).unwrap();
    assert_eq!(work["Username"], "work-user");
    assert_eq!(work["Secret"], "work-token");

    let personal = fixture.helper_with_docker_config("get", b"ghcr.io\n", &alternate_docker);
    assert_success("personal Docker get", &personal);
    let personal: Value = serde_json::from_slice(&personal.stdout).unwrap();
    assert_eq!(personal["Username"], "personal-user");
    assert_eq!(personal["Secret"], "personal-token");
}

#[test]
fn embedded_credentials_ignore_the_cwd_manifest_and_isolate_each_registry() {
    let fixture = Fixture::new();
    let store = fixture.root.join("docker-credentials.env");
    let provider = format!("dotenv://{}", store.display());

    let output = fixture
        .embedded_secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "github-user",
            "--provider",
            &provider,
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("embedded GHCR configure", &output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("secretspec docker login 'ghcr.io'"));
    assert!(!stdout.contains("SecretSpec manifest:"));

    let output = command_with_stdin(
        fixture.embedded_secretspec(),
        &["docker", "login", "ghcr.io", "--provider", &provider],
        b"github-token\n",
    );
    assert_success("embedded GHCR login", &output);

    let output = fixture
        .embedded_secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "registry.example.com:5000",
            "--username",
            "private-user",
            "--provider",
            &provider,
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("embedded private registry configure", &output);
    let output = command_with_stdin(
        fixture.embedded_secretspec(),
        &[
            "docker",
            "login",
            "registry.example.com:5000",
            "--provider",
            &provider,
        ],
        b"private-token\n",
    );
    assert_success("embedded private registry login", &output);

    let github = fixture.helper("get", b"ghcr.io\n");
    assert_success("embedded GHCR get", &github);
    let github: Value = serde_json::from_slice(&github.stdout).unwrap();
    assert_eq!(github["Username"], "github-user");
    assert_eq!(github["Secret"], "github-token");

    let private = fixture.helper("get", b"registry.example.com:5000\n");
    assert_success("embedded private registry get", &private);
    let private: Value = serde_json::from_slice(&private.stdout).unwrap();
    assert_eq!(private["Username"], "private-user");
    assert_eq!(private["Secret"], "private-token");

    let output = fixture
        .embedded_secretspec()
        .args(["docker", "logout", "ghcr.io", "--provider", &provider])
        .output()
        .unwrap();
    assert_success("embedded GHCR logout", &output);
    assert!(!fixture.helper("get", b"ghcr.io\n").status.success());
    let private = fixture.helper("get", b"registry.example.com:5000\n");
    assert_success("private registry remains after GHCR logout", &private);
}

#[test]
fn embedded_and_custom_manifest_options_cannot_be_mixed() {
    let fixture = Fixture::new();
    let output = fixture
        .embedded_secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "registry-user",
            "--token-secret",
            "DOCKER_TOKEN",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--token-secret") && stderr.contains("require --file"));

    let output = fixture
        .secretspec()
        .args(["docker", "login", "ghcr.io"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("manages the embedded Docker credential store")
    );
}

#[cfg(unix)]
#[test]
fn custom_manifest_symlink_keeps_relative_extends_working() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let project = fixture.root.join("project");
    fs::create_dir(&project).unwrap();
    let shared = project.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::write(
        shared.join("secretspec.toml"),
        r#"
[project]
name = "docker-helper-shared"
revision = "1.0"
require_reason = false

[profiles.default]
SYMLINK_TOKEN = { description = "Symlink token", default = "symlink-token", providers = ["null"] }
"#,
    )
    .unwrap();

    let target = fixture.root.join("manifest-target.toml");
    fs::write(
        &target,
        r#"
[project]
name = "docker-helper-symlink"
revision = "1.0"
require_reason = false
extends = ["shared"]

[profiles.default]
"#,
    )
    .unwrap();
    let manifest_link = project.join("linked-secretspec.toml");
    symlink(&target, &manifest_link).unwrap();

    let output = fixture
        .embedded_secretspec()
        .arg("--file")
        .arg(&manifest_link)
        .args([
            "docker",
            "configure",
            "--registry",
            "symlink.example.com",
            "--token-secret",
            "SYMLINK_TOKEN",
            "--username",
            "registry-user",
            "--provider",
            "null",
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("symlinked manifest configure", &output);

    let output = fixture.helper("get", b"symlink.example.com\n");
    assert_success("symlinked manifest credential get", &output);
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["Secret"], "symlink-token");
}

#[test]
fn exported_variables_do_not_become_durable_docker_configuration() {
    let fixture = Fixture::new();
    let store = format!("file://{}", fixture.root.join("ambient-store").display());
    let manifest = fixture.manifest.to_str().unwrap();
    let ambient = [
        ("SECRETSPEC_FILE", manifest),
        ("SECRETSPEC_PROFILE", "production"),
        ("SECRETSPEC_PROVIDER", store.as_str()),
        ("SECRETSPEC_REASON", "deploy frontend"),
    ];

    let mut command = fixture.embedded_secretspec();
    command.envs(ambient);
    let output = command
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "registry-user",
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("ambient docker configure", &output);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("SECRETSPEC_PROVIDER was not recorded")
    );

    let state_path = find_named(&fixture.root, "docker-credentials.json").unwrap();
    let state = read_json(&state_path);
    let credential = &state["credentials"][0];
    assert!(credential["provider"].is_null());
    assert!(credential["reason"].is_null());
    assert_eq!(credential["source"]["kind"], "embedded");

    let mut command = fixture.embedded_secretspec();
    command.envs(ambient);
    let output = command_with_stdin(
        command,
        &["docker", "login", "ghcr.io"],
        b"registry-token\n",
    );
    assert_success("ambient docker login", &output);

    let mut command = fixture.embedded_secretspec();
    command.envs(ambient);
    let output = command
        .args(["docker", "logout", "ghcr.io"])
        .output()
        .unwrap();
    assert_success("ambient docker logout", &output);

    let mut command = fixture.embedded_secretspec();
    command
        .env("SECRETSPEC_PROVIDER", "ignored")
        .env("SECRETSPEC_REASON", "ignored");
    let output = command
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "registry-user",
            "--provider",
            "null",
            "--reason",
            "team onboarding",
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("typed Docker overrides", &output);
    let state = read_json(&state_path);
    let credential = &state["credentials"][0];
    assert_eq!(credential["provider"], "null");
    assert_eq!(credential["reason"], "team onboarding");

    let output = fixture
        .embedded_secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "registry-user",
            "--profile",
            "production",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("require --file"));
}

#[test]
fn audit_context_does_not_report_the_secretspec_version_as_docker() {
    let fixture = Fixture::new();
    let store = fixture.root.join("audit.env");
    let provider = format!("dotenv://{}", store.display());
    let output = fixture
        .embedded_secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "registry-user",
            "--provider",
            &provider,
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("audit Docker configure", &output);

    let output = command_with_stdin(
        fixture.embedded_secretspec(),
        &["docker", "login", "ghcr.io", "--provider", &provider],
        b"registry-token\n",
    );
    assert_success("audit Docker login", &output);
    let output = fixture.helper("get", b"ghcr.io\n");
    assert_success("audit Docker get", &output);

    let audit_path = find_named(&fixture.root, "audit.log").unwrap();
    let audit = fs::read_to_string(audit_path).unwrap();
    let events: Vec<Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for operation in ["credential_login", "credential_get"] {
        let event = events
            .iter()
            .find(|event| event["caller"]["operation"] == operation)
            .unwrap();
        assert_eq!(event["caller"]["name"], "docker");
        assert_eq!(event["caller"]["resource"], "ghcr.io");
        assert!(event["caller"].get("version").is_none());
        assert!(event["version"].is_string());
    }
}

#[test]
fn repeated_configuration_is_idempotent() {
    let fixture = Fixture::new();
    assert_success("first docker configure", &fixture.configure("ghcr.io"));
    let configured = fs::read(&fixture.docker_config).unwrap();

    let output = fixture.configure("ghcr.io");
    assert_success("second docker configure", &output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("already configured"));
    assert_eq!(fs::read(&fixture.docker_config).unwrap(), configured);
}

#[test]
fn reconfiguration_reports_replaced_metadata_without_removing_the_secret() {
    let fixture = Fixture::new();
    let store = fixture.root.join("replacement-store");
    let provider = format!("file://{}", store.display());
    let output = fixture
        .embedded_secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "old-user",
            "--provider",
            &provider,
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("initial Docker configure", &output);
    let output = command_with_stdin(
        fixture.embedded_secretspec(),
        &["docker", "login", "ghcr.io", "--provider", &provider],
        b"stored-token\n",
    );
    assert_success("Docker login", &output);

    let output = fixture
        .embedded_secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--username",
            "new-user",
            "--provider",
            &provider,
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("replacement Docker configure", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Replaced the previous SecretSpec configuration"));
    assert!(stdout.contains("No stored credential was removed"));

    let output = fixture.helper("get", b"ghcr.io\n");
    assert_success("Docker get after replacement", &output);
    let credential: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(credential["Username"], "new-user");
    assert_eq!(credential["Secret"], "stored-token");
}

#[test]
fn unconfigure_all_removes_only_managed_registry_helpers() {
    let fixture = Fixture::new();
    let original = read_json(&fixture.docker_config);
    assert_success("first docker configure", &fixture.configure("ghcr.io"));
    assert_success(
        "second docker configure",
        &fixture.configure("registry.example.com:5000"),
    );

    let output = fixture
        .secretspec()
        .args(["docker", "unconfigure", "--all", "--yes"])
        .output()
        .unwrap();
    assert_success("docker unconfigure --all", &output);
    assert_eq!(read_json(&fixture.docker_config), original);
}

#[test]
fn configure_refuses_to_replace_an_existing_registry_helper() {
    let fixture = Fixture::new();
    let mut config = read_json(&fixture.docker_config);
    config["credHelpers"]["ghcr.io"] = Value::String("pass".to_string());
    fs::write(
        &fixture.docker_config,
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    let original = fs::read(&fixture.docker_config).unwrap();

    let output = fixture.configure("ghcr.io");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already uses credential helper 'pass'"));
    assert!(stderr.contains("refusing"));
    assert_eq!(fs::read(&fixture.docker_config).unwrap(), original);
}

#[test]
fn unconfigure_refuses_to_remove_an_externally_changed_helper() {
    let fixture = Fixture::new();
    assert_success("docker configure", &fixture.configure("ghcr.io"));
    let mut config = read_json(&fixture.docker_config);
    config["credHelpers"]["ghcr.io"] = Value::String("pass".to_string());
    fs::write(
        &fixture.docker_config,
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    let changed = fs::read(&fixture.docker_config).unwrap();

    let output = fixture
        .secretspec()
        .args(["docker", "unconfigure", "--registry", "ghcr.io", "--yes"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("changed to 'pass'"));
    assert_eq!(fs::read(&fixture.docker_config).unwrap(), changed);
}

#[test]
fn unconfigure_recovers_after_the_helper_entry_was_already_removed() {
    let fixture = Fixture::new();
    assert_success("docker configure", &fixture.configure("ghcr.io"));
    let state_path = find_named(&fixture.root, "docker-credentials.json").unwrap();

    let mut config = read_json(&fixture.docker_config);
    config["credHelpers"]
        .as_object_mut()
        .unwrap()
        .remove("ghcr.io");
    fs::write(
        &fixture.docker_config,
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();

    let output = fixture
        .secretspec()
        .args(["docker", "unconfigure", "--registry", "ghcr.io", "--yes"])
        .output()
        .unwrap();
    assert_success("recovering docker unconfigure", &output);
    assert!(!state_path.exists());
    assert_eq!(read_json(&fixture.docker_config), config);
}

#[cfg(unix)]
#[test]
fn managed_state_is_owner_only_and_preserves_a_symlink() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let fixture = Fixture::new();
    let docker_mode = fs::metadata(&fixture.docker_config)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_success("first docker configure", &fixture.configure("ghcr.io"));
    let state_path = find_named(&fixture.root, "docker-credentials.json").unwrap();
    assert_eq!(
        fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&fixture.docker_config)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        docker_mode
    );

    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o644)).unwrap();
    let target = state_path.with_file_name("actual-docker-credentials.json");
    fs::rename(&state_path, &target).unwrap();
    symlink(&target, &state_path).unwrap();

    assert_success(
        "second docker configure",
        &fixture.configure("registry.example.com:5000"),
    );
    assert!(
        fs::symlink_metadata(&state_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        read_json(&target)["credentials"].as_array().unwrap().len(),
        2
    );

    let output = fixture
        .secretspec()
        .args(["docker", "unconfigure", "--all", "--yes"])
        .output()
        .unwrap();
    assert_success("symlinked state unconfigure all", &output);
    assert!(
        fs::symlink_metadata(&state_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        read_json(&target)["credentials"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    assert_success(
        "configure after symlinked state cleanup",
        &fixture.configure("ghcr.io"),
    );
}

#[test]
fn non_interactive_configuration_requires_confirmation() {
    let fixture = Fixture::new();
    let original = fs::read(&fixture.docker_config).unwrap();
    let output = fixture
        .secretspec()
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--token-secret",
            "DOCKER_TOKEN",
            "--username",
            "registry-user",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pass --yes"));
    assert_eq!(fs::read(&fixture.docker_config).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn configuration_preserves_a_symlinked_docker_config() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let target = fixture.docker_config.with_file_name("actual-config.json");
    fs::rename(&fixture.docker_config, &target).unwrap();
    symlink(&target, &fixture.docker_config).unwrap();
    let original = read_json(&target);

    assert_success("docker configure", &fixture.configure("ghcr.io"));
    assert!(
        fs::symlink_metadata(&fixture.docker_config)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(read_json(&target)["credHelpers"]["ghcr.io"], "secretspec");

    let output = fixture
        .secretspec()
        .args(["docker", "unconfigure", "--registry", "ghcr.io", "--yes"])
        .output()
        .unwrap();
    assert_success("docker unconfigure", &output);
    assert!(
        fs::symlink_metadata(&fixture.docker_config)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(read_json(&target), original);
}

#[cfg(unix)]
#[test]
fn configuration_identity_resolves_a_symlinked_parent_directory() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let original = read_json(&fixture.docker_config);
    let docker_link = fixture.root.join("docker-link");
    symlink(fixture.root.join("docker"), &docker_link).unwrap();

    let mut command = fixture.secretspec();
    command.env("DOCKER_CONFIG", &docker_link);
    let output = command
        .args([
            "docker",
            "configure",
            "--registry",
            "ghcr.io",
            "--token-secret",
            "DOCKER_TOKEN",
            "--username-secret",
            "DOCKER_USERNAME",
            "--provider",
            "null",
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("symlinked parent Docker configure", &output);

    let output = fixture.helper("get", b"ghcr.io\n");
    assert_success("real parent Docker get", &output);
    let output = fixture.helper_with_docker_config("get", b"ghcr.io\n", &docker_link);
    assert_success("symlinked parent Docker get", &output);

    let mut command = fixture.secretspec();
    command.env("DOCKER_CONFIG", &docker_link);
    let output = command
        .args(["docker", "unconfigure", "--registry", "ghcr.io", "--yes"])
        .output()
        .unwrap();
    assert_success("symlinked parent Docker unconfigure", &output);
    assert_eq!(read_json(&fixture.docker_config), original);
}

#[test]
fn helper_is_read_only() {
    let fixture = Fixture::new();
    for (operation, input) in [
        (
            "store",
            br#"{"ServerURL":"ghcr.io","Username":"user","Secret":"secret"}"#.as_slice(),
        ),
        ("erase", b"ghcr.io".as_slice()),
    ] {
        let output = fixture.helper(operation, input);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("read-only"));
    }
}
