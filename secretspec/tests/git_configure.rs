use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    repository: PathBuf,
    manifest: PathBuf,
    global_config: PathBuf,
    path: OsString,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        let repository = root.join("repository");
        fs::create_dir(&repository).unwrap();
        let output = Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&repository)
            .env("HOME", &root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert_success("git init", &output);
        let output = Command::new("git")
            .args([
                "-c",
                "user.name=SecretSpec Test",
                "-c",
                "user.email=secretspec@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "--quiet",
                "-m",
                "initial",
            ])
            .current_dir(&repository)
            .env("HOME", &root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert_success("git commit", &output);

        let manifest = repository.join("secretspec.toml");
        fs::write(
            &manifest,
            r#"
[project]
name = "git-configure"
revision = "1.0"
require_reason = false

[profiles.default]
GITHUB_TOKEN = { description = "GitHub token", default = "token=value", providers = ["null"] }
ORG_TOKEN = { description = "Organization token", default = "org-token", providers = ["null"] }
"#,
        )
        .unwrap();

        let binary = Path::new(env!("CARGO_BIN_EXE_secretspec"));
        let helper = Path::new(env!("CARGO_BIN_EXE_git-credential-secretspec"));
        assert_eq!(binary.parent(), helper.parent());
        let existing_path = env::var_os("PATH").unwrap_or_default();
        let path = env::join_paths(
            std::iter::once(binary.parent().unwrap().to_path_buf())
                .chain(env::split_paths(&existing_path)),
        )
        .unwrap();

        Self {
            _temp: temp,
            root: root.clone(),
            repository,
            manifest,
            global_config: root.join("global.gitconfig"),
            path,
        }
    }

    fn command(&self) -> Command {
        self.command_in(&self.repository)
    }

    fn command_in(&self, directory: &Path) -> Command {
        self.command_with_manifest(directory, true)
    }

    fn embedded_command(&self) -> Command {
        self.command_with_manifest(&self.repository, false)
    }

    fn command_with_manifest(&self, directory: &Path, manifest: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
        if manifest {
            command.arg("--file").arg(&self.manifest);
        }
        command
            .current_dir(directory)
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("APPDATA", self.root.join("config"))
            .env("LOCALAPPDATA", self.root.join("state"))
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("PATH", &self.path)
            .env_remove("SECRETSPEC_FILE")
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_REASON");
        command
    }

    fn git(&self, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(&self.repository)
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("APPDATA", self.root.join("config"))
            .env("LOCALAPPDATA", self.root.join("state"))
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("PATH", &self.path)
            .output()
            .unwrap()
    }

    fn git_ok(&self, args: &[&str]) -> String {
        let output = self.git(args);
        assert_success("git", &output);
        String::from_utf8(output.stdout).unwrap()
    }

    fn credential_fill(&self, request: &[u8]) -> Output {
        let mut child = Command::new("git")
            .args(["credential", "fill"])
            .current_dir(&self.repository)
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("APPDATA", self.root.join("config"))
            .env("LOCALAPPDATA", self.root.join("state"))
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("PATH", &self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(request).unwrap();
        child.wait_with_output().unwrap()
    }

    /// Like `embedded_command`, but with `SECRETSPEC_*` variables exported the
    /// way a user who selected a profile or provider for their shell has them.
    fn ambient_command(&self, variables: &[(&str, &str)]) -> Command {
        let mut command = self.embedded_command();
        for (name, value) in variables {
            command.env(name, value);
        }
        command
    }

    fn configure_args(global: bool) -> Vec<&'static str> {
        let mut args = vec![
            "git",
            "configure",
            "--url",
            "https://github.com",
            "--token-secret",
            "GITHUB_TOKEN",
            "--username",
            "vimjoyer",
        ];
        if global {
            args.extend(["--global", "--yes"]);
        }
        args
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

#[test]
fn local_configuration_can_be_removed_from_a_linked_worktree() {
    let fixture = Fixture::new();
    fixture.git_ok(&["config", "--local", "user.name", "Existing User"]);
    let config_path = fixture.git_ok(&["rev-parse", "--git-path", "config"]);
    let config_path = fixture.repository.join(config_path.trim());
    let original_config = fs::read(&config_path).unwrap();
    let worktree = fixture.root.join("linked-worktree");
    let output = fixture.git(&[
        "worktree",
        "add",
        "--detach",
        worktree.to_str().unwrap(),
        "HEAD",
    ]);
    assert_success("git worktree add", &output);

    let output = fixture
        .command()
        .args(Fixture::configure_args(false))
        .output()
        .unwrap();
    assert_success("local configure", &output);
    let includes = fixture.git_ok(&["config", "--local", "--get-all", "include.path"]);
    let managed_path = PathBuf::from(includes.lines().next().unwrap());
    assert!(managed_path.exists());

    let output = fixture
        .command_in(&worktree)
        .args(["git", "unconfigure", "--all"])
        .output()
        .unwrap();
    assert_success("linked-worktree unconfigure all", &output);
    assert!(!managed_path.exists());
    assert_eq!(fs::read(&config_path).unwrap(), original_config);
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
fn local_configure_works_and_unconfigure_restores_existing_config() {
    let fixture = Fixture::new();
    fixture.git_ok(&["config", "--local", "user.name", "Existing User"]);
    fixture.git_ok(&["config", "--local", "credential.helper", "!true"]);
    fixture.git_ok(&[
        "config",
        "--local",
        "credential.https://github.com.username",
        "existing-user",
    ]);
    fixture.git_ok(&[
        "config",
        "--local",
        "include.path",
        "/tmp/unrelated-git-config",
    ]);
    let config_path = fixture.git_ok(&["rev-parse", "--git-path", "config"]);
    let config_path = fixture.repository.join(config_path.trim());
    let original_config = fs::read(&config_path).unwrap();

    let output = fixture
        .command()
        .args(Fixture::configure_args(false))
        .output()
        .unwrap();
    assert_success("local configure", &output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Undo with: secretspec git unconfigure"));
    assert!(stdout.contains("SecretSpec manifest:"));
    assert!(!stdout.contains("token=value"));

    let includes = fixture.git_ok(&["config", "--local", "--get-all", "include.path"]);
    assert!(includes.contains("/tmp/unrelated-git-config"));
    let managed_path = includes
        .lines()
        .map(PathBuf::from)
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name == "secretspec-credentials")
        })
        .unwrap();
    assert!(managed_path.exists());

    let output = fixture
        .command()
        .args(Fixture::configure_args(false))
        .output()
        .unwrap();
    assert_success("repeated local configure", &output);
    let includes = fixture.git_ok(&["config", "--local", "--get-all", "include.path"]);
    assert_eq!(
        includes
            .lines()
            .filter(|line| Path::new(line) == managed_path)
            .count(),
        1
    );

    let fill = fixture.credential_fill(b"protocol=https\nhost=github.com\n\n");
    assert_success("git credential fill", &fill);
    let filled = String::from_utf8(fill.stdout).unwrap();
    assert!(filled.contains("username=vimjoyer\n"));
    assert!(filled.contains("password=token=value\n"));

    let output = fixture
        .command()
        .args(["git", "unconfigure", "--url", "https://github.com"])
        .output()
        .unwrap();
    assert_success("local unconfigure", &output);
    assert!(!managed_path.exists());
    assert_eq!(fs::read(&config_path).unwrap(), original_config);

    let output = fixture
        .command()
        .args([
            "git",
            "configure",
            "--url",
            "https://github.com/cachix",
            "--token-secret",
            "GITHUB_TOKEN",
            "--username",
            "vimjoyer",
        ])
        .output()
        .unwrap();
    assert_success("path-scoped local configure", &output);
    let fill =
        fixture.credential_fill(b"protocol=https\nhost=github.com\npath=cachix/secretspec\n\n");
    assert_success("path-scoped git credential fill", &fill);
    let filled = String::from_utf8(fill.stdout).unwrap();
    assert!(filled.contains("username=vimjoyer\n"));
    assert!(filled.contains("password=token=value\n"));

    let output = fixture
        .command()
        .args(["git", "unconfigure", "--all"])
        .output()
        .unwrap();
    assert_success("local unconfigure all", &output);
    assert_eq!(fs::read(&config_path).unwrap(), original_config);
}

#[test]
fn more_specific_credential_helper_wins_over_host_wide_helper() {
    let fixture = Fixture::new();
    for (target, secret) in [
        ("https://github.com", "GITHUB_TOKEN"),
        ("https://github.com/cachix", "ORG_TOKEN"),
    ] {
        let output = fixture
            .command()
            .args([
                "git",
                "configure",
                "--url",
                target,
                "--token-secret",
                secret,
                "--username",
                "vimjoyer",
            ])
            .output()
            .unwrap();
        assert_success("overlapping credential configure", &output);
    }

    let fill =
        fixture.credential_fill(b"protocol=https\nhost=github.com\npath=cachix/secretspec\n\n");
    assert_success("path-scoped credential fill", &fill);
    let filled = String::from_utf8(fill.stdout).unwrap();
    assert!(filled.contains("password=org-token\n"), "{filled}");
    assert!(!filled.contains("password=token=value\n"), "{filled}");
}

#[cfg(unix)]
#[test]
fn custom_manifest_symlink_keeps_relative_extends_working() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let shared = fixture.repository.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::write(
        shared.join("secretspec.toml"),
        r#"
[project]
name = "git-configure-shared"
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
name = "git-configure-symlink"
revision = "1.0"
require_reason = false
extends = ["shared"]

[profiles.default]
"#,
    )
    .unwrap();
    let manifest_link = fixture.repository.join("linked-secretspec.toml");
    symlink(&target, &manifest_link).unwrap();

    let mut command = fixture.embedded_command();
    let output = command
        .arg("--file")
        .arg(&manifest_link)
        .args([
            "git",
            "configure",
            "--url",
            "https://symlink.example.com",
            "--token-secret",
            "SYMLINK_TOKEN",
            "--username",
            "user",
        ])
        .output()
        .unwrap();
    assert_success("symlinked manifest configure", &output);

    let fill = fixture.credential_fill(b"protocol=https\nhost=symlink.example.com\n\n");
    assert_success("symlinked manifest credential fill", &fill);
    assert!(
        String::from_utf8(fill.stdout)
            .unwrap()
            .contains("password=symlink-token\n")
    );
}

#[test]
fn embedded_credentials_ignore_the_cwd_manifest_and_isolate_each_target() {
    let fixture = Fixture::new();
    let store = fixture.root.join("git-credentials.env");
    let provider = format!("dotenv://{}", store.display());

    let output = fixture
        .embedded_command()
        .args([
            "git",
            "configure",
            "--url",
            "https://github.com",
            "--username",
            "vimjoyer",
            "--provider",
            &provider,
        ])
        .output()
        .unwrap();
    assert_success("embedded GitHub configure", &output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("secretspec git login 'https://github.com'"));
    assert!(!stdout.contains("SecretSpec manifest:"));

    let includes = fixture.git_ok(&["config", "--local", "--get-all", "include.path"]);
    let managed_path = PathBuf::from(includes.lines().next().unwrap());
    let managed = fs::read_to_string(&managed_path).unwrap();
    assert!(!managed.contains("--file"));
    assert!(!managed.contains(&fixture.manifest.to_string_lossy().to_string()));
    assert!(managed.contains("--password-secret 'PASSWORD_"));
    assert!(managed.contains("--username-secret 'USERNAME_"));

    let output = command_with_stdin(
        fixture.embedded_command(),
        &[
            "git",
            "login",
            "https://github.com",
            "--provider",
            &provider,
        ],
        b"github-token\n",
    );
    assert_success("embedded GitHub login", &output);

    let output = fixture
        .embedded_command()
        .args([
            "git",
            "configure",
            "--url",
            "https://gitlab.com",
            "--provider",
            &provider,
        ])
        .output()
        .unwrap();
    assert_success("embedded GitLab configure", &output);
    let output = command_with_stdin(
        fixture.embedded_command(),
        &[
            "git",
            "login",
            "https://gitlab.com",
            "--username",
            "gitlab-user",
            "--provider",
            &provider,
        ],
        b"gitlab-token\n",
    );
    assert_success("embedded GitLab login", &output);

    let github = fixture.credential_fill(b"protocol=https\nhost=github.com\n\n");
    assert_success("embedded GitHub fill", &github);
    let github = String::from_utf8(github.stdout).unwrap();
    assert!(github.contains("username=vimjoyer\n"));
    assert!(github.contains("password=github-token\n"));

    let gitlab = fixture.credential_fill(b"protocol=https\nhost=gitlab.com\n\n");
    assert_success("embedded GitLab fill", &gitlab);
    let gitlab = String::from_utf8(gitlab.stdout).unwrap();
    assert!(gitlab.contains("username=gitlab-user\n"));
    assert!(gitlab.contains("password=gitlab-token\n"));

    let output = fixture
        .embedded_command()
        .args([
            "git",
            "logout",
            "https://github.com",
            "--provider",
            &provider,
        ])
        .output()
        .unwrap();
    assert_success("embedded GitHub logout", &output);
    let github = fixture.credential_fill(b"protocol=https\nhost=github.com\n\n");
    assert!(!github.status.success());
    let gitlab = fixture.credential_fill(b"protocol=https\nhost=gitlab.com\n\n");
    assert_success("GitLab remains after GitHub logout", &gitlab);
    assert!(
        String::from_utf8(gitlab.stdout)
            .unwrap()
            .contains("password=gitlab-token\n")
    );
}

#[test]
fn manual_embedded_aliases_use_the_canonical_target_identity() {
    let fixture = Fixture::new();
    let store = fixture.root.join("manual-git-credentials.env");
    let provider = format!("dotenv://{}", store.display());

    let output = command_with_stdin(
        fixture.embedded_command(),
        &[
            "git",
            "login",
            "https://github.com/%66oo",
            "--username",
            "manual-user",
            "--provider",
            &provider,
        ],
        b"manual-token\n",
    );
    assert_success("embedded login with encoded path", &output);

    fixture.git_ok(&[
        "config",
        "--local",
        "credential.https://github.com/foo.useHttpPath",
        "true",
    ]);
    let helper = format!(
        "secretspec --url https://github.com/foo --password-secret PASSWORD --username-secret USERNAME --provider '{}'",
        provider.replace('\'', "'\\''")
    );
    fixture.git_ok(&[
        "config",
        "--local",
        "credential.https://github.com/foo.helper",
        &helper,
    ]);

    let fill = fixture.credential_fill(b"protocol=https\nhost=github.com\npath=foo/repository\n\n");
    assert_success("manually configured embedded credential fill", &fill);
    let filled = String::from_utf8(fill.stdout).unwrap();
    assert!(filled.contains("username=manual-user\n"), "{filled}");
    assert!(filled.contains("password=manual-token\n"), "{filled}");
}

#[test]
fn embedded_and_custom_manifest_options_cannot_be_mixed() {
    let fixture = Fixture::new();
    let output = fixture
        .embedded_command()
        .args([
            "git",
            "configure",
            "--url",
            "https://github.com",
            "--token-secret",
            "GITHUB_TOKEN",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--token-secret") && stderr.contains("require --file"));

    let output = fixture
        .command()
        .args(["git", "login", "https://github.com"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("manages the embedded Git credential store"));
}

#[test]
fn unconfigure_clears_a_duplicated_include_without_losing_credentials() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args(Fixture::configure_args(false))
        .output()
        .unwrap();
    assert_success("local configure", &output);
    let managed_path = fixture
        .git_ok(&["config", "--local", "--get-all", "include.path"])
        .lines()
        .next()
        .unwrap()
        .to_string();
    // A second registration of the same include, as a crashed or concurrent
    // run can leave behind.
    fixture.git_ok(&["config", "--local", "--add", "include.path", &managed_path]);

    let output = fixture
        .command()
        .args(["git", "unconfigure", "--all"])
        .output()
        .unwrap();
    assert_success("unconfigure with a duplicated include", &output);
    assert!(!Path::new(&managed_path).exists());
    let includes = fixture.git(&["config", "--local", "--get-all", "include.path"]);
    assert!(!String::from_utf8_lossy(&includes.stdout).contains(&managed_path));
}

#[test]
fn exported_variables_neither_block_commands_nor_reach_git_configuration() {
    let fixture = Fixture::new();
    let manifest = fixture.manifest.to_str().unwrap();
    let store = format!("file://{}", fixture.root.join("ambient-store").display());
    let ambient = [
        ("SECRETSPEC_FILE", manifest),
        ("SECRETSPEC_PROFILE", "production"),
        ("SECRETSPEC_PROVIDER", store.as_str()),
        ("SECRETSPEC_REASON", "deploy web frontend"),
    ];

    let output = fixture
        .ambient_command(&ambient)
        .args([
            "git",
            "configure",
            "--url",
            "https://github.com",
            "--username",
            "vimjoyer",
        ])
        .output()
        .unwrap();
    assert_success("configure with exported variables", &output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("SECRETSPEC_PROVIDER was not recorded"),
        "{stdout}"
    );

    let helper = fixture.git_ok(&["config", "--get", "credential.https://github.com.helper"]);
    for flag in ["--reason", "--provider", "--profile", "--file"] {
        assert!(!helper.contains(flag), "{flag} leaked into {helper}");
    }
    assert!(helper.contains("--password-secret 'PASSWORD_"), "{helper}");

    for action in ["login", "logout"] {
        let output = fixture
            .ambient_command(&ambient)
            .args(["git", action, "https://github.com"])
            .stdin(Stdio::piped())
            .spawn()
            .map(|mut child| {
                child.stdin.take().unwrap().write_all(b"token\n").unwrap();
                child.wait_with_output().unwrap()
            })
            .unwrap();
        assert_success(action, &output);
    }

    // A typed --file is still rejected: it selects a manifest these
    // subcommands intentionally do not manage.
    let output = fixture
        .command()
        .args(["git", "logout", "https://github.com"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("manages the embedded Git credential store")
    );
}

#[test]
fn typed_provider_and_reason_are_recorded_in_the_helper() {
    let fixture = Fixture::new();
    let output = fixture
        .ambient_command(&[
            ("SECRETSPEC_PROVIDER", "ignored-ambient"),
            ("SECRETSPEC_REASON", "ignored ambient"),
        ])
        .args([
            "git",
            "configure",
            "--url",
            "https://github.com",
            "--username",
            "vimjoyer",
            "--provider",
            "null",
            "--reason",
            "team onboarding",
        ])
        .output()
        .unwrap();
    assert_success("configure with typed overrides", &output);

    let helper = fixture.git_ok(&["config", "--get", "credential.https://github.com.helper"]);
    assert!(helper.contains("--provider 'null'"), "{helper}");
    assert!(helper.contains("--reason 'team onboarding'"), "{helper}");
    assert!(!helper.contains("ignored"), "{helper}");
}

#[test]
fn typed_profile_is_still_rejected_for_the_embedded_store() {
    let fixture = Fixture::new();
    let output = fixture
        .embedded_command()
        .args([
            "git",
            "configure",
            "--url",
            "https://github.com",
            "--username",
            "vimjoyer",
            "--profile",
            "production",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("require --file"));
}

#[test]
fn mixed_case_smtp_target_answers_the_lowercased_request() {
    let fixture = Fixture::new();
    let store = fixture.root.join("smtp-case-store");
    let provider = format!("file://{}", store.display());

    let output = fixture
        .embedded_command()
        .args([
            "git",
            "configure",
            "--url",
            "smtp://SMTP.Example.COM:2525",
            "--username",
            "user@example.com",
            "--provider",
            &provider,
        ])
        .output()
        .unwrap();
    assert_success("mixed case SMTP configure", &output);

    // `login` reads the username back through git config --get-urlmatch, and
    // Git lowercases the host on both sides of that lookup.
    let output = command_with_stdin(
        fixture.embedded_command(),
        &[
            "git",
            "login",
            "smtp://smtp.example.com:2525",
            "--provider",
            &provider,
        ],
        b"smtp-password\n",
    );
    assert_success("lowercase SMTP login", &output);

    let fill = fixture.credential_fill(
        b"protocol=smtp\nhost=smtp.example.com:2525\nusername=user@example.com\n\n",
    );
    assert_success("lowercase SMTP fill", &fill);
    assert!(
        String::from_utf8(fill.stdout)
            .unwrap()
            .contains("password=smtp-password\n")
    );
}

#[test]
fn smtp_credentials_are_scoped_to_the_exact_account() {
    let fixture = Fixture::new();
    let store = fixture.root.join("smtp-credential-store");
    let provider = format!("file://{}", store.display());
    let target = "smtp://smtp.example.com:587";

    let configure = |username: &str| {
        fixture
            .embedded_command()
            .args([
                "git",
                "configure",
                "--url",
                target,
                "--username",
                username,
                "--provider",
                &provider,
            ])
            .output()
            .unwrap()
    };

    let output = configure("first@example.com");
    assert_success("first SMTP configure", &output);
    let includes = fixture.git_ok(&["config", "--local", "--get-all", "include.path"]);
    let managed = fs::read_to_string(includes.lines().next().unwrap()).unwrap();
    assert!(managed.contains("--username 'first@example.com'"));

    let output = command_with_stdin(
        fixture.embedded_command(),
        &["git", "login", target, "--provider", &provider],
        b"first-password\n",
    );
    assert_success("first SMTP login", &output);

    for (description, request) in [
        (
            "another SMTP account",
            b"protocol=smtp\nhost=smtp.example.com:587\nusername=other@example.com\n\n".as_slice(),
        ),
        (
            "another SMTP port",
            b"protocol=smtp\nhost=smtp.example.com:465\nusername=first@example.com\n\n".as_slice(),
        ),
        (
            "HTTPS on the SMTP host",
            b"protocol=https\nhost=smtp.example.com:587\nusername=first@example.com\n\n".as_slice(),
        ),
    ] {
        let output = fixture.credential_fill(request);
        assert!(
            !output.status.success(),
            "{description} unexpectedly received the SMTP credential"
        );
    }

    let output = configure("second@example.com");
    assert_success("second SMTP configure", &output);
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(
        stdout.contains("This replaced the entry configured for username first@example.com"),
        "{stdout}"
    );
    let output = command_with_stdin(
        fixture.embedded_command(),
        &["git", "login", target, "--provider", &provider],
        b"second-password\n",
    );
    assert_success("second SMTP login", &output);

    let second = fixture.credential_fill(
        b"protocol=smtp\nhost=smtp.example.com:587\nusername=second@example.com\n\n",
    );
    assert_success("second SMTP fill", &second);
    assert!(
        String::from_utf8(second.stdout)
            .unwrap()
            .contains("password=second-password\n")
    );

    let output = configure("first@example.com");
    assert_success("restore first SMTP configure", &output);
    let first = fixture.credential_fill(
        b"protocol=smtp\nhost=smtp.example.com:587\nusername=first@example.com\n\n",
    );
    assert_success("first SMTP fill", &first);
    assert!(
        String::from_utf8(first.stdout)
            .unwrap()
            .contains("password=first-password\n")
    );

    let output = fixture
        .embedded_command()
        .args(["git", "logout", target, "--provider", &provider])
        .output()
        .unwrap();
    assert_success("first SMTP logout", &output);
    let first = fixture.credential_fill(
        b"protocol=smtp\nhost=smtp.example.com:587\nusername=first@example.com\n\n",
    );
    assert!(!first.status.success());

    let output = fixture
        .embedded_command()
        .args([
            "git",
            "configure",
            "--url",
            "smtp://smtp.example.com:587/mail",
            "--username",
            "first@example.com",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not include a path"));

    let output = fixture
        .embedded_command()
        .args([
            "git",
            "configure",
            "--url",
            "smtp://smtp.example.com",
            "--username",
            "first@example.com",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("explicit port"));
}

#[test]
fn global_changes_require_confirmation_and_unconfigure_all_restores_config() {
    let fixture = Fixture::new();
    fs::write(
        &fixture.global_config,
        "[user]\n\tname = Existing User\n[credential]\n\thelper = !true\n",
    )
    .unwrap();
    let original_config = fs::read(&fixture.global_config).unwrap();

    let output = fixture
        .command()
        .args([
            "git",
            "configure",
            "--url",
            "https://github.com",
            "--token-secret",
            "GITHUB_TOKEN",
            "--global",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("confirmation")
            && String::from_utf8_lossy(&output.stderr).contains("--yes"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&fixture.global_config).unwrap(), original_config);

    let output = fixture
        .command()
        .args(Fixture::configure_args(true))
        .output()
        .unwrap();
    assert_success("global configure", &output);
    let output = fixture
        .command()
        .args([
            "git",
            "configure",
            "--url",
            "https://gitlab.com",
            "--token-secret",
            "GITHUB_TOKEN",
            "--global",
            "--yes",
        ])
        .output()
        .unwrap();
    assert_success("second global configure", &output);

    let fill = fixture.credential_fill(b"protocol=https\nhost=github.com\n\n");
    assert_success("global git credential fill", &fill);
    let filled = String::from_utf8(fill.stdout).unwrap();
    assert!(filled.contains("username=vimjoyer\n"));
    assert!(filled.contains("password=token=value\n"));

    let includes = fixture.git_ok(&["config", "--global", "--get-all", "include.path"]);
    let managed_path = PathBuf::from(includes.lines().next().unwrap());
    assert!(managed_path.exists());
    let configured_config = fs::read(&fixture.global_config).unwrap();
    let configured_managed = fs::read(&managed_path).unwrap();

    let output = fixture
        .command()
        .args(["git", "unconfigure", "--all", "--global"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("confirmation")
            && String::from_utf8_lossy(&output.stderr).contains("--yes")
    );
    assert_eq!(fs::read(&fixture.global_config).unwrap(), configured_config);
    assert_eq!(fs::read(&managed_path).unwrap(), configured_managed);

    let output = fixture
        .command()
        .args(["git", "unconfigure", "--all", "--global", "--yes"])
        .output()
        .unwrap();
    assert_success("global unconfigure all", &output);
    assert!(!managed_path.exists());
    assert_eq!(fs::read(&fixture.global_config).unwrap(), original_config);
}
