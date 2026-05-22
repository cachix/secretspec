use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn check_resolves_required_object_form_provider_refs_with_key_hints() {
    let temp_dir = TempDir::new().expect("create temp test directory");
    let env_file = temp_dir.path().join("provider.env");
    let secretspec_file = temp_dir.path().join("secretspec.toml");
    let xdg_config_home = temp_dir.path().join("xdg-config");
    let secretspec_config_dir = xdg_config_home.join("secretspec");

    fs::create_dir_all(&secretspec_config_dir).expect("create secretspec config directory");
    fs::write(
        secretspec_config_dir.join("config.toml"),
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
        env_content.push_str(&format!("STORED_SECRET_{index}=value-{index}\n"));
        profile_content.push_str(&format!(
            "SECRET_{index} = {{ description = \"Required secret {index}\", required = true, providers = [{{ provider = \"detail_env\", path = [\"Important Details\", \"Company Details\"], key = \"STORED_SECRET_{index}\" }}] }}\n"
        ));
    }

    fs::write(&env_file, env_content).expect("write dotenv provider data");
    fs::write(
        &secretspec_file,
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
    .expect("write secretspec config");

    let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .arg("-f")
        .arg(&secretspec_file)
        .arg("check")
        .arg("--no-prompt")
        .env("RUST_LOG", "verbose")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("HOME", temp_dir.path())
        .env("NO_COLOR", "1")
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .output()
        .expect("run secretspec check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "check should succeed for object-form provider refs\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stderr.contains("Summary: 15 found, 0 missing"),
        "expected all object-form provider refs to resolve\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("resolved provider reference"),
        "RUST_LOG=verbose should enable provider-resolution diagnostics\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("provider lookup found secret"),
        "RUST_LOG=verbose should log provider lookup results\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("required"),
        "resolved object-form provider refs must not be reported missing\nstderr:\n{stderr}"
    );
}

#[test]
#[cfg(unix)]
fn onepassword_auth_failures_are_error_logs() {
    let temp_dir = TempDir::new().expect("create temp test directory");
    let op = temp_dir.path().join("op");
    let secretspec_file = temp_dir.path().join("secretspec.toml");

    fs::write(
        &op,
        r#"#!/usr/bin/env sh
printf '%s\n' 'not currently signed in' >&2
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
        &secretspec_file,
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
    .expect("write secretspec config");

    let path = format!(
        "{}:{}",
        temp_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .arg("-f")
        .arg(&secretspec_file)
        .arg("check")
        .arg("--no-prompt")
        .env("PATH", path)
        .env("RUST_LOG", "verbose")
        .env("HOME", temp_dir.path())
        .env("NO_COLOR", "1")
        .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .output()
        .expect("run secretspec check");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "check should fail when 1Password auth fails\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("ERROR")
            && stderr.contains("1Password CLI command failed due to authentication"),
        "auth failures should be logged at error level\nstderr:\n{stderr}"
    );
}

#[test]
#[cfg(unix)]
fn onepassword_lookup_failures_are_warning_logs() {
    let temp_dir = TempDir::new().expect("create temp test directory");
    let op = temp_dir.path().join("op");
    let secretspec_file = temp_dir.path().join("secretspec.toml");

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
        &secretspec_file,
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
    .expect("write secretspec config");

    let path = format!(
        "{}:{}",
        temp_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .arg("-f")
        .arg(&secretspec_file)
        .arg("check")
        .arg("--no-prompt")
        .env("PATH", path)
        .env("RUST_LOG", "verbose")
        .env("HOME", temp_dir.path())
        .env("NO_COLOR", "1")
        .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .output()
        .expect("run secretspec check");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "check should fail when the required secret is missing\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("WARN") && stderr.contains("1Password CLI command failed"),
        "lookup failures should be logged at warning level\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("1Password CLI command failed due to authentication"),
        "non-auth lookup failures should not be classified as auth errors\nstderr:\n{stderr}"
    );
}

#[test]
fn lightweight_logging_honors_verbosity_and_rust_log_filters() {
    let temp_dir = TempDir::new().expect("create temp test directory");
    let secretspec_file = temp_dir.path().join("secretspec.toml");
    fs::write(
        &secretspec_file,
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
    .expect("write secretspec config");

    let cases = [
        (vec!["-v"], None, true),
        (Vec::new(), Some("secretspec=debug"), true),
        (Vec::new(), Some("quiet"), false),
        (Vec::new(), None, false),
    ];

    for (verbosity_args, rust_log, should_log_debug) in cases {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
        command.arg("-f").arg(&secretspec_file);
        for arg in verbosity_args {
            command.arg(arg);
        }
        command
            .arg("check")
            .arg("--no-prompt")
            .env("HOME", temp_dir.path())
            .env("NO_COLOR", "1")
            .env("TOKEN", "value")
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_PROFILE");

        match rust_log {
            Some(value) => {
                command.env("RUST_LOG", value);
            }
            None => {
                command.env_remove("RUST_LOG");
            }
        }

        let output = command.output().expect("run secretspec check");
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
    let secretspec_file = temp_dir.path().join("secretspec.toml");
    let empty_provider_file = temp_dir.path().join("empty.env");
    let broken_provider_dir = temp_dir.path().join("broken-provider");
    fs::write(&empty_provider_file, "").expect("write empty provider file");
    fs::create_dir_all(&broken_provider_dir).expect("create broken provider directory");
    fs::write(
        &secretspec_file,
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
    .expect("write secretspec config");

    let cases = [
        (vec!["-v"], None),
        (vec!["-vv"], None),
        (vec!["--verbose"], None),
        (vec!["--verbose", "--verbose"], None),
        (Vec::new(), Some("quiet")),
        (Vec::new(), Some("debug")),
    ];

    for (verbosity_args, rust_log) in cases {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
        command.arg("-f").arg(&secretspec_file);
        for arg in verbosity_args {
            command.arg(arg);
        }
        command
            .arg("check")
            .arg("--no-prompt")
            .env("HOME", temp_dir.path())
            .env("NO_COLOR", "1")
            .env("TOKEN", "value")
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_PROFILE");

        match rust_log {
            Some(value) => {
                command.env("RUST_LOG", value);
            }
            None => {
                command.env_remove("RUST_LOG");
            }
        }

        let output = command.output().expect("run secretspec check");
        assert!(
            output.status.success(),
            "check should accept verbosity/filter input\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
