use std::fs;
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
        !stderr.contains("required"),
        "resolved object-form provider refs must not be reported missing\nstderr:\n{stderr}"
    );
}
