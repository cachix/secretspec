use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn env_values(path: &Path) -> HashMap<String, String> {
    dotenv::EnvLoader::with_path(path)
        .sequence(dotenv::EnvSequence::InputOnly)
        .load()
        .unwrap()
        .into_iter()
        .collect()
}

#[test]
fn import_profile_selection_controls_secrets_and_both_provider_addresses() {
    for (args, environment_profile, configured_profile, expected_profile) in [
        (
            vec!["--profile", "production"],
            Some("development"),
            Some("default"),
            "production",
        ),
        (
            vec!["-P", "production"],
            None,
            Some("development"),
            "production",
        ),
        (
            vec!["--profile", "production", "--delete-source"],
            Some("development"),
            Some("default"),
            "production",
        ),
        (
            vec![],
            Some("production"),
            Some("development"),
            "production",
        ),
        (vec![], None, Some("production"), "production"),
        (vec![], None, None, "default"),
        (
            vec!["--profile", "default"],
            Some("production"),
            Some("production"),
            "default",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let project = temp.path();
        fs::write(
            project.join("secretspec.toml"),
            r#"
[project]
name = "import-profile"
revision = "1.0"
require_reason = false

[providers]
source = { uri = "dotenv:.env.source", ref = { item = "SOURCE_{profile}_{key}" } }
target = { uri = "dotenv:.env.target", ref = { item = "TARGET_{profile}_{key}" } }

[profiles.default]
SHARED = { description = "Inherited secret" }

[profiles.production]
TOKEN = { description = "Production token" }

[profiles.development]
DEV_ONLY = { description = "Development token" }
"#,
        )
        .unwrap();
        let config_home = project.join("config");
        let config_dir = if cfg!(windows) {
            config_home.join("secretspec/config")
        } else {
            config_home.join("secretspec")
        };
        fs::create_dir_all(&config_dir).unwrap();
        let profile_setting = configured_profile
            .map(|profile| format!("profile = \"{profile}\"\n"))
            .unwrap_or_default();
        fs::write(
            config_dir.join("config.toml"),
            format!("[defaults]\nprovider = \"target\"\n{profile_setting}"),
        )
        .unwrap();
        let source_path = project.join(".env.source");
        fs::write(
            &source_path,
            "SOURCE_default_SHARED=default-value\n\
             SOURCE_production_SHARED=production-shared\n\
             SOURCE_production_TOKEN=production-token\n\
             SOURCE_development_SHARED=development-shared\n\
             SOURCE_development_DEV_ONLY=development-token\n",
        )
        .unwrap();
        let original_source = env_values(&source_path);
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
        command
            .args(["import", "source"])
            .args(&args)
            .current_dir(project)
            .env("HOME", project)
            .env("XDG_CONFIG_HOME", &config_home)
            .env("APPDATA", &config_home)
            .env("XDG_STATE_HOME", project.join("state"))
            .env("LOCALAPPDATA", project.join("state"))
            .env_remove("SECRETSPEC_PROVIDER")
            .env_remove("SECRETSPEC_PROFILE")
            .env_remove("SECRETSPEC_SCOPE")
            .env_remove("SECRETSPEC_REASON");
        if let Some(profile) = environment_profile {
            command.env("SECRETSPEC_PROFILE", profile);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "args {args:?}, env {environment_profile:?}, config {configured_profile:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let expected_keys = if expected_profile == "production" {
            vec!["SHARED", "TOKEN"]
        } else {
            vec!["SHARED"]
        };
        let mut expected_source = original_source.clone();
        let mut expected_target = HashMap::new();
        for key in expected_keys {
            let source_key = format!("SOURCE_{expected_profile}_{key}");
            expected_target.insert(
                format!("TARGET_{expected_profile}_{key}"),
                original_source[&source_key].clone(),
            );
            if args.contains(&"--delete-source") {
                expected_source.remove(&source_key);
            }
        }
        assert_eq!(env_values(&project.join(".env.target")), expected_target);
        assert_eq!(env_values(&source_path), expected_source);
    }
}
