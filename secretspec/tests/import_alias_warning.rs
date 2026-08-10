use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn run_import(project: &Path, source: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .args([
            "--file",
            project.join("secretspec.toml").to_str().unwrap(),
            "import",
            source,
        ])
        .current_dir(project)
        // Keep the subprocess hermetic: no user aliases, defaults, profile, or
        // audit path may influence the import under test.
        .env("HOME", project)
        .env("XDG_CONFIG_HOME", config_home(project))
        .env("XDG_STATE_HOME", project.join("state"))
        // Windows ignores the XDG variables: there the config and audit
        // directories come from APPDATA and the cache from LOCALAPPDATA.
        .env("APPDATA", config_home(project))
        .env("LOCALAPPDATA", project.join("state"))
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .output()
        .expect("run secretspec import")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "import failed with {}:\n{}",
        output.status,
        stderr(output)
    );
}

fn env_values(path: &Path) -> HashMap<String, String> {
    dotenvy::from_path_iter(path)
        .unwrap()
        .map(|item| item.unwrap())
        .collect()
}

/// Per-user config home handed to the subprocess.
fn config_home(project: &Path) -> PathBuf {
    project.join("config")
}

/// Where the CLI reads `config.toml` beneath that config home. etcetera's
/// Windows strategy nests one more `config` component than its XDG strategy.
fn global_config_path(project: &Path) -> PathBuf {
    let directory = config_home(project).join("secretspec");
    if cfg!(windows) {
        directory.join("config").join("config.toml")
    } else {
        directory.join("config.toml")
    }
}

fn write_global_config(project: &Path, contents: &str) {
    let path = global_config_path(project);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

#[test]
fn literal_source_warns_when_an_alias_template_addresses_the_same_store_differently() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    fs::write(project.join(".env.source"), "SOURCE_API_KEY=from-source\n").unwrap();
    write_global_config(
        project,
        r#"
[defaults]
provider = "target"
profile = "default"

[defaults.providers]
src = { uri = "dotenv:.env.source", ref = { item = "SOURCE_{key}" } }
target = "dotenv:.env.target"
"#,
    );
    fs::write(
        project.join("secretspec.toml"),
        r#"
[project]
name = "literal-template-warning"
revision = "1.0"
require_reason = false

[profiles.default]
API_KEY = { description = "API key" }
"#,
    )
    .unwrap();

    let literal = run_import(project, "dotenv:.env.source");
    assert_success(&literal);
    let literal_stderr = stderr(&literal);
    assert!(literal_stderr.contains("import source dotenv:"));
    assert!(literal_stderr.contains("uses convention naming"));
    assert!(literal_stderr.contains("provider alias 'src' addresses 1 secret differently"));
    assert!(literal_stderr.contains("for example, API_KEY"));
    assert!(literal_stderr.contains("keep the literal source to use convention-named entries"));
    assert!(!literal_stderr.contains("from-source"));
    assert!(!project.join(".env.target").exists());

    let alias = run_import(project, "src");
    assert_success(&alias);
    let alias_stderr = stderr(&alias);
    assert!(!alias_stderr.contains("uses convention naming"));
    assert!(alias_stderr.contains("Importing secrets from provider alias 'src' (dotenv:"));
    assert_eq!(
        env_values(&project.join(".env.target")).get("API_KEY"),
        Some(&"from-source".to_string())
    );
}

#[test]
fn literal_source_warns_for_an_active_scoped_ref() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    fs::write(project.join(".env.source"), "SOURCE_API_KEY=from-source\n").unwrap();
    fs::write(
        project.join("secretspec.toml"),
        r#"
[project]
name = "literal-scoped-warning"
revision = "1.0"
require_reason = false

[providers]
src = "dotenv:.env.source"
target = "dotenv:.env.target"

[profiles.default]
API_KEY = { description = "API key", providers = ["target"], refs = { src = { item = "SOURCE_API_KEY" } } }
"#,
    )
    .unwrap();

    let literal = run_import(project, "dotenv:.env.source");
    assert_success(&literal);
    let literal_stderr = stderr(&literal);
    assert!(literal_stderr.contains("uses convention naming"));
    assert!(literal_stderr.contains("provider alias 'src' addresses 1 secret differently"));
    assert!(!project.join(".env.target").exists());
}

#[test]
fn convention_equivalent_template_and_legacy_ref_do_not_warn() {
    for (case, template, secret, source_contents) in [
        (
            "equivalent-template",
            "{key}",
            r#"API_KEY = { description = "API key", providers = ["target"] }"#,
            "API_KEY=from-source\n",
        ),
        (
            "legacy-ref",
            "SOURCE_{key}",
            r#"API_KEY = { description = "API key", providers = ["target"], ref = { item = "LEGACY" } }"#,
            "LEGACY=from-source\n",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let project = temp.path();
        fs::write(project.join(".env.source"), source_contents).unwrap();
        fs::write(
            project.join("secretspec.toml"),
            format!(
                r#"
[project]
name = "{case}"
revision = "1.0"
require_reason = false

[providers]
src = {{ uri = "dotenv:.env.source", ref = {{ item = "{template}" }} }}
target = "dotenv:.env.target"

[profiles.default]
{secret}
"#
            ),
        )
        .unwrap();

        let literal = run_import(project, "dotenv:.env.source");
        assert_success(&literal);
        assert!(
            !stderr(&literal).contains("uses convention naming"),
            "{case} should resolve the same physical entry"
        );
    }
}

#[test]
fn literal_source_can_intentionally_migrate_between_addresses_in_one_store() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    fs::write(project.join(".env.store"), "API_KEY=from-convention\n").unwrap();
    fs::write(
        project.join("secretspec.toml"),
        r#"
[project]
name = "same-store-address-migration"
revision = "1.0"
require_reason = false

[providers]
mapped = { uri = "dotenv:.env.store", ref = { item = "MAPPED_{key}" } }

[profiles.default]
API_KEY = { description = "API key", providers = ["mapped"] }
"#,
    )
    .unwrap();

    let literal = run_import(project, "dotenv:.env.store");
    assert_success(&literal);
    let literal_stderr = stderr(&literal);
    assert!(literal_stderr.contains("provider alias 'mapped' addresses 1 secret differently"));
    assert!(literal_stderr.contains("if its alias-specific coordinates are intended"));

    let values = env_values(&project.join(".env.store"));
    assert_eq!(values.get("API_KEY"), Some(&"from-convention".to_string()));
    assert_eq!(
        values.get("MAPPED_API_KEY"),
        Some(&"from-convention".to_string())
    );
}

#[test]
fn literal_source_warning_does_not_resolve_candidate_alias_credentials() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    fs::write(project.join(".env.source"), "API_KEY=from-convention\n").unwrap();
    fs::write(
        project.join("secretspec.toml"),
        r#"
[project]
name = "literal-warning-no-credentials"
revision = "1.0"
require_reason = false

[providers]
src = { uri = "dotenv:.env.source", credentials = { unused = "dotenv:.env.missing-credentials" }, ref = { item = "SOURCE_{key}" } }
target = "dotenv:.env.target"

[profiles.default]
API_KEY = { description = "API key", providers = ["target"] }
"#,
    )
    .unwrap();

    let literal = run_import(project, "dotenv:.env.source");
    assert_success(&literal);
    let literal_stderr = stderr(&literal);
    assert!(literal_stderr.contains("provider alias 'src' addresses 1 secret differently"));
    assert!(!literal_stderr.contains("credential 'unused'"));
    assert_eq!(
        env_values(&project.join(".env.target")).get("API_KEY"),
        Some(&"from-convention".to_string())
    );
}
