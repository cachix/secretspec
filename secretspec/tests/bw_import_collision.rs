#![cfg(all(unix, feature = "bw", feature = "cli"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

/// Installs the fake `bw` with a stateful vault holding `items`.
fn install_vault(project: &Path, items: &serde_json::Value) {
    let shim = project.join("bw");
    fs::write(&shim, include_str!("../../tests/fixtures/bw-shim.sh")).unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(project.join("items.json"), items.to_string()).unwrap();
    fs::write(project.join("stateful"), "").unwrap();
}

/// Writes a manifest importing `secrets` (name, bw item, bw field) from a
/// dotenv source into `bw://`, with one source value per secret.
fn write_manifest(project: &Path, secrets: &[(String, String, String)]) {
    let source: String = secrets
        .iter()
        .map(|(name, _, _)| format!("{name}={}-value\n", name.to_lowercase()))
        .collect();
    fs::write(project.join(".env.source"), source).unwrap();
    let declarations: String = secrets
        .iter()
        .map(|(name, item, field)| {
            format!(
                "{name} = {{ description = \"{name}\", providers = [\"target\"], refs = {{ target = {{ item = \"{item}\", field = \"{field}\" }} }} }}\n"
            )
        })
        .collect();
    fs::write(
        project.join("secretspec.toml"),
        format!(
            r#"
[project]
name = "bw-import-collision"
revision = "1.0"
require_reason = false

[providers]
src = "dotenv:.env.source"
target = "bw://"

[profiles.default]
{declarations}"#
        ),
    )
    .unwrap();
}

fn import(project: &Path) -> Output {
    let path = std::env::join_paths(std::iter::once(project.to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .args(["--file", "secretspec.toml", "import", "src"])
        .current_dir(project)
        .env("PATH", path)
        .env("HOME", project)
        .env("XDG_CONFIG_HOME", project.join("config"))
        .env("XDG_STATE_HOME", project.join("state"))
        .env("BITWARDENCLI_APPDATA_DIR", project.join("appdata"))
        .env("BW_SESSION", "test-session")
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .env_remove("BITWARDEN_ORGANIZATION")
        .env_remove("BITWARDEN_COLLECTION")
        .env_remove("BITWARDEN_DEFAULT_TYPE")
        .env_remove("BITWARDEN_DEFAULT_FIELD")
        .output()
        .unwrap()
}

/// Asserts that importing FIRST and SECOND was refused as one destination
/// entry before anything was written to the vault.
fn assert_rejected_before_writing(project: &Path, output: &Output, items: &serde_json::Value) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "import must reject colliding refs"
    );
    assert!(
        stderr.contains("same destination provider entry"),
        "{stderr}"
    );
    assert!(
        stderr.contains("FIRST") && stderr.contains("SECOND"),
        "{stderr}"
    );
    let log = fs::read_to_string(project.join("invocations.log")).unwrap();
    assert!(
        !log.contains("<edit>") && !log.contains("<create>"),
        "{log}"
    );
    let after: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project.join("items.json")).unwrap()).unwrap();
    assert_eq!(
        &after, items,
        "collision preflight must leave the vault unchanged"
    );
}

fn pair(first: (&str, &str), second: (&str, &str)) -> Vec<(String, String, String)> {
    vec![
        ("FIRST".into(), first.0.into(), first.1.into()),
        ("SECOND".into(), second.0.into(), second.1.into()),
    ]
}

#[test]
fn import_rejects_bitwarden_title_and_uuid_destinations_before_writing() {
    let id = "22222222-2222-2222-2222-222222222222";
    let items = serde_json::json!([{
        "id": id,
        "name": "Shared Login",
        "type": 1,
        "login": { "username": "alice" }
    }]);
    for (first, second) in [("Shared Login", id), (id, "shared login")] {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path();
        install_vault(project, &items);
        write_manifest(project, &pair((first, "api_key"), (second, "api_key")));
        let output = import(project);
        assert_rejected_before_writing(project, &output, &items);
    }
}

#[test]
fn import_rejects_bitwarden_references_that_differ_only_in_case_before_writing() {
    // Reads and writes match item titles and field names case-insensitively,
    // so none of these pairs can hold two values: before the item exists, the
    // second write lands on the item the first one created.
    let id = "22222222-2222-2222-2222-222222222222";
    for (first, second) in [
        (("API_KEY", "password"), ("api_key", "password")),
        (("Service", "Token"), ("Service", "token")),
        (
            (id, "api_key"),
            ("22222222-2222-2222-2222-222222222222", "API_KEY"),
        ),
    ] {
        let items = serde_json::json!([]);
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path();
        install_vault(project, &items);
        write_manifest(project, &pair(first, second));
        let output = import(project);
        assert_rejected_before_writing(project, &output, &items);
    }
}

#[test]
fn import_collision_checks_list_the_vault_once_rather_than_per_pair() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    install_vault(project, &serde_json::json!([]));
    let count = 30;
    let secrets: Vec<(String, String, String)> = (0..count)
        .map(|index| {
            (
                format!("SECRET_{index}"),
                format!("Item {index}"),
                "password".to_string(),
            )
        })
        .collect();
    write_manifest(project, &secrets);

    let output = import(project);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let log = fs::read_to_string(project.join("invocations.log")).unwrap();
    let listings = log
        .lines()
        .filter(|line| line.contains("<list> <items>"))
        .count();
    // Reading and writing each secret lists the vault a bounded number of
    // times; the collision checks add one listing, not one per pair of
    // secrets (435 pairs here).
    assert!(
        listings <= 3 * count + 1,
        "{listings} listings for {count} secrets:\n{log}"
    );
}
