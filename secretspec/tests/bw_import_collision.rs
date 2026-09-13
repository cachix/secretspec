#![cfg(all(unix, feature = "bw", feature = "cli"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn import_rejects_bitwarden_title_and_uuid_destinations_before_writing() {
    let id = "22222222-2222-2222-2222-222222222222";
    for (first, second) in [("Shared Login", id), (id, "shared login")] {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path();
        let shim = project.join("bw");
        fs::write(&shim, include_str!("../../tests/fixtures/bw-shim.sh")).unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        let items = serde_json::json!([{
            "id": id,
            "name": "Shared Login",
            "type": 1,
            "login": { "username": "alice" }
        }]);
        fs::write(project.join("items.json"), items.to_string()).unwrap();
        fs::write(project.join("stateful"), "").unwrap();
        fs::write(
            project.join(".env.source"),
            "FIRST=first-value\nSECOND=second-value\n",
        )
        .unwrap();
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
FIRST = {{ description = "First secret", providers = ["target"], refs = {{ target = {{ item = "{first}", field = "api_key" }} }} }}
SECOND = {{ description = "Second secret", providers = ["target"], refs = {{ target = {{ item = "{second}", field = "api_key" }} }} }}
"#
            ),
        )
        .unwrap();

        let path = std::env::join_paths(std::iter::once(project.to_path_buf()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
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
            .unwrap();
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
            after, items,
            "collision preflight must leave the vault unchanged"
        );
    }
}
