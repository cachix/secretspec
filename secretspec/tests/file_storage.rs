#![cfg(feature = "cli")]

use std::{
    path::Path,
    process::{Command, Output},
};

fn project() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("tmp")).unwrap();
    std::fs::write(root.path().join("secretspec.toml"),
        "[project]\nname='file-storage-test'\nrevision='1.0'\nrequire_reason=false\n[profiles.default]\nKEY={description='file',default='fixture',as_path=true}\n").unwrap();
    root
}

fn get(root: &Path, mode: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    command
        .current_dir(root)
        .args(["get", "KEY", "--provider", "env"])
        .env("TMPDIR", root.join("tmp"))
        .env("TMP", root.join("tmp"))
        .env("TEMP", root.join("tmp"))
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("SECRETSPEC_BIN", root.join("missing-helper"))
        .env_remove("SECRETSPEC_FILE_STORAGE")
        .env_remove("SECRETSPEC_FILE")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON")
        .env_remove("KEY");
    if let Some(mode) = mode {
        command.env("SECRETSPEC_FILE_STORAGE", mode);
    }
    command.output().unwrap()
}

#[test]
fn default_and_explicit_temp_paths_work_without_a_helper_and_are_persisted() {
    for mode in [None, Some("temp")] {
        let root = project();
        let result = get(root.path(), mode);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let path = std::path::PathBuf::from(String::from_utf8(result.stdout).unwrap().trim());
        assert_eq!(
            path.parent().unwrap().canonicalize().unwrap(),
            root.path().join("tmp").canonicalize().unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn explicit_lease_failure_and_invalid_selection_never_create_temp_payloads() {
    for mode in ["file-lease", "invalid"] {
        let root = project();
        let result = get(root.path(), Some(mode));
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(
            std::fs::read_dir(root.path().join("tmp")).unwrap().count(),
            0
        );
        if mode == "invalid" {
            assert!(String::from_utf8_lossy(&result.stderr).contains("SECRETSPEC_FILE_STORAGE"));
        }
    }
}

#[test]
fn owned_temp_files_survive_clones_and_clean_up_after_the_last_owner() {
    let root = project();
    let mut spec = secretspec::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_provider("env");
    spec.set_file_storage(secretspec::FileStorageMode::Temp);
    let validated = spec.validate().unwrap().unwrap();
    let path = std::path::PathBuf::from(validated.resolved.secrets["KEY"].try_as_utf8().unwrap());
    let cloned = validated.resolved.clone();
    drop(validated);
    drop(spec);
    assert_eq!(std::fs::read(&path).unwrap(), b"fixture");
    drop(cloned);
    assert!(!path.exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn changing_storage_preserves_existing_results() {
    let root = project();
    let mut spec = secretspec::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_provider("env");
    spec.set_file_storage(secretspec::FileStorageMode::Temp);
    let first = spec.validate().unwrap().unwrap();
    let one = std::path::PathBuf::from(first.resolved.secrets["KEY"].try_as_utf8().unwrap());
    spec.set_file_storage(secretspec::FileStorageMode::FileLease);
    let second = spec.validate().unwrap().unwrap();
    let two = std::path::PathBuf::from(second.resolved.secrets["KEY"].try_as_utf8().unwrap());
    assert_ne!(one, two);
    drop(second);
    assert!(!two.exists());
    assert_eq!(std::fs::read(&one).unwrap(), b"fixture");
    drop(first);
    assert!(!one.exists());
}

#[test]
fn temporary_result_cleanup_revokes_hidden_dependencies_and_preserves_neighbours() {
    let root = project();
    std::fs::write(root.path().join("secretspec.toml"),
        "[project]\nname='temp-cleanup'\nrevision='1.0'\nrequire_reason=false\n[profiles.default]\nKEY={description='file',default='fixture',as_path=true}\nARGS={description='args',composed='key=${KEY}'}\n[scopes.app]\nsecrets=['ARGS']\n").unwrap();
    let mut spec = secretspec::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_provider("env");
    spec.set_scope("app");
    spec.set_file_storage(secretspec::FileStorageMode::Temp);
    let first = spec.resolve().unwrap();
    let second = spec.resolve().unwrap();
    let path = |resolved: &secretspec::ResolveResponse| {
        std::path::PathBuf::from(
            resolved.secrets["ARGS"]
                .value
                .as_ref()
                .unwrap()
                .strip_prefix("key=")
                .unwrap(),
        )
    };
    let one = path(&first);
    let two = path(&second);
    assert!(!first.secrets.contains_key("KEY"));
    first.close().unwrap();
    first.close().unwrap();
    assert!(!one.exists());
    assert_eq!(std::fs::read(&two).unwrap(), b"fixture");
    second.close().unwrap();
    assert!(!two.exists());
}
