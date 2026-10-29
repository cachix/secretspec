use secretspec::Secrets;
use std::{io, path::Path, sync::Arc};

fn project(root: &Path) -> Secrets {
    std::fs::write(
        root.join("secretspec.toml"),
        r#"
[project]
name = "custom-materializer"
revision = "1.0"
require_reason = false

[profiles.default]
KEY = { description = "binary key", as_path = true, encoding = "base64" }
ARGS = { description = "arguments", composed = "key=${KEY}" }
"#,
    )
    .unwrap();
    std::fs::write(root.join(".env"), "KEY=/wA=\n").unwrap();
    let mut spec = Secrets::load_from(&root.join("secretspec.toml")).unwrap();
    spec.set_provider("dotenv:.env");
    spec
}

#[test]
fn materializer_receives_logical_bytes_and_owns_composed_paths() {
    let root = tempfile::tempdir().unwrap();
    let owner = Arc::new(tempfile::tempdir().unwrap());
    let owner_path = owner.path().to_owned();
    let mut spec = project(root.path());
    spec.set_as_path_materializer(move |bytes, suffix| {
        assert_eq!(bytes, &[0xff, 0]);
        assert!(suffix.is_none());
        let path = owner.path().join("custom-key");
        std::fs::write(&path, bytes)?;
        Ok(path)
    });
    let validated = spec.validate().unwrap().unwrap();
    let path = owner_path.join("custom-key");
    assert_eq!(
        validated.resolved.secrets["ARGS"].try_as_utf8().unwrap(),
        format!("key={}", path.display())
    );
    drop(spec);
    let values = validated.resolved.secrets.clone();
    let resolved = validated.into_resolved(values);
    let clone = resolved.clone();
    drop(resolved);
    assert_eq!(std::fs::read(&path).unwrap(), [0xff, 0]);
    drop(clone);
    assert!(!owner_path.exists());
}

#[test]
fn materializer_errors_do_not_fall_back_to_temporary_files() {
    let root = tempfile::tempdir().unwrap();
    let mut spec = project(root.path());
    spec.set_as_path_materializer(|_, _| {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "deliberate materializer rejection",
        ))
    });
    let error = spec
        .validate()
        .err()
        .expect("custom storage must fail closed");
    assert!(
        error
            .to_string()
            .contains("deliberate materializer rejection")
    );
}

#[test]
fn custom_paths_cannot_be_detached_from_their_owner() {
    let root = tempfile::tempdir().unwrap();
    let mut spec = project(root.path());
    spec.set_as_path_materializer(|_, _| Ok("/custom/key".into()));
    let error = spec.resolve().unwrap_err();
    assert!(error.to_string().contains("cannot be persisted"));
}

#[test]
fn custom_paths_must_be_absolute() {
    let root = tempfile::tempdir().unwrap();
    let mut spec = project(root.path());
    spec.set_as_path_materializer(|_, _| Ok("relative-key".into()));
    let error = spec
        .validate()
        .err()
        .expect("relative custom path must fail");
    assert!(error.to_string().contains("absolute path"));
}

#[test]
fn scoped_compositions_cannot_detach_hidden_file_dependencies() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let _ = project(root.path());
    let mut manifest = std::fs::OpenOptions::new()
        .append(true)
        .open(root.path().join("secretspec.toml"))
        .unwrap();
    writeln!(manifest, "\n[scopes.app]\nsecrets = [\"ARGS\"]").unwrap();
    let mut spec = Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_provider("dotenv:.env");
    spec.set_scope("app");
    spec.set_as_path_materializer(|_, _| Ok("/custom/key".into()));
    assert!(
        spec.resolve()
            .unwrap_err()
            .to_string()
            .contains("cannot be persisted")
    );
}
