use secretspec::{Profile, Secret, SecretSpecError, Spec};

fn test_spec() -> Spec {
    Spec::builder("schema-test")
        .secret("SHARED_TOKEN", Secret::required("Shared token"))
        .secret("OPTIONAL_TOKEN", Secret::optional("Optional token"))
        .profile(
            "production",
            Profile::new().secret("PRODUCTION_TOKEN", Secret::required("Production token")),
        )
        .build()
        .unwrap()
}

#[test]
fn public_api_emits_union_and_profile_schemas() {
    let spec = test_spec();

    let union: serde_json::Value = serde_json::from_str(&spec.schema_json(None).unwrap()).unwrap();
    assert_eq!(union["title"], "SecretSpec");
    assert_eq!(union["additionalProperties"], false);
    assert_eq!(union["properties"]["SHARED_TOKEN"]["type"], "string");
    assert_eq!(
        union["properties"]["OPTIONAL_TOKEN"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert!(union["properties"]["PRODUCTION_TOKEN"].is_object());

    let production: serde_json::Value =
        serde_json::from_str(&spec.schema_json(Some("production")).unwrap()).unwrap();
    assert_eq!(production["title"], "ProductionSecrets");
    assert!(production["properties"]["SHARED_TOKEN"].is_object());
    assert!(production["properties"]["PRODUCTION_TOKEN"].is_object());
    assert!(production["properties"]["OPTIONAL_TOKEN"].is_object());
}

#[test]
fn public_api_reports_an_unknown_profile() {
    let error = test_spec().schema_json(Some("missing")).unwrap_err();
    match error {
        SecretSpecError::InvalidProfile(message) => {
            assert!(message.contains("missing"));
            assert!(message.contains("production"));
        }
        other => panic!("expected InvalidProfile, got {other:?}"),
    }
}

#[cfg(feature = "cli")]
#[test]
fn cli_schema_matches_the_public_api() {
    use std::fs;
    use std::process::Command;

    let project = tempfile::tempdir().unwrap();
    let path = project.path().join("secretspec.toml");
    fs::write(
        &path,
        r#"[project]
name = "schema-test"
revision = "1.0"

[profiles.default]
SHARED_TOKEN = { description = "Shared token", required = true }

[profiles.production]
PRODUCTION_TOKEN = { description = "Production token", required = true }
"#,
    )
    .unwrap();

    let expected = Spec::try_from(path.as_path())
        .unwrap()
        .schema_json(Some("production"))
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .args([
            "--file",
            path.to_str().unwrap(),
            "schema",
            "--profile",
            "production",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "schema command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}
