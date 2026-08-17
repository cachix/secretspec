#![cfg(feature = "cli")]

use secretspec_ipc::lifecycle::{Environment, LaunchOptions, ResolutionSession};
use secretspec_ipc::protocol::client::{
    InitializeApplication, Manifest, Purpose, ReleaseParams, Representation, ResolveParams,
    ResolveResult,
};
use secretspec_ipc::protocol::{Limits, Product};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn deadline(after: Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .saturating_add(after.as_millis()) as u64
}

#[tokio::test]
async fn checked_in_broker_case_runs_against_the_real_cli() {
    let case: Value = serde_json::from_str(include_str!(
        "../../conformance/ipc/cases/broker-leases.json"
    ))
    .unwrap();
    assert_eq!(case["schema_version"], 1);
    assert_eq!(case["id"], "broker.file-leases");
    assert!(
        case["targets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|target| target == "broker")
    );
    let actions = case["actions"].as_array().unwrap();
    let initialize_action = actions
        .iter()
        .find(|action| action["kind"] == "initialize")
        .unwrap();
    assert_eq!(initialize_action["manifest"], "inline");
    assert_eq!(initialize_action["profile"], "default");

    let directory = tempfile::tempdir().unwrap();
    let dotenv = directory.path().join("values.env");
    std::fs::write(&dotenv, "TOKEN=inline-value\nCERT=leased-value\n").unwrap();
    let manifest = r#"
[project]
name = "black-box-ipc"
revision = "1.0"
require_reason = false

[profiles.default]
TOKEN = { description = "token" }
CERT = { description = "certificate", as_path = true }
OPTIONAL = { description = "optional", required = false }
UNRELATED = { description = "named resolution must not read this", required = true }
"#;

    let application = InitializeApplication {
        manifest: Manifest::Inline {
            toml: manifest.into(),
            base_dir: directory.path().to_string_lossy().into_owned(),
        },
        provider: Some(format!("dotenv:{}", dotenv.display())),
        profile: Some("default".into()),
        scope: None,
        reason: None,
    };
    let session = ResolutionSession::launch(
        LaunchOptions {
            executable: PathBuf::from(env!("CARGO_BIN_EXE_secretspec")),
            arguments: vec![OsString::from("broker"), OsString::from("--stdio")],
            environment: Environment::Inherit(BTreeMap::new()),
            allow_path_discovery: false,
            max_stderr_bytes: 64 * 1024,
        },
        Product {
            name: "integration-test".into(),
            version: "1".into(),
        },
        Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 4,
        },
        application,
        deadline(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    let purpose = Purpose {
        consumer: "integration-test".into(),
        operation: "resolve".into(),
        host: None,
        path: None,
    };
    let mut events = BTreeSet::from(["initialized"]);
    let mut active_lease: Option<(String, String)> = None;

    for action in actions.iter().skip(1) {
        match action["kind"].as_str().unwrap() {
            "resolve" => {
                let name = action["name"].as_str().unwrap();
                let representation = match action["representation"].as_str().unwrap() {
                    "auto" => Representation::Auto,
                    "value" => Representation::Value,
                    "file" => Representation::File,
                    other => panic!("unsupported representation {other}"),
                };
                let result = session
                    .resolve(
                        &ResolveParams {
                            name: name.into(),
                            representation,
                            purpose: purpose.clone(),
                        },
                        deadline(Duration::from_secs(5)),
                    )
                    .await
                    .unwrap();
                match (name, result) {
                    ("TOKEN", ResolveResult::Value(value)) => {
                        assert_eq!(value.value, "inline-value");
                        assert_eq!(value.expires_at_unix_ms, None);
                        events.insert("resolved_value");
                    }
                    ("OPTIONAL", ResolveResult::Missing(missing)) => {
                        assert!(!missing.required);
                        events.insert("missing");
                    }
                    ("UNKNOWN", ResolveResult::Undeclared(_)) => {
                        events.insert("undeclared");
                    }
                    ("CERT", ResolveResult::File(file)) => {
                        assert_eq!(std::fs::read_to_string(&file.path).unwrap(), "leased-value");
                        assert_eq!(file.expires_at_unix_ms, None);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            assert_eq!(
                                std::fs::metadata(&file.path).unwrap().permissions().mode() & 0o777,
                                0o400
                            );
                        }
                        active_lease = Some((file.path, file.lease_id));
                        events.insert("lease_created");
                    }
                    _ => panic!("broker returned the wrong result for {name}"),
                }
            }
            "release" => {
                assert_eq!(action["duplicates"], true);
                let (path, lease_id) = active_lease.take().unwrap();
                let released = session
                    .release(
                        &ReleaseParams {
                            lease_ids: vec![lease_id.clone(), lease_id],
                        },
                        deadline(Duration::from_secs(5)),
                    )
                    .await
                    .unwrap();
                assert_eq!(released.released, 1);
                assert!(!std::path::Path::new(&path).exists());
                events.insert("lease_removed");
            }
            "disconnect" => {
                let (path, _) = active_lease.take().unwrap();
                session
                    .close(deadline(Duration::from_secs(5)))
                    .await
                    .unwrap();
                assert!(!std::path::Path::new(&path).exists());
                events.insert("disconnect_cleanup");
                events.insert("closed");
            }
            other => panic!("unsupported broker case action {other}"),
        }
    }

    let required = case["required_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(events, required);
}
