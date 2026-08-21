#![cfg(feature = "cli")]

use secretspec_ipc::client::Client;
use secretspec_ipc::error::RpcError;
use secretspec_ipc::lifecycle::{Environment, LaunchOptions, PromptResponder, ResolverSession};
use secretspec_ipc::protocol::callback::{PromptParams, PromptResult};
use secretspec_ipc::protocol::resolver::{
    DeleteParams, GetParams, GetResult, InitializeApplication, Manifest, Purpose, RejectParams,
    ReleaseParams, Representation, SetParams, method,
};
use secretspec_ipc::protocol::{InitializeParams, Limits, Product};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn deadline(after: Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .saturating_add(after.as_millis()) as u64
}

fn launch_options() -> LaunchOptions {
    LaunchOptions {
        executable: PathBuf::from(env!("CARGO_BIN_EXE_secretspec")),
        arguments: vec![OsString::from("serve")],
        environment: Environment::Inherit(BTreeMap::new()),
        allow_path_discovery: false,
        max_stderr_bytes: 64 * 1024,
    }
}

fn product() -> Product {
    Product {
        name: "integration-test".into(),
        version: "1".into(),
    }
}

fn limits() -> Limits {
    Limits {
        max_frame_bytes: 32 * 1024,
        max_in_flight: 4,
    }
}

/// The events a case demands. Comparing the observed set against exactly this
/// is what makes a case-driven test fail when it silently stops exercising a
/// branch the case still claims to cover.
fn required_events(case: &Value) -> BTreeSet<&str> {
    case["required_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event.as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn checked_in_resolver_case_runs_against_the_real_cli() {
    let case: Value = serde_json::from_str(include_str!(
        "../../conformance/ipc/cases/resolver-leases.json"
    ))
    .unwrap();
    assert_eq!(case["schema_version"], 1);
    assert_eq!(case["id"], "resolver.path-leases");
    assert!(
        case["targets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|target| target == "resolver")
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
    let session = ResolverSession::launch(
        LaunchOptions {
            executable: PathBuf::from(env!("CARGO_BIN_EXE_secretspec")),
            arguments: vec![OsString::from("serve")],
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
                    "path" => Representation::Path,
                    other => panic!("unsupported representation {other}"),
                };
                let result = session
                    .get(
                        &GetParams {
                            name: name.into(),
                            representation,
                            purpose: purpose.clone(),
                        },
                        deadline(Duration::from_secs(5)),
                    )
                    .await
                    .unwrap();
                match (name, result) {
                    ("TOKEN", GetResult::Value(value)) => {
                        assert_eq!(value.value, "inline-value");
                        assert_eq!(value.expires_at_unix_ms, None);
                        events.insert("resolved_value");
                    }
                    ("OPTIONAL", GetResult::Missing(missing)) => {
                        assert!(!missing.required);
                        events.insert("missing");
                    }
                    ("UNKNOWN", GetResult::Undeclared(_)) => {
                        events.insert("undeclared");
                    }
                    ("CERT", GetResult::Path(leased)) => {
                        assert_eq!(
                            std::fs::read_to_string(&leased.path).unwrap(),
                            "leased-value"
                        );
                        assert_eq!(leased.expires_at_unix_ms, None);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            assert_eq!(
                                std::fs::metadata(&leased.path)
                                    .unwrap()
                                    .permissions()
                                    .mode()
                                    & 0o777,
                                0o400
                            );
                        }
                        active_lease = Some((leased.path, leased.path_lease_id));
                        events.insert("lease_created");
                    }
                    _ => panic!("resolver returned the wrong result for {name}"),
                }
            }
            "release" => {
                assert_eq!(action["duplicates"], true);
                let (path, lease_id) = active_lease.take().unwrap();
                let released = session
                    .release(
                        &ReleaseParams {
                            path_lease_ids: vec![lease_id.clone(), lease_id],
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
            other => panic!("unsupported resolver case action {other}"),
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

/// The mutation methods against the real CLI, which is what a consumer such as
/// `cargo login` drives: a stored value must be exactly what the same session
/// then resolves, and removing it must be idempotent.
#[tokio::test]
async fn stored_values_round_trip_against_the_real_cli() {
    let directory = tempfile::tempdir().unwrap();
    let dotenv = directory.path().join("values.env");
    std::fs::write(&dotenv, "").unwrap();
    let manifest = r#"
[project]
name = "cargo"
revision = "1.0"
require_reason = false

[profiles.default]
CARGO_REGISTRY_TOKEN = { description = "Cargo registry token", required = false }
"#;

    let session = ResolverSession::launch(
        LaunchOptions {
            executable: PathBuf::from(env!("CARGO_BIN_EXE_secretspec")),
            arguments: vec![OsString::from("serve")],
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
        InitializeApplication {
            manifest: Manifest::Inline {
                toml: manifest.into(),
                base_dir: directory.path().to_string_lossy().into_owned(),
            },
            provider: Some(format!("dotenv:{}", dotenv.display())),
            profile: Some("default".into()),
            scope: None,
            reason: None,
        },
        deadline(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(session.supports(method::SET));
    assert!(session.supports(method::DELETE));

    let purpose = Purpose {
        consumer: "cargo".into(),
        operation: "login".into(),
        host: Some("crates.io".into()),
        path: None,
    };
    let stored = session
        .set(
            &SetParams {
                name: "CARGO_REGISTRY_TOKEN".into(),
                value: "stored-token".into(),
                purpose: purpose.clone(),
            },
            deadline(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    assert!(stored.target_provider.unwrap().starts_with("dotenv:"));

    let resolved = session
        .get(
            &GetParams {
                name: "CARGO_REGISTRY_TOKEN".into(),
                representation: Representation::Value,
                purpose: purpose.clone(),
            },
            deadline(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    let GetResult::Value(value) = resolved else {
        panic!("expected the stored value")
    };
    assert_eq!(value.value, "stored-token");

    let removed = session
        .delete(
            &DeleteParams {
                name: "CARGO_REGISTRY_TOKEN".into(),
                purpose: purpose.clone(),
            },
            deadline(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    assert!(removed.deleted);
    let resolved = session
        .get(
            &GetParams {
                name: "CARGO_REGISTRY_TOKEN".into(),
                representation: Representation::Value,
                purpose: purpose.clone(),
            },
            deadline(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    assert!(matches!(resolved, GetResult::Missing(_)));

    // Removing what is no longer there is a success, not an error.
    let removed = session
        .delete(
            &DeleteParams {
                name: "CARGO_REGISTRY_TOKEN".into(),
                purpose,
            },
            deadline(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    assert!(!removed.deleted);
    session
        .close(deadline(Duration::from_secs(5)))
        .await
        .unwrap();
}

/// The checked-in `resolver.reject` case, against the real CLI.
///
/// A cached route is the only place rejection does anything: a value revoked at
/// its issuer stays fresh by the clock, so nothing but an explicit report from
/// the consumer retires the cached copy before it ages out. The case drives the
/// whole sequence, including the read that proves the stale value really was
/// being served beforehand.
#[tokio::test]
async fn checked_in_reject_case_runs_against_the_real_cli() {
    let case: Value = serde_json::from_str(include_str!(
        "../../conformance/ipc/cases/resolver-reject.json"
    ))
    .unwrap();
    assert_eq!(case["schema_version"], 1);
    assert_eq!(case["id"], "resolver.reject");
    let actions = case["actions"].as_array().unwrap();

    let directory = tempfile::tempdir().unwrap();
    let upstream = directory.path().join("upstream.env");
    let cache = directory.path().join("cache.env");
    std::fs::write(&upstream, "FORGE_TOKEN=first\n").unwrap();
    std::fs::write(&cache, "").unwrap();
    // The paths are serialised as TOML strings rather than interpolated raw:
    // a Windows path embeds backslashes, which are escape sequences in a TOML
    // basic string.
    let cache_uri = toml::Value::String(format!("dotenv:{}", cache.display())).to_string();
    let upstream_uri = toml::Value::String(format!("dotenv:{}", upstream.display())).to_string();
    let manifest = format!(
        r#"
[project]
name = "reject"
revision = "1.0"
require_reason = false

[providers]
store = {cache_uri}
cached = {{ uri = {upstream_uri}, cache = {{ provider = "store", max_age = "8h" }} }}

[profiles.default]
FORGE_TOKEN = {{ description = "forge token", providers = ["cached"] }}
"#,
        cache_uri = cache_uri,
        upstream_uri = upstream_uri,
    );

    let session = ResolverSession::launch(
        launch_options(),
        product(),
        limits(),
        InitializeApplication {
            manifest: Manifest::Inline {
                toml: manifest,
                base_dir: directory.path().to_string_lossy().into_owned(),
            },
            // No override: one would collapse the route and hide the very
            // cache entry this case is about.
            provider: None,
            profile: Some("default".into()),
            scope: None,
            reason: None,
        },
        deadline(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(session.supports(method::REJECT));

    let purpose = Purpose {
        consumer: "integration-test".into(),
        operation: "fetch".into(),
        host: Some("forge.example".into()),
        path: None,
    };
    let mut events = BTreeSet::from(["initialized"]);
    let mut rotated = false;

    for action in actions.iter().skip(1) {
        match action["kind"].as_str().unwrap() {
            "rotate_upstream" => {
                let value = action["value"].as_str().unwrap();
                std::fs::write(&upstream, format!("FORGE_TOKEN={value}\n")).unwrap();
                rotated = true;
            }
            "resolve" => {
                let result = session
                    .get(
                        &GetParams {
                            name: action["name"].as_str().unwrap().into(),
                            representation: Representation::Value,
                            purpose: purpose.clone(),
                        },
                        deadline(Duration::from_secs(5)),
                    )
                    .await
                    .unwrap();
                let GetResult::Value(value) = result else {
                    panic!("expected an inline value")
                };
                assert_eq!(value.value, action["expect"].as_str().unwrap());
                // The read after the rotation is the one that matters: it
                // proves the cache really was serving a value the issuer had
                // already replaced, so the rejection below is not a no-op.
                if rotated {
                    if value.value == "first" {
                        events.insert("stale_value_served");
                    } else {
                        events.insert("fresh_value_served");
                    }
                }
            }
            "reject" => {
                let name = action["name"].as_str().unwrap();
                let rejected = session
                    .reject(
                        &RejectParams {
                            name: name.into(),
                            purpose: purpose.clone(),
                        },
                        deadline(Duration::from_secs(5)),
                    )
                    .await
                    .unwrap();
                let expected = action["invalidated"].as_bool().unwrap();
                assert_eq!(rejected.invalidated, expected, "{name}");
                if expected {
                    events.insert("cache_invalidated");
                } else if name == "NOT_DECLARED" {
                    events.insert("undeclared_reject");
                } else {
                    events.insert("idempotent_reject");
                }
            }
            "disconnect" => {
                session
                    .close(deadline(Duration::from_secs(5)))
                    .await
                    .unwrap();
                events.insert("closed");
            }
            other => panic!("unsupported reject case action {other}"),
        }
    }

    assert_eq!(events, required_events(&case));
}

/// The checked-in `resolver.prompt` case, against the real CLI.
///
/// The resolver has no terminal of its own, so the question travels back to
/// this process and the answer travels forward. The second session in the case
/// advertises nothing and must resolve to a plain missing result without a
/// prompt ever being sent, which is what keeps a headless consumer from waiting
/// out its deadline.
#[tokio::test]
async fn checked_in_prompt_case_runs_against_the_real_cli() {
    struct Responder {
        asked: Arc<Mutex<Vec<PromptParams>>>,
    }

    #[async_trait::async_trait]
    impl PromptResponder for Responder {
        async fn prompt(&self, params: PromptParams) -> Result<PromptResult, RpcError> {
            self.asked.lock().unwrap().push(params);
            Ok(PromptResult {
                value: "typed-by-a-person".into(),
            })
        }
    }

    let case: Value = serde_json::from_str(include_str!(
        "../../conformance/ipc/cases/resolver-prompt.json"
    ))
    .unwrap();
    assert_eq!(case["schema_version"], 1);
    assert_eq!(case["id"], "resolver.prompt");
    let actions = case["actions"].as_array().unwrap();

    let directory = tempfile::tempdir().unwrap();
    let dotenv = directory.path().join("values.env");
    std::fs::write(&dotenv, "").unwrap();
    let manifest = r#"
[project]
name = "prompted"
revision = "1.0"
require_reason = false

[profiles.default]
DEPLOY_PASSWORD = { description = "deploy password", prompt = true }
"#;
    let application = || InitializeApplication {
        manifest: Manifest::Inline {
            toml: manifest.into(),
            base_dir: directory.path().to_string_lossy().into_owned(),
        },
        provider: Some(format!("dotenv:{}", dotenv.display())),
        profile: Some("default".into()),
        scope: None,
        reason: None,
    };
    let purpose = Purpose {
        consumer: "integration-test".into(),
        operation: "resolve".into(),
        host: None,
        path: None,
    };

    let asked = Arc::new(Mutex::new(Vec::new()));
    let mut events = BTreeSet::new();
    let mut session: Option<ResolverSession> = None;

    for action in actions {
        match action["kind"].as_str().unwrap() {
            "initialize" => {
                let advertises = !action["client_capabilities"].as_array().unwrap().is_empty();
                let responder: Option<Arc<dyn PromptResponder>> = advertises.then(|| {
                    Arc::new(Responder {
                        asked: asked.clone(),
                    }) as Arc<dyn PromptResponder>
                });
                session = Some(
                    ResolverSession::launch_with_prompt(
                        launch_options(),
                        product(),
                        limits(),
                        application(),
                        deadline(Duration::from_secs(5)),
                        responder,
                    )
                    .await
                    .unwrap(),
                );
                events.insert("initialized");
            }
            "resolve" => {
                let before = asked.lock().unwrap().len();
                let result = session
                    .as_ref()
                    .unwrap()
                    .get(
                        &GetParams {
                            name: action["name"].as_str().unwrap().into(),
                            representation: Representation::Value,
                            purpose: purpose.clone(),
                        },
                        deadline(Duration::from_secs(10)),
                    )
                    .await
                    .unwrap();
                let asked_now = asked.lock().unwrap().len();
                match action["expect"].as_str().unwrap() {
                    "prompted" => {
                        let GetResult::Value(value) = result else {
                            panic!("expected the answered value")
                        };
                        assert_eq!(value.value, "typed-by-a-person");
                        assert_eq!(asked_now, before + 1);
                        let params = asked.lock().unwrap().last().unwrap().clone();
                        assert_eq!(params.name, "DEPLOY_PASSWORD");
                        assert_eq!(params.profile, "default");
                        // Named because the answer is stored there, and
                        // credential-free.
                        assert!(params.target_provider.unwrap().starts_with("dotenv:"));
                        events.insert("prompt_requested");
                        events.insert("prompt_answered");
                    }
                    "missing" => {
                        let GetResult::Missing(missing) = result else {
                            panic!("a prompt nobody can answer resolves to no value")
                        };
                        assert!(missing.required);
                        assert_eq!(asked_now, before, "a headless session was still asked");
                        events.insert("headless_missing");
                        events.insert("no_prompt_requested");
                    }
                    other => panic!("unsupported prompt expectation {other}"),
                }
            }
            "disconnect" => {
                session
                    .take()
                    .unwrap()
                    .close(deadline(Duration::from_secs(5)))
                    .await
                    .unwrap();
                // The answer was provisioned into the store, so it survives the
                // session that obtained it. Cleared afterwards so the headless
                // session starts from the same empty store.
                if std::fs::read_to_string(&dotenv)
                    .unwrap()
                    .contains("typed-by-a-person")
                {
                    events.insert("answer_persisted");
                    std::fs::write(&dotenv, "").unwrap();
                }
                events.insert("closed");
            }
            other => panic!("unsupported prompt case action {other}"),
        }
    }

    assert_eq!(events, required_events(&case));
}

#[tokio::test]
async fn resolver_ephemeral_generation_is_silent_on_stderr() {
    use tokio::io::AsyncReadExt;

    let directory = tempfile::tempdir().unwrap();
    let manifest = r#"
[project]
name = "silent-generation"
revision = "1.0"
require_reason = false

[profiles.default]
SESSION_TOKEN = { description = "session token", type = "password", generate = true }
"#;
    let application = InitializeApplication {
        manifest: Manifest::Inline {
            toml: manifest.into(),
            base_dir: directory.path().to_string_lossy().into_owned(),
        },
        provider: Some("null://".into()),
        profile: Some("default".into()),
        scope: None,
        reason: None,
    };

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_secretspec"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let initialize = InitializeParams {
        protocol: "secretspec.resolver".into(),
        versions: vec![1],
        client: product(),
        limits: limits(),
        client_methods: Vec::new(),
        application,
    };
    let (client, _): (
        Client,
        secretspec_ipc::protocol::InitializeResult<
            secretspec_ipc::protocol::resolver::InitializedApplication,
        >,
    ) = Client::connect(stdout, stdin, initialize, deadline(Duration::from_secs(5)))
        .await
        .unwrap();
    let result: GetResult = client
        .call(
            method::GET,
            &GetParams {
                name: "SESSION_TOKEN".into(),
                representation: Representation::Value,
                purpose: Purpose {
                    consumer: "integration-test".into(),
                    operation: "resolve".into(),
                    host: None,
                    path: None,
                },
            },
            deadline(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    assert!(matches!(result, GetResult::Value(_)));
    client
        .close(deadline(Duration::from_secs(5)))
        .await
        .unwrap();

    let status = child.wait().await.unwrap();
    let mut diagnostics = Vec::new();
    stderr.read_to_end(&mut diagnostics).await.unwrap();
    assert!(status.success());
    assert!(
        diagnostics.is_empty(),
        "resolver leaked generation progress: {}",
        String::from_utf8_lossy(&diagnostics)
    );
}
