#![cfg(feature = "tokio")]

use async_trait::async_trait;
use secretspec_ipc::connection::FilesystemAccess;
use secretspec_ipc::lifecycle::{PromptResponder, ResolverSession};
use secretspec_ipc::protocol::callback::{PromptParams, PromptResult};
use secretspec_ipc::protocol::resolver::{
    GetParams, GetResult, InitializeApplication, Manifest, Purpose, Representation,
};
use secretspec_ipc::server::{ApplicationHandler, RequestContext, RpcResult, ServerConfig, serve};
use secretspec_ipc::{Error, Limits, Product, deadline_unix_ms_after};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

fn deadline() -> u64 {
    deadline_unix_ms_after(Duration::from_secs(5))
}

fn application() -> InitializeApplication {
    InitializeApplication {
        manifest: Manifest::Path {
            path: "/remote/project/secretspec.toml".into(),
        },
        provider: None,
        profile: None,
        scope: None,
        reason: None,
        requested_authorization_duration_ms: None,
    }
}

fn get(name: &str, representation: Representation) -> GetParams {
    GetParams {
        name: name.into(),
        representation,
        purpose: Purpose {
            consumer: "connection-test".into(),
            operation: "resolve".into(),
            host: None,
            path: None,
        },
    }
}

struct Endpoint {
    calls: Mutex<Vec<Value>>,
    initializations: AtomicUsize,
    shutdowns: AtomicUsize,
    started: Semaphore,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            initializations: AtomicUsize::new(0),
            shutdowns: AtomicUsize::new(0),
            started: Semaphore::new(0),
        }
    }
}

#[async_trait]
impl ApplicationHandler for Endpoint {
    fn protocol(&self) -> &'static str {
        "secretspec.resolver"
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["resolver.get".into(), "resolver.release".into()]
    }

    async fn initialize(&self, _: &RequestContext, application: Value) -> RpcResult<Value> {
        assert_eq!(
            application["manifest"]["path"],
            "/remote/project/secretspec.toml"
        );
        self.initializations.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"manifest_kind": "path", "supports_inline_manifest": true}))
    }

    async fn call(&self, context: RequestContext, method: &str, params: Value) -> RpcResult<Value> {
        assert_eq!(method, "resolver.get");
        self.calls.lock().unwrap().push(params.clone());
        if params["name"] == "INTERRUPTED" {
            self.started.add_permits(1);
            context.cancellation.cancelled().await;
        }
        if params["name"] == "BAD_PATH" || params["representation"] == "path" {
            return Ok(json!({
                "status": "resolved", "representation": "path", "path": "/remote/secret",
                "path_lease_id": "lease", "source": "provider",
                "expires_at_unix_ms": null, "refresh_at_unix_ms": null
            }));
        }
        let value = if params["name"] == "PROMPT" {
            secretspec_ipc::resolver::prompt(
                &context,
                &PromptParams {
                    name: "PROMPT".into(),
                    profile: "default".into(),
                    target_provider: None,
                },
            )
            .await?
            .value
        } else {
            "example".into()
        };
        Ok(json!({
            "status": "resolved", "representation": "value", "value": value,
            "source": "provider", "expires_at_unix_ms": null, "refresh_at_unix_ms": null
        }))
    }

    async fn shutdown(&self) {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
}

async fn connect(
    endpoint: Arc<Endpoint>,
    filesystem: FilesystemAccess,
    responder: Option<Arc<dyn PromptResponder>>,
) -> (
    ResolverSession,
    tokio::task::JoinHandle<secretspec_ipc::Result<()>>,
) {
    let (client, server) = tokio::io::duplex(8192);
    let (server_reader, server_writer) = tokio::io::split(server);
    let task = tokio::spawn(serve(
        server_reader,
        server_writer,
        endpoint,
        ServerConfig::default(),
    ));
    let (reader, writer) = tokio::io::split(client);
    let session = ResolverSession::connect_with_prompt(
        reader,
        writer,
        Product {
            name: "test".into(),
            version: "1".into(),
        },
        Limits {
            max_frame_bytes: 8192,
            max_in_flight: 4,
        },
        application(),
        filesystem,
        deadline(),
        responder,
    )
    .await
    .unwrap();
    (session, task)
}

#[tokio::test]
async fn remote_auto_requests_values_and_explicit_paths_never_reach_the_server() {
    let endpoint = Arc::new(Endpoint::default());
    let (session, server) = connect(endpoint.clone(), FilesystemAccess::Remote, None).await;
    assert!(matches!(
        session
            .get(&get("TOKEN", Representation::Path), deadline())
            .await,
        Err(Error::Protocol(_))
    ));
    assert!(endpoint.calls.lock().unwrap().is_empty());
    assert!(matches!(
        session
            .get(&get("TOKEN", Representation::Auto), deadline())
            .await
            .unwrap(),
        GetResult::Value(_)
    ));
    assert_eq!(endpoint.calls.lock().unwrap()[0]["representation"], "value");
    session.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
    assert_eq!(endpoint.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shared_filesystem_keeps_path_results() {
    let endpoint = Arc::new(Endpoint::default());
    let (session, server) = connect(endpoint, FilesystemAccess::Shared, None).await;
    assert!(matches!(
        session
            .get(&get("CERT", Representation::Path), deadline())
            .await
            .unwrap(),
        GetResult::Path(_)
    ));
    session.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn unexpected_remote_path_closes_the_session_and_cleans_up() {
    let endpoint = Arc::new(Endpoint::default());
    let (session, server) = connect(endpoint.clone(), FilesystemAccess::Remote, None).await;
    assert!(matches!(
        session
            .get(&get("BAD_PATH", Representation::Value), deadline())
            .await,
        Err(Error::Protocol(_))
    ));
    assert!(session.is_closed());
    server.await.unwrap().unwrap();
    assert_eq!(endpoint.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reconnect_initializes_again_without_replaying_the_interrupted_operation() {
    let endpoint = Arc::new(Endpoint::default());
    let (session, server) = connect(endpoint.clone(), FilesystemAccess::Remote, None).await;
    let session = Arc::new(session);
    let calling = session.clone();
    let request = tokio::spawn(async move {
        calling
            .get(&get("INTERRUPTED", Representation::Value), deadline())
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), endpoint.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert!(request.await.unwrap().is_err());
    assert!(session.is_closed());
    assert!(
        session
            .get(&get("TOKEN", Representation::Value), deadline())
            .await
            .is_err()
    );
    let (fresh, server) = connect(endpoint.clone(), FilesystemAccess::Remote, None).await;
    assert_eq!(endpoint.initializations.load(Ordering::SeqCst), 2);
    assert_eq!(endpoint.calls.lock().unwrap().len(), 1);
    fresh
        .get(&get("TOKEN", Representation::Value), deadline())
        .await
        .unwrap();
    assert_eq!(endpoint.calls.lock().unwrap().len(), 2);
    fresh.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn dropping_a_connected_session_closes_its_stream() {
    let endpoint = Arc::new(Endpoint::default());
    let (session, server) = connect(endpoint.clone(), FilesystemAccess::Remote, None).await;
    drop(session);
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(endpoint.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_resolver_handshakes_close_the_connected_session() {
    struct InvalidEndpoint {
        bad_metadata: bool,
        shutdowns: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl ApplicationHandler for InvalidEndpoint {
        fn protocol(&self) -> &'static str {
            "secretspec.resolver"
        }
        fn capabilities(&self) -> Vec<String> {
            if self.bad_metadata {
                vec!["resolver.get".into(), "resolver.release".into()]
            } else {
                vec!["resolver.get".into()]
            }
        }
        async fn initialize(&self, _: &RequestContext, _: Value) -> RpcResult<Value> {
            Ok(json!({
                "manifest_kind": if self.bad_metadata { "unknown" } else { "path" },
                "supports_inline_manifest": true,
            }))
        }
        async fn call(&self, _: RequestContext, _: &str, _: Value) -> RpcResult<Value> {
            panic!("invalid endpoint must never receive an application call")
        }
        async fn shutdown(&self) {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
    }
    for bad_metadata in [true, false] {
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let endpoint = Arc::new(InvalidEndpoint {
            bad_metadata,
            shutdowns: shutdowns.clone(),
        });
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let server = tokio::spawn(serve(reader, writer, endpoint, ServerConfig::default()));
        let (reader, writer) = tokio::io::split(client);
        let result = ResolverSession::connect(
            reader,
            writer,
            Product {
                name: "test".into(),
                version: "1".into(),
            },
            Limits {
                max_frame_bytes: 8192,
                max_in_flight: 4,
            },
            application(),
            FilesystemAccess::Remote,
            deadline(),
        )
        .await;
        assert!(matches!(result, Err(Error::Protocol(_))));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn prompts_travel_back_over_a_connected_stream() {
    struct Responder;
    #[async_trait]
    impl PromptResponder for Responder {
        async fn prompt(&self, params: PromptParams) -> RpcResult<PromptResult> {
            assert_eq!(params.name, "PROMPT");
            Ok(PromptResult {
                value: "from-client".into(),
            })
        }
    }
    let (session, server) = connect(
        Arc::new(Endpoint::default()),
        FilesystemAccess::Remote,
        Some(Arc::new(Responder)),
    )
    .await;
    let GetResult::Value(result) = session
        .get(&get("PROMPT", Representation::Auto), deadline())
        .await
        .unwrap()
    else {
        panic!("expected value")
    };
    assert_eq!(result.value, "from-client");
    session.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}
