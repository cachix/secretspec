use async_trait::async_trait;
use secretspec_ipc::client::Client;
use secretspec_ipc::frame::{read_frame, write_frame};
use secretspec_ipc::protocol::{InitializeParams, Limits, Product};
use secretspec_ipc::server::{ApplicationHandler, RequestContext, RpcResult, ServerConfig, serve};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Echo;

#[async_trait]
impl ApplicationHandler for Echo {
    fn protocol(&self) -> &'static str {
        "secretspec.resolver"
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["resolver.get".into()]
    }

    async fn initialize(&self, _context: &RequestContext, application: Value) -> RpcResult<Value> {
        Ok(application)
    }

    async fn call(
        &self,
        context: RequestContext,
        _method: &str,
        params: Value,
    ) -> RpcResult<Value> {
        if params.get("wait").and_then(Value::as_bool) == Some(true) {
            context.cancellation.cancelled().await;
        }
        Ok(params)
    }
}

struct SlowInitialize {
    started: Arc<tokio::sync::Semaphore>,
}

#[async_trait]
impl ApplicationHandler for SlowInitialize {
    fn protocol(&self) -> &'static str {
        "secretspec.resolver"
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["resolver.get".into()]
    }

    async fn initialize(&self, context: &RequestContext, _application: Value) -> RpcResult<Value> {
        self.started.add_permits(1);
        context.cancellation.cancelled().await;
        Ok(json!({}))
    }

    async fn call(
        &self,
        _context: RequestContext,
        _method: &str,
        params: Value,
    ) -> RpcResult<Value> {
        Ok(params)
    }
}

fn deadline(after: Duration) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    now + after.as_millis() as u64
}

async fn session() -> (Client, tokio::task::JoinHandle<secretspec_ipc::Result<()>>) {
    session_with_limit(4).await
}

async fn session_with_limit(
    max_in_flight: usize,
) -> (Client, tokio::task::JoinHandle<secretspec_ipc::Result<()>>) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_io);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = tokio::spawn(serve(
        server_read,
        server_write,
        Arc::new(Echo),
        ServerConfig::default(),
    ));
    let initialize = InitializeParams {
        protocol: "secretspec.resolver".into(),
        versions: vec![1],
        client: Product {
            name: "test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight,
        },
        client_methods: Vec::new(),
        application: json!({}),
    };
    let (client, _initialized) = Client::connect::<_, _, _, Value>(
        client_read,
        client_write,
        initialize,
        deadline(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    (client, server)
}

fn initialize_request(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "rpc.initialize",
        "_meta": {"deadline_unix_ms": deadline(Duration::from_secs(2))},
        "params": {
            "protocol": "secretspec.resolver",
            "versions": [1],
            "client": {"name": "test", "version": "1"},
            "limits": {"max_frame_bytes": 32 * 1024, "max_in_flight": 4},
            "application": {}
        }
    })
}

async fn raw_server() -> (
    tokio::io::DuplexStream,
    tokio::task::JoinHandle<secretspec_ipc::Result<()>>,
) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = tokio::spawn(serve(
        server_read,
        server_write,
        Arc::new(Echo),
        ServerConfig::default(),
    ));
    (client_io, server)
}

async fn call_when_slot_is_released(client: &Client, label: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match client
                .call::<_, Value>(
                    "resolver.get",
                    &json!({"after": label}),
                    deadline(Duration::from_secs(2)),
                )
                .await
            {
                Err(secretspec_ipc::Error::Unavailable) => tokio::task::yield_now().await,
                outcome => return outcome.unwrap(),
            }
        }
    })
    .await
    .expect("the abandoned request never released its in-flight slot")
}

#[tokio::test]
async fn initializes_calls_and_shuts_down() {
    let (client, server) = session().await;
    let call_deadline = deadline(Duration::from_secs(2));
    let result: Value = client
        .call("resolver.get", &json!({"value": 42}), call_deadline)
        .await
        .unwrap();
    assert_eq!(result["value"], 42);
    client
        .close(deadline(Duration::from_secs(2)))
        .await
        .unwrap();
    server.await.unwrap().unwrap();
}

struct DiscoveryWitness {
    initialized: AtomicUsize,
    shutdown: AtomicUsize,
}

#[async_trait]
impl ApplicationHandler for DiscoveryWitness {
    fn protocol(&self) -> &'static str {
        "secretspec.resolver"
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["resolver.get".into(), "resolver.release".into()]
    }

    async fn initialize(&self, _context: &RequestContext, application: Value) -> RpcResult<Value> {
        self.initialized.fetch_add(1, Ordering::SeqCst);
        Ok(application)
    }

    async fn call(
        &self,
        _context: RequestContext,
        _method: &str,
        params: Value,
    ) -> RpcResult<Value> {
        Ok(params)
    }

    async fn shutdown(&self) {
        self.shutdown.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn discovery_is_side_effect_free_before_and_available_after_initialization() {
    let (mut client_io, server_io) = tokio::io::duplex(256 * 1024);
    let (server_read, server_write) = tokio::io::split(server_io);
    let witness = Arc::new(DiscoveryWitness {
        initialized: AtomicUsize::new(0),
        shutdown: AtomicUsize::new(0),
    });
    let server = tokio::spawn(serve(
        server_read,
        server_write,
        witness.clone(),
        ServerConfig {
            product: Product {
                name: "discovery-test".into(),
                version: "20".into(),
            },
            ..ServerConfig::default()
        },
    ));

    let expired = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "rpc.discover",
        "_meta": {"deadline_unix_ms": 1},
        "params": {},
    });
    write_frame(
        &mut client_io,
        &serde_json::to_vec(&expired).unwrap(),
        1_048_576,
    )
    .await
    .unwrap();
    let expired_reply = read_frame(&mut client_io, 1_048_576)
        .await
        .unwrap()
        .unwrap();
    let expired_reply: Value = serde_json::from_slice(&expired_reply).unwrap();
    assert_eq!(expired_reply["error"]["data"]["kind"], "deadline_exceeded");

    let discover = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "rpc.discover",
        "_meta": {"deadline_unix_ms": deadline(Duration::from_secs(2))},
        "params": {},
    });
    write_frame(
        &mut client_io,
        &serde_json::to_vec(&discover).unwrap(),
        1_048_576,
    )
    .await
    .unwrap();
    let discovered = read_frame(&mut client_io, 1_048_576)
        .await
        .unwrap()
        .unwrap();
    let discovered: Value = serde_json::from_slice(&discovered).unwrap();
    assert_eq!(discovered["result"]["openrpc"], "1.3.2");
    assert_eq!(
        discovered["result"]["x-secretspec"]["protocol"],
        "secretspec.resolver"
    );
    assert_eq!(
        discovered["result"]["x-secretspec"]["server"]["name"],
        "discovery-test"
    );
    assert_eq!(
        discovered["result"]["x-secretspec"]["methods"],
        json!(["resolver.get", "resolver.release"])
    );
    assert!(
        discovered["result"]["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method["name"] == "rpc.discover")
    );
    assert!(discovered["result"]["components"]["schemas"].is_object());
    assert_eq!(witness.initialized.load(Ordering::SeqCst), 0);
    assert_eq!(witness.shutdown.load(Ordering::SeqCst), 0);

    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "rpc.initialize",
        "_meta": {"deadline_unix_ms": deadline(Duration::from_secs(2))},
        "params": {
            "protocol": "secretspec.resolver",
            "versions": [1],
            "client": {"name": "test", "version": "1"},
            "limits": {"max_frame_bytes": 256 * 1024, "max_in_flight": 4},
            "application": {},
        },
    });
    write_frame(
        &mut client_io,
        &serde_json::to_vec(&initialize).unwrap(),
        1_048_576,
    )
    .await
    .unwrap();
    let initialized = read_frame(&mut client_io, 1_048_576)
        .await
        .unwrap()
        .unwrap();
    let initialized: Value = serde_json::from_slice(&initialized).unwrap();
    assert!(initialized.get("result").is_some());
    assert_eq!(witness.initialized.load(Ordering::SeqCst), 1);

    let discover_again = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "rpc.discover",
        "_meta": {"deadline_unix_ms": deadline(Duration::from_secs(2))},
        "params": {},
    });
    write_frame(
        &mut client_io,
        &serde_json::to_vec(&discover_again).unwrap(),
        256 * 1024,
    )
    .await
    .unwrap();
    let discovered_again = read_frame(&mut client_io, 256 * 1024)
        .await
        .unwrap()
        .unwrap();
    let discovered_again: Value = serde_json::from_slice(&discovered_again).unwrap();
    assert_eq!(
        discovered_again["result"]["x-secretspec"]["protocol"],
        "secretspec.resolver"
    );
    assert_eq!(witness.initialized.load(Ordering::SeqCst), 1);

    let shutdown = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "rpc.shutdown",
        "_meta": {"deadline_unix_ms": deadline(Duration::from_secs(2))},
        "params": {},
    });
    write_frame(
        &mut client_io,
        &serde_json::to_vec(&shutdown).unwrap(),
        256 * 1024,
    )
    .await
    .unwrap();
    let shutdown_reply = read_frame(&mut client_io, 256 * 1024)
        .await
        .unwrap()
        .unwrap();
    let shutdown_reply: Value = serde_json::from_slice(&shutdown_reply).unwrap();
    assert!(shutdown_reply.get("result").is_some());
    server.await.unwrap().unwrap();
    assert_eq!(witness.shutdown.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancellation_has_one_terminal_result() {
    let (client, server) = session().await;
    let call_deadline = deadline(Duration::from_secs(2));
    let mut call = client
        .start("resolver.get", &json!({"wait": true}), call_deadline)
        .await
        .unwrap();
    call.cancel().await.unwrap();
    assert!(matches!(
        call.wait().await,
        Err(secretspec_ipc::Error::Cancelled)
    ));
    client
        .close(deadline(Duration::from_secs(2)))
        .await
        .unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn deadline_has_one_terminal_result() {
    let (client, server) = session().await;
    let call_deadline = deadline(Duration::from_millis(50));
    let error = client
        .call::<_, Value>("resolver.get", &json!({"wait": true}), call_deadline)
        .await
        .unwrap_err();
    assert!(matches!(error, secretspec_ipc::Error::DeadlineExceeded));
    client
        .close(deadline(Duration::from_secs(2)))
        .await
        .unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn an_in_flight_slot_is_reused_after_every_abandonment_path() {
    let (client, server) = session_with_limit(1).await;

    let mut cancelled = client
        .start(
            "resolver.get",
            &json!({"wait": true}),
            deadline(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    assert!(matches!(
        client
            .call::<_, Value>(
                "resolver.get",
                &json!({"while": "cancel"}),
                deadline(Duration::from_secs(2)),
            )
            .await,
        Err(secretspec_ipc::Error::Unavailable)
    ));
    cancelled.cancel().await.unwrap();
    assert!(matches!(
        cancelled.wait().await,
        Err(secretspec_ipc::Error::Cancelled)
    ));
    assert_eq!(
        call_when_slot_is_released(&client, "cancel").await,
        json!({"after": "cancel"})
    );

    let mut expired = client
        .start(
            "resolver.get",
            &json!({"wait": true}),
            deadline(Duration::from_millis(50)),
        )
        .await
        .unwrap();
    assert!(matches!(
        client
            .call::<_, Value>(
                "resolver.get",
                &json!({"while": "deadline"}),
                deadline(Duration::from_secs(2)),
            )
            .await,
        Err(secretspec_ipc::Error::Unavailable)
    ));
    assert!(matches!(
        expired.wait().await,
        Err(secretspec_ipc::Error::DeadlineExceeded)
    ));
    assert_eq!(
        call_when_slot_is_released(&client, "deadline").await,
        json!({"after": "deadline"})
    );

    let dropped = client
        .start(
            "resolver.get",
            &json!({"wait": true}),
            deadline(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    assert!(matches!(
        client
            .call::<_, Value>(
                "resolver.get",
                &json!({"while": "drop"}),
                deadline(Duration::from_secs(2)),
            )
            .await,
        Err(secretspec_ipc::Error::Unavailable)
    ));
    drop(dropped);
    assert_eq!(
        call_when_slot_is_released(&client, "drop").await,
        json!({"after": "drop"})
    );

    client
        .close(deadline(Duration::from_secs(2)))
        .await
        .unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn rejected_initialization_closes_both_transport_tasks() {
    let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(async move {
        let request = read_frame(&mut peer_io, 1_048_576)
            .await
            .unwrap()
            .expect("initialization request");
        assert_eq!(serde_json::from_slice::<Value>(&request).unwrap()["id"], 1);
        let response = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocol": "wrong.protocol",
                "version": 1,
                "server": {"name": "fake", "version": "1"},
                "methods": ["resolver.get"],
                "capabilities": {},
                "limits": {"max_frame_bytes": 32768, "max_in_flight": 4},
                "application": {}
            }
        }))
        .unwrap();
        write_frame(&mut peer_io, &response, 1_048_576)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), read_frame(&mut peer_io, 1_048_576))
            .await
            .expect("failed initialization leaked a transport task")
            .unwrap()
            .is_none()
    });

    let (client_read, client_write) = tokio::io::split(client_io);
    let initialize = InitializeParams {
        protocol: "secretspec.resolver".into(),
        versions: vec![1],
        client: Product {
            name: "test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 4,
        },
        client_methods: Vec::new(),
        application: json!({}),
    };
    assert!(
        Client::connect::<_, _, _, Value>(
            client_read,
            client_write,
            initialize,
            deadline(Duration::from_secs(2)),
        )
        .await
        .is_err()
    );
    assert!(peer.await.unwrap());
}

#[tokio::test]
async fn deadline_does_not_wait_for_cancel_queue_capacity() {
    let (client_io, mut peer_io) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let request = read_frame(&mut peer_io, 1_048_576)
            .await
            .unwrap()
            .expect("initialization request");
        assert_eq!(serde_json::from_slice::<Value>(&request).unwrap()["id"], 1);
        let response = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocol": "secretspec.resolver",
                "version": 1,
                "server": {"name": "backpressured", "version": "1"},
                "methods": ["resolver.get"],
                "capabilities": {},
                "limits": {"max_frame_bytes": 4096, "max_in_flight": 4},
                "application": {}
            }
        }))
        .unwrap();
        write_frame(&mut peer_io, &response, 1_048_576)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let (client_read, client_write) = tokio::io::split(client_io);
    let initialize = InitializeParams {
        protocol: "secretspec.resolver".into(),
        versions: vec![1],
        client: Product {
            name: "test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 4096,
            max_in_flight: 4,
        },
        client_methods: Vec::new(),
        application: json!({}),
    };
    let (client, _) = Client::connect::<_, _, _, Value>(
        client_read,
        client_write,
        initialize,
        deadline(Duration::from_secs(2)),
    )
    .await
    .unwrap();

    let call_deadline = deadline(Duration::from_millis(75));
    let mut waiters = Vec::new();
    for _ in 0..4 {
        let mut call = client
            .start(
                "resolver.get",
                &json!({
                    "padding": "x".repeat(3000)
                }),
                call_deadline,
            )
            .await
            .unwrap();
        waiters.push(tokio::spawn(async move { call.wait().await }));
    }

    tokio::time::timeout(Duration::from_millis(500), async {
        for waiter in waiters {
            assert!(matches!(
                waiter.await.unwrap(),
                Err(secretspec_ipc::Error::DeadlineExceeded)
            ));
        }
    })
    .await
    .expect("deadline handling blocked behind the writer queue");

    let _ = client.close(deadline(Duration::from_millis(100))).await;
    peer.abort();
    let _ = peer.await;
}

#[tokio::test]
async fn dropped_calls_are_bounded_as_abandoned_requests() {
    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let request = read_frame(&mut peer_io, 1_048_576)
            .await
            .unwrap()
            .expect("initialization request");
        assert_eq!(serde_json::from_slice::<Value>(&request).unwrap()["id"], 1);
        let response = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocol": "secretspec.resolver",
                "version": 1,
                "server": {"name": "nonresponsive", "version": "1"},
                "methods": ["resolver.get"],
                "capabilities": {},
                "limits": {"max_frame_bytes": 4096, "max_in_flight": 4},
                "application": {}
            }
        }))
        .unwrap();
        write_frame(&mut peer_io, &response, 1_048_576)
            .await
            .unwrap();
        while read_frame(&mut peer_io, 4096).await.unwrap().is_some() {}
    });

    let (client_read, client_write) = tokio::io::split(client_io);
    let initialize = InitializeParams {
        protocol: "secretspec.resolver".into(),
        versions: vec![1],
        client: Product {
            name: "test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 4096,
            max_in_flight: 4,
        },
        client_methods: Vec::new(),
        application: json!({}),
    };
    let (client, _) = Client::connect::<_, _, _, Value>(
        client_read,
        client_write,
        initialize,
        deadline(Duration::from_secs(2)),
    )
    .await
    .unwrap();

    for _ in 0..200 {
        let call_deadline = deadline(Duration::from_secs(5));
        match client
            .start("resolver.get", &json!({}), call_deadline)
            .await
        {
            Ok(call) => drop(call),
            Err(secretspec_ipc::Error::Closed) => break,
            Err(error) => panic!("unexpected call error: {error:?}"),
        }
    }
    assert!(client.is_closed());

    client
        .close(deadline(Duration::from_millis(100)))
        .await
        .unwrap();
    peer.await.unwrap();
}

/// Records whether the session ran its shutdown hook.
struct ShutdownWitness {
    shutdown: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl ApplicationHandler for ShutdownWitness {
    fn protocol(&self) -> &'static str {
        "secretspec.resolver"
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["resolver.get".into()]
    }

    async fn initialize(&self, _context: &RequestContext, application: Value) -> RpcResult<Value> {
        Ok(application)
    }

    async fn call(
        &self,
        _context: RequestContext,
        _method: &str,
        params: Value,
    ) -> RpcResult<Value> {
        Ok(params)
    }

    async fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

#[tokio::test]
async fn transport_failure_still_runs_session_cleanup() {
    // A frame that violates the wire rules used to propagate straight out of
    // `serve`, skipping in-flight cancellation, task joining, and the handler's
    // shutdown hook. Resources such as resolver leases depend on that hook, so a
    // hostile or broken peer must not be able to skip it.
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_io);
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let observed = shutdown.clone();
    let witness = Arc::new(ShutdownWitness {
        shutdown: shutdown.clone(),
    });
    let server = tokio::spawn(serve(
        server_read,
        server_write,
        witness,
        ServerConfig::default(),
    ));

    // Initialize by hand so the session owns application state; `shutdown` is
    // deliberately not called for a session that never initialized.
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "rpc.initialize",
        "_meta": {"deadline_unix_ms": deadline(Duration::from_secs(2))},
        "params": {
            "protocol": "secretspec.resolver",
            "versions": [1],
            "client": {"name": "test", "version": "1"},
            "limits": {"max_frame_bytes": 32 * 1024, "max_in_flight": 4},
            "application": {},
        },
    });
    write_frame(
        &mut client_io,
        &serde_json::to_vec(&initialize).unwrap(),
        1_048_576,
    )
    .await
    .unwrap();
    let reply = read_frame(&mut client_io, 1_048_576)
        .await
        .unwrap()
        .unwrap();
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    assert!(reply.get("result").is_some(), "initialization must succeed");

    let ready = tokio::spawn(async move { observed.notified().await });
    // Let the watcher arm before the session fails.
    tokio::task::yield_now().await;

    // An unterminated line beyond the active frame limit must fail the session
    // without allocating an unbounded buffer.
    {
        use tokio::io::AsyncWriteExt;
        client_io
            .write_all(&vec![b'x'; 32 * 1024 + 1])
            .await
            .unwrap();
        client_io.flush().await.unwrap();
    }

    // The session reports the protocol violation to its caller ...
    let outcome = server.await.unwrap();
    assert!(outcome.is_err(), "an oversized frame must fail the session");
    // ... and still ran cleanup on the way out.
    tokio::time::timeout(Duration::from_secs(2), ready)
        .await
        .expect("session cleanup must run even when the transport fails")
        .unwrap();
}

#[tokio::test]
async fn initialization_state_violations_return_one_error_and_close() {
    // An application request before initialization is rejected and terminal.
    let (mut io, server) = raw_server().await;
    let request = json!({
        "jsonrpc":"2.0", "id":1, "method":"resolver.get",
        "_meta":{"deadline_unix_ms":deadline(Duration::from_secs(2))}, "params":{}
    });
    write_frame(&mut io, &serde_json::to_vec(&request).unwrap(), 1_048_576)
        .await
        .unwrap();
    let response: Value =
        serde_json::from_slice(&read_frame(&mut io, 1_048_576).await.unwrap().unwrap()).unwrap();
    assert_eq!(response["error"]["data"]["kind"], "invalid_request");
    assert!(read_frame(&mut io, 1_048_576).await.unwrap().is_none());
    server.await.unwrap().unwrap();

    // A response that cannot belong to an initialization callback closes
    // immediately because responses have no response channel.
    let (mut io, server) = raw_server().await;
    let response = json!({"jsonrpc":"2.0", "id":1, "result":{}});
    write_frame(&mut io, &serde_json::to_vec(&response).unwrap(), 1_048_576)
        .await
        .unwrap();
    assert!(read_frame(&mut io, 1_048_576).await.unwrap().is_none());
    server.await.unwrap().unwrap();

    // A second initialize after readiness receives one error and closes.
    let (mut io, server) = raw_server().await;
    write_frame(
        &mut io,
        &serde_json::to_vec(&initialize_request(1)).unwrap(),
        1_048_576,
    )
    .await
    .unwrap();
    let initialized: Value =
        serde_json::from_slice(&read_frame(&mut io, 1_048_576).await.unwrap().unwrap()).unwrap();
    assert!(initialized.get("result").is_some());
    write_frame(
        &mut io,
        &serde_json::to_vec(&initialize_request(2)).unwrap(),
        32 * 1024,
    )
    .await
    .unwrap();
    let response: Value =
        serde_json::from_slice(&read_frame(&mut io, 32 * 1024).await.unwrap().unwrap()).unwrap();
    assert_eq!(response["error"]["data"]["kind"], "invalid_request");
    assert!(read_frame(&mut io, 32 * 1024).await.unwrap().is_none());
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn second_initialize_while_the_first_is_active_cancels_startup_and_closes() {
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_io);
    let started = Arc::new(tokio::sync::Semaphore::new(0));
    let server_started = started.clone();
    let server = tokio::spawn(serve(
        server_read,
        server_write,
        Arc::new(SlowInitialize {
            started: server_started,
        }),
        ServerConfig::default(),
    ));
    write_frame(
        &mut client_io,
        &serde_json::to_vec(&initialize_request(1)).unwrap(),
        1_048_576,
    )
    .await
    .unwrap();
    started.acquire().await.unwrap().forget();
    write_frame(
        &mut client_io,
        &serde_json::to_vec(&initialize_request(2)).unwrap(),
        1_048_576,
    )
    .await
    .unwrap();
    let response: Value = serde_json::from_slice(
        &read_frame(&mut client_io, 1_048_576)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response["id"], 2);
    assert_eq!(response["error"]["data"]["kind"], "invalid_request");
    assert!(
        read_frame(&mut client_io, 1_048_576)
            .await
            .unwrap()
            .is_none()
    );
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn invalid_initialization_is_distinct_from_unsupported_version() {
    for (mut request, expected) in [
        (
            {
                let mut request = initialize_request(1);
                request["params"]["limits"]["max_in_flight"] = json!(0);
                request
            },
            "invalid_params",
        ),
        (
            {
                let mut request = initialize_request(1);
                request["params"]["protocol"] = json!("unknown.protocol");
                request
            },
            "unsupported_version",
        ),
        (
            {
                let mut request = initialize_request(1);
                request["params"]["versions"] = json!([999]);
                request
            },
            "unsupported_version",
        ),
    ] {
        let (mut io, server) = raw_server().await;
        request["_meta"]["deadline_unix_ms"] = json!(deadline(Duration::from_secs(2)));
        write_frame(&mut io, &serde_json::to_vec(&request).unwrap(), 1_048_576)
            .await
            .unwrap();
        let response: Value =
            serde_json::from_slice(&read_frame(&mut io, 1_048_576).await.unwrap().unwrap())
                .unwrap();
        assert_eq!(response["error"]["data"]["kind"], expected);
        assert!(read_frame(&mut io, 1_048_576).await.unwrap().is_none());
        server.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn notifications_are_structurally_strict_but_unknown_methods_are_ignored() {
    let (mut io, server) = raw_server().await;
    write_frame(
        &mut io,
        &serde_json::to_vec(&initialize_request(1)).unwrap(),
        1_048_576,
    )
    .await
    .unwrap();
    let _ = read_frame(&mut io, 1_048_576).await.unwrap().unwrap();

    for notification in [
        json!({"jsonrpc":"2.0", "method":"future.notice", "params":{}}),
        json!({"jsonrpc":"2.0", "method":"rpc.cancel", "params":{"id":"bad"}}),
        json!({"jsonrpc":"2.0", "method":"rpc.cancel", "params":{"id":999}}),
        json!({"jsonrpc":"2.0", "method":"rpc.cancel", "params":{"id":1}}),
    ] {
        write_frame(
            &mut io,
            &serde_json::to_vec(&notification).unwrap(),
            32 * 1024,
        )
        .await
        .unwrap();
    }
    let discover = json!({
        "jsonrpc":"2.0", "id":2, "method":"rpc.discover",
        "_meta":{"deadline_unix_ms":deadline(Duration::from_secs(2))}, "params":{}
    });
    write_frame(&mut io, &serde_json::to_vec(&discover).unwrap(), 32 * 1024)
        .await
        .unwrap();
    let response: Value =
        serde_json::from_slice(&read_frame(&mut io, 32 * 1024).await.unwrap().unwrap()).unwrap();
    assert_eq!(response["id"], 2);

    let invalid = json!({
        "jsonrpc":"2.0", "method":"future.notice", "params":{}, "extra":true
    });
    write_frame(&mut io, &serde_json::to_vec(&invalid).unwrap(), 32 * 1024)
        .await
        .unwrap();
    let response: Value =
        serde_json::from_slice(&read_frame(&mut io, 32 * 1024).await.unwrap().unwrap()).unwrap();
    assert_eq!(response["error"]["data"]["kind"], "invalid_request");
    assert!(read_frame(&mut io, 32 * 1024).await.unwrap().is_none());
    server.await.unwrap().unwrap();
}

/// The one direction reversal in version 1, at the wire layer.
///
/// A handler asks its client something mid-request; the answer comes back on
/// the same connection while the client is still waiting for its own response.
/// The client that advertised nothing must be told immediately instead, which
/// is what keeps a headless consumer from waiting out a deadline.
mod callbacks {
    use super::*;
    use secretspec_ipc::client::CallbackHandler;
    use secretspec_ipc::error::{ErrorKind, RpcError};
    use secretspec_ipc::server::Peer;
    use std::future::pending;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Semaphore;

    const CANARY: &str = "SECRETSPEC_LATE_CALLBACK_SECRET";

    fn initialize_response(id: u64, max_in_flight: usize) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocol": "secretspec.resolver",
                "version": 1,
                "server": {"name": "callback-peer", "version": "1"},
                "methods": ["resolver.get"],
                "capabilities": {},
                "limits": {
                    "max_frame_bytes": 32 * 1024,
                    "max_in_flight": max_in_flight
                },
                "application": {}
            }
        }))
        .unwrap()
    }

    fn callback(id: u64, deadline_unix_ms: u64) -> Vec<u8> {
        callback_with_parent(id, deadline_unix_ms, Some(2))
    }

    fn callback_with_parent(
        id: u64,
        deadline_unix_ms: u64,
        parent_request_id: Option<u64>,
    ) -> Vec<u8> {
        let mut request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "client.prompt",
            "_meta": {"deadline_unix_ms": deadline_unix_ms},
            "params": {"name": "TOKEN"}
        });
        if let Some(parent_request_id) = parent_request_id {
            request["_meta"]["parent_request_id"] = json!(parent_request_id);
        }
        serde_json::to_vec(&request).unwrap()
    }

    async fn raw_client(
        client_io: tokio::io::DuplexStream,
        max_in_flight: usize,
        handler: Arc<dyn CallbackHandler>,
    ) -> Client {
        let (client_read, client_write) = tokio::io::split(client_io);
        let initialize = InitializeParams {
            protocol: "secretspec.resolver".into(),
            versions: vec![1],
            client: Product {
                name: "callback-test".into(),
                version: "1".into(),
            },
            limits: Limits {
                max_frame_bytes: 32 * 1024,
                max_in_flight,
            },
            client_methods: vec!["client.prompt".into()],
            application: json!({}),
        };
        Client::connect_with_callbacks::<_, _, _, Value>(
            client_read,
            client_write,
            initialize,
            deadline(Duration::from_secs(2)),
            Some(handler),
        )
        .await
        .unwrap()
        .0
    }

    struct Asks;

    #[async_trait]
    impl ApplicationHandler for Asks {
        fn protocol(&self) -> &'static str {
            "secretspec.resolver"
        }

        fn capabilities(&self) -> Vec<String> {
            vec!["resolver.get".into()]
        }

        async fn initialize(&self, _context: &RequestContext, _: Value) -> RpcResult<Value> {
            Ok(json!({}))
        }

        async fn call(
            &self,
            context: RequestContext,
            _method: &str,
            _params: Value,
        ) -> RpcResult<Value> {
            let supported = context.peer.supports("client.prompt");
            let answer: Value = context
                .peer
                .call("client.prompt", &json!({"name": "TOKEN"}), &context)
                .await
                .unwrap_or_else(|error| json!({"error": error.data.kind.as_str()}));
            Ok(json!({"supported": supported, "answer": answer}))
        }
    }

    struct Answers;

    #[async_trait]
    impl CallbackHandler for Answers {
        async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            if method != "client.prompt" {
                return Err(RpcError::new(ErrorKind::MethodNotFound));
            }
            Ok(json!({"echoed": params["name"]}))
        }
    }

    struct AsksUntilExpiry;

    #[async_trait]
    impl ApplicationHandler for AsksUntilExpiry {
        fn protocol(&self) -> &'static str {
            "secretspec.resolver"
        }

        fn capabilities(&self) -> Vec<String> {
            vec!["resolver.get".into()]
        }

        async fn initialize(&self, _context: &RequestContext, _: Value) -> RpcResult<Value> {
            Ok(json!({}))
        }

        async fn call(
            &self,
            context: RequestContext,
            _method: &str,
            params: Value,
        ) -> RpcResult<Value> {
            if params.get("prompt").and_then(Value::as_bool) == Some(true) {
                let outcome: Result<Value, _> = context
                    .peer
                    .call("client.prompt", &json!({"name": "TOKEN"}), &context)
                    .await;
                return Ok(json!({
                    "callback": outcome
                        .map(|_| "answered")
                        .unwrap_or_else(|error| error.data.kind.as_str())
                }));
            }
            Ok(json!({"alive": true}))
        }
    }

    struct DetachesInitializeCallback {
        callback_started: Arc<Semaphore>,
    }

    #[async_trait]
    impl ApplicationHandler for DetachesInitializeCallback {
        fn protocol(&self) -> &'static str {
            "secretspec.resolver"
        }

        fn capabilities(&self) -> Vec<String> {
            vec!["resolver.get".into()]
        }

        async fn initialize(&self, context: &RequestContext, _: Value) -> RpcResult<Value> {
            let peer = context.peer.clone();
            let context = context.clone();
            tokio::spawn(async move {
                let _: RpcResult<Value> = peer
                    .call("client.prompt", &json!({"name": "TOKEN"}), &context)
                    .await;
            });
            // Return while the callback is still running so its cancellation
            // races the initialize response boundary deterministically.
            self.callback_started.acquire().await.unwrap().forget();
            Ok(json!({}))
        }

        async fn call(
            &self,
            _context: RequestContext,
            _method: &str,
            params: Value,
        ) -> RpcResult<Value> {
            Ok(params)
        }
    }

    struct NeverAnswers;

    #[async_trait]
    impl CallbackHandler for NeverAnswers {
        async fn call(&self, _method: &str, _params: Value) -> Result<Value, RpcError> {
            pending().await
        }
    }

    struct RecordsCancellation {
        started: Arc<Semaphore>,
        dropped: Arc<AtomicBool>,
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[async_trait]
    impl CallbackHandler for RecordsCancellation {
        async fn call(&self, _method: &str, _params: Value) -> Result<Value, RpcError> {
            let _drop = DropFlag(self.dropped.clone());
            self.started.add_permits(1);
            pending().await
        }
    }

    async fn ask(advertise: bool) -> Value {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_io);
        let (server_read, server_write) = tokio::io::split(server_io);
        let server = tokio::spawn(serve(
            server_read,
            server_write,
            Arc::new(Asks),
            ServerConfig::default(),
        ));
        let (capabilities, handler): (Vec<String>, Option<Arc<dyn CallbackHandler>>) = if advertise
        {
            (vec!["client.prompt".into()], Some(Arc::new(Answers)))
        } else {
            (Vec::new(), None)
        };
        let initialize = InitializeParams {
            protocol: "secretspec.resolver".into(),
            versions: vec![1],
            client: Product {
                name: "callback-test".into(),
                version: "1".into(),
            },
            limits: Limits {
                max_frame_bytes: 32 * 1024,
                max_in_flight: 4,
            },
            client_methods: capabilities,
            application: json!({}),
        };
        let (client, _): (Client, secretspec_ipc::protocol::InitializeResult<Value>) =
            Client::connect_with_callbacks(
                client_read,
                client_write,
                initialize,
                deadline(Duration::from_secs(2)),
                handler,
            )
            .await
            .unwrap();
        let result: Value = client
            .call("resolver.get", &json!({}), deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        client
            .close(deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        let _ = server.await;
        result
    }

    #[tokio::test]
    async fn an_advertised_callback_is_answered_mid_request() {
        let result = ask(true).await;
        assert_eq!(result["supported"], json!(true));
        assert_eq!(result["answer"], json!({"echoed": "TOKEN"}));
    }

    #[tokio::test]
    async fn initialize_response_cancels_a_still_running_callback() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_io);
        let (server_read, server_write) = tokio::io::split(server_io);
        let started = Arc::new(Semaphore::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let server = tokio::spawn(serve(
            server_read,
            server_write,
            Arc::new(DetachesInitializeCallback {
                callback_started: started.clone(),
            }),
            ServerConfig::default(),
        ));
        let initialize = InitializeParams {
            protocol: "secretspec.resolver".into(),
            versions: vec![1],
            client: Product {
                name: "callback-test".into(),
                version: "1".into(),
            },
            limits: Limits {
                max_frame_bytes: 32 * 1024,
                max_in_flight: 2,
            },
            client_methods: vec!["client.prompt".into()],
            application: json!({}),
        };
        let (client, _): (Client, secretspec_ipc::protocol::InitializeResult<Value>) =
            Client::connect_with_callbacks(
                client_read,
                client_write,
                initialize,
                deadline(Duration::from_secs(2)),
                Some(Arc::new(RecordsCancellation {
                    started,
                    dropped: dropped.clone(),
                })),
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("initialize-time callback survived readiness");
        let result: Value = client
            .call(
                "resolver.get",
                &json!({"alive": true}),
                deadline(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(result, json!({"alive": true}));
        client
            .close(deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_unadvertised_callback_is_refused_without_reaching_the_client() {
        let result = ask(false).await;
        assert_eq!(result["supported"], json!(false));
        assert_eq!(result["answer"], json!({"error": "capability_required"}));
    }

    #[tokio::test]
    async fn a_completed_callback_id_cannot_be_reused() {
        let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(async move {
            let initialize = read_frame(&mut peer_io, 1024 * 1024)
                .await
                .unwrap()
                .unwrap();
            let initialize: Value = serde_json::from_slice(&initialize).unwrap();
            write_frame(
                &mut peer_io,
                &initialize_response(initialize["id"].as_u64().unwrap(), 1),
                1024 * 1024,
            )
            .await
            .unwrap();

            let call = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            let call: Value = serde_json::from_slice(&call).unwrap();
            let parent_deadline = call["_meta"]["deadline_unix_ms"].as_u64().unwrap();
            write_frame(&mut peer_io, &callback(7, parent_deadline), 32 * 1024)
                .await
                .unwrap();
            let answer = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&answer).unwrap()["id"], 7);
            write_frame(&mut peer_io, &callback(7, parent_deadline), 32 * 1024)
                .await
                .unwrap();
            while read_frame(&mut peer_io, 32 * 1024).await.unwrap().is_some() {}
        });

        let client = raw_client(client_io, 1, Arc::new(Answers)).await;
        let error = client
            .call::<_, Value>("resolver.get", &json!({}), deadline(Duration::from_secs(2)))
            .await
            .unwrap_err();
        assert!(matches!(error, secretspec_ipc::Error::Closed));
        assert!(client.is_closed());
        client
            .close(deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn callbacks_obey_the_negotiated_in_flight_limit() {
        let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(async move {
            let initialize = read_frame(&mut peer_io, 1024 * 1024)
                .await
                .unwrap()
                .unwrap();
            let initialize: Value = serde_json::from_slice(&initialize).unwrap();
            write_frame(
                &mut peer_io,
                &initialize_response(initialize["id"].as_u64().unwrap(), 1),
                1024 * 1024,
            )
            .await
            .unwrap();

            let call = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            let call: Value = serde_json::from_slice(&call).unwrap();
            let parent_deadline = call["_meta"]["deadline_unix_ms"].as_u64().unwrap();
            write_frame(&mut peer_io, &callback(8, parent_deadline), 32 * 1024)
                .await
                .unwrap();
            write_frame(&mut peer_io, &callback(9, parent_deadline), 32 * 1024)
                .await
                .unwrap();
            while read_frame(&mut peer_io, 32 * 1024).await.unwrap().is_some() {}
        });

        let client = raw_client(client_io, 1, Arc::new(NeverAnswers)).await;
        let error = client
            .call::<_, Value>("resolver.get", &json!({}), deadline(Duration::from_secs(2)))
            .await
            .unwrap_err();
        assert!(matches!(error, secretspec_ipc::Error::Closed));
        assert!(client.is_closed());
        client
            .close(deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn callback_deadline_cannot_exceed_its_parent() {
        let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(async move {
            let initialize = read_frame(&mut peer_io, 1024 * 1024)
                .await
                .unwrap()
                .unwrap();
            let initialize: Value = serde_json::from_slice(&initialize).unwrap();
            write_frame(
                &mut peer_io,
                &initialize_response(initialize["id"].as_u64().unwrap(), 1),
                1024 * 1024,
            )
            .await
            .unwrap();

            let call = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            let call: Value = serde_json::from_slice(&call).unwrap();
            let parent_deadline = call["_meta"]["deadline_unix_ms"].as_u64().unwrap();
            write_frame(
                &mut peer_io,
                &callback(8, parent_deadline.saturating_add(1)),
                32 * 1024,
            )
            .await
            .unwrap();
            read_frame(&mut peer_io, 32 * 1024).await.unwrap().is_none()
        });

        let client = raw_client(client_io, 1, Arc::new(Answers)).await;
        assert!(matches!(
            client
                .call::<_, Value>("resolver.get", &json!({}), deadline(Duration::from_secs(2)))
                .await,
            Err(secretspec_ipc::Error::Closed)
        ));
        client
            .close(deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        assert!(peer.await.unwrap());
    }

    #[tokio::test]
    async fn callback_parent_must_be_present_and_active() {
        for parent_request_id in [None, Some(999)] {
            let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
            let peer = tokio::spawn(async move {
                let initialize = read_frame(&mut peer_io, 1024 * 1024)
                    .await
                    .unwrap()
                    .unwrap();
                let initialize: Value = serde_json::from_slice(&initialize).unwrap();
                write_frame(
                    &mut peer_io,
                    &initialize_response(initialize["id"].as_u64().unwrap(), 1),
                    1024 * 1024,
                )
                .await
                .unwrap();

                let call = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
                let call: Value = serde_json::from_slice(&call).unwrap();
                let deadline = call["_meta"]["deadline_unix_ms"].as_u64().unwrap();
                write_frame(
                    &mut peer_io,
                    &callback_with_parent(8, deadline, parent_request_id),
                    32 * 1024,
                )
                .await
                .unwrap();
                read_frame(&mut peer_io, 32 * 1024).await.unwrap().is_none()
            });

            let client = raw_client(client_io, 1, Arc::new(Answers)).await;
            assert!(matches!(
                client
                    .call::<_, Value>("resolver.get", &json!({}), deadline(Duration::from_secs(2)))
                    .await,
                Err(secretspec_ipc::Error::Closed)
            ));
            client
                .close(deadline(Duration::from_secs(2)))
                .await
                .unwrap();
            assert!(peer.await.unwrap());
        }
    }

    #[tokio::test]
    async fn cancelling_a_parent_cancels_its_running_callback() {
        let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
        let started = Arc::new(Semaphore::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let observed_started = started.clone();
        let peer = tokio::spawn(async move {
            let initialize = read_frame(&mut peer_io, 1024 * 1024)
                .await
                .unwrap()
                .unwrap();
            let initialize: Value = serde_json::from_slice(&initialize).unwrap();
            write_frame(
                &mut peer_io,
                &initialize_response(initialize["id"].as_u64().unwrap(), 1),
                1024 * 1024,
            )
            .await
            .unwrap();

            let call = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            let call: Value = serde_json::from_slice(&call).unwrap();
            let parent_id = call["id"].as_u64().unwrap();
            let parent_deadline = call["_meta"]["deadline_unix_ms"].as_u64().unwrap();
            write_frame(&mut peer_io, &callback(8, parent_deadline), 32 * 1024)
                .await
                .unwrap();

            let mut saw_cancel = false;
            let mut saw_callback_terminal = false;
            for _ in 0..2 {
                let frame = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
                let frame: Value = serde_json::from_slice(&frame).unwrap();
                if frame.get("method").and_then(Value::as_str) == Some("rpc.cancel") {
                    saw_cancel = frame["params"]["id"] == parent_id;
                } else if frame.get("id").and_then(Value::as_u64) == Some(8) {
                    saw_callback_terminal = frame["error"]["data"]["kind"] == "cancelled";
                }
            }
            assert!(saw_cancel);
            assert!(saw_callback_terminal);
            write_frame(
                &mut peer_io,
                &serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":parent_id,"result":{"done":true}}),
                )
                .unwrap(),
                32 * 1024,
            )
            .await
            .unwrap();
            let shutdown = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            let shutdown: Value = serde_json::from_slice(&shutdown).unwrap();
            write_frame(
                &mut peer_io,
                &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":shutdown["id"],"result":{}}))
                    .unwrap(),
                32 * 1024,
            )
            .await
            .unwrap();
        });

        let client = raw_client(
            client_io,
            1,
            Arc::new(RecordsCancellation {
                started,
                dropped: dropped.clone(),
            }),
        )
        .await;
        let mut call = client
            .start("resolver.get", &json!({}), deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        observed_started.acquire().await.unwrap().forget();
        call.cancel().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("callback handler survived parent cancellation");
        assert_eq!(call.wait().await.unwrap(), json!({"done": true}));
        client
            .close(deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_cancels_a_running_callback() {
        let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
        let started = Arc::new(Semaphore::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let peer_started = started.clone();
        let peer = tokio::spawn(async move {
            let initialize = read_frame(&mut peer_io, 1024 * 1024)
                .await
                .unwrap()
                .unwrap();
            let initialize: Value = serde_json::from_slice(&initialize).unwrap();
            write_frame(
                &mut peer_io,
                &initialize_response(initialize["id"].as_u64().unwrap(), 1),
                1024 * 1024,
            )
            .await
            .unwrap();
            let call = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            let call: Value = serde_json::from_slice(&call).unwrap();
            let parent_deadline = call["_meta"]["deadline_unix_ms"].as_u64().unwrap();
            write_frame(&mut peer_io, &callback(8, parent_deadline), 32 * 1024)
                .await
                .unwrap();
            peer_started.acquire().await.unwrap().forget();
        });

        let client = raw_client(
            client_io,
            1,
            Arc::new(RecordsCancellation {
                started,
                dropped: dropped.clone(),
            }),
        )
        .await;
        assert!(matches!(
            client
                .call::<_, Value>("resolver.get", &json!({}), deadline(Duration::from_secs(2)))
                .await,
            Err(secretspec_ipc::Error::Closed)
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("callback handler survived disconnect");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn terminal_parent_cancels_callback_and_discards_its_result() {
        let (client_io, mut peer_io) = tokio::io::duplex(64 * 1024);
        let started = Arc::new(Semaphore::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let peer_started = started.clone();
        let peer = tokio::spawn(async move {
            let initialize = read_frame(&mut peer_io, 1024 * 1024)
                .await
                .unwrap()
                .unwrap();
            let initialize: Value = serde_json::from_slice(&initialize).unwrap();
            write_frame(
                &mut peer_io,
                &initialize_response(initialize["id"].as_u64().unwrap(), 1),
                1024 * 1024,
            )
            .await
            .unwrap();

            let call = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            let call: Value = serde_json::from_slice(&call).unwrap();
            let parent_deadline = call["_meta"]["deadline_unix_ms"].as_u64().unwrap();
            write_frame(&mut peer_io, &callback(8, parent_deadline), 32 * 1024)
                .await
                .unwrap();
            peer_started.acquire().await.unwrap().forget();
            write_frame(
                &mut peer_io,
                &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":2,"result":{"done":true}}))
                    .unwrap(),
                32 * 1024,
            )
            .await
            .unwrap();

            let callback_response = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            assert!(
                !callback_response
                    .windows(CANARY.len())
                    .any(|bytes| bytes == CANARY.as_bytes())
            );
            let callback_response: Value = serde_json::from_slice(&callback_response).unwrap();
            assert_eq!(callback_response["id"], 8);
            assert_eq!(callback_response["error"]["data"]["kind"], "cancelled");

            let shutdown = read_frame(&mut peer_io, 32 * 1024).await.unwrap().unwrap();
            let shutdown: Value = serde_json::from_slice(&shutdown).unwrap();
            write_frame(
                &mut peer_io,
                &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":shutdown["id"],"result":{}}))
                    .unwrap(),
                32 * 1024,
            )
            .await
            .unwrap();
        });

        let handler = RecordsCancellation {
            started,
            dropped: dropped.clone(),
        };
        let client = raw_client(client_io, 1, Arc::new(handler)).await;
        let result: Value = client
            .call("resolver.get", &json!({}), deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        assert_eq!(result, json!({"done": true}));
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::Acquire));
        client
            .close(deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn a_detached_peer_advertises_nothing() {
        // What a handler exercised outside a live transport sees. It must match
        // what a real session reports for a client that advertised nothing, so
        // a test cannot accidentally prove behavior a headless consumer would
        // not get.
        assert!(!Peer::detached().supports("client.prompt"));
    }

    #[tokio::test]
    async fn an_expired_callback_terminal_does_not_close_the_session() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_io);
        let (server_read, server_write) = tokio::io::split(server_io);
        let server = tokio::spawn(serve(
            server_read,
            server_write,
            Arc::new(AsksUntilExpiry),
            ServerConfig::default(),
        ));
        let initialize = InitializeParams {
            protocol: "secretspec.resolver".into(),
            versions: vec![1],
            client: Product {
                name: "expired-callback-test".into(),
                version: "1".into(),
            },
            limits: Limits {
                max_frame_bytes: 32 * 1024,
                max_in_flight: 4,
            },
            client_methods: vec!["client.prompt".into()],
            application: json!({}),
        };
        let (client, _): (Client, secretspec_ipc::protocol::InitializeResult<Value>) =
            Client::connect_with_callbacks(
                client_read,
                client_write,
                initialize,
                deadline(Duration::from_secs(2)),
                Some(Arc::new(NeverAnswers)),
            )
            .await
            .unwrap();

        // Repetition proves consumed late terminals do not accumulate in the
        // bounded abandoned-ID set. Each health check also proves the response
        // did not get misclassified as an unmatched terminal and kill the
        // transport.
        for _ in 0..16 {
            let outcome = client
                .call::<_, Value>(
                    "resolver.get",
                    &json!({"prompt": true}),
                    deadline(Duration::from_millis(50)),
                )
                .await;
            match outcome {
                Ok(result) => assert_eq!(result, json!({"callback": "deadline_exceeded"})),
                Err(error) => {
                    assert_eq!(error.rpc_kind(), Some(ErrorKind::DeadlineExceeded));
                }
            }

            let result: Value = client
                .call(
                    "resolver.get",
                    &json!({"prompt": false}),
                    deadline(Duration::from_secs(2)),
                )
                .await
                .unwrap();
            assert_eq!(result, json!({"alive": true}));
        }

        client
            .close(deadline(Duration::from_secs(2)))
            .await
            .unwrap();
        server.await.unwrap().unwrap();
    }
}
