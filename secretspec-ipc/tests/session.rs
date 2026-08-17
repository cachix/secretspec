use async_trait::async_trait;
use secretspec_ipc::client::Client;
use secretspec_ipc::frame::{read_frame, write_frame};
use secretspec_ipc::protocol::{InitializeParams, Limits, Product};
use secretspec_ipc::server::{ApplicationHandler, RequestContext, RpcResult, ServerConfig, serve};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Echo;

#[async_trait]
impl ApplicationHandler for Echo {
    fn protocol(&self) -> &'static str {
        "secretspec.client"
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["client.resolve".into()]
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

fn deadline(after: Duration) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    now + after.as_millis() as u64
}

async fn session() -> (Client, tokio::task::JoinHandle<secretspec_ipc::Result<()>>) {
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
        protocol: "secretspec.client".into(),
        versions: vec![1],
        client: Product {
            name: "test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 4,
        },
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

#[tokio::test]
async fn initializes_calls_and_shuts_down() {
    let (client, server) = session().await;
    let call_deadline = deadline(Duration::from_secs(2));
    let result: Value = client
        .call("client.resolve", &json!({"value": 42}), call_deadline)
        .await
        .unwrap();
    assert_eq!(result["value"], 42);
    client
        .close(deadline(Duration::from_secs(2)))
        .await
        .unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn cancellation_has_one_terminal_result() {
    let (client, server) = session().await;
    let call_deadline = deadline(Duration::from_secs(2));
    let mut call = client
        .start("client.resolve", &json!({"wait": true}), call_deadline)
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
        .call::<_, Value>("client.resolve", &json!({"wait": true}), call_deadline)
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
                "capabilities": ["client.resolve"],
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
        protocol: "secretspec.client".into(),
        versions: vec![1],
        client: Product {
            name: "test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 4,
        },
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
                "protocol": "secretspec.client",
                "version": 1,
                "server": {"name": "backpressured", "version": "1"},
                "capabilities": ["client.resolve"],
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
        protocol: "secretspec.client".into(),
        versions: vec![1],
        client: Product {
            name: "test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 4096,
            max_in_flight: 4,
        },
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
                "client.resolve",
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
                "protocol": "secretspec.client",
                "version": 1,
                "server": {"name": "nonresponsive", "version": "1"},
                "capabilities": ["client.resolve"],
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
        protocol: "secretspec.client".into(),
        versions: vec![1],
        client: Product {
            name: "test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 4096,
            max_in_flight: 4,
        },
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
            .start("client.resolve", &json!({}), call_deadline)
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
        "secretspec.client"
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["client.resolve".into()]
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
    // shutdown hook. Resources such as broker leases depend on that hook, so a
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
        "deadline_unix_ms": deadline(Duration::from_secs(2)),
        "params": {
            "protocol": "secretspec.client",
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

    // Declare a payload above the absolute frame ceiling. The reader rejects it
    // before allocating, which is exactly the path that used to bypass cleanup.
    let oversized: u32 = 2_000_000;
    {
        use tokio::io::AsyncWriteExt;
        client_io.write_all(&oversized.to_be_bytes()).await.unwrap();
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
