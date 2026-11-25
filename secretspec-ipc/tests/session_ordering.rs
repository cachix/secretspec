use async_trait::async_trait;
use secretspec_ipc::client::{CallbackHandler, Client};
use secretspec_ipc::frame::{read_frame, write_frame};
use secretspec_ipc::protocol::{InitializeParams, Limits, Product};
use secretspec_ipc::server::{ApplicationHandler, RequestContext, RpcResult, ServerConfig, serve};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::sync::{Barrier, Semaphore};

const LIMITS: Limits = Limits {
    max_frame_bytes: 1024 * 1024,
    max_in_flight: 32,
};

struct Handler {
    started: Semaphore,
    proceed: Semaphore,
    shutdowns: AtomicUsize,
}

impl Default for Handler {
    fn default() -> Self {
        Self {
            started: Semaphore::new(0),
            proceed: Semaphore::new(0),
            shutdowns: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ApplicationHandler for Handler {
    fn protocol(&self) -> &'static str {
        "secretspec.resolver"
    }
    fn capabilities(&self) -> Vec<String> {
        vec!["resolver.get".into()]
    }
    async fn initialize(&self, _: &RequestContext, _: Value) -> RpcResult<Value> {
        Ok(json!({}))
    }
    async fn call(&self, context: RequestContext, _: &str, params: Value) -> RpcResult<Value> {
        if params["gate"] == true {
            self.started.add_permits(1);
            self.proceed.acquire().await.unwrap().forget();
        }
        assert_ne!(params["panic"], true, "test handler panic");
        if params["callback"] == true {
            return context
                .peer
                .call("client.prompt", &json!({}), &context)
                .await;
        }
        if params["concurrent_callbacks"] == true {
            let mut tasks = tokio::task::JoinSet::new();
            let barrier = Arc::new(Barrier::new(16));
            for i in 0..16 {
                let context = context.clone();
                let barrier = barrier.clone();
                tasks.spawn(async move {
                    let params = padding(i);
                    barrier.wait().await;
                    context
                        .peer
                        .call::<_, Value>("client.prompt", &params, &context)
                        .await
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap()?;
            }
        }
        Ok(json!({"done": true}))
    }
    async fn shutdown(&self) {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
}

struct Answers;
#[async_trait]
impl CallbackHandler for Answers {
    async fn call(&self, _: &str, _: Value) -> RpcResult<Value> {
        Ok(json!({"answered": true}))
    }
}

fn deadline() -> u64 {
    secretspec_ipc::deadline_unix_ms_after(Duration::from_secs(10))
}
fn offer() -> InitializeParams<Value> {
    InitializeParams {
        protocol: "secretspec.resolver".into(),
        versions: vec![1],
        client: Product {
            name: "ordering-test".into(),
            version: "1".into(),
        },
        limits: LIMITS,
        client_methods: vec!["client.prompt".into()],
        application: json!({}),
    }
}
fn padding(i: usize) -> Value {
    // Escaping makes envelope serialization expensive after ID allocation.
    json!({"padding": if i.is_multiple_of(2) { "\0".repeat(100_000) } else { String::new() }})
}
fn spawn_server(
    handler: Arc<Handler>,
) -> (
    DuplexStream,
    tokio::task::JoinHandle<secretspec_ipc::Result<()>>,
) {
    let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
    let (read, write) = tokio::io::split(server);
    let server = tokio::spawn(serve(
        read,
        write,
        handler,
        ServerConfig {
            limits: LIMITS,
            ..ServerConfig::default()
        },
    ));
    (client, server)
}
async fn connect(
    handler: Arc<Handler>,
) -> (
    Arc<Client>,
    tokio::task::JoinHandle<secretspec_ipc::Result<()>>,
) {
    let (io, server) = spawn_server(handler);
    let (read, write) = tokio::io::split(io);
    let (client, _) = Client::connect_with_callbacks::<_, _, _, Value>(
        read,
        write,
        offer(),
        deadline(),
        Some(Arc::new(Answers)),
    )
    .await
    .unwrap();
    (Arc::new(client), server)
}
async fn send(io: &mut DuplexStream, value: Value) {
    write_frame(
        io,
        &serde_json::to_vec(&value).unwrap(),
        LIMITS.max_frame_bytes,
    )
    .await
    .unwrap();
}
async fn receive(io: &mut DuplexStream) -> Value {
    let frame = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame(io, LIMITS.max_frame_bytes),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    serde_json::from_slice(&frame).unwrap()
}
fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params, "_meta":{"deadline_unix_ms":deadline()}})
}
async fn raw(
    handler: Arc<Handler>,
) -> (
    DuplexStream,
    tokio::task::JoinHandle<secretspec_ipc::Result<()>>,
) {
    let (mut io, server) = spawn_server(handler);
    send(
        &mut io,
        request(1, "rpc.initialize", serde_json::to_value(offer()).unwrap()),
    )
    .await;
    assert!(receive(&mut io).await["result"].is_object());
    (io, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_calls_and_callbacks_keep_ids_in_wire_order() {
    let (client, server) = connect(Arc::new(Handler::default())).await;
    for _ in 0..8 {
        let barrier = Arc::new(Barrier::new(16));
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..16 {
            let client = client.clone();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                let params = padding(i);
                barrier.wait().await;
                client
                    .call::<_, Value>("resolver.get", &params, deadline())
                    .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        client
            .call::<_, Value>(
                "resolver.get",
                &json!({"concurrent_callbacks":true}),
                deadline(),
            )
            .await
            .unwrap();
    }
    client.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_drains_accepted_work_and_keeps_callbacks_live() {
    let handler = Arc::new(Handler::default());
    let (mut io, server) = raw(handler.clone()).await;
    send(
        &mut io,
        request(2, "resolver.get", json!({"gate":true,"callback":true})),
    )
    .await;
    handler.started.acquire().await.unwrap().forget();
    send(&mut io, request(3, "rpc.shutdown", json!({}))).await;
    send(&mut io, request(4, "resolver.get", json!({}))).await;
    let rejected = receive(&mut io).await;
    assert_eq!(rejected["id"], 4);
    assert_eq!(rejected["error"]["data"]["kind"], "unavailable");
    handler.proceed.add_permits(1);
    let callback = receive(&mut io).await;
    assert_eq!(callback["method"], "client.prompt");
    send(
        &mut io,
        json!({"jsonrpc":"2.0","id":callback["id"],"result":{"answered":true}}),
    )
    .await;
    let completed = receive(&mut io).await;
    assert_eq!(completed["id"], 2);
    assert_eq!(completed["result"]["answered"], true);
    let closed = receive(&mut io).await;
    assert_eq!(closed["id"], 3);
    assert_eq!(closed["result"], json!({}));
    server.await.unwrap().unwrap();
    assert_eq!(handler.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shutdown_deadline_aborts_stuck_work_and_runs_cleanup() {
    let handler = Arc::new(Handler::default());
    let (mut io, server) = raw(handler.clone()).await;
    send(&mut io, request(2, "resolver.get", json!({"gate":true}))).await;
    handler.started.acquire().await.unwrap().forget();
    let mut shutdown = request(3, "rpc.shutdown", json!({}));
    shutdown["_meta"]["deadline_unix_ms"] = json!(secretspec_ipc::deadline_unix_ms_after(
        Duration::from_millis(50)
    ));
    send(&mut io, shutdown).await;
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(handler.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reaping_completed_work_preserves_a_partially_read_frame() {
    let handler = Arc::new(Handler::default());
    let (mut io, server) = raw(handler.clone()).await;
    send(&mut io, request(2, "resolver.get", json!({"gate":true}))).await;
    handler.started.acquire().await.unwrap().forget();
    let next = serde_json::to_vec(&request(3, "resolver.get", json!({}))).unwrap();
    io.write_all(&next[..12]).await.unwrap();
    // Let the reader consume the prefix while the first request is gated.
    tokio::time::sleep(Duration::from_millis(20)).await;
    handler.proceed.add_permits(1);
    assert_eq!(receive(&mut io).await["id"], 2);
    tokio::time::sleep(Duration::from_millis(20)).await;
    io.write_all(&next[12..]).await.unwrap();
    io.write_all(b"\n").await.unwrap();
    assert_eq!(receive(&mut io).await["id"], 3);
    drop(io);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn failed_tasks_are_reaped_without_waiting_for_another_frame() {
    let handler = Arc::new(Handler::default());
    let (mut io, server) = raw(handler.clone()).await;
    send(&mut io, request(2, "resolver.get", json!({"panic":true}))).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(handler.shutdowns.load(Ordering::SeqCst), 1);
}
