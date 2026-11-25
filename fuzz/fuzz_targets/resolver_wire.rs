#![no_main]

use async_trait::async_trait;
use libfuzzer_sys::fuzz_target;
use secretspec_ipc::frame::encode;
use secretspec_ipc::protocol::resolver::{
    GetParams, GetResult, InitializeApplication, InitializedApplication, ReleaseParams,
    ReleaseResult, UndeclaredResult, UndeclaredStatus,
};
use secretspec_ipc::resolver::{ResolverHandler, serve_resolver};
use secretspec_ipc::server::{RequestContext, RpcResult, ServerConfig};
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_INPUT_BYTES: usize = 64 * 1024;
const STREAM_CAPACITY: usize = 256 * 1024;

/// A side-effect-free resolver that lets the fuzzer exercise the actual IPC
/// server stack. It deliberately returns fixed responses: the target is the
/// untrusted wire boundary, not provider or filesystem behavior.
struct FuzzResolver;

#[async_trait]
impl ResolverHandler for FuzzResolver {
    async fn initialize(
        &self,
        _context: &RequestContext,
        _application: InitializeApplication,
    ) -> RpcResult<InitializedApplication> {
        Ok(InitializedApplication {
            manifest_kind: "inline".to_string(),
            supports_inline_manifest: true,
        })
    }

    async fn get(&self, _context: RequestContext, _params: GetParams) -> RpcResult<GetResult> {
        Ok(GetResult::Undeclared(UndeclaredResult {
            status: UndeclaredStatus::Undeclared,
        }))
    }

    async fn release(
        &self,
        _context: RequestContext,
        _params: ReleaseParams,
    ) -> RpcResult<ReleaseResult> {
        Ok(ReleaseResult { released: 0 })
    }
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fuzz runtime must initialize")
    })
}

/// A NUL-prefixed input is sent verbatim, reaching malformed frame delimiters,
/// truncated frames, and non-UTF-8 payloads. Every other input is made into one
/// or more valid UTF-8 frames (separated by a blank line), concentrating fuzz
/// mutations on JSON-RPC and resolver request handling.
fn wire_input(input: &[u8]) -> Vec<u8> {
    let input = &input[..input.len().min(MAX_INPUT_BYTES)];
    if let Some(raw) = input.strip_prefix(&[0]) {
        return raw.to_vec();
    }

    let text = String::from_utf8_lossy(input);
    text.split("\n\n")
        .filter(|payload| !payload.is_empty())
        .filter_map(|payload| encode(payload.as_bytes(), MAX_INPUT_BYTES).ok())
        .flatten()
        .collect()
}

async fn fuzz_session(input: &[u8]) {
    let wire = wire_input(input);
    let (mut client_writer, server_reader) = tokio::io::duplex(STREAM_CAPACITY);
    let (server_writer, mut client_reader) = tokio::io::duplex(STREAM_CAPACITY);

    // Drain replies concurrently. Otherwise a request-heavy corpus input could
    // block the server writer and turn an ordinary protocol error into a hang.
    let drain = tokio::spawn(async move {
        let mut discarded = Vec::new();
        client_reader.read_to_end(&mut discarded).await
    });
    let server = tokio::spawn(serve_resolver(
        server_reader,
        server_writer,
        FuzzResolver,
        ServerConfig::default(),
    ));

    client_writer
        .write_all(&wire)
        .await
        .expect("fuzz stream must accept bounded input");
    client_writer
        .shutdown()
        .await
        .expect("fuzz stream must close");

    // Protocol failures are expected. A panic in the resolver task is not.
    let _ = server.await.expect("resolver server must not panic");
    let _ = drain.await.expect("reply drain must not panic");
}

fuzz_target!(|input: &[u8]| {
    runtime().block_on(fuzz_session(input));
});
