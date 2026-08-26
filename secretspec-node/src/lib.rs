//! napi-rs Node addon for SecretSpec.
//!
//! A thin wrapper over `secretspec::resolve_json`, the same JSON-in/JSON-out
//! boundary the C ABI uses, so the Node binding shares one envelope contract
//! with every other language. The JS layer (index.js) does the request/response
//! marshaling and exposes the builder API.

use napi::{Env, Result, Task, bindgen_prelude::AsyncTask};
use napi_derive::napi;

/// Resolve secrets from a JSON request string, returning the JSON response
/// envelope (`{"ok": true, "response": ...}` or `{"ok": false, "error": ...}`).
///
/// This is synchronous and runs on the Node main thread; prefer [`resolve_async`]
/// when a provider may do network I/O.
#[napi]
pub fn resolve(request_json: String) -> String {
    secretspec::resolve_json(&request_json)
}

/// Process a versioned native operation request, including inline specs.
#[napi]
pub fn call(request_json: String) -> String {
    secretspec::call_json(&request_json)
}

/// Dispatches `resolve_json` from the libuv threadpool to one short-lived Rust
/// thread, so it never runs on the JS thread and provider runtime/TLS state is
/// torn down before the libuv worker is returned to Node.
pub struct ResolveTask {
    request_json: String,
    versioned_call: bool,
}

impl Task for ResolveTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        // A libuv threadpool worker lives until Node shuts down. Network stacks
        // initialized directly on it may retain thread-local runtime/TLS state
        // until that late teardown; on macOS the AWS clients could then leave a
        // short-lived Node process stuck after the Promise had resolved. Keep
        // the N-API async work as the dispatcher, but run providers on a thread
        // whose lifetime ends with this operation so all per-thread state is
        // destroyed before `compute` returns the worker to libuv.
        std::thread::scope(|scope| {
            let resolver = std::thread::Builder::new()
                .name("secretspec-resolve".to_string())
                .spawn_scoped(scope, || {
                    if self.versioned_call {
                        secretspec::call_json(&self.request_json)
                    } else {
                        secretspec::resolve_json(&self.request_json)
                    }
                })
                .map_err(|error| {
                    napi::Error::from_reason(format!(
                        "failed to start the SecretSpec resolver thread: {error}"
                    ))
                })?;
            resolver.join().map_err(|_| {
                napi::Error::from_reason("the SecretSpec resolver thread panicked".to_string())
            })
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Async variant of [`resolve`]: dispatches from the libuv threadpool to a
/// short-lived resolver thread so a provider doing network I/O does not block
/// the Node event loop or leave provider thread state on a persistent libuv
/// worker. Returns a Promise of the same JSON response envelope string.
#[napi]
pub fn resolve_async(request_json: String) -> AsyncTask<ResolveTask> {
    AsyncTask::new(ResolveTask {
        request_json,
        versioned_call: false,
    })
}

/// Async variant of [`call`].
#[napi]
pub fn call_async(request_json: String) -> AsyncTask<ResolveTask> {
    AsyncTask::new(ResolveTask {
        request_json,
        versioned_call: true,
    })
}

/// The addon (ABI) version.
#[napi]
pub fn abi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
