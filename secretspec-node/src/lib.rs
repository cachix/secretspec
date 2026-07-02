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

/// Runs `resolve_json` on the libuv threadpool (via [`AsyncTask`]) so it never
/// runs on the JS thread.
pub struct ResolveTask {
    request_json: String,
}

impl Task for ResolveTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(secretspec::resolve_json(&self.request_json))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Async variant of [`resolve`]: resolves on the libuv threadpool so a provider
/// doing network I/O (1Password, LastPass) does not block the Node event loop.
/// Returns a Promise of the same JSON response envelope string.
#[napi]
pub fn resolve_async(request_json: String) -> AsyncTask<ResolveTask> {
    AsyncTask::new(ResolveTask { request_json })
}

/// The addon (ABI) version.
#[napi]
pub fn abi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
