//! napi-rs Node addon for SecretSpec.
//!
//! A thin wrapper over `secretspec::resolve_json`, the same JSON-in/JSON-out
//! boundary the C ABI uses, so the Node binding shares one envelope contract
//! with every other language. The JS layer (index.js) does the request/response
//! marshaling and exposes the builder API.

use napi_derive::napi;

/// Resolve secrets from a JSON request string, returning the JSON response
/// envelope (`{"ok": true, "response": ...}` or `{"ok": false, "error": ...}`).
#[napi]
pub fn resolve(request_json: String) -> String {
    secretspec::resolve_json(&request_json)
}

/// The addon (ABI) version.
#[napi]
pub fn abi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
