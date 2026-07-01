//! pyo3 extension for the Python SDK.
//!
//! A thin wrapper over `secretspec::resolve_json`, the same JSON-in/JSON-out
//! boundary the C ABI uses, so this binding shares one envelope contract with
//! every other language. The pure-Python layer (`secretspec/__init__.py`) does
//! the request/response marshaling and exposes the builder API.

use pyo3::prelude::*;

/// Resolve secrets from a JSON request string, returning the JSON response
/// envelope (`{"ok": true, "response": ...}` or `{"ok": false, "error": ...}`).
#[pyfunction]
fn resolve(request_json: &str) -> String {
    secretspec::resolve_json(request_json)
}

/// The extension's version (tracks the crate version).
#[pyfunction]
fn abi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(resolve, m)?)?;
    m.add_function(wrap_pyfunction!(abi_version, m)?)?;
    Ok(())
}
