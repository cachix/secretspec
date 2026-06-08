//! The SecretSpec C ABI: a deliberately narrow, JSON-in/JSON-out boundary.
//!
//! The entire native surface is three functions. Richness lives in the
//! versioned JSON contract, not in a wide C API, so that every language binding
//! (Python via cffi, Go via purego, Ruby via ffi, Node via napi-rs) stays a
//! thin shell: marshal a request string in, get a response string out, free it.
//! Resolution logic lives only in the `secretspec` crate; this is a wrapper.
//!
//! # Contract
//!
//! - [`secretspec_resolve`] takes a UTF-8, NUL-terminated JSON **request** and
//!   returns a heap-allocated, NUL-terminated JSON **response envelope**. The
//!   caller owns the returned pointer and must free it with [`secretspec_free`].
//! - [`secretspec_abi_version`] returns a static version string (do not free).
//!
//! ## Request JSON
//!
//! ```json
//! { "path": "…/secretspec.toml", "provider": "keyring://",
//!   "profile": "production", "reason": "boot", "no_values": false }
//! ```
//!
//! All fields are optional. `path` omitted means "walk up from the working
//! directory" like the CLI. `no_values` strips secret values from the response.
//!
//! ## Response envelope
//!
//! ```json
//! { "ok": true,  "response": { …ResolveResponse… } }
//! { "ok": false, "error": { "kind": "io", "message": "…" } }
//! ```
//!
//! `ok: true` carries the value-carrying [`secretspec::ResolveResponse`] (which
//! still reports domain failures like `missing_required` in its own fields).
//! `ok: false` means the call itself failed (bad manifest, provider error,
//! reason policy). This separates transport failure from "a required secret is
//! missing", which the SDK surfaces differently.
//!
//! # Safety
//!
//! Returned response strings carry secret values (unless `no_values`). Treat
//! them as sensitive and free them promptly. The host language's heap cannot be
//! zeroized; for file-shaped secrets prefer `as_path`, whose value never crosses
//! the boundary (only the temp-file path does).

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use secretspec::{ResolveResponse, Secrets};
use serde::{Deserialize, Serialize};

/// ABI version, NUL-terminated for direct return as a C string.
const ABI_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[derive(Debug, Default, Deserialize)]
struct ResolveRequest {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    no_values: bool,
}

#[derive(Debug, Serialize)]
struct FfiError {
    kind: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct Envelope {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<ResolveResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<FfiError>,
}

impl Envelope {
    fn ok(response: ResolveResponse) -> Self {
        Self {
            ok: true,
            response: Some(response),
            error: None,
        }
    }

    fn err(kind: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            response: None,
            error: Some(FfiError {
                kind: kind.to_string(),
                message: message.into(),
            }),
        }
    }
}

/// Returns the ABI version as a static NUL-terminated string. Do not free.
///
/// # Safety
/// The returned pointer is valid for the lifetime of the loaded library.
#[unsafe(no_mangle)]
pub extern "C" fn secretspec_abi_version() -> *const c_char {
    ABI_VERSION.as_ptr().cast()
}

/// Frees a string previously returned by [`secretspec_resolve`].
///
/// # Safety
/// `ptr` must be either null or a pointer returned by [`secretspec_resolve`]
/// that has not already been freed. Passing anything else is undefined
/// behavior. Null is accepted and ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secretspec_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // Retake ownership and drop.
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

/// Resolves secrets described by a JSON request, returning a JSON response
/// envelope. See the module docs for the request/response shapes.
///
/// # Safety
/// `request_json` must be null or a valid pointer to a NUL-terminated C string.
/// The returned pointer is owned by the caller and must be freed with
/// [`secretspec_free`]. Returns null only on catastrophic allocation failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secretspec_resolve(request_json: *const c_char) -> *mut c_char {
    // Never let a panic unwind across the FFI boundary (that is UB).
    let envelope = match catch_unwind(AssertUnwindSafe(|| resolve_inner(request_json))) {
        Ok(env) => env,
        Err(_) => Envelope::err("panic", "internal panic during resolve"),
    };

    let json = serde_json::to_string(&envelope).unwrap_or_else(|_| {
        // Should be unreachable; fall back to a hand-built valid envelope.
        "{\"ok\":false,\"error\":{\"kind\":\"serialize\",\"message\":\"failed to serialize response\"}}"
            .to_string()
    });

    match CString::new(json) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn resolve_inner(request_json: *const c_char) -> Envelope {
    if request_json.is_null() {
        return Envelope::err("invalid_input", "request_json was null");
    }

    // Safety: caller contract guarantees a NUL-terminated string when non-null.
    let raw = unsafe { CStr::from_ptr(request_json) };
    let text = match raw.to_str() {
        Ok(s) => s,
        Err(_) => return Envelope::err("invalid_input", "request_json was not valid UTF-8"),
    };

    let request: ResolveRequest = match serde_json::from_str(text) {
        Ok(req) => req,
        Err(e) => return Envelope::err("invalid_request", format!("invalid request JSON: {e}")),
    };

    let loaded = match &request.path {
        Some(path) => Secrets::load_from(Path::new(path)),
        None => Secrets::load(),
    };
    let mut app = match loaded {
        Ok(app) => app,
        Err(e) => return Envelope::err(e.kind(), e.to_string()),
    };

    if let Some(provider) = request.provider {
        app.set_provider(provider);
    }
    if let Some(profile) = request.profile {
        app.set_profile(profile);
    }
    if let Some(reason) = request.reason {
        app = app.with_reason(reason);
    }

    match app.resolve() {
        Ok(mut response) => {
            if request.no_values {
                response = response.without_values();
            }
            Envelope::ok(response)
        }
        Err(e) => Envelope::err(e.kind(), e.to_string()),
    }
}
