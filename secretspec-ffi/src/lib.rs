//! The SecretSpec C ABI: a deliberately narrow, JSON-in/JSON-out boundary.
//!
//! The entire native surface is three functions. Richness lives in the
//! versioned JSON contract, not in a wide C API, so that every consumer of
//! this ABI (Go via purego, Ruby via ffi, Haskell via the GHC FFI) stays a
//! thin shell: marshal a request string in, get a response string out, free it.
//! Python (pyo3) and Node (napi-rs) skip this C ABI and call
//! `secretspec::resolve_json` directly, but share the same JSON envelope
//! contract. Resolution logic lives only in the `secretspec` crate; this is a
//! wrapper.
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
//!   "profile": "production", "reason": "boot", "no_values": false,
//!   "mode": "resolve" }
//! ```
//!
//! All fields are optional. `path` omitted means "walk up from the working
//! directory" like the CLI.
//!
//! `mode` selects which shape comes back, and defaults to `"resolve"`:
//!
//! - `"resolve"` — the value-carrying [`secretspec::ResolveResponse`]. Set
//!   `no_values` to strip the values from it.
//! - `"report"` — the value-free [`secretspec::ResolutionReport`]: the
//!   inventory/preflight view the CLI exposes as `check --json`.
//!
//! Any other value is rejected with an `invalid_request` error.
//!
//! ### `no_values` is not `mode: "report"`
//!
//! They are different shapes, and a consumer that wants an inventory wants
//! `report`:
//!
//! - `no_values` returns a `ResolveResponse` with the values blanked. Its
//!   `secrets` is an object keyed by name, it never reports whether a secret is
//!   *declared* required, and when a required secret is missing that object is
//!   **empty** — so the one case a preflight check exists to describe is the case
//!   it tells you least about.
//! - `report` returns a `ResolutionReport`, whose `secrets` is an **array** of
//!   per-secret entries carrying `name`, `required`, `status`
//!   (`resolved` / `missing_required` / `missing_optional`) and provenance. Every
//!   declared secret is listed whether or not it resolved. `required` is
//!   reachable *only* here.
//!
//! ## Response envelope
//!
//! ```json
//! { "ok": true,  "response": { …ResolveResponse | ResolutionReport… } }
//! { "ok": false, "error": { "kind": "io", "message": "…" } }
//! ```
//!
//! `ok: true` carries whichever shape `mode` selected. `ok: false` means the call
//! itself failed (bad manifest, provider error, reason policy, unknown `mode`).
//! This separates transport failure from "a required secret is missing", which is
//! a domain result reported inside an `ok: true` response and which the SDK
//! surfaces differently.
//!
//! # Safety
//!
//! Returned response strings carry secret values (unless `no_values`). Treat
//! them as sensitive and free them promptly. The host language's heap cannot be
//! zeroized; for file-shaped secrets prefer `as_path`, whose value never crosses
//! the boundary (only the temp-file path does).

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// ABI version, NUL-terminated for direct return as a C string.
const ABI_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// A hand-built error envelope for failures that occur before the request
/// reaches the shared resolver (null pointer, non-UTF-8 input).
fn input_error(message: &str) -> String {
    format!("{{\"ok\":false,\"error\":{{\"kind\":\"invalid_input\",\"message\":{message:?}}}}}")
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
    let json = match catch_unwind(AssertUnwindSafe(|| resolve_inner(request_json))) {
        Ok(json) => json,
        Err(_) => input_error("internal panic during resolve"),
    };

    match CString::new(json) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn resolve_inner(request_json: *const c_char) -> String {
    if request_json.is_null() {
        return input_error("request_json was null");
    }

    // Safety: caller contract guarantees a NUL-terminated string when non-null.
    let raw = unsafe { CStr::from_ptr(request_json) };
    match raw.to_str() {
        Ok(text) => secretspec::resolve_json(text),
        Err(_) => input_error("request_json was not valid UTF-8"),
    }
}
