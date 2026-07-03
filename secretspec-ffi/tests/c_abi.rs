//! Exercises the C ABI through the real extern "C" entry points, as a native
//! caller would: build a request JSON, call `secretspec_resolve`, parse the
//! returned envelope, then `secretspec_free`.

use std::ffi::{CStr, CString, c_char};
use std::fs;

use secretspec_ffi::{secretspec_abi_version, secretspec_free, secretspec_resolve};
use serde_json::Value;
use tempfile::TempDir;

/// Call the C ABI with a Rust string request and return the parsed JSON
/// envelope, freeing the native allocation.
fn resolve(request: &str) -> Value {
    let c_request = CString::new(request).unwrap();
    let ptr: *mut c_char = unsafe { secretspec_resolve(c_request.as_ptr()) };
    assert!(!ptr.is_null(), "resolve returned null");
    let json = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
    unsafe { secretspec_free(ptr) };
    serde_json::from_str(&json).unwrap()
}

fn write_project(dir: &TempDir, manifest: &str, dotenv: &str) -> (String, String) {
    let manifest_path = dir.path().join("secretspec.toml");
    let env_path = dir.path().join(".env");
    fs::write(&manifest_path, manifest).unwrap();
    fs::write(&env_path, dotenv).unwrap();
    (
        manifest_path.display().to_string(),
        format!("dotenv://{}", env_path.display()),
    )
}

const MANIFEST: &str = r#"
[project]
name = "ffi-test"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "DB", required = true }
LOG_LEVEL = { description = "log", required = false, default = "info" }
SENTRY_DSN = { description = "sentry", required = false }
"#;

#[test]
fn abi_version_is_nonempty() {
    let ptr = secretspec_abi_version();
    assert!(!ptr.is_null());
    let version = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
    assert!(!version.is_empty());
    // Static string: no free.
}

#[test]
fn resolve_returns_values_and_provenance() {
    let dir = TempDir::new().unwrap();
    let (manifest_path, provider) = write_project(&dir, MANIFEST, "DATABASE_URL=postgres://db\n");

    let request = serde_json::json!({
        "path": manifest_path,
        "provider": provider,
        "reason": "ffi test",
    })
    .to_string();

    let env = resolve(&request);
    assert_eq!(env["ok"], true, "envelope: {env}");
    let response = &env["response"];
    assert_eq!(response["schema_version"], 1);
    assert_eq!(response["profile"], "default");
    assert_eq!(
        response["secrets"]["DATABASE_URL"]["value"],
        "postgres://db"
    );
    assert_eq!(response["secrets"]["DATABASE_URL"]["source"], "provider");
    assert_eq!(response["secrets"]["LOG_LEVEL"]["value"], "info");
    assert_eq!(response["secrets"]["LOG_LEVEL"]["source"], "default");
    assert_eq!(response["missing_optional"][0], "SENTRY_DSN");
    assert!(response["missing_required"].as_array().unwrap().is_empty());
}

#[test]
fn resolve_no_values_strips_secrets() {
    let dir = TempDir::new().unwrap();
    let (manifest_path, provider) = write_project(&dir, MANIFEST, "DATABASE_URL=postgres://db\n");

    let request = serde_json::json!({
        "path": manifest_path,
        "provider": provider,
        "reason": "ffi test",
        "no_values": true,
    })
    .to_string();

    let env = resolve(&request);
    assert_eq!(env["ok"], true);
    // Structure and provenance remain, but no value is present.
    let db = &env["response"]["secrets"]["DATABASE_URL"];
    assert_eq!(db["source"], "provider");
    assert!(db.get("value").is_none(), "value should be stripped: {db}");
}

#[test]
fn resolve_missing_required_is_ok_envelope_with_error_list() {
    let dir = TempDir::new().unwrap();
    // DATABASE_URL is required but absent from the backend.
    let (manifest_path, provider) = write_project(&dir, MANIFEST, "");

    let request = serde_json::json!({
        "path": manifest_path,
        "provider": provider,
        "reason": "ffi test",
    })
    .to_string();

    let env = resolve(&request);
    // A missing required secret is a domain result, not a transport error:
    // the envelope is ok, but the response reports it.
    assert_eq!(env["ok"], true, "envelope: {env}");
    assert_eq!(env["response"]["missing_required"][0], "DATABASE_URL");
    assert!(env["response"]["secrets"].as_object().unwrap().is_empty());
}

#[test]
fn invalid_request_json_yields_error_envelope() {
    let env = resolve("not json at all");
    assert_eq!(env["ok"], false);
    assert_eq!(env["error"]["kind"], "invalid_request");
}

#[test]
fn missing_manifest_yields_error_envelope() {
    let request = serde_json::json!({
        "path": "/definitely/does/not/exist/secretspec.toml",
        "reason": "ffi test",
    })
    .to_string();

    let env = resolve(&request);
    assert_eq!(env["ok"], false, "envelope: {env}");
    assert!(env["error"]["kind"].is_string());
    assert!(env["error"]["message"].is_string());
}
