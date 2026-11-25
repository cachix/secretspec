#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use tempfile::TempDir;

// Compile the real C ABI wrapper into this fuzz executable and call its extern
// functions exactly as a C consumer does. Keeping the wrapper as the source of
// truth avoids a second, test-only imitation of its allocation and UTF-8 rules.
#[path = "../../libsecretspec/src/lib.rs"]
mod capi;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MANIFEST: &str = r#"
[project]
name = "resolver-fuzz"

[defaults]
provider = "null://"

[profiles.default]
FUZZ_VALUE = { required = false, default = "fixed-value" }
"#;

struct Fixture {
    _directory: TempDir,
    manifest_path: String,
}

impl Fixture {
    fn create() -> Self {
        let directory = TempDir::new().expect("fuzz fixture directory must exist");
        let manifest = directory.path().join("secretspec.toml");
        std::fs::write(&manifest, MANIFEST).expect("fuzz fixture manifest must be writable");
        Self {
            _directory: directory,
            manifest_path: manifest.to_string_lossy().into_owned(),
        }
    }
}

thread_local! {
    static FIXTURE: RefCell<Fixture> = RefCell::new(Fixture::create());
}

/// `resolve_json` accepts a path and a provider override, so raw fuzz objects
/// could otherwise read arbitrary files or contact a configured backend. Keep
/// all fuzzed fields except those two, pin them to a temporary null-provider
/// manifest, and still pass malformed/non-object JSON through unchanged to
/// exercise the Rust parser boundary.
fn safe_request(input: &[u8]) -> String {
    let input = &input[..input.len().min(MAX_INPUT_BYTES)];
    let text = String::from_utf8_lossy(input);
    let Ok(Value::Object(mut request)) = serde_json::from_str::<Value>(&text) else {
        return text.into_owned();
    };

    request.remove("path");
    request.remove("provider");
    FIXTURE.with(|fixture| {
        request.insert(
            "path".to_string(),
            Value::String(fixture.borrow().manifest_path.clone()),
        );
    });
    serde_json::to_string(&Value::Object(request)).expect("JSON values serialize")
}

fn call_c_api(request: &CStr) -> String {
    // Safety: `request` is NUL-terminated; the ABI returns an owned allocation
    // that is released exactly once below.
    let result: *mut c_char = unsafe { capi::secretspec_resolve(request.as_ptr()) };
    assert!(!result.is_null(), "C resolver must return an envelope");
    let response = unsafe { CStr::from_ptr(result) }
        .to_str()
        .expect("C resolver response must be UTF-8 JSON")
        .to_owned();
    unsafe { capi::secretspec_free(result) };
    response
}

fn assert_json_envelope(response: &str) {
    let envelope: Value = serde_json::from_str(response).expect("resolver response must be JSON");
    assert!(
        envelope.get("ok").and_then(Value::as_bool).is_some(),
        "resolver response must carry an ok flag: {envelope}"
    );
}

fn fuzz(input: &[u8]) {
    let request = safe_request(input);
    let rust_response = secretspec_core::resolve_json(&request);
    assert_json_envelope(&rust_response);

    // Malformed JSON is intentionally passed through unchanged. It can contain
    // an interior NUL, which Rust accepts in a `str` but the C ABI cannot
    // represent in its NUL-terminated request argument.
    if let Ok(c_request) = CString::new(request) {
        let c_response = call_c_api(&c_request);
        assert_json_envelope(&c_response);
        assert_eq!(
            c_response, rust_response,
            "C and Rust resolver APIs diverged"
        );
    }

    // Raw bytes exercise the C-only invalid-UTF-8 path too. An interior NUL is
    // excluded because it cannot be represented by the ABI's C-string input.
    let bytes = &input[..input.len().min(MAX_INPUT_BYTES)];
    if let Ok(raw_request) = CString::new(bytes) {
        assert_json_envelope(&call_c_api(&raw_request));
    }
}

fuzz_target!(|input: &[u8]| {
    fuzz(input);
});
