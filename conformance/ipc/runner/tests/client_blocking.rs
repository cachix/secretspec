//! Behavior of the synchronous `secretspec.resolver/1` client.
//!
//! The blocking client speaks the same wire protocol as the async one, so it is
//! exercised against the same fake peer: only the transport differs.

use secretspec_ipc::blocking::ResolverSession;
use secretspec_ipc::error::{Error, ErrorKind};
use secretspec_ipc::launch::{Environment, LaunchOptions};
use secretspec_ipc::protocol::resolver::{
    GetParams, GetResult, InitializeApplication, Manifest, Purpose, ReleaseParams, Representation,
};
use secretspec_ipc::protocol::{Limits, Product};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn deadline_after(duration: Duration) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    now + duration.as_millis() as u64
}

fn peer() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_ipc-fake-peer-rust"))
}

fn launch_options(arguments: &[&str]) -> LaunchOptions {
    LaunchOptions {
        executable: peer().to_path_buf(),
        arguments: arguments.iter().map(OsString::from).collect(),
        environment: Environment::Replace(BTreeMap::new()),
        allow_path_discovery: false,
        max_stderr_bytes: 4096,
    }
}

fn base_dir() -> PathBuf {
    // The protocol requires an absolute, lexically normalized base directory.
    std::env::current_dir()
        .unwrap()
        .canonicalize()
        .unwrap()
        .to_path_buf()
}

fn application() -> InitializeApplication {
    InitializeApplication {
        manifest: Manifest::Inline {
            toml: "[project]\nname = \"conformance\"\nrevision = \"1.0\"\n".into(),
            base_dir: base_dir().to_string_lossy().into_owned(),
        },
        provider: None,
        profile: None,
        scope: None,
        reason: None,
        requested_authorization_duration_ms: None,
    }
}

fn resolve_params(name: &str) -> GetParams {
    GetParams {
        name: name.into(),
        representation: Representation::Value,
        purpose: Purpose {
            consumer: "conformance".into(),
            operation: "test".into(),
            host: None,
            path: None,
        },
    }
}

fn launch(options: LaunchOptions) -> secretspec_ipc::Result<ResolverSession> {
    ResolverSession::launch(
        options,
        Product {
            name: "blocking-test".into(),
            version: "1".into(),
        },
        Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 4,
        },
        application(),
        deadline_after(Duration::from_secs(5)),
    )
}

fn session(arguments: &[&str]) -> ResolverSession {
    launch(launch_options(arguments)).expect("the peer completes initialization")
}

/// `ResolverSession` is deliberately not `Debug`, so a failed launch is
/// unwrapped by hand rather than through `unwrap_err`.
fn launch_error(options: LaunchOptions) -> Error {
    match launch(options) {
        Ok(_) => panic!("initialization was expected to fail"),
        Err(error) => error,
    }
}

#[test]
fn resolves_releases_and_shuts_down() {
    let mut session = session(&[]);
    assert!(session.capabilities().contains("resolver.get"));
    assert!(session.initialized().supports_inline_manifest);

    let resolved = session
        .get(
            &resolve_params("RESOLVED_VALUE"),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap();
    match resolved {
        GetResult::Value(value) => {
            assert_eq!(value.value, "canary-value");
            assert_eq!(value.source_provider.as_deref(), Some("keyring://"));
        }
        other => panic!("expected an inline value, got {other:?}"),
    }

    let released = session
        .release(
            &ReleaseParams {
                path_lease_ids: vec!["lease-one".into()],
            },
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap();
    assert_eq!(released.released, 1);

    session
        .close(deadline_after(Duration::from_secs(5)))
        .unwrap();
    assert!(session.is_closed());
}

#[test]
fn missing_and_undeclared_are_domain_results_rather_than_errors() {
    let mut session = session(&[]);
    let missing = session
        .get(
            &resolve_params("MISSING_REQUIRED"),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap();
    assert!(matches!(missing, GetResult::Missing(result) if result.required));

    let undeclared = session
        .get(
            &resolve_params("UNDECLARED"),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap();
    assert!(matches!(undeclared, GetResult::Undeclared(_)));
    session
        .close(deadline_after(Duration::from_secs(5)))
        .unwrap();
}

#[test]
fn remote_errors_keep_their_closed_kind() {
    let mut session = session(&[]);
    let error = session
        .get(
            &resolve_params("REFUSED"),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap_err();
    assert_eq!(error.rpc_kind(), Some(ErrorKind::PermissionDenied));
    // A refusal is answered on the wire, so the session survives it.
    assert!(!session.is_closed());
    session
        .close(deadline_after(Duration::from_secs(5)))
        .unwrap();
}

#[test]
fn a_silent_endpoint_does_not_hang_the_caller() {
    let mut session = session(&[]);
    // The peer accepts this name and never answers. A blocking read cannot be
    // interrupted, so this only returns if the deadline kills the transport.
    let error = session
        .get(
            &resolve_params("SILENT"),
            deadline_after(Duration::from_millis(250)),
        )
        .unwrap_err();
    assert!(matches!(error, Error::DeadlineExceeded));
    assert!(session.is_closed());
    // Closing an already-dead session still reaps the child rather than failing.
    session
        .close(deadline_after(Duration::from_secs(5)))
        .unwrap();
}

#[test]
fn an_inherited_stdout_pipe_does_not_extend_the_deadline() {
    let mut session = session(&["--descendant-holds-pipes"]);
    let started = Instant::now();
    let error = session
        .get(
            &resolve_params("SILENT"),
            deadline_after(Duration::from_millis(250)),
        )
        .unwrap_err();
    assert!(matches!(error, Error::DeadlineExceeded));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(session.is_closed());
}

#[test]
fn an_expired_deadline_is_rejected_before_sending() {
    let mut session = session(&[]);
    let error = session
        .get(&resolve_params("RESOLVED_VALUE"), 1)
        .unwrap_err();
    assert!(matches!(error, Error::DeadlineExceeded));
    // Nothing was written, so the session is still usable.
    assert!(!session.is_closed());
    let resolved = session
        .get(
            &resolve_params("RESOLVED_VALUE"),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap();
    assert!(matches!(resolved, GetResult::Value(_)));
    session
        .close(deadline_after(Duration::from_secs(5)))
        .unwrap();
}

#[test]
fn a_fragmented_initialization_is_reassembled() {
    // One byte at a time exercises the incremental decoder across both the
    // length prefix and the payload.
    let mut session = session(&["--fragment-init", "1,1,1,1,1,1,1,1,1"]);
    let resolved = session
        .get(
            &resolve_params("RESOLVED_VALUE"),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap();
    assert!(matches!(resolved, GetResult::Value(_)));
    session
        .close(deadline_after(Duration::from_secs(5)))
        .unwrap();
}

#[test]
fn malformed_initialization_frames_are_rejected() {
    for rejection in [
        "empty",
        "batch",
        "duplicate-key",
        "invalid-utf8",
        "truncated-header",
        "truncated-payload",
        "unknown-id",
        "oversized:1048577",
    ] {
        let error = launch_error(launch_options(&["--reject-init", rejection]));
        assert!(
            matches!(
                error,
                Error::Protocol(_) | Error::ProtocolOwned(_) | Error::Closed
            ),
            "{rejection} produced {error:?}"
        );
    }
}

#[test]
fn a_relative_executable_requires_explicit_discovery() {
    let mut options = launch_options(&[]);
    options.executable = PathBuf::from("ipc-fake-peer-rust");
    assert!(matches!(launch_error(options), Error::Protocol(_)));
}
