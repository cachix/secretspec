use secretspec_ipc::deadline_unix_ms_after;
use secretspec_ipc::lifecycle::{Environment, LaunchOptions, spawn};
use secretspec_ipc::protocol::{
    InitializeParams, InitializeResult, Limits, PROTOCOL_VERSION, Product, RESOLVER_PROTOCOL,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

fn peer() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_ipc-fake-peer-rust"))
}

fn launch_options(arguments: &[&str], environment: BTreeMap<OsString, OsString>) -> LaunchOptions {
    LaunchOptions {
        executable: peer().to_path_buf(),
        arguments: arguments.iter().map(OsString::from).collect(),
        environment: Environment::Inherit(environment),
        allow_path_discovery: false,
        max_stderr_bytes: 4096,
    }
}

fn initialize() -> InitializeParams<Value> {
    InitializeParams {
        protocol: RESOLVER_PROTOCOL.to_string(),
        versions: vec![PROTOCOL_VERSION],
        client: Product {
            name: "async-lifecycle-test".to_string(),
            version: "1".to_string(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 4,
        },
        client_methods: Vec::new(),
        application: json!({}),
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_expired_startup_kills_and_reaps_the_child() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("child.pid");
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("SECRETSPEC_TEST_PID_FILE"),
        pid_file.as_os_str().to_os_string(),
    );

    let result = spawn::<_, Value>(
        launch_options(&["--silent-init"], environment),
        initialize(),
        deadline_unix_ms_after(Duration::from_secs(1)),
    )
    .await;
    assert!(
        matches!(result, Err(secretspec_ipc::Error::DeadlineExceeded)),
        "silent initialization produced an unexpected result"
    );

    let pid = std::fs::read_to_string(&pid_file)
        .expect("the child did not record its PID before the startup deadline")
        .parse::<u32>()
        .unwrap();
    assert!(
        !Path::new("/proc").join(pid.to_string()).exists(),
        "startup failure left child PID {pid} alive or unreaped"
    );
}

#[tokio::test]
async fn an_immediate_exit_after_shutdown_keeps_the_response() {
    for _ in 0..32 {
        let (session, _): (_, InitializeResult<Value>) = spawn(
            launch_options(&[], BTreeMap::new()),
            initialize(),
            deadline_unix_ms_after(Duration::from_secs(2)),
        )
        .await
        .unwrap();

        session
            .close(deadline_unix_ms_after(Duration::from_secs(2)))
            .await
            .unwrap();
    }
}
