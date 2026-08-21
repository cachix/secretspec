use proptest::prelude::*;
use secretspec_ipc::error::Error;
use secretspec_ipc::lifecycle::{self, Environment, LaunchOptions};
use secretspec_ipc::protocol::{InitializeParams, Limits, Product};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::{c_uchar, c_void};
use std::path::Path;
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ABI_VERSION: u32 = 1 << 16;
const STATUS_OK: i32 = 0;
const STATUS_CANCELLED: i32 = 6;
const STATUS_DEADLINE_EXCEEDED: i32 = 7;

/// An absolute deadline far enough in the past that both clients reject the
/// call before writing anything. Using a real elapsed timeout instead would
/// make the outcome depend on how fast this machine round-trips to a child
/// process, which is the one thing a differential comparison must not vary on.
const EXPIRED_DEADLINE_UNIX_MS: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum Action {
    Echo { token: u8 },
    Cancel,
    Deadline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
enum Outcome {
    Echo(u8),
    Cancelled,
    DeadlineExceeded,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Slice {
    data: *const c_uchar,
    size: usize,
}

#[repr(C)]
struct Options {
    struct_size: u32,
    abi_version: u32,
    flags: u32,
    reserved: u32,
    executable: Slice,
    arguments: *const Slice,
    argument_count: usize,
    environment: *const Slice,
    environment_count: usize,
    initialize_params_json: Slice,
    max_stderr_bytes: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Buffer {
    data: *mut c_uchar,
    size: usize,
}

unsafe extern "C" {
    fn secretspec_resolver_abi_version() -> u32;
    fn secretspec_resolver_client_open(
        options: *const Options,
        deadline_unix_ms: u64,
        client: *mut *mut c_void,
        server_info: *mut Buffer,
        error: *mut Buffer,
    ) -> i32;
    fn secretspec_resolver_call_start(
        client: *mut c_void,
        method: *const c_uchar,
        method_size: usize,
        params_json: *const c_uchar,
        params_size: usize,
        deadline_unix_ms: u64,
        call: *mut *mut c_void,
        error: *mut Buffer,
    ) -> i32;
    fn secretspec_resolver_client_call(
        client: *mut c_void,
        method: *const c_uchar,
        method_size: usize,
        params_json: *const c_uchar,
        params_size: usize,
        deadline_unix_ms: u64,
        result: *mut Buffer,
        error: *mut Buffer,
    ) -> i32;
    fn secretspec_resolver_call_wait(
        call: *mut c_void,
        result: *mut Buffer,
        error: *mut Buffer,
    ) -> i32;
    fn secretspec_resolver_call_cancel(call: *mut c_void);
    fn secretspec_resolver_call_free(call: *mut c_void);
    fn secretspec_resolver_client_close(
        client: *mut c_void,
        deadline_unix_ms: u64,
        error: *mut Buffer,
    ) -> i32;
    fn secretspec_resolver_client_free(client: *mut c_void);
    fn secretspec_resolver_buffer_free(buffer: Buffer);
}

struct CClient(*mut c_void);

impl CClient {
    fn open(executable: &Path) -> Result<Self, String> {
        let executable = executable.to_string_lossy().into_owned().into_bytes();
        let initialize =
            serde_json::to_vec(&initialize_params()).map_err(|error| error.to_string())?;
        let options = Options {
            struct_size: u32::try_from(std::mem::size_of::<Options>()).unwrap(),
            abi_version: ABI_VERSION,
            flags: 0,
            reserved: 0,
            executable: slice(&executable),
            arguments: ptr::null(),
            argument_count: 0,
            environment: ptr::null(),
            environment_count: 0,
            initialize_params_json: slice(&initialize),
            max_stderr_bytes: 4096,
        };
        let mut client = ptr::null_mut();
        let mut server = empty_buffer();
        let mut error = empty_buffer();
        // SAFETY: all slices remain alive for the duration of the call and all
        // output pointers refer to initialized writable storage.
        let status = unsafe {
            secretspec_resolver_client_open(
                &options,
                deadline_after(Duration::from_secs(2)),
                &mut client,
                &mut server,
                &mut error,
            )
        };
        free_buffer(server);
        if status == STATUS_OK && !client.is_null() {
            free_buffer(error);
            Ok(Self(client))
        } else {
            Err(take_error(error, status))
        }
    }

    fn execute(&self, action: &Action) -> Result<Outcome, String> {
        let (params, deadline_unix_ms, cancel) = match action {
            Action::Echo { token } => (
                json!({
                    "mode": "echo",
                    "token": token
                }),
                deadline_after(Duration::from_secs(2)),
                false,
            ),
            Action::Cancel => (
                json!({
                    "mode": "pending"
                }),
                deadline_after(Duration::from_secs(2)),
                true,
            ),
            Action::Deadline => (
                json!({
                    "mode": "pending"
                }),
                EXPIRED_DEADLINE_UNIX_MS,
                false,
            ),
        };
        let params = serde_json::to_vec(&params).map_err(|error| error.to_string())?;
        let method = b"resolver.get";
        if matches!(action, Action::Echo { .. }) {
            let mut result = empty_buffer();
            let mut error = empty_buffer();
            // SAFETY: the client and input slices are live and both outputs are writable.
            let status = unsafe {
                secretspec_resolver_client_call(
                    self.0,
                    method.as_ptr(),
                    method.len(),
                    params.as_ptr(),
                    params.len(),
                    deadline_unix_ms,
                    &mut result,
                    &mut error,
                )
            };
            if status != STATUS_OK {
                free_buffer(result);
                return Err(take_error(error, status));
            }
            let value = copy_buffer(result)?;
            free_buffer(error);
            let value: Value = serde_json::from_slice(&value).map_err(|error| error.to_string())?;
            let token = value
                .get("echo")
                .and_then(Value::as_u64)
                .ok_or("missing echo")?;
            return Ok(Outcome::Echo(
                u8::try_from(token).map_err(|_| "invalid echo")?,
            ));
        }
        let mut call = ptr::null_mut();
        let mut error = empty_buffer();
        // SAFETY: the client is live, byte slices remain valid for this call,
        // and the output pointers refer to writable storage.
        let start_status = unsafe {
            secretspec_resolver_call_start(
                self.0,
                method.as_ptr(),
                method.len(),
                params.as_ptr(),
                params.len(),
                deadline_unix_ms,
                &mut call,
                &mut error,
            )
        };
        if start_status == STATUS_DEADLINE_EXCEEDED {
            free_buffer(error);
            return Ok(Outcome::DeadlineExceeded);
        }
        if start_status != STATUS_OK || call.is_null() {
            return Err(take_error(error, start_status));
        }
        free_buffer(error);
        if cancel {
            // SAFETY: `call` remains owned until the matching free below.
            unsafe { secretspec_resolver_call_cancel(call) };
        }
        let mut result = empty_buffer();
        let mut error = empty_buffer();
        // SAFETY: exactly one waiter uses this live call handle.
        let status = unsafe { secretspec_resolver_call_wait(call, &mut result, &mut error) };
        // SAFETY: waiting has completed and no other thread uses the handle.
        unsafe { secretspec_resolver_call_free(call) };
        match status {
            STATUS_OK => {
                let value = copy_buffer(result)?;
                free_buffer(error);
                let value: Value =
                    serde_json::from_slice(&value).map_err(|error| error.to_string())?;
                let token = value
                    .get("echo")
                    .and_then(Value::as_u64)
                    .ok_or("missing echo")?;
                Ok(Outcome::Echo(
                    u8::try_from(token).map_err(|_| "invalid echo")?,
                ))
            }
            STATUS_CANCELLED => {
                free_buffer(result);
                free_buffer(error);
                Ok(Outcome::Cancelled)
            }
            STATUS_DEADLINE_EXCEEDED => {
                free_buffer(result);
                free_buffer(error);
                Ok(Outcome::DeadlineExceeded)
            }
            other => {
                free_buffer(result);
                Err(take_error(error, other))
            }
        }
    }

    fn close(mut self) -> Result<(), String> {
        let mut error = empty_buffer();
        // SAFETY: this is the sole close of the live client.
        let status = unsafe {
            secretspec_resolver_client_close(
                self.0,
                deadline_after(Duration::from_secs(2)),
                &mut error,
            )
        };
        // SAFETY: close has made every call terminal and joined the worker.
        unsafe { secretspec_resolver_client_free(self.0) };
        self.0 = ptr::null_mut();
        if status == STATUS_OK {
            free_buffer(error);
            Ok(())
        } else {
            Err(take_error(error, status))
        }
    }
}

impl Drop for CClient {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: emergency free accepts a live client and performs its
            // bounded close; ownership is not used afterward.
            unsafe { secretspec_resolver_client_free(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

fn run_c(executable: &Path, history: &[Action]) -> Result<Vec<Outcome>, String> {
    // SAFETY: this function takes no pointers and reports the linked ABI value.
    if unsafe { secretspec_resolver_abi_version() } != ABI_VERSION {
        return Err("C ABI version mismatch".into());
    }
    let client = CClient::open(executable)?;
    let outcomes = history
        .iter()
        .map(|action| client.execute(action))
        .collect::<Result<Vec<_>, _>>()?;
    client.close()?;
    Ok(outcomes)
}

fn run_rust(executable: &Path, history: &[Action]) -> Result<Vec<Outcome>, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let launch = LaunchOptions {
            executable: executable.to_path_buf(),
            arguments: Vec::new(),
            environment: Environment::Replace(BTreeMap::new()),
            allow_path_discovery: false,
            max_stderr_bytes: 4096,
        };
        let (session, _) = lifecycle::spawn::<_, Value>(
            launch,
            initialize_params(),
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(|error| error.stable_message().to_string())?;
        let mut outcomes = Vec::with_capacity(history.len());
        for action in history {
            let outcome = match action {
                Action::Echo { token } => {
                    let deadline = deadline_after(Duration::from_secs(2));
                    let value: Value = session
                        .client()
                        .call(
                            "resolver.get",
                            &json!({
                                "mode": "echo",
                                "token": token
                            }),
                            deadline,
                        )
                        .await
                        .map_err(|error| error.stable_message().to_string())?;
                    Outcome::Echo(
                        value
                            .get("echo")
                            .and_then(Value::as_u64)
                            .and_then(|value| u8::try_from(value).ok())
                            .ok_or_else(|| "invalid Rust echo".to_string())?,
                    )
                }
                Action::Cancel => {
                    let deadline = deadline_after(Duration::from_secs(2));
                    let mut call = session
                        .client()
                        .start("resolver.get", &json!({"mode": "pending"}), deadline)
                        .await
                        .map_err(|error| error.stable_message().to_string())?;
                    call.cancel()
                        .await
                        .map_err(|error| error.stable_message().to_string())?;
                    match call.wait().await {
                        Err(Error::Cancelled) => Outcome::Cancelled,
                        other => return Err(format!("unexpected Rust cancellation: {other:?}")),
                    }
                }
                Action::Deadline => {
                    // An expired deadline is rejected before anything is
                    // written, so accept it at either point: what matters is
                    // that both clients report it and stay usable.
                    match session
                        .client()
                        .start(
                            "resolver.get",
                            &json!({"mode": "pending"}),
                            EXPIRED_DEADLINE_UNIX_MS,
                        )
                        .await
                    {
                        Err(Error::DeadlineExceeded) => Outcome::DeadlineExceeded,
                        Err(other) => {
                            return Err(format!("unexpected Rust deadline: {other:?}"));
                        }
                        Ok(mut call) => match call.wait().await {
                            Err(Error::DeadlineExceeded) => Outcome::DeadlineExceeded,
                            other => return Err(format!("unexpected Rust deadline: {other:?}")),
                        },
                    }
                }
            };
            outcomes.push(outcome);
        }
        session
            .close(deadline_after(Duration::from_secs(2)))
            .await
            .map_err(|error| error.stable_message().to_string())?;
        Ok(outcomes)
    })
}

fn initialize_params() -> InitializeParams<Value> {
    InitializeParams {
        protocol: "secretspec.resolver".into(),
        versions: vec![1],
        client: Product {
            name: "differential-client".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 32768,
            max_in_flight: 4,
        },
        client_methods: Vec::new(),
        application: json!({}),
    }
}

fn deadline_after(duration: Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .saturating_add(duration.as_millis())
        .min(u64::MAX as u128) as u64
}

fn slice(bytes: &[u8]) -> Slice {
    Slice {
        data: bytes.as_ptr(),
        size: bytes.len(),
    }
}

const fn empty_buffer() -> Buffer {
    Buffer {
        data: ptr::null_mut(),
        size: 0,
    }
}

fn copy_buffer(buffer: Buffer) -> Result<Vec<u8>, String> {
    if buffer.data.is_null() && buffer.size != 0 {
        return Err("C returned an invalid buffer".into());
    }
    if buffer.size == 0 {
        free_buffer(buffer);
        return Ok(Vec::new());
    }
    // SAFETY: successful C buffers are library-owned allocations valid for
    // `size` bytes until `secretspec_resolver_buffer_free`.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.data, buffer.size) }.to_vec();
    free_buffer(buffer);
    Ok(bytes)
}

fn take_error(buffer: Buffer, status: i32) -> String {
    let bytes = copy_buffer(buffer).unwrap_or_default();
    format!("C status {status}: {}", String::from_utf8_lossy(&bytes))
}

fn free_buffer(buffer: Buffer) {
    // SAFETY: buffers are either `{NULL, 0}` or returned by the linked C
    // library, and each is passed here at most once.
    unsafe { secretspec_resolver_buffer_free(buffer) };
}

fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        any::<u8>().prop_map(|token| Action::Echo { token }),
        Just(Action::Cancel),
        Just(Action::Deadline),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    #[test]
    fn c_and_rust_clients_produce_the_same_normalized_history(
        history in prop::collection::vec(action_strategy(), 1..8),
    ) {
        let peer = Path::new(env!("CARGO_BIN_EXE_ipc-fake-peer-rust"));
        let serialized = serde_json::to_vec(&history).unwrap();
        let replay: Vec<Action> = serde_json::from_slice(&serialized).unwrap();
        let c = run_c(peer, &replay).map_err(TestCaseError::fail)?;
        let rust = run_rust(peer, &replay).map_err(TestCaseError::fail)?;
        prop_assert_eq!(c, rust, "history: {}", String::from_utf8_lossy(&serialized));
    }
}
