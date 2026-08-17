use secretspec_ipc::error::Error;
use secretspec_ipc::lifecycle::{self, Environment, LaunchOptions};
use secretspec_ipc::protocol::{InitializeParams, Limits, Product};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::{c_uchar, c_void};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ABI_VERSION: u32 = 1 << 16;
const STATUS_OK: i32 = 0;
const STATUS_CANCELLED: i32 = 6;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    schema_version: u32,
    id: String,
    targets: Vec<String>,
    timeout_ms: u64,
    actions: Vec<Value>,
    required_events: Vec<String>,
}

enum Implementation {
    C,
    Rust,
}

enum Scenario {
    Fragmented {
        chunks: Vec<usize>,
    },
    Rejections {
        peer_arguments: Vec<Vec<String>>,
    },
    Lifecycle {
        method: String,
        call_timeout: Duration,
        close_timeout: Duration,
    },
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("client conformance driver: {error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), String> {
    let (implementation, peer) = arguments()?;
    let mut input = Vec::new();
    io::stdin()
        .take(1024 * 1024)
        .read_to_end(&mut input)
        .map_err(|error| error.to_string())?;
    let case: Case = serde_json::from_slice(&input).map_err(|error| error.to_string())?;
    if case.schema_version != 1
        || case.targets.is_empty()
        || case.timeout_ms == 0
        || case.required_events.is_empty()
    {
        return Err("invalid conformance case envelope".into());
    }
    let scenario = scenario(&case)?;
    let events = match implementation {
        Implementation::C => run_c(&peer, scenario)?,
        Implementation::Rust => run_rust(&peer, scenario)?,
    };
    serde_json::to_writer(
        io::stdout().lock(),
        &json!({"case": case.id, "events": events}),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn arguments() -> Result<(Implementation, PathBuf), String> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--implementation")) {
        return Err("expected --implementation c|rust --peer PATH".into());
    }
    let implementation = match arguments.next().and_then(|value| value.into_string().ok()) {
        Some(value) if value == "c" => Implementation::C,
        Some(value) if value == "rust" => Implementation::Rust,
        _ => return Err("implementation must be c or rust".into()),
    };
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--peer")) {
        return Err("expected --peer PATH".into());
    }
    let peer = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing peer path".to_string())?;
    if arguments.next().is_some() {
        return Err("unexpected driver argument".into());
    }
    Ok((implementation, peer))
}

fn scenario(case: &Case) -> Result<Scenario, String> {
    match case.id.as_str() {
        "wire.fragmented-frame" => {
            require_action(&case.actions, "launch")?;
            require_action(&case.actions, "shutdown")?;
            let chunks = require_action(&case.actions, "peer_write")?
                .get("chunks")
                .and_then(Value::as_array)
                .ok_or_else(|| "fragmented case has no chunks".to_string())?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|value| usize::try_from(value).ok())
                        .filter(|value| *value != 0)
                        .ok_or_else(|| "invalid fragment size".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Scenario::Fragmented { chunks })
        }
        "wire.strict-rejections" => {
            let peer_arguments = case
                .actions
                .iter()
                .filter(|action| action.get("kind").and_then(Value::as_str) == Some("raw_frame"))
                .map(rejection_arguments)
                .collect::<Result<Vec<_>, _>>()?;
            if peer_arguments.is_empty() {
                return Err("strict rejection case has no frames".into());
            }
            Ok(Scenario::Rejections { peer_arguments })
        }
        "client.lifecycle" => {
            let initialize = require_action(&case.actions, "initialize")?;
            if initialize.get("protocol").and_then(Value::as_str) != Some("secretspec.client")
                || initialize.get("version").and_then(Value::as_u64) != Some(1)
            {
                return Err("client lifecycle selects an unsupported protocol".into());
            }
            require_action(&case.actions, "cancel")?;
            let call = require_action(&case.actions, "call")?;
            let close = require_action(&case.actions, "close")?;
            Ok(Scenario::Lifecycle {
                method: call
                    .get("method")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "client lifecycle call has no method".to_string())?
                    .to_string(),
                call_timeout: action_timeout(call)?,
                close_timeout: action_timeout(close)?,
            })
        }
        other => Err(format!("unsupported client conformance case {other}")),
    }
}

fn require_action<'a>(actions: &'a [Value], kind: &str) -> Result<&'a Value, String> {
    actions
        .iter()
        .find(|action| action.get("kind").and_then(Value::as_str) == Some(kind))
        .ok_or_else(|| format!("case has no {kind} action"))
}

fn action_timeout(action: &Value) -> Result<Duration, String> {
    action
        .get("deadline_after_ms")
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .map(Duration::from_millis)
        .ok_or_else(|| "action has no positive deadline".to_string())
}

fn rejection_arguments(action: &Value) -> Result<Vec<String>, String> {
    let value = if action.get("payload_hex").and_then(Value::as_str) == Some("") {
        "empty".to_string()
    } else if action.get("payload_utf8").and_then(Value::as_str) == Some("[]") {
        "batch".to_string()
    } else if action
        .get("payload_utf8")
        .and_then(Value::as_str)
        .is_some_and(|value| value == r#"{"jsonrpc":"2.0","jsonrpc":"2.0"}"#)
    {
        "duplicate-key".to_string()
    } else if let Some(length) = action.get("declared_length").and_then(Value::as_u64) {
        format!(
            "oversized:{}",
            u32::try_from(length).map_err(|_| "declared length exceeds u32".to_string())?
        )
    } else {
        return Err("unsupported strict rejection action".into());
    };
    Ok(vec!["--reject-init".into(), value])
}

fn event(kind: &str) -> Value {
    json!({"kind": kind})
}

fn initialize_params() -> InitializeParams<Value> {
    InitializeParams {
        protocol: "secretspec.client".into(),
        versions: vec![1],
        client: Product {
            name: "conformance-driver".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 4,
        },
        application: json!({}),
    }
}

fn launch_options(peer: &Path, arguments: &[String]) -> LaunchOptions {
    LaunchOptions {
        executable: peer.to_path_buf(),
        arguments: arguments.iter().map(Into::into).collect(),
        environment: Environment::Replace(BTreeMap::new()),
        allow_path_discovery: false,
        max_stderr_bytes: 4096,
    }
}

fn run_rust(peer: &Path, scenario: Scenario) -> Result<Vec<Value>, String> {
    tokio::runtime::Runtime::new()
        .map_err(|error| error.to_string())?
        .block_on(async move {
            match scenario {
                Scenario::Fragmented { chunks } => {
                    let arguments = vec![
                        "--fragment-init".into(),
                        chunks
                            .iter()
                            .map(usize::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                    ];
                    let (session, _) = lifecycle::spawn::<_, Value>(
                        launch_options(peer, &arguments),
                        initialize_params(),
                        deadline_after(Duration::from_secs(2)),
                    )
                    .await
                    .map_err(stable)?;
                    session
                        .close(deadline_after(Duration::from_secs(2)))
                        .await
                        .map_err(stable)?;
                    Ok(vec![
                        event("initialized"),
                        event("frame_accepted"),
                        event("closed"),
                    ])
                }
                Scenario::Rejections { peer_arguments } => {
                    let mut events = Vec::with_capacity(peer_arguments.len() + 1);
                    for arguments in peer_arguments {
                        if lifecycle::spawn::<_, Value>(
                            launch_options(peer, &arguments),
                            initialize_params(),
                            deadline_after(Duration::from_secs(2)),
                        )
                        .await
                        .is_ok()
                        {
                            return Err(
                                "Rust client accepted an invalid initialization frame".into()
                            );
                        }
                        events.push(event("rejected"));
                    }
                    events.push(event("closed"));
                    Ok(events)
                }
                Scenario::Lifecycle {
                    method,
                    call_timeout,
                    close_timeout,
                } => {
                    let (session, _) = lifecycle::spawn::<_, Value>(
                        launch_options(peer, &[]),
                        initialize_params(),
                        deadline_after(Duration::from_secs(2)),
                    )
                    .await
                    .map_err(stable)?;
                    let deadline = deadline_after(call_timeout);
                    let mut call = session
                        .client()
                        .start(&method, &json!({"mode": "pending"}), deadline)
                        .await
                        .map_err(stable)?;
                    call.cancel().await.map_err(stable)?;
                    if !matches!(call.wait().await, Err(Error::Cancelled)) {
                        return Err(
                            "Rust cancellation did not produce one cancelled terminal".into()
                        );
                    }
                    session
                        .close(deadline_after(close_timeout))
                        .await
                        .map_err(stable)?;
                    Ok(vec![
                        event("initialized"),
                        event("terminal"),
                        event("child_reaped"),
                        event("closed"),
                    ])
                }
            }
        })
}

fn stable(error: secretspec_ipc::Error) -> String {
    error.stable_message().to_string()
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
    fn secretspec_ipc_abi_version() -> u32;
    fn secretspec_ipc_client_open(
        options: *const Options,
        deadline_unix_ms: u64,
        client: *mut *mut c_void,
        server_info: *mut Buffer,
        error: *mut Buffer,
    ) -> i32;
    fn secretspec_ipc_call_start(
        client: *mut c_void,
        method: *const c_uchar,
        method_size: usize,
        params_json: *const c_uchar,
        params_size: usize,
        deadline_unix_ms: u64,
        call: *mut *mut c_void,
        error: *mut Buffer,
    ) -> i32;
    fn secretspec_ipc_call_wait(call: *mut c_void, result: *mut Buffer, error: *mut Buffer) -> i32;
    fn secretspec_ipc_call_cancel(call: *mut c_void);
    fn secretspec_ipc_call_free(call: *mut c_void);
    fn secretspec_ipc_client_close(
        client: *mut c_void,
        deadline_unix_ms: u64,
        error: *mut Buffer,
    ) -> i32;
    fn secretspec_ipc_client_free(client: *mut c_void);
    fn secretspec_ipc_buffer_free(buffer: Buffer);
}

struct CClient(*mut c_void);

impl CClient {
    fn open(peer: &Path, arguments: &[String]) -> Result<Self, String> {
        // SAFETY: this function has no pointer arguments and returns a scalar.
        if unsafe { secretspec_ipc_abi_version() } != ABI_VERSION {
            return Err("C client ABI version mismatch".into());
        }
        let executable = peer.to_string_lossy().into_owned().into_bytes();
        let argument_bytes = arguments
            .iter()
            .map(|argument| argument.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let argument_slices = argument_bytes
            .iter()
            .map(|argument| slice(argument))
            .collect::<Vec<_>>();
        let initialize =
            serde_json::to_vec(&initialize_params()).map_err(|error| error.to_string())?;
        let options = Options {
            struct_size: u32::try_from(std::mem::size_of::<Options>()).unwrap(),
            abi_version: ABI_VERSION,
            flags: 0,
            reserved: 0,
            executable: slice(&executable),
            arguments: if argument_slices.is_empty() {
                ptr::null()
            } else {
                argument_slices.as_ptr()
            },
            argument_count: argument_slices.len(),
            environment: ptr::null(),
            environment_count: 0,
            initialize_params_json: slice(&initialize),
            max_stderr_bytes: 4096,
        };
        let mut client = ptr::null_mut();
        let mut server = empty_buffer();
        let mut error = empty_buffer();
        // SAFETY: all input slices remain live for this call and outputs point
        // to initialized writable storage.
        let status = unsafe {
            secretspec_ipc_client_open(
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
            if !client.is_null() {
                // SAFETY: a non-null failure output is still owned by the caller.
                unsafe { secretspec_ipc_client_free(client) };
            }
            Err(take_error(error, status))
        }
    }

    fn cancel_pending(&self, method: &str, timeout: Duration) -> Result<(), String> {
        let deadline = deadline_after(timeout);
        let params =
            serde_json::to_vec(&json!({"mode": "pending"})).map_err(|error| error.to_string())?;
        let mut call = ptr::null_mut();
        let mut error = empty_buffer();
        // SAFETY: the client is live, input slices outlive the call, and the
        // output pointers refer to initialized writable storage.
        let status = unsafe {
            secretspec_ipc_call_start(
                self.0,
                method.as_ptr(),
                method.len(),
                params.as_ptr(),
                params.len(),
                deadline,
                &mut call,
                &mut error,
            )
        };
        if status != STATUS_OK || call.is_null() {
            return Err(take_error(error, status));
        }
        free_buffer(error);
        // SAFETY: the call handle remains live until the matching free.
        unsafe { secretspec_ipc_call_cancel(call) };
        let mut result = empty_buffer();
        let mut error = empty_buffer();
        // SAFETY: exactly one waiter consumes the live call's terminal result.
        let status = unsafe { secretspec_ipc_call_wait(call, &mut result, &mut error) };
        // SAFETY: waiting is complete and no other thread uses the call.
        unsafe { secretspec_ipc_call_free(call) };
        free_buffer(result);
        free_buffer(error);
        if status == STATUS_CANCELLED {
            Ok(())
        } else {
            Err(format!("C cancellation returned status {status}"))
        }
    }

    fn close(mut self, timeout: Duration) -> Result<(), String> {
        let mut error = empty_buffer();
        // SAFETY: this is the sole close of the live client.
        let status =
            unsafe { secretspec_ipc_client_close(self.0, deadline_after(timeout), &mut error) };
        // SAFETY: close made calls terminal and joined the process worker.
        unsafe { secretspec_ipc_client_free(self.0) };
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
            // SAFETY: emergency free accepts a live client and owns cleanup.
            unsafe { secretspec_ipc_client_free(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

fn run_c(peer: &Path, scenario: Scenario) -> Result<Vec<Value>, String> {
    match scenario {
        Scenario::Fragmented { chunks } => {
            let arguments = vec![
                "--fragment-init".into(),
                chunks
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ];
            CClient::open(peer, &arguments)?.close(Duration::from_secs(2))?;
            Ok(vec![
                event("initialized"),
                event("frame_accepted"),
                event("closed"),
            ])
        }
        Scenario::Rejections { peer_arguments } => {
            let mut events = Vec::with_capacity(peer_arguments.len() + 1);
            for arguments in peer_arguments {
                if let Ok(client) = CClient::open(peer, &arguments) {
                    drop(client);
                    return Err("C client accepted an invalid initialization frame".into());
                }
                events.push(event("rejected"));
            }
            events.push(event("closed"));
            Ok(events)
        }
        Scenario::Lifecycle {
            method,
            call_timeout,
            close_timeout,
        } => {
            let client = CClient::open(peer, &[])?;
            client.cancel_pending(&method, call_timeout)?;
            client.close(close_timeout)?;
            Ok(vec![
                event("initialized"),
                event("terminal"),
                event("child_reaped"),
                event("closed"),
            ])
        }
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

fn copy_buffer(buffer: Buffer) -> Vec<u8> {
    if buffer.data.is_null() || buffer.size == 0 {
        free_buffer(buffer);
        return Vec::new();
    }
    // SAFETY: C-owned buffers are valid for `size` bytes until freed below.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.data, buffer.size) }.to_vec();
    free_buffer(buffer);
    bytes
}

fn take_error(buffer: Buffer, status: i32) -> String {
    format!(
        "C status {status}: {}",
        String::from_utf8_lossy(&copy_buffer(buffer))
    )
}

fn free_buffer(buffer: Buffer) {
    // SAFETY: the buffer is empty or is an unconsumed C library allocation.
    unsafe { secretspec_ipc_buffer_free(buffer) };
}
