use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};

const MAX_FRAME_BYTES: usize = 1_048_576;

enum Mode {
    Normal,
    SilentInitialize,
    FragmentInitialize(Vec<usize>),
    NotifyInitialize,
    RejectInitialize(Rejection),
    DescendantHoldsPipes,
    HoldPipes,
}

enum Rejection {
    Empty,
    Batch,
    DuplicateKey,
    InvalidUtf8,
    TruncatedHeader,
    TruncatedPayload,
    UnknownId,
    Oversized(u32),
}

fn main() {
    if record_pid()
        .and_then(|()| parse_mode())
        .and_then(serve)
        .is_err()
    {
        std::process::exit(1);
    }
}

fn record_pid() -> Result<(), ()> {
    let Some(path) = std::env::var_os("SECRETSPEC_TEST_PID_FILE") else {
        return Ok(());
    };
    std::fs::write(path, std::process::id().to_string()).map_err(|_| ())
}

fn parse_mode() -> Result<Mode, ()> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        None => Ok(Mode::Normal),
        Some("--silent-init") if arguments.next().is_none() => Ok(Mode::SilentInitialize),
        Some("--descendant-holds-pipes") if arguments.next().is_none() => {
            Ok(Mode::DescendantHoldsPipes)
        }
        Some("--hold-pipes") if arguments.next().is_none() => Ok(Mode::HoldPipes),
        Some("--notify-init") if arguments.next().is_none() => Ok(Mode::NotifyInitialize),
        Some("--fragment-init") => {
            let chunks = arguments
                .next()
                .ok_or(())?
                .split(',')
                .map(|value| value.parse::<usize>().map_err(|_| ()))
                .collect::<Result<Vec<_>, _>>()?;
            if chunks.is_empty() || chunks.contains(&0) || arguments.next().is_some() {
                return Err(());
            }
            Ok(Mode::FragmentInitialize(chunks))
        }
        Some("--reject-init") => {
            let rejection = match arguments.next().as_deref() {
                Some("empty") => Rejection::Empty,
                Some("batch") => Rejection::Batch,
                Some("duplicate-key") => Rejection::DuplicateKey,
                Some("invalid-utf8") => Rejection::InvalidUtf8,
                Some("truncated-header") => Rejection::TruncatedHeader,
                Some("truncated-payload") => Rejection::TruncatedPayload,
                Some("unknown-id") => Rejection::UnknownId,
                Some(value) if value.starts_with("oversized:") => Rejection::Oversized(
                    value
                        .strip_prefix("oversized:")
                        .ok_or(())?
                        .parse()
                        .map_err(|_| ())?,
                ),
                _ => return Err(()),
            };
            if arguments.next().is_some() {
                return Err(());
            }
            Ok(Mode::RejectInitialize(rejection))
        }
        Some(_) => Err(()),
    }
}

fn serve(mode: Mode) -> Result<(), ()> {
    if matches!(&mode, Mode::HoldPipes) {
        std::thread::sleep(std::time::Duration::from_secs(5));
        return Ok(());
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut pending = BTreeSet::new();
    let mut mode = Some(mode);
    loop {
        let Some(payload) = read_frame(&mut input)? else {
            return Ok(());
        };
        let envelope: Value = serde_json::from_slice(&payload).map_err(|_| ())?;
        let method = envelope.get("method").and_then(Value::as_str).ok_or(())?;
        let id = envelope.get("id").and_then(Value::as_u64);
        match method {
            "rpc.initialize" => {
                let id = id.ok_or(())?;
                let response = initialize_response(id);
                match mode.take().ok_or(())? {
                    Mode::Normal => write_frame(&mut output, &response)?,
                    Mode::SilentInitialize => {}
                    Mode::FragmentInitialize(chunks) => {
                        write_frame_fragmented(&mut output, &response, &chunks)?
                    }
                    Mode::NotifyInitialize => {
                        write_frame(
                            &mut output,
                            &json!({
                                "jsonrpc": "2.0",
                                "method": "future.notice",
                                "params": {}
                            }),
                        )?;
                        write_frame(&mut output, &response)?;
                    }
                    Mode::DescendantHoldsPipes => {
                        write_frame(&mut output, &response)?;
                        std::process::Command::new(std::env::current_exe().map_err(|_| ())?)
                            .arg("--hold-pipes")
                            .spawn()
                            .map_err(|_| ())?;
                    }
                    Mode::HoldPipes => return Err(()),
                    Mode::RejectInitialize(rejection) => {
                        write_rejection(&mut output, rejection)?;
                        return Ok(());
                    }
                }
            }
            "resolver.get" => {
                let id = id.ok_or(())?;
                let params = envelope
                    .get("params")
                    .and_then(Value::as_object)
                    .ok_or(())?;
                match params.get("mode").and_then(Value::as_str) {
                    Some("echo") => write_frame(
                        &mut output,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {"echo": params.get("token").cloned().ok_or(())?}
                        }),
                    )?,
                    Some("pending") => {
                        pending.insert(id);
                    }
                    // A typed client sends real `GetParams`, which carry no
                    // `mode`. The declared name selects the outcome so one peer
                    // covers every branch of `GetResult`.
                    None => {
                        let name = params.get("name").and_then(Value::as_str).ok_or(())?;
                        match resolve_response(id, name) {
                            Some(response) => write_frame(&mut output, &response)?,
                            None => {
                                pending.insert(id);
                            }
                        }
                    }
                    _ => return Err(()),
                }
            }
            "resolver.release" => {
                let id = id.ok_or(())?;
                let released = envelope
                    .get("params")
                    .and_then(|params| params.get("path_lease_ids"))
                    .and_then(Value::as_array)
                    .ok_or(())?
                    .len();
                write_frame(
                    &mut output,
                    &json!({"jsonrpc": "2.0", "id": id, "result": {"released": released}}),
                )?;
            }
            "rpc.cancel" => {
                if id.is_some() {
                    return Err(());
                }
                let cancelled = envelope
                    .get("params")
                    .and_then(|params| params.get("id"))
                    .and_then(Value::as_u64)
                    .ok_or(())?;
                if pending.remove(&cancelled) {
                    write_frame(
                        &mut output,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": cancelled,
                            "error": {
                                "code": -32003,
                                "message": "cancelled",
                                "data": {"kind": "cancelled", "retryable": false}
                            }
                        }),
                    )?;
                }
            }
            "rpc.shutdown" => {
                let id = id.ok_or(())?;
                write_frame(
                    &mut output,
                    &json!({"jsonrpc": "2.0", "id": id, "result": {}}),
                )?;
                return Ok(());
            }
            _ => return Err(()),
        }
    }
}

/// `None` leaves the request unanswered so a caller can observe its deadline.
fn resolve_response(id: u64, name: &str) -> Option<Value> {
    let result = match name {
        "RESOLVED_VALUE" => json!({
            "status": "resolved",
            "representation": "value",
            "value": "canary-value",
            "source": "provider",
            "source_provider": "keyring://",
            "expires_at_unix_ms": null,
            "refresh_at_unix_ms": null
        }),
        "MISSING_REQUIRED" => json!({"status": "missing", "required": true}),
        "UNDECLARED" => json!({"status": "undeclared"}),
        "SILENT" => return None,
        _ => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32005,
                    "message": "permission denied",
                    "data": {"kind": "permission_denied", "retryable": false}
                }
            }));
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn initialize_response(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocol": "secretspec.resolver",
            "version": 1,
            "server": {"name": "differential-peer", "version": "1"},
            "methods": ["resolver.get", "resolver.release"],
            "capabilities": {},
            "limits": {"max_frame_bytes": 32768, "max_in_flight": 4},
            "application": {"manifest_kind": "inline", "supports_inline_manifest": true}
        }
    })
}

fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, ()> {
    let mut payload = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let count = reader.read(&mut byte).map_err(|_| ())?;
        if count == 0 {
            return if payload.is_empty() {
                Ok(None)
            } else {
                Err(())
            };
        }
        if byte[0] == b'\n' {
            return if payload.is_empty() {
                Err(())
            } else {
                Ok(Some(payload))
            };
        }
        if byte[0] == b'\r' || payload.len() >= MAX_FRAME_BYTES {
            return Err(());
        }
        payload.push(byte[0]);
    }
}

fn write_frame(writer: &mut impl Write, value: &Value) -> Result<(), ()> {
    let payload = serde_json::to_vec(value).map_err(|_| ())?;
    writer.write_all(&payload).map_err(|_| ())?;
    writer.write_all(b"\n").map_err(|_| ())?;
    writer.flush().map_err(|_| ())
}

fn write_frame_fragmented(
    writer: &mut impl Write,
    value: &Value,
    chunks: &[usize],
) -> Result<(), ()> {
    let payload = serde_json::to_vec(value).map_err(|_| ())?;
    let mut frame = payload;
    frame.push(b'\n');
    let mut offset = 0;
    for chunk in chunks {
        if offset == frame.len() {
            break;
        }
        let end = offset.saturating_add(*chunk).min(frame.len());
        writer.write_all(&frame[offset..end]).map_err(|_| ())?;
        writer.flush().map_err(|_| ())?;
        offset = end;
    }
    if offset < frame.len() {
        writer.write_all(&frame[offset..]).map_err(|_| ())?;
    }
    writer.flush().map_err(|_| ())
}

fn write_rejection(writer: &mut impl Write, rejection: Rejection) -> Result<(), ()> {
    match rejection {
        Rejection::Empty => writer.write_all(b"\n").map_err(|_| ())?,
        Rejection::Batch => write_raw_frame(writer, b"[]")?,
        Rejection::DuplicateKey => {
            write_raw_frame(writer, br#"{"jsonrpc":"2.0","jsonrpc":"2.0"}"#)?
        }
        Rejection::InvalidUtf8 => write_raw_frame(writer, &[0xff])?,
        Rejection::TruncatedHeader => writer.write_all(b"{").map_err(|_| ())?,
        Rejection::TruncatedPayload => {
            writer.write_all(b"{}").map_err(|_| ())?;
        }
        Rejection::UnknownId => {
            write_frame(writer, &json!({"jsonrpc": "2.0", "id": 999, "result": {}}))?
        }
        Rejection::Oversized(length) => writer
            .write_all(&vec![b'x'; length as usize])
            .map_err(|_| ())?,
    }
    writer.flush().map_err(|_| ())
}

fn write_raw_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), ()> {
    writer.write_all(payload).map_err(|_| ())?;
    writer.write_all(b"\n").map_err(|_| ())
}
