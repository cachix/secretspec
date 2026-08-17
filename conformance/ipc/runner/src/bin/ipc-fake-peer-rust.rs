use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};

const MAX_FRAME_BYTES: usize = 1_048_576;

enum Mode {
    Normal,
    FragmentInitialize(Vec<usize>),
    RejectInitialize(Rejection),
}

enum Rejection {
    Empty,
    Batch,
    DuplicateKey,
    Oversized(u32),
}

fn main() {
    if parse_mode().and_then(serve).is_err() {
        std::process::exit(1);
    }
}

fn parse_mode() -> Result<Mode, ()> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        None => Ok(Mode::Normal),
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
                    Mode::FragmentInitialize(chunks) => {
                        write_frame_fragmented(&mut output, &response, &chunks)?
                    }
                    Mode::RejectInitialize(rejection) => {
                        write_rejection(&mut output, rejection)?;
                        return Ok(());
                    }
                }
            }
            "client.resolve" => {
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
                    _ => return Err(()),
                }
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

fn initialize_response(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocol": "secretspec.client",
            "version": 1,
            "server": {"name": "differential-peer", "version": "1"},
            "capabilities": ["client.resolve", "client.release"],
            "limits": {"max_frame_bytes": 32768, "max_in_flight": 4},
            "application": {}
        }
    })
}

fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, ()> {
    let mut prefix = [0_u8; 4];
    let mut read = 0;
    while read < prefix.len() {
        let count = reader.read(&mut prefix[read..]).map_err(|_| ())?;
        if count == 0 {
            return if read == 0 { Ok(None) } else { Err(()) };
        }
        read += count;
    }
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(());
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).map_err(|_| ())?;
    Ok(Some(payload))
}

fn write_frame(writer: &mut impl Write, value: &Value) -> Result<(), ()> {
    let payload = serde_json::to_vec(value).map_err(|_| ())?;
    let length = u32::try_from(payload.len()).map_err(|_| ())?;
    writer.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    writer.write_all(&payload).map_err(|_| ())?;
    writer.flush().map_err(|_| ())
}

fn write_frame_fragmented(
    writer: &mut impl Write,
    value: &Value,
    chunks: &[usize],
) -> Result<(), ()> {
    let payload = serde_json::to_vec(value).map_err(|_| ())?;
    let length = u32::try_from(payload.len()).map_err(|_| ())?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
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
        Rejection::Empty => writer.write_all(&0_u32.to_be_bytes()).map_err(|_| ())?,
        Rejection::Batch => write_raw_frame(writer, b"[]")?,
        Rejection::DuplicateKey => {
            write_raw_frame(writer, br#"{"jsonrpc":"2.0","jsonrpc":"2.0"}"#)?
        }
        Rejection::Oversized(length) => writer.write_all(&length.to_be_bytes()).map_err(|_| ())?,
    }
    writer.flush().map_err(|_| ())
}

fn write_raw_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), ()> {
    let length = u32::try_from(payload.len()).map_err(|_| ())?;
    writer.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    writer.write_all(payload).map_err(|_| ())
}
