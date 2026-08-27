use async_trait::async_trait;
use secretspec_ipc::error::{ErrorKind, RpcError};
use secretspec_ipc::protocol::provider::{
    self as wire, Address, ClearParams, ClearScope, GetManyParams, GetManyResult,
    InitializeApplication, Metadata, NamedGetResult, Persistence, ReflectParams, ReflectResult,
    ResolveAddressResult,
};
use secretspec_ipc::provider::{ProvidedSecret, ProviderHandler, SecretValue, serve_provider};
use secretspec_ipc::server::{RequestContext, RpcResult, ServerConfig};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_FRAME_BYTES: usize = 1024 * 1024;

enum Mode {
    Serve { crash_on_get_once: Option<PathBuf> },
    FragmentInitialize(Vec<usize>),
    RejectInitialize(Rejection),
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

struct StoredValue {
    value: String,
    storage_expires_at: Option<Instant>,
    secret_expires_at_unix_ms: Option<u64>,
}

#[derive(Default)]
struct MemoryProvider {
    values: Mutex<HashMap<String, StoredValue>>,
    errors_seen: Mutex<HashSet<String>>,
    crash_on_get_once: Option<PathBuf>,
}

impl MemoryProvider {
    fn key(address: &Address) -> String {
        match address {
            Address::Convention {
                project,
                profile,
                key,
            } => format!("convention/{project}/{profile}/{key}"),
            Address::Native { coordinates } => format!(
                "native/{}/{}/{}/{}/{}",
                coordinates.item,
                coordinates.field.as_deref().unwrap_or(""),
                coordinates.vault.as_deref().unwrap_or(""),
                coordinates.section.as_deref().unwrap_or(""),
                coordinates.version.as_deref().unwrap_or("")
            ),
        }
    }

    fn read(values: &mut HashMap<String, StoredValue>, key: &str) -> Option<(String, Option<u64>)> {
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|now| u64::try_from(now.as_millis()).ok());
        let expired = values.get(key).is_some_and(|entry| {
            entry
                .storage_expires_at
                .is_some_and(|expires_at| expires_at <= Instant::now())
                || entry
                    .secret_expires_at_unix_ms
                    .is_some_and(|expires_at| now_unix_ms.is_some_and(|now| now >= expires_at))
        });
        if expired {
            values.remove(key);
            return None;
        }
        values
            .get(key)
            .map(|entry| (entry.value.clone(), entry.secret_expires_at_unix_ms))
    }

    fn maybe_crash(&self) {
        let Some(marker) = &self.crash_on_get_once else {
            return;
        };
        if !marker.exists() && std::fs::write(marker, b"crashed").is_ok() {
            std::process::exit(42);
        }
    }

    fn one_shot_error(&self, key: &str) -> Option<RpcError> {
        let kind = if key.ends_with("/__INTERACTION_REQUIRED__") {
            ErrorKind::InteractionRequired
        } else if key.ends_with("/__PERMISSION_DENIED__") {
            ErrorKind::PermissionDenied
        } else if key.ends_with("/__UNAVAILABLE__") {
            ErrorKind::Unavailable
        } else if key.ends_with("/__CONFLICT__") {
            ErrorKind::Conflict
        } else {
            return None;
        };
        if self.errors_seen.lock().unwrap().insert(key.to_string()) {
            Some(RpcError::new(kind))
        } else {
            None
        }
    }
}

#[async_trait]
impl ProviderHandler for MemoryProvider {
    fn capabilities(&self) -> Vec<String> {
        wire::CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_string())
            .collect()
    }

    async fn initialize(
        &self,
        _context: &RequestContext,
        application: InitializeApplication,
    ) -> RpcResult<Metadata> {
        Ok(Metadata {
            name: application.scheme.clone(),
            display_uri: format!("{}://conformance", application.scheme),
            supported_coordinates: vec![
                wire::CoordinateName::Field,
                wire::CoordinateName::Vault,
                wire::CoordinateName::Section,
                wire::CoordinateName::Version,
            ],
            generated_value_persistence: Persistence::Persist,
            prompted_value_persistence: Persistence::Ephemeral,
            storage_identity: format!("{}://conformance", application.scheme),
            entry_container_identity: format!("{}://conformance", application.scheme),
            physical_store_path: None,
        })
    }

    async fn resolve_address(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<ResolveAddressResult> {
        let coordinates = match address {
            Address::Convention {
                project,
                profile,
                key,
            } => wire::Coordinates {
                item: format!("{project}/{profile}/{key}"),
                field: None,
                vault: None,
                section: None,
                version: None,
            },
            Address::Native { coordinates } => coordinates,
        };
        Ok(ResolveAddressResult { coordinates })
    }

    async fn get(
        &self,
        context: RequestContext,
        address: Address,
    ) -> RpcResult<Option<ProvidedSecret>> {
        let key = Self::key(&address);
        if key.ends_with("/__BLOCK__") {
            context.cancellation.cancelled().await;
            return Err(RpcError::new(ErrorKind::Cancelled));
        }
        if let Some(error) = self.one_shot_error(&key) {
            return Err(error);
        }
        self.maybe_crash();
        Ok(Self::read(&mut self.values.lock().unwrap(), &key)
            .map(|(value, expires_at)| ProvidedSecret::new(value, expires_at)))
    }

    async fn get_many(
        &self,
        _context: RequestContext,
        params: GetManyParams,
    ) -> RpcResult<GetManyResult> {
        self.maybe_crash();
        let mut values = self.values.lock().unwrap();
        Ok(GetManyResult {
            results: params
                .requests
                .into_iter()
                .map(|request| NamedGetResult {
                    name: request.name,
                    outcome: match Self::read(&mut values, &Self::key(&request.address)) {
                        Some((value, expires_at_unix_ms)) => wire::GetResult::Found {
                            value,
                            expires_at_unix_ms,
                        },
                        None => wire::GetResult::Missing,
                    },
                })
                .collect(),
        })
    }

    async fn exists(&self, _context: RequestContext, address: Address) -> RpcResult<bool> {
        self.maybe_crash();
        Ok(Self::read(&mut self.values.lock().unwrap(), &Self::key(&address)).is_some())
    }

    async fn set(
        &self,
        _context: RequestContext,
        address: Address,
        value: SecretValue,
    ) -> RpcResult<()> {
        if let Some(error) = self.one_shot_error(&Self::key(&address)) {
            return Err(error);
        }
        let key = Self::key(&address);
        let secret_expires_at_unix_ms = key
            .ends_with("/SECRET_EXPIRY")
            .then(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|now| u64::try_from(now.as_millis()).ok())
                    .and_then(|now| now.checked_add(60_000))
            })
            .flatten();
        self.values.lock().unwrap().insert(
            key,
            StoredValue {
                value: value.expose().to_string(),
                storage_expires_at: None,
                secret_expires_at_unix_ms,
            },
        );
        Ok(())
    }

    async fn set_expiring(
        &self,
        _context: RequestContext,
        address: Address,
        value: SecretValue,
        ttl_ms: u64,
    ) -> RpcResult<()> {
        self.values.lock().unwrap().insert(
            Self::key(&address),
            StoredValue {
                value: value.expose().to_string(),
                storage_expires_at: Some(Instant::now() + Duration::from_millis(ttl_ms)),
                secret_expires_at_unix_ms: None,
            },
        );
        Ok(())
    }

    async fn delete(&self, _context: RequestContext, address: Address) -> RpcResult<bool> {
        Ok(self
            .values
            .lock()
            .unwrap()
            .remove(&Self::key(&address))
            .is_some())
    }

    async fn clear(&self, _context: RequestContext, params: ClearParams) -> RpcResult<usize> {
        let mut values = self.values.lock().unwrap();
        values.retain(|_, value| {
            value
                .storage_expires_at
                .is_none_or(|expiry| expiry > Instant::now())
        });
        let before = values.len();
        match params.scope {
            ClearScope::All => values.clear(),
            ClearScope::Convention { project, profile } => {
                let prefix = format!("convention/{project}/{profile}/");
                values.retain(|key, _| !key.starts_with(&prefix));
            }
        }
        Ok(before - values.len())
    }

    async fn check_writable(&self, _context: RequestContext, _address: Address) -> RpcResult<()> {
        Ok(())
    }

    async fn check_deletable(&self, _context: RequestContext, _address: Address) -> RpcResult<()> {
        Ok(())
    }

    async fn describe_write_target(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<String> {
        Ok(format!("memory {}", Self::key(&address)))
    }

    async fn reflect(
        &self,
        _context: RequestContext,
        _params: ReflectParams,
    ) -> RpcResult<ReflectResult> {
        Ok(ReflectResult {
            schema_version: 1,
            declarations: BTreeMap::from([(
                "TOKEN".into(),
                wire::ReflectedDeclaration {
                    description: "Conformance token".into(),
                    required: true,
                    reference: wire::Coordinates {
                        item: "token".into(),
                        field: None,
                        vault: None,
                        section: None,
                        version: None,
                    },
                },
            )]),
        })
    }
}

fn arguments() -> Result<Mode, ()> {
    let mut arguments = std::env::args_os().skip(1);
    match arguments.next() {
        None => Ok(Mode::Serve {
            crash_on_get_once: None,
        }),
        Some(argument) if argument == "--crash-on-get-once" => {
            let marker = arguments.next().map(PathBuf::from).ok_or(())?;
            if arguments.next().is_some() {
                return Err(());
            }
            Ok(Mode::Serve {
                crash_on_get_once: Some(marker),
            })
        }
        Some(argument) if argument == "--fragment-init" => {
            let chunks = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or(())?
                .split(',')
                .map(|value| value.parse::<usize>().map_err(|_| ()))
                .collect::<Result<Vec<_>, _>>()?;
            if chunks.is_empty() || chunks.contains(&0) || arguments.next().is_some() {
                return Err(());
            }
            Ok(Mode::FragmentInitialize(chunks))
        }
        Some(argument) if argument == "--reject-init" => {
            let rejection = match arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .as_deref()
            {
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

#[tokio::main]
async fn main() {
    let Ok(mode) = arguments() else {
        std::process::exit(2);
    };
    let Mode::Serve { crash_on_get_once } = mode else {
        if manual_peer(mode).is_err() {
            std::process::exit(1);
        }
        return;
    };
    let handler = MemoryProvider {
        values: Mutex::new(HashMap::new()),
        errors_seen: Mutex::new(HashSet::new()),
        crash_on_get_once,
    };
    if serve_provider(
        tokio::io::stdin(),
        tokio::io::stdout(),
        handler,
        ServerConfig::default(),
    )
    .await
    .is_err()
    {
        std::process::exit(1);
    }
}

fn manual_peer(mode: Mode) -> Result<(), ()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let request = read_json_frame(&mut input)?;
    if request.get("method").and_then(Value::as_str) != Some("rpc.initialize") {
        return Err(());
    }
    let id = request.get("id").and_then(Value::as_u64).ok_or(())?;
    match mode {
        Mode::FragmentInitialize(chunks) => {
            write_fragmented(&mut output, &initialize_response(id), &chunks)?;
            let shutdown = read_json_frame(&mut input)?;
            if shutdown.get("method").and_then(Value::as_str) != Some("rpc.shutdown") {
                return Err(());
            }
            let shutdown_id = shutdown.get("id").and_then(Value::as_u64).ok_or(())?;
            write_json_frame(
                &mut output,
                &json!({"jsonrpc": "2.0", "id": shutdown_id, "result": {}}),
            )
        }
        Mode::RejectInitialize(rejection) => write_rejection(&mut output, rejection),
        Mode::Serve { .. } => Err(()),
    }
}

fn initialize_response(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocol": "secretspec.provider",
            "version": 1,
            "server": {"name": "provider-conformance-peer", "version": "1"},
            "methods": wire::CAPABILITIES,
            "capabilities": {},
            "limits": {"max_frame_bytes": 32768, "max_in_flight": 8},
            "application": {
                "provider": {
                    "name": "memory",
                    "display_uri": "memory://conformance",
                    "supported_coordinates": ["field", "vault", "section", "version"],
                    "generated_value_persistence": "persist",
                    "prompted_value_persistence": "ephemeral",
                    "storage_identity": "memory://conformance",
                    "entry_container_identity": "memory://conformance",
                    "physical_store_path": null
                }
            }
        }
    })
}

fn read_json_frame(reader: &mut impl Read) -> Result<Value, ()> {
    let mut payload = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        reader.read_exact(&mut byte).map_err(|_| ())?;
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' || payload.len() >= MAX_FRAME_BYTES {
            return Err(());
        }
        payload.push(byte[0]);
    }
    if payload.is_empty() {
        return Err(());
    }
    serde_json::from_slice(&payload).map_err(|_| ())
}

fn write_json_frame(writer: &mut impl Write, value: &Value) -> Result<(), ()> {
    let payload = serde_json::to_vec(value).map_err(|_| ())?;
    write_raw_frame(writer, &payload)
}

fn write_fragmented(writer: &mut impl Write, value: &Value, chunks: &[usize]) -> Result<(), ()> {
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
    writer.write_all(&frame[offset..]).map_err(|_| ())?;
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
            write_json_frame(writer, &json!({"jsonrpc": "2.0", "id": 999, "result": {}}))?
        }
        Rejection::Oversized(length) => writer
            .write_all(&vec![b'x'; length as usize])
            .map_err(|_| ())?,
    }
    writer.flush().map_err(|_| ())
}

fn write_raw_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), ()> {
    writer.write_all(payload).map_err(|_| ())?;
    writer.write_all(b"\n").map_err(|_| ())?;
    writer.flush().map_err(|_| ())
}
