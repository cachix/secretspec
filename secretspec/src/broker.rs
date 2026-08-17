use crate::resolve::ResolvedSource;
use crate::secrets::{IpcAuditPurpose, OwnedNamedResolution};
use crate::{SecretSpecError, Secrets};
use async_trait::async_trait;
use rand::RngCore;
use secretspec_ipc::RequestId;
use secretspec_ipc::error::{ErrorKind, RpcError};
use secretspec_ipc::protocol::client::{
    FileRepresentation, InitializeApplication, InitializedApplication, Manifest, MissingResult,
    MissingStatus, ReleaseParams, ReleaseResult, Representation, ResolveParams, ResolveResult,
    ResolvedFileResult, ResolvedStatus, ResolvedValueResult, Source, UndeclaredResult,
    UndeclaredStatus, ValueRepresentation,
};
use secretspec_ipc::resolution::{ResolutionHandler, serve_resolution};
use secretspec_ipc::server::{RequestContext, RpcResult, ServerConfig};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use tokio::sync::Mutex;

const MAX_SESSION_LEASES: usize = 1024;
const MAX_SESSION_SUPPORTING_FILES: usize = 4096;
#[cfg(unix)]
const STALE_SESSION_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

struct Lease {
    path: PathBuf,
    identity: same_file::Handle,
}

struct BrokerState {
    secrets: Arc<Secrets>,
    session_dir: PathBuf,
    leases: Mutex<HashMap<String, Lease>>,
    pending_leases: Mutex<HashMap<RequestId, String>>,
    supporting_files: Mutex<Vec<NamedTempFile>>,
    pending_supporting_files: Mutex<HashMap<RequestId, Vec<NamedTempFile>>>,
    _session_dir_owner: TempDir,
}

#[derive(Default)]
struct BrokerHandler {
    state: Mutex<Option<Arc<BrokerState>>>,
}

impl BrokerHandler {
    async fn state(&self) -> RpcResult<Arc<BrokerState>> {
        self.state
            .lock()
            .await
            .clone()
            .ok_or_else(|| RpcError::new(ErrorKind::Internal))
    }
}

#[async_trait]
impl ResolutionHandler for BrokerHandler {
    async fn initialize(
        &self,
        _context: &RequestContext,
        application: InitializeApplication,
    ) -> RpcResult<InitializedApplication> {
        let manifest_kind = application.manifest.kind().to_string();
        let loaded = tokio::task::spawn_blocking(move || {
            let mut secrets = match application.manifest {
                Manifest::Path { path } => Secrets::load_from_ipc(PathBuf::from(path).as_path()),
                Manifest::Inline { toml, base_dir } => {
                    Secrets::load_inline_ipc(&toml, PathBuf::from(base_dir).as_path())
                }
            }?;
            if let Some(provider) = application.provider {
                secrets.set_provider(provider);
            }
            if let Some(profile) = application.profile {
                secrets.set_profile(profile);
            }
            if let Some(scope) = application.scope {
                secrets.set_scope(scope);
            }
            if let Some(reason) = application.reason {
                secrets = secrets.with_reason(reason);
            }
            secrets.validate_ipc_selection()?;
            cleanup_stale_session_dirs_once();
            let session_dir = tempfile::Builder::new()
                .prefix("secretspec-ipc-")
                .tempdir()
                .map_err(SecretSpecError::Io)?;
            harden_session_dir(&session_dir).map_err(SecretSpecError::Io)?;
            mark_session_dir(&session_dir).map_err(SecretSpecError::Io)?;
            Ok::<_, SecretSpecError>((secrets, session_dir))
        })
        .await
        .map_err(|_| RpcError::new(ErrorKind::Internal))?
        .map_err(map_resolver_error)?;

        let (secrets, session_dir) = loaded;
        let state = Arc::new(BrokerState {
            secrets: Arc::new(secrets),
            session_dir: session_dir.path().to_path_buf(),
            leases: Mutex::new(HashMap::new()),
            pending_leases: Mutex::new(HashMap::new()),
            supporting_files: Mutex::new(Vec::new()),
            pending_supporting_files: Mutex::new(HashMap::new()),
            _session_dir_owner: session_dir,
        });
        let mut slot = self.state.lock().await;
        if slot.is_some() {
            return Err(RpcError::new(ErrorKind::Conflict));
        }
        *slot = Some(state);
        Ok(InitializedApplication {
            manifest_kind,
            supports_inline_manifest: true,
        })
    }

    async fn resolve(
        &self,
        context: RequestContext,
        params: ResolveParams,
    ) -> RpcResult<ResolveResult> {
        let state = self.state().await?;
        let name = params.name;
        let purpose = IpcAuditPurpose {
            consumer: params.purpose.consumer,
            operation: params.purpose.operation,
            host: params.purpose.host,
            path: params.purpose.path,
        };
        let secrets = state.secrets.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            secrets.resolve_named_owned_for_ipc(&name, purpose)
        })
        .await
        .map_err(|_| RpcError::new(ErrorKind::Internal))?
        .map_err(map_resolver_error)?;
        if context.cancellation.is_cancelled() {
            return Err(RpcError::new(ErrorKind::Cancelled));
        }

        match resolved {
            OwnedNamedResolution::Undeclared => Ok(ResolveResult::Undeclared(UndeclaredResult {
                status: UndeclaredStatus::Undeclared,
            })),
            OwnedNamedResolution::Missing { required } => {
                Ok(ResolveResult::Missing(MissingResult {
                    status: MissingStatus::Missing,
                    required,
                }))
            }
            OwnedNamedResolution::Value {
                value,
                source,
                source_provider,
                expires_at_unix_ms,
                supporting_files,
            } => {
                if params.representation == Representation::File {
                    return Err(RpcError::new(ErrorKind::RepresentationMismatch));
                }
                retain_pending_supporting_files(&state, context.request_id, supporting_files)
                    .await?;
                Ok(ResolveResult::Value(ResolvedValueResult {
                    status: ResolvedStatus::Resolved,
                    representation: ValueRepresentation::Value,
                    value,
                    source: map_source(source),
                    source_provider,
                    expires_at_unix_ms,
                }))
            }
            OwnedNamedResolution::File {
                file,
                source,
                source_provider,
                expires_at_unix_ms,
                supporting_files,
            } => {
                if params.representation == Representation::Value {
                    return Err(RpcError::new(ErrorKind::RepresentationMismatch));
                }
                let (path, persisted) = persist_lease_file(file, &state.session_dir)?;
                let identity = match same_file::Handle::from_file(persisted) {
                    Ok(identity) => identity,
                    Err(_) => {
                        let _ = std::fs::remove_file(&path);
                        return Err(RpcError::new(ErrorKind::OperationFailed));
                    }
                };
                if context.cancellation.is_cancelled() {
                    drop(identity);
                    let _ = std::fs::remove_file(&path);
                    return Err(RpcError::new(ErrorKind::Cancelled));
                }
                if let Err(error) =
                    retain_pending_supporting_files(&state, context.request_id, supporting_files)
                        .await
                {
                    drop(identity);
                    let _ = std::fs::remove_file(&path);
                    return Err(error);
                }
                let mut leases = state.leases.lock().await;
                if leases.len() >= MAX_SESSION_LEASES {
                    drop(leases);
                    drop(identity);
                    let _ = std::fs::remove_file(&path);
                    state
                        .pending_supporting_files
                        .lock()
                        .await
                        .remove(&context.request_id);
                    return Err(RpcError::unavailable(None));
                }
                let lease_id = loop {
                    let candidate = random_token();
                    if !leases.contains_key(&candidate) {
                        break candidate;
                    }
                };
                leases.insert(
                    lease_id.clone(),
                    Lease {
                        path: path.clone(),
                        identity,
                    },
                );
                drop(leases);
                state
                    .pending_leases
                    .lock()
                    .await
                    .insert(context.request_id, lease_id.clone());
                Ok(ResolveResult::File(ResolvedFileResult {
                    status: ResolvedStatus::Resolved,
                    representation: FileRepresentation::File,
                    path: path.to_string_lossy().into_owned(),
                    lease_id,
                    source: map_source(source),
                    source_provider,
                    expires_at_unix_ms,
                }))
            }
        }
    }

    async fn release(
        &self,
        _context: RequestContext,
        params: ReleaseParams,
    ) -> RpcResult<ReleaseResult> {
        let state = self.state().await?;
        let mut leases = state.leases.lock().await;
        let mut unique = HashSet::new();
        let mut released = 0;
        for lease_id in params.lease_ids {
            if !unique.insert(lease_id.clone()) {
                continue;
            }
            if let Some(lease) = leases.remove(&lease_id) {
                remove_lease(lease);
                released += 1;
            }
        }
        Ok(ReleaseResult { released })
    }

    async fn request_finished(&self, request_id: RequestId, committed: bool) {
        let Ok(state) = self.state().await else {
            return;
        };
        let lease_id = state.pending_leases.lock().await.remove(&request_id);
        let supporting_files = state
            .pending_supporting_files
            .lock()
            .await
            .remove(&request_id)
            .unwrap_or_default();
        if committed {
            state.supporting_files.lock().await.extend(supporting_files);
            return;
        }
        if let Some(lease_id) = lease_id
            && let Some(lease) = state.leases.lock().await.remove(&lease_id)
        {
            remove_lease(lease);
        }
    }

    async fn shutdown(&self) {
        let state = self.state.lock().await.take();
        if let Some(state) = state {
            let leases = std::mem::take(&mut *state.leases.lock().await);
            state.pending_leases.lock().await.clear();
            state.pending_supporting_files.lock().await.clear();
            for lease in leases.into_values() {
                remove_lease(lease);
            }
            state.supporting_files.lock().await.clear();
        }
    }
}

/// Runs the stale-session sweep at most once per process.
///
/// The sweep only ever removes directories older than a week, so repeating it
/// per session buys nothing while charging a full temp-directory scan to every
/// session's startup deadline.
fn cleanup_stale_session_dirs_once() {
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(cleanup_stale_session_dirs);
}

fn random_token() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    data_encoding::BASE64URL_NOPAD.encode(&bytes)
}

fn persist_lease_file(
    mut file: NamedTempFile,
    session_dir: &std::path::Path,
) -> RpcResult<(PathBuf, File)> {
    harden_lease_file(file.path()).map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
    for _ in 0..8 {
        let path = session_dir.join(random_token());
        match file.persist_noclobber(&path) {
            Ok(persisted) => {
                if harden_lease_file(&path).is_err() {
                    drop(persisted);
                    let _ = std::fs::remove_file(&path);
                    return Err(RpcError::new(ErrorKind::OperationFailed));
                }
                return Ok((path, persisted));
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                file = error.file;
            }
            Err(_) => return Err(RpcError::new(ErrorKind::OperationFailed)),
        }
    }
    Err(RpcError::unavailable(None))
}

#[cfg(windows)]
fn harden_session_dir(directory: &TempDir) -> std::io::Result<()> {
    crate::windows_security::make_path_private(directory.path())
}

#[cfg(not(windows))]
fn harden_session_dir(_: &TempDir) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn harden_lease_file(path: &std::path::Path) -> std::io::Result<()> {
    crate::windows_security::make_path_private(path)
}

#[cfg(not(windows))]
fn harden_lease_file(_: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

async fn retain_pending_supporting_files(
    state: &BrokerState,
    request_id: RequestId,
    files: Vec<NamedTempFile>,
) -> RpcResult<()> {
    if files.len() > MAX_SESSION_SUPPORTING_FILES {
        return Err(RpcError::unavailable(None));
    }
    let mut pending = state.pending_supporting_files.lock().await;
    let retained = state.supporting_files.lock().await;
    let pending_count = pending.values().map(Vec::len).sum::<usize>();
    if retained
        .len()
        .saturating_add(pending_count)
        .saturating_add(files.len())
        > MAX_SESSION_SUPPORTING_FILES
    {
        return Err(RpcError::unavailable(None));
    }
    drop(retained);
    pending.insert(request_id, files);
    Ok(())
}

fn remove_lease(lease: Lease) {
    let current = same_file::Handle::from_path(&lease.path);
    let same = current
        .as_ref()
        .is_ok_and(|current| current == &lease.identity);
    drop(current);
    drop(lease.identity);
    if same {
        let _ = std::fs::remove_file(lease.path);
    }
}

#[cfg(unix)]
fn mark_session_dir(directory: &TempDir) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let marker = directory.path().join(".owner");
    std::fs::write(&marker, std::process::id().to_string())?;
    std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o400))
}

#[cfg(not(unix))]
fn mark_session_dir(_: &TempDir) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn cleanup_stale_session_dirs() {
    use std::os::unix::fs::MetadataExt;

    unsafe extern "C" {
        fn geteuid() -> u32;
        fn kill(pid: i32, signal: i32) -> i32;
    }
    // SAFETY: `geteuid` has no arguments and no memory-safety preconditions.
    let uid = unsafe { geteuid() };
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("secretspec-ipc-") {
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
            || metadata
                .modified()
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_none_or(|age| age < STALE_SESSION_AGE)
        {
            continue;
        }
        let marker = path.join(".owner");
        let marker_safe = std::fs::symlink_metadata(&marker).is_ok_and(|metadata| {
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.len() <= 32
        });
        let owner_pid = marker_safe
            .then(|| std::fs::read_to_string(marker).ok())
            .flatten()
            .and_then(|pid| pid.parse::<i32>().ok())
            .filter(|pid| *pid > 0);
        if owner_pid.is_some_and(|pid| {
            // SAFETY: signal zero performs existence/permission probing only.
            unsafe { kill(pid, 0) == 0 }
        }) {
            continue;
        }
        let Ok(children) = std::fs::read_dir(&path) else {
            continue;
        };
        let children = children
            .take(MAX_SESSION_LEASES + 2)
            .collect::<Result<Vec<_>, _>>();
        let Ok(children) = children else { continue };
        if children.len() > MAX_SESSION_LEASES + 1
            || children.iter().any(|child| {
                std::fs::symlink_metadata(child.path()).map_or(true, |metadata| {
                    !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.uid() != uid
                })
            })
        {
            continue;
        }
        for child in children {
            let _ = std::fs::remove_file(child.path());
        }
        let _ = std::fs::remove_dir(path);
    }
}

#[cfg(not(unix))]
fn cleanup_stale_session_dirs() {
    // Refuse cleanup on platforms where this build cannot prove ownership and
    // ACL isolation. Normal session shutdown still removes its own TempDir.
}

fn map_source(source: ResolvedSource) -> Source {
    match source {
        ResolvedSource::Provider => Source::Provider,
        ResolvedSource::Generated => Source::Generated,
        ResolvedSource::Default => Source::Default,
        ResolvedSource::Composed => Source::Composed,
    }
}

fn map_resolver_error(error: SecretSpecError) -> RpcError {
    let kind = match error {
        SecretSpecError::ProviderProtocol(kind) => kind,
        SecretSpecError::PromptUnavailable(_) | SecretSpecError::ReasonRequired => {
            ErrorKind::InteractionRequired
        }
        _ => ErrorKind::OperationFailed,
    };
    RpcError::new(kind)
}

pub(crate) async fn run_stdio() -> secretspec_ipc::Result<()> {
    serve_resolution(
        tokio::io::stdin(),
        tokio::io::stdout(),
        BrokerHandler::default(),
        ServerConfig {
            product: secretspec_ipc::Product {
                name: "secretspec-broker".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            ..ServerConfig::default()
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretspec_ipc::client::Client;
    use secretspec_ipc::protocol::client::{Purpose, method};
    use secretspec_ipc::protocol::{CLIENT_PROTOCOL, InitializeParams, Limits, Product};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn deadline() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 2_000
    }

    #[test]
    fn provider_protocol_error_kind_reaches_the_client_boundary() {
        for kind in [
            ErrorKind::InteractionRequired,
            ErrorKind::PermissionDenied,
            ErrorKind::Conflict,
            ErrorKind::Unavailable,
        ] {
            let mapped = map_resolver_error(SecretSpecError::ProviderProtocol(kind));
            assert_eq!(mapped.data.kind, kind);
            assert_eq!(mapped.message, kind.message());
        }
    }

    #[tokio::test]
    async fn exact_resolution_and_file_leases_are_session_owned() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("secretspec.toml");
        let dotenv = directory.path().join("values.env");
        std::fs::write(&dotenv, "TOKEN=inline-value\nCERT=file-value\n").unwrap();
        std::fs::write(
            &manifest,
            r#"
[project]
name = "ipc-test"
revision = "1.0"
require_reason = false

[profiles.default]
TOKEN = { description = "token" }
CERT = { description = "certificate", as_path = true }
UNRELATED = { description = "must not fail named resolution", required = true }
"#,
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_io);
        let (server_read, server_write) = tokio::io::split(server_io);
        let server = tokio::spawn(serve_resolution(
            server_read,
            server_write,
            BrokerHandler::default(),
            ServerConfig::default(),
        ));
        let initialize = InitializeParams {
            protocol: CLIENT_PROTOCOL.to_string(),
            versions: vec![1],
            client: Product {
                name: "broker-test".to_string(),
                version: "1".to_string(),
            },
            limits: Limits {
                max_frame_bytes: 32 * 1024,
                max_in_flight: 4,
            },
            application: InitializeApplication {
                manifest: Manifest::Path {
                    path: manifest.to_string_lossy().into_owned(),
                },
                provider: Some(format!("dotenv:{}", dotenv.display())),
                profile: Some("default".to_string()),
                scope: None,
                reason: None,
            },
        };
        let (raw, _initialized) = Client::connect::<_, _, _, InitializedApplication>(
            client_read,
            client_write,
            initialize,
            deadline(),
        )
        .await
        .unwrap();
        let client = raw;
        let purpose = Purpose {
            consumer: "test".to_string(),
            operation: "resolve".to_string(),
            host: None,
            path: None,
        };
        let value = client
            .call(
                method::RESOLVE,
                &ResolveParams {
                    name: "TOKEN".to_string(),
                    representation: Representation::Value,
                    purpose: purpose.clone(),
                },
                deadline(),
            )
            .await
            .unwrap();
        assert!(matches!(
            value,
            ResolveResult::Value(ResolvedValueResult { ref value, .. }) if value == "inline-value"
        ));

        let file = client
            .call(
                method::RESOLVE,
                &ResolveParams {
                    name: "CERT".to_string(),
                    representation: Representation::File,
                    purpose,
                },
                deadline(),
            )
            .await
            .unwrap();
        let ResolveResult::File(file) = file else {
            panic!("expected file result")
        };
        assert_eq!(std::fs::read_to_string(&file.path).unwrap(), "file-value");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&file.path).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        let released: ReleaseResult = client
            .call(
                method::RELEASE,
                &ReleaseParams {
                    lease_ids: vec![file.lease_id.clone(), file.lease_id],
                },
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(released.released, 1);
        assert!(!std::path::Path::new(&file.path).exists());
        client.close(deadline()).await.unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn uncommitted_file_response_drops_its_lease() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("secretspec.toml");
        let dotenv = directory.path().join("values.env");
        std::fs::write(&dotenv, "CERT=file-value\n").unwrap();
        std::fs::write(
            &manifest,
            r#"
[project]
name = "ipc-test"
revision = "1.0"
require_reason = false

[profiles.default]
CERT = { description = "certificate", as_path = true }
"#,
        )
        .unwrap();

        let handler = BrokerHandler::default();
        let initialize_context = RequestContext {
            request_id: RequestId::new(1).unwrap(),
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
            cancellation: Default::default(),
        };
        handler
            .initialize(
                &initialize_context,
                InitializeApplication {
                    manifest: Manifest::Path {
                        path: manifest.to_string_lossy().into_owned(),
                    },
                    provider: Some(format!("dotenv:{}", dotenv.display())),
                    profile: Some("default".into()),
                    scope: None,
                    reason: None,
                },
            )
            .await
            .unwrap();
        let request_id = RequestId::new(2).unwrap();
        let result = handler
            .resolve(
                RequestContext {
                    request_id,
                    deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                    cancellation: Default::default(),
                },
                ResolveParams {
                    name: "CERT".into(),
                    representation: Representation::File,
                    purpose: Purpose {
                        consumer: "test".into(),
                        operation: "resolve".into(),
                        host: None,
                        path: None,
                    },
                },
            )
            .await
            .unwrap();
        let ResolveResult::File(file) = result else {
            panic!("expected file result")
        };
        assert!(std::path::Path::new(&file.path).exists());
        handler.request_finished(request_id, false).await;
        assert!(!std::path::Path::new(&file.path).exists());
        handler.shutdown().await;
    }
}
