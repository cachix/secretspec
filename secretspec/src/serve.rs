use crate::resolve::ResolvedSource;
use crate::secrets::{IpcAuditPurpose, OwnedNamedResolution};
use crate::{SecretSpecError, Secrets};
use async_trait::async_trait;
use rand::RngCore;
use secrecy::SecretString;
use secretspec_ipc::RequestId;
use secretspec_ipc::error::{ErrorKind, RpcError};
use secretspec_ipc::protocol::callback::{self, PromptParams};
use secretspec_ipc::protocol::resolver::{
    CAPABILITIES, DeleteParams, DeleteResult, DeletedStatus, GetParams, GetResult,
    InitializeApplication, InitializedApplication, MUTATION_CAPABILITIES, Manifest, MissingResult,
    MissingStatus, PathRepresentation, ReleaseParams, ReleaseResult, Representation,
    ResolvedPathResult, ResolvedStatus, ResolvedValueResult, SetParams, SetResult, Source,
    StoredStatus, UndeclaredResult, UndeclaredStatus, ValueRepresentation,
};
use secretspec_ipc::resolver::{ResolverHandler, serve_resolver};
use secretspec_ipc::server::{RequestContext, RpcResult, ServerConfig};
use std::cell::RefCell;
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

struct ResolverState {
    secrets: Arc<Secrets>,
    session_dir: PathBuf,
    leases: Mutex<HashMap<String, Lease>>,
    pending_leases: Mutex<HashMap<RequestId, String>>,
    supporting_files: Mutex<Vec<NamedTempFile>>,
    pending_supporting_files: Mutex<HashMap<RequestId, Vec<NamedTempFile>>>,
    _session_dir_owner: TempDir,
}

#[derive(Default)]
struct ResolverHandlerImpl {
    state: Mutex<Option<Arc<ResolverState>>>,
    /// Withholds the mutation capabilities, so the session can resolve secrets
    /// but not change them. Off by default: a consumer that may read a store
    /// can already run `secretspec set` against it, so refusing writes protects
    /// nothing unless an operator deliberately launches the resolver this way.
    read_only: bool,
}

impl ResolverHandlerImpl {
    fn new(read_only: bool) -> Self {
        Self {
            state: Mutex::new(None),
            read_only,
        }
    }

    async fn state(&self) -> RpcResult<Arc<ResolverState>> {
        self.state
            .lock()
            .await
            .clone()
            .ok_or_else(|| RpcError::new(ErrorKind::Internal))
    }

    fn audit_purpose(purpose: secretspec_ipc::protocol::resolver::Purpose) -> IpcAuditPurpose {
        IpcAuditPurpose {
            consumer: purpose.consumer,
            operation: purpose.operation,
            host: purpose.host,
            path: purpose.path,
        }
    }
}

#[async_trait]
impl ResolverHandler for ResolverHandlerImpl {
    async fn initialize(
        &self,
        _context: &RequestContext,
        application: InitializeApplication,
    ) -> RpcResult<InitializedApplication> {
        let manifest_kind = application.manifest.kind().to_string();
        let read_only = self.read_only;
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
            // The terminal reader would open /dev/tty, which in resolver mode
            // belongs to whatever launched this process rather than to it.
            // Every prompt goes back over the session instead, and reaches
            // nothing at all unless the request being served has a channel.
            secrets.set_prompt_reader(prompt_over_ipc);
            secrets.silence_progress();
            if read_only {
                // Withholding the mutation methods is not enough on its own:
                // resolving a generatable or prompted name stores what it
                // produced, so a read would still reach the store.
                secrets.refuse_produced_writes();
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
        let state = Arc::new(ResolverState {
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

    fn capabilities(&self) -> Vec<String> {
        CAPABILITIES
            .iter()
            .chain(if self.read_only {
                [].iter()
            } else {
                MUTATION_CAPABILITIES.iter()
            })
            .map(|method| (*method).to_string())
            .collect()
    }

    async fn get(&self, context: RequestContext, params: GetParams) -> RpcResult<GetResult> {
        let state = self.state().await?;
        let name = params.name;
        let purpose = Self::audit_purpose(params.purpose);
        let secrets = state.secrets.clone();
        // A `prompt = true` declaration with no stored value can only be
        // answered by a person, and this process has no terminal: its stdin and
        // stdout are the protocol. Asking is therefore possible exactly when the
        // client said it could answer. When it did not, resolution runs in the
        // non-prompting mode so the declaration fails immediately instead of
        // blocking on a question nobody would see.
        let interactive = context.peer.supports(callback::method::PROMPT);
        let (prompt_tx, mut prompt_rx) = tokio::sync::mpsc::channel::<PromptRequest>(1);
        let resolve = tokio::task::spawn_blocking(move || {
            with_prompt_channel(prompt_tx, || {
                secrets.resolve_named_owned_for_ipc(&name, purpose, interactive)
            })
        });
        tokio::pin!(resolve);
        // The resolve holds this request's only in-flight slot, so its prompts
        // are pumped here rather than by a session-wide task: a prompt then
        // inherits exactly the deadline and cancellation of the read that
        // raised it, and cannot be answered on behalf of some other request.
        let resolved = loop {
            tokio::select! {
                finished = &mut resolve => break finished,
                Some(request) = prompt_rx.recv() => {
                    let answer = ask(&context, &request).await;
                    let _ = request.answer.send(answer);
                }
            }
        }
        .map_err(|_| RpcError::new(ErrorKind::Internal))?
        .map_err(map_resolver_error)?;
        if context.cancellation.is_cancelled() {
            return Err(RpcError::new(ErrorKind::Cancelled));
        }

        match resolved {
            OwnedNamedResolution::Undeclared => Ok(GetResult::Undeclared(UndeclaredResult {
                status: UndeclaredStatus::Undeclared,
            })),
            OwnedNamedResolution::Missing { required } => Ok(GetResult::Missing(MissingResult {
                status: MissingStatus::Missing,
                required,
            })),
            OwnedNamedResolution::Value {
                value,
                source,
                source_provider,
                expires_at_unix_ms,
                refresh_at_unix_ms,
                supporting_files,
            } => {
                if params.representation == Representation::Path {
                    return Err(RpcError::new(ErrorKind::RepresentationMismatch));
                }
                retain_pending_supporting_files(&state, context.request_id, supporting_files)
                    .await?;
                Ok(GetResult::Value(ResolvedValueResult {
                    status: ResolvedStatus::Resolved,
                    representation: ValueRepresentation::Value,
                    value,
                    source: map_source(source),
                    source_provider,
                    expires_at_unix_ms,
                    refresh_at_unix_ms,
                }))
            }
            OwnedNamedResolution::File {
                file,
                source,
                source_provider,
                expires_at_unix_ms,
                refresh_at_unix_ms,
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
                Ok(GetResult::Path(ResolvedPathResult {
                    status: ResolvedStatus::Resolved,
                    representation: PathRepresentation::Path,
                    path: path.to_string_lossy().into_owned(),
                    path_lease_id: lease_id,
                    source: map_source(source),
                    source_provider,
                    expires_at_unix_ms,
                    refresh_at_unix_ms,
                }))
            }
        }
    }

    async fn set(&self, _context: RequestContext, params: SetParams) -> RpcResult<SetResult> {
        let state = self.state().await?;
        let name = params.name;
        let value = params.value;
        let purpose = Self::audit_purpose(params.purpose);
        let secrets = state.secrets.clone();
        // No cancellation check after the write, unlike `get`: the value is
        // already in the store by then, and reporting `cancelled` would tell
        // the consumer that nothing happened. A caller whose request was
        // cancelled or timed out learns the outcome by resolving the name.
        let stored =
            tokio::task::spawn_blocking(move || secrets.store_named_for_ipc(&name, value, purpose))
                .await
                .map_err(|_| RpcError::new(ErrorKind::Internal))?
                .map_err(map_resolver_error)?;
        Ok(SetResult {
            status: StoredStatus::Stored,
            target_provider: Some(stored.provider_uri),
        })
    }

    async fn delete(
        &self,
        _context: RequestContext,
        params: DeleteParams,
    ) -> RpcResult<DeleteResult> {
        let state = self.state().await?;
        let name = params.name;
        let purpose = Self::audit_purpose(params.purpose);
        let secrets = state.secrets.clone();
        let removed =
            tokio::task::spawn_blocking(move || secrets.delete_named_for_ipc(&name, purpose))
                .await
                .map_err(|_| RpcError::new(ErrorKind::Internal))?
                .map_err(map_resolver_error)?;
        Ok(DeleteResult {
            status: DeletedStatus::Deleted,
            deleted: removed.deleted,
            target_provider: Some(removed.provider_uri),
        })
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
        for lease_id in params.path_lease_ids {
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
    state: &ResolverState,
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

/// One `prompt = true` declaration waiting for a person, carried from the
/// blocking resolve to the async handler that owns the session's transport.
struct PromptRequest {
    name: String,
    profile: String,
    target_provider: Option<String>,
    answer: tokio::sync::oneshot::Sender<Option<String>>,
}

thread_local! {
    /// Set for the duration of one blocking resolve. Scoping it to the worker
    /// thread rather than to the shared `Secrets` is what keeps a prompt tied to
    /// the request that raised it: `Secrets` is shared by every request on the
    /// session and could not name which one is asking.
    static PROMPT_CHANNEL: RefCell<Option<tokio::sync::mpsc::Sender<PromptRequest>>> =
        const { RefCell::new(None) };
}

struct PromptChannelGuard(Option<tokio::sync::mpsc::Sender<PromptRequest>>);

impl Drop for PromptChannelGuard {
    fn drop(&mut self) {
        PROMPT_CHANNEL.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

fn with_prompt_channel<T>(
    sender: tokio::sync::mpsc::Sender<PromptRequest>,
    operation: impl FnOnce() -> T,
) -> T {
    let previous = PROMPT_CHANNEL.with(|slot| slot.replace(Some(sender)));
    let _guard = PromptChannelGuard(previous);
    operation()
}

/// The `prompt = true` reader installed on every resolver-mode `Secrets`.
///
/// Blocking here is correct and bounded: this runs on a blocking worker, and
/// the handler that answers is bound by the originating request's deadline and
/// cancellation, so a caller that goes away takes the wait with it.
fn prompt_over_ipc(
    name: &str,
    profile: &str,
    target_provider: Option<&str>,
) -> Result<SecretString, SecretSpecError> {
    let sender = PROMPT_CHANNEL.with(|slot| slot.borrow().clone());
    let Some(sender) = sender else {
        return Err(SecretSpecError::PromptUnavailable(name.to_string()));
    };
    let (answer_tx, answer_rx) = tokio::sync::oneshot::channel();
    let request = PromptRequest {
        name: name.to_string(),
        profile: profile.to_string(),
        target_provider: target_provider.map(str::to_string),
        answer: answer_tx,
    };
    if sender.blocking_send(request).is_err() {
        return Err(SecretSpecError::PromptUnavailable(name.to_string()));
    }
    match answer_rx.blocking_recv() {
        Ok(Some(value)) => Ok(SecretString::new(value.into())),
        Ok(None) | Err(_) => Err(SecretSpecError::PromptUnavailable(name.to_string())),
    }
}

/// Put one prompt to the client and return its answer, or `None` for every way
/// it can fail. The distinction between declined, cancelled, and expired is not
/// carried back: the read fails as unavailable either way, and the session's
/// own cancellation or deadline produces the terminal response the caller sees.
async fn ask(context: &RequestContext, request: &PromptRequest) -> Option<String> {
    let params = PromptParams {
        name: request.name.clone(),
        profile: request.profile.clone(),
        target_provider: request.target_provider.clone(),
    };
    secretspec_ipc::resolver::prompt(context, &params)
        .await
        .ok()
        .map(|result| result.value)
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
        // Not a provider refusal and not a missing value: this session was
        // configured without the authority to store what the read would have
        // produced, which is the caller's answer.
        SecretSpecError::ProducedValueWriteRefused(_) => ErrorKind::PermissionDenied,
        _ => ErrorKind::OperationFailed,
    };
    RpcError::new(kind)
}

pub(crate) async fn run_stdio(read_only: bool) -> secretspec_ipc::Result<()> {
    serve_resolver(
        tokio::io::stdin(),
        tokio::io::stdout(),
        ResolverHandlerImpl::new(read_only),
        ServerConfig {
            product: secretspec_ipc::Product {
                name: "secretspec-resolver".to_string(),
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
    use secretspec_ipc::protocol::resolver::{Purpose, method};
    use secretspec_ipc::protocol::{InitializeParams, Limits, Product, RESOLVER_PROTOCOL};
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
        let server = tokio::spawn(serve_resolver(
            server_read,
            server_write,
            ResolverHandlerImpl::default(),
            ServerConfig::default(),
        ));
        let initialize = InitializeParams {
            protocol: RESOLVER_PROTOCOL.to_string(),
            versions: vec![1],
            client: Product {
                name: "resolver-test".to_string(),
                version: "1".to_string(),
            },
            limits: Limits {
                max_frame_bytes: 32 * 1024,
                max_in_flight: 4,
            },
            client_methods: Vec::new(),
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
                method::GET,
                &GetParams {
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
            GetResult::Value(ResolvedValueResult { ref value, .. }) if value == "inline-value"
        ));

        let file = client
            .call(
                method::GET,
                &GetParams {
                    name: "CERT".to_string(),
                    representation: Representation::Path,
                    purpose,
                },
                deadline(),
            )
            .await
            .unwrap();
        let GetResult::Path(file) = file else {
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
                    path_lease_ids: vec![file.path_lease_id.clone(), file.path_lease_id],
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

        let handler = ResolverHandlerImpl::default();
        let initialize_context = RequestContext {
            request_id: RequestId::new(1).unwrap(),
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
            cancellation: Default::default(),
            peer: secretspec_ipc::server::Peer::detached(),
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
            .get(
                RequestContext {
                    request_id,
                    deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                    cancellation: Default::default(),
                    peer: secretspec_ipc::server::Peer::detached(),
                },
                GetParams {
                    name: "CERT".into(),
                    representation: Representation::Path,
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
        let GetResult::Path(file) = result else {
            panic!("expected file result")
        };
        assert!(std::path::Path::new(&file.path).exists());
        handler.request_finished(request_id, false).await;
        assert!(!std::path::Path::new(&file.path).exists());
        handler.shutdown().await;
    }

    /// Manifest for the mutation tests: one writable name, plus a scope that
    /// excludes it so the same session can be pointed at a name it may not
    /// touch.
    const MUTABLE_MANIFEST: &str = r#"
[project]
name = "ipc-test"
revision = "1.0"
require_reason = false

[profiles.default]
TOKEN = { description = "token", required = false }
OTHER = { description = "another secret", required = false }

[scopes.reader]
secrets = ["OTHER"]
"#;

    async fn initialized_handler(
        manifest: &std::path::Path,
        dotenv: &std::path::Path,
        scope: Option<&str>,
        read_only: bool,
    ) -> ResolverHandlerImpl {
        let handler = ResolverHandlerImpl::new(read_only);
        handler
            .initialize(
                &RequestContext {
                    request_id: RequestId::new(1).unwrap(),
                    deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                    cancellation: Default::default(),
                    peer: secretspec_ipc::server::Peer::detached(),
                },
                InitializeApplication {
                    manifest: Manifest::Path {
                        path: manifest.to_string_lossy().into_owned(),
                    },
                    provider: Some(format!("dotenv:{}", dotenv.display())),
                    profile: Some("default".into()),
                    scope: scope.map(str::to_string),
                    reason: None,
                },
            )
            .await
            .unwrap();
        handler
    }

    fn request(id: u64) -> RequestContext {
        RequestContext {
            request_id: RequestId::new(id).unwrap(),
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
            cancellation: Default::default(),
            peer: secretspec_ipc::server::Peer::detached(),
        }
    }

    fn test_purpose() -> Purpose {
        Purpose {
            consumer: "test".into(),
            operation: "store".into(),
            host: None,
            path: None,
        }
    }

    #[tokio::test]
    async fn a_stored_value_is_where_the_same_session_resolves_it() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("secretspec.toml");
        let dotenv = directory.path().join("values.env");
        std::fs::write(&dotenv, "").unwrap();
        std::fs::write(&manifest, MUTABLE_MANIFEST).unwrap();
        let handler = initialized_handler(&manifest, &dotenv, None, false).await;

        let stored = handler
            .set(
                request(2),
                SetParams {
                    name: "TOKEN".into(),
                    value: "stored-value".into(),
                    purpose: test_purpose(),
                },
            )
            .await
            .unwrap();
        assert_eq!(stored.status, StoredStatus::Stored);
        assert!(stored.target_provider.unwrap().starts_with("dotenv:"));

        let resolved = handler
            .get(
                request(3),
                GetParams {
                    name: "TOKEN".into(),
                    representation: Representation::Value,
                    purpose: test_purpose(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            GetResult::Value(ResolvedValueResult { ref value, .. }) if value == "stored-value"
        ));

        let removed = handler
            .delete(
                request(4),
                DeleteParams {
                    name: "TOKEN".into(),
                    purpose: test_purpose(),
                },
            )
            .await
            .unwrap();
        assert!(removed.deleted);
        let resolved = handler
            .get(
                request(5),
                GetParams {
                    name: "TOKEN".into(),
                    representation: Representation::Value,
                    purpose: test_purpose(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(resolved, GetResult::Missing(_)));

        // Removing what is no longer stored reports `false` rather than failing.
        let removed = handler
            .delete(
                request(6),
                DeleteParams {
                    name: "TOKEN".into(),
                    purpose: test_purpose(),
                },
            )
            .await
            .unwrap();
        assert!(!removed.deleted);
        handler.shutdown().await;
    }

    #[tokio::test]
    async fn a_scope_bounds_what_the_session_may_write() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("secretspec.toml");
        let dotenv = directory.path().join("values.env");
        std::fs::write(&dotenv, "").unwrap();
        std::fs::write(&manifest, MUTABLE_MANIFEST).unwrap();
        let handler = initialized_handler(&manifest, &dotenv, Some("reader"), false).await;

        let refused = handler
            .set(
                request(2),
                SetParams {
                    name: "TOKEN".into(),
                    value: "stored-value".into(),
                    purpose: test_purpose(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(refused.data.kind, ErrorKind::OperationFailed);
        // The write was refused before the store was touched.
        assert_eq!(std::fs::read_to_string(&dotenv).unwrap(), "");
        handler.shutdown().await;
    }

    /// Withholding the mutation methods is not by itself read-only. Resolving
    /// a generatable name mints the value and stores it, so a read reached the
    /// provider through a session that advertised no way to write.
    #[tokio::test]
    async fn a_read_only_endpoint_refuses_a_read_that_would_store() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("secretspec.toml");
        let dotenv = directory.path().join("values.env");
        std::fs::write(&dotenv, "").unwrap();
        std::fs::write(
            &manifest,
            r#"
[project]
name = "ipc-test"
revision = "1.0"
require_reason = false

[profiles.default]
MINTED = { description = "minted", type = "password", generate = true }
"#,
        )
        .unwrap();

        let params = || GetParams {
            name: "MINTED".into(),
            representation: Representation::Auto,
            purpose: test_purpose(),
        };

        let handler = initialized_handler(&manifest, &dotenv, None, true).await;
        let error = handler.get(request(2), params()).await.unwrap_err();
        assert_eq!(error.data.kind, ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read_to_string(&dotenv).unwrap(),
            "",
            "a read-only session wrote the value it produced"
        );
        handler.shutdown().await;

        // The same read on a writable session is unchanged: it mints, stores,
        // and resolves.
        let handler = initialized_handler(&manifest, &dotenv, None, false).await;
        let resolved = handler.get(request(3), params()).await.unwrap();
        assert!(matches!(resolved, GetResult::Value(_)));
        assert!(std::fs::read_to_string(&dotenv).unwrap().contains("MINTED"));
        handler.shutdown().await;
    }

    #[tokio::test]
    async fn a_read_only_endpoint_advertises_no_mutation() {
        let handler = ResolverHandlerImpl::new(true);
        assert_eq!(
            handler.capabilities(),
            vec![method::GET.to_string(), method::RELEASE.to_string()]
        );
        assert!(
            ResolverHandlerImpl::new(false)
                .capabilities()
                .contains(&method::SET.to_string())
        );
    }
}
