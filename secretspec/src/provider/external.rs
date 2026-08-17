//! External provider discovery and the `secretspec.provider/1` adapter.
//!
//! Available since SecretSpec 0.20.

use super::{
    Address, DiscoveryContext, ProducedValuePersistence, Provider, ProviderCredentials,
    ProviderUrl, get_each,
};
use crate::config::{NativeAddress, Secret};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use secretspec_ipc::deadline_unix_ms_after;
use secretspec_ipc::lifecycle::{Environment, LaunchOptions, ProviderSession};
use secretspec_ipc::protocol::provider::{
    self as wire, AddressParams, GetManyParams, GetResult, InitializeApplication, NamedRequest,
    Persistence, ReflectParams, SetExpiringParams, SetParams,
};
use secretspec_ipc::protocol::{Limits, Product};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::Duration;

const REGISTRATION_MAX_BYTES: u64 = 64 * 1024;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// A closed provider registration and its fixed executable identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEndpoint {
    pub schema_version: u32,
    pub scheme: String,
    pub executable: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub credential_names: Vec<String>,
}

/// Explicit inputs to external-provider discovery.
#[derive(Debug, Clone, Default)]
pub struct ProviderDiscovery {
    pub explicit: BTreeMap<String, ProviderEndpoint>,
    pub user_directory: Option<PathBuf>,
    pub system_directory: Option<PathBuf>,
    pub allow_path: bool,
}

/// Scope used by the injectable endpoint security policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationScope {
    Explicit,
    User,
    System,
    Path,
}

/// Platform security seam used by discovery tests and embedders with a
/// stronger host-specific ACL policy.
pub trait EndpointSecurity: Send + Sync {
    fn check_registration(&self, path: &Path, scope: RegistrationScope) -> Result<()>;
    fn check_executable(&self, path: &Path, scope: RegistrationScope) -> Result<()>;
    fn privileged(&self) -> bool;
}

#[derive(Debug, Default)]
pub struct PlatformEndpointSecurity;

impl EndpointSecurity for PlatformEndpointSecurity {
    fn check_registration(&self, path: &Path, scope: RegistrationScope) -> Result<()> {
        check_file_security(path, scope, false)?;
        check_parent_security(path, scope)
    }

    fn check_executable(&self, path: &Path, scope: RegistrationScope) -> Result<()> {
        check_file_security(path, scope, true)?;
        check_parent_security(path, scope)
    }

    fn privileged(&self) -> bool {
        is_privileged_process()
    }
}

impl ProviderDiscovery {
    /// Platform registration directories with PATH discovery disabled.
    pub fn platform_default() -> Self {
        let (user_directory, system_directory) = platform_directories();
        Self {
            explicit: BTreeMap::new(),
            user_directory,
            system_directory,
            allow_path: false,
        }
    }

    pub fn resolve(&self, scheme: &str) -> Result<Option<ProviderEndpoint>> {
        self.resolve_with_security(scheme, &PlatformEndpointSecurity)
    }

    pub fn resolve_with_security(
        &self,
        scheme: &str,
        security: &dyn EndpointSecurity,
    ) -> Result<Option<ProviderEndpoint>> {
        let search_path = std::env::var_os("PATH");
        self.resolve_with_security_and_search_path(scheme, security, search_path.as_deref())
    }

    fn resolve_with_security_and_search_path(
        &self,
        scheme: &str,
        security: &dyn EndpointSecurity,
        search_path: Option<&std::ffi::OsStr>,
    ) -> Result<Option<ProviderEndpoint>> {
        validate_scheme(scheme)?;
        if let Some(endpoint) = self.explicit.get(scheme) {
            return validate_endpoint(
                endpoint.clone(),
                scheme,
                RegistrationScope::Explicit,
                security,
            )
            .map(Some);
        }
        for (directory, scope) in [
            (self.user_directory.as_deref(), RegistrationScope::User),
            (self.system_directory.as_deref(), RegistrationScope::System),
        ] {
            let Some(directory) = directory else { continue };
            let path = directory.join(format!("{scheme}.json"));
            if path.try_exists().map_err(discovery_io)? {
                return load_registration(&path, scheme, scope, security).map(Some);
            }
        }
        if !self.allow_path || security.privileged() {
            return Ok(None);
        }
        let executable_name = if cfg!(windows) {
            format!("secretspec-provider-{scheme}.exe")
        } else {
            format!("secretspec-provider-{scheme}")
        };
        let Some(path) = search_path
            .into_iter()
            .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
            .map(|directory| directory.join(&executable_name))
            .find(|candidate| candidate.is_file())
        else {
            return Ok(None);
        };
        validate_endpoint(
            ProviderEndpoint {
                schema_version: 1,
                scheme: scheme.to_string(),
                executable: path,
                arguments: Vec::new(),
                credential_names: Vec::new(),
            },
            scheme,
            RegistrationScope::Path,
            security,
        )
        .map(Some)
    }
}

static ACTIVE_DISCOVERY: LazyLock<RwLock<ProviderDiscovery>> =
    LazyLock::new(|| RwLock::new(ProviderDiscovery::platform_default()));

/// Replaces the process-wide discovery inputs used by ordinary provider URI
/// construction. Embedders can use this to supply trusted direct endpoints or
/// to opt into PATH discovery. Available since SecretSpec 0.20.
pub fn set_provider_discovery(discovery: ProviderDiscovery) {
    *ACTIVE_DISCOVERY
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = discovery;
}

pub(crate) fn discover(scheme: &str) -> Result<Option<ProviderEndpoint>> {
    // This helper is also used to distinguish provider specs from project
    // aliases. Alias spelling is intentionally broader than URI schemes, so
    // an alias that cannot be an external scheme is simply not discovered.
    if !is_valid_scheme(scheme) {
        return Ok(None);
    }
    ACTIVE_DISCOVERY
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .resolve(scheme)
}

fn load_registration(
    path: &Path,
    scheme: &str,
    scope: RegistrationScope,
    security: &dyn EndpointSecurity,
) -> Result<ProviderEndpoint> {
    let metadata = std::fs::symlink_metadata(path).map_err(discovery_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(discovery_error(
            "provider registration is not a regular non-symlink file",
        ));
    }
    if metadata.len() > REGISTRATION_MAX_BYTES {
        return Err(discovery_error("provider registration exceeds 64 KiB"));
    }
    let mut file = File::open(path).map_err(discovery_io)?;
    let opened_metadata = file.metadata().map_err(discovery_io)?;
    if !same_file_metadata(&metadata, &opened_metadata) {
        return Err(discovery_error(
            "provider registration changed while it was opened",
        ));
    }
    security.check_registration(path, scope)?;
    let current_metadata = std::fs::symlink_metadata(path).map_err(discovery_io)?;
    if current_metadata.file_type().is_symlink()
        || !same_file_metadata(&metadata, &current_metadata)
    {
        return Err(discovery_error(
            "provider registration changed during validation",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(REGISTRATION_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(discovery_io)?;
    if bytes.len() as u64 > REGISTRATION_MAX_BYTES {
        return Err(discovery_error("provider registration exceeds 64 KiB"));
    }
    let endpoint: ProviderEndpoint = serde_json::from_slice(&bytes)
        .map_err(|_| discovery_error("invalid provider registration"))?;
    let file_stem = path.file_stem().and_then(|value| value.to_str());
    if file_stem != Some(scheme) {
        return Err(discovery_error(
            "provider registration filename does not match its scheme",
        ));
    }
    validate_endpoint(endpoint, scheme, scope, security)
}

fn validate_endpoint(
    mut endpoint: ProviderEndpoint,
    expected_scheme: &str,
    scope: RegistrationScope,
    security: &dyn EndpointSecurity,
) -> Result<ProviderEndpoint> {
    if endpoint.schema_version != 1 || endpoint.scheme != expected_scheme {
        return Err(discovery_error(
            "provider registration schema or scheme does not match",
        ));
    }
    validate_scheme(&endpoint.scheme)?;
    let mut credentials = BTreeSet::new();
    for name in &endpoint.credential_names {
        validate_credential_name(name)?;
        if !credentials.insert(name) {
            return Err(discovery_error(
                "provider credential names must be distinct",
            ));
        }
    }
    if !endpoint.executable.is_absolute() {
        return Err(discovery_error("provider executable must be absolute"));
    }
    let executable = std::fs::canonicalize(&endpoint.executable).map_err(discovery_io)?;
    if !executable.is_file() {
        return Err(discovery_error("provider executable is not a regular file"));
    }
    security.check_executable(&executable, scope)?;
    endpoint.executable = executable;
    Ok(endpoint)
}

fn validate_scheme(value: &str) -> Result<()> {
    if is_valid_scheme(value) {
        Ok(())
    } else {
        Err(discovery_error("invalid external provider scheme"))
    }
}

fn is_valid_scheme(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn validate_credential_name(value: &str) -> Result<()> {
    let mut chars = value.chars();
    if value.len() > 256
        || !matches!(chars.next(), Some('a'..='z'))
        || chars.any(|character| !matches!(character, 'a'..='z' | '0'..='9' | '_'))
    {
        return Err(discovery_error("invalid provider credential name"));
    }
    Ok(())
}

#[cfg(unix)]
fn check_file_security(path: &Path, scope: RegistrationScope, executable: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).map_err(discovery_io)?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 {
        return Err(discovery_error(if executable {
            "provider executable is group- or world-writable"
        } else {
            "provider registration is group- or world-writable"
        }));
    }
    let uid = effective_uid();
    let owner_ok = match scope {
        RegistrationScope::System => metadata.uid() == 0,
        RegistrationScope::Explicit | RegistrationScope::User | RegistrationScope::Path => {
            metadata.uid() == uid || metadata.uid() == 0
        }
    };
    if !owner_ok {
        return Err(discovery_error(
            "provider endpoint ownership is outside the trust domain",
        ));
    }
    if executable && metadata.mode() & 0o111 == 0 {
        return Err(discovery_error("provider executable is not executable"));
    }
    Ok(())
}

#[cfg(unix)]
fn check_parent_security(path: &Path, scope: RegistrationScope) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = path
        .parent()
        .ok_or_else(|| discovery_error("provider endpoint has no parent directory"))?;
    let metadata = std::fs::metadata(parent).map_err(discovery_io)?;
    if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(discovery_error(
            "provider endpoint directory is group- or world-writable",
        ));
    }
    let uid = effective_uid();
    let owner_ok = match scope {
        RegistrationScope::System => metadata.uid() == 0,
        RegistrationScope::Explicit | RegistrationScope::User | RegistrationScope::Path => {
            metadata.uid() == uid || metadata.uid() == 0
        }
    };
    if owner_ok {
        Ok(())
    } else {
        Err(discovery_error(
            "provider endpoint directory ownership is outside the trust domain",
        ))
    }
}

#[cfg(windows)]
fn check_file_security(path: &Path, _scope: RegistrationScope, _executable: bool) -> Result<()> {
    if !path.is_file() {
        return Err(discovery_error("provider endpoint is not a regular file"));
    }
    let system_scope = _scope == RegistrationScope::System;
    match crate::windows_security::path_acl_is_trusted(path, system_scope) {
        Ok(true) => Ok(()),
        Ok(false) => Err(discovery_error(
            "provider endpoint ACL is outside the trust domain",
        )),
        Err(_) => Err(discovery_error(
            "provider endpoint ACL could not be validated",
        )),
    }
}

#[cfg(windows)]
fn check_parent_security(path: &Path, _scope: RegistrationScope) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| discovery_error("provider endpoint has no parent directory"))?;
    if !parent.is_dir() {
        return Err(discovery_error(
            "provider endpoint parent is not a directory",
        ));
    }
    let system_scope = _scope == RegistrationScope::System;
    match crate::windows_security::path_acl_is_trusted(parent, system_scope) {
        Ok(true) => Ok(()),
        Ok(false) => Err(discovery_error(
            "provider endpoint directory ACL is outside the trust domain",
        )),
        Err(_) => Err(discovery_error(
            "provider endpoint directory ACL could not be validated",
        )),
    }
}

#[cfg(unix)]
fn same_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len()
        && left.file_type() == right.file_type()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn is_privileged_process() -> bool {
    effective_uid() == 0 || effective_uid() != real_uid() || effective_gid() != real_gid()
}

#[cfg(windows)]
fn is_privileged_process() -> bool {
    // The default policy cannot safely distinguish every Windows service and
    // elevated-token shape without broadening the platform dependency surface.
    // Fail closed for PATH; an embedder may opt in through an injected policy.
    true
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: `geteuid` has no arguments and no memory-safety preconditions.
    unsafe { geteuid() }
}

#[cfg(unix)]
fn real_uid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: `getuid` has no arguments and no memory-safety preconditions.
    unsafe { getuid() }
}

#[cfg(unix)]
fn effective_gid() -> u32 {
    unsafe extern "C" {
        fn getegid() -> u32;
    }
    // SAFETY: `getegid` has no arguments and no memory-safety preconditions.
    unsafe { getegid() }
}

#[cfg(unix)]
fn real_gid() -> u32 {
    unsafe extern "C" {
        fn getgid() -> u32;
    }
    // SAFETY: `getgid` has no arguments and no memory-safety preconditions.
    unsafe { getgid() }
}

fn platform_directories() -> (Option<PathBuf>, Option<PathBuf>) {
    #[cfg(target_os = "linux")]
    {
        let user = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|base| base.join("secretspec/providers.d"));
        (user, Some(PathBuf::from("/etc/secretspec/providers.d")))
    }
    #[cfg(target_os = "macos")]
    {
        let user = std::env::var_os("HOME").map(|home| {
            PathBuf::from(home).join("Library/Application Support/SecretSpec/providers.d")
        });
        (
            user,
            Some(PathBuf::from(
                "/Library/Application Support/SecretSpec/providers.d",
            )),
        )
    }
    #[cfg(windows)]
    {
        let user = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|base| base.join("SecretSpec/providers.d"));
        let system = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .map(|base| base.join("SecretSpec/providers.d"));
        (user, system)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        (None, None)
    }
}

fn discovery_io(_: std::io::Error) -> SecretSpecError {
    discovery_error("provider discovery I/O failed")
}

fn discovery_error(message: &str) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.to_string())
}

struct ExternalState {
    base_dir: Option<PathBuf>,
    credentials: ProviderCredentials,
    reason: Option<String>,
    /// Latched rejection from the last `with_base_dir`, cleared when a later
    /// call supplies an acceptable value.
    base_dir_error: Option<String>,
    /// Latched rejection from the last `with_credentials`, cleared likewise.
    credentials_error: Option<String>,
    session: Option<Arc<ProviderSession>>,
}

impl ExternalState {
    /// The configuration rejection that must block session startup, if any.
    fn configuration_error(&self) -> Option<&str> {
        self.base_dir_error
            .as_deref()
            .or(self.credentials_error.as_deref())
    }
}

/// A core provider backed by one `secretspec.provider/1` endpoint.
///
/// Endpoint startup is lazy so `with_base_dir`, `with_credentials`, and the
/// initial `set_reason` are applied to immutable initialization state first.
pub struct ExternalProvider {
    endpoint: ProviderEndpoint,
    scheme: String,
    configured_uri: String,
    state: Mutex<ExternalState>,
    metadata: OnceLock<wire::Metadata>,
}

impl ExternalProvider {
    /// Constructs a provider from an explicit endpoint and configured URI.
    /// The executable is canonicalized and checked before it is retained.
    pub fn new(endpoint: ProviderEndpoint, uri: &str) -> Result<Self> {
        let endpoint = validate_endpoint(
            endpoint.clone(),
            &endpoint.scheme,
            RegistrationScope::Explicit,
            &PlatformEndpointSecurity,
        )?;
        let url =
            url::Url::parse(uri).map_err(|_| discovery_error("invalid external provider URI"))?;
        let url = ProviderUrl::new(url);
        if url.scheme() != endpoint.scheme {
            return Err(discovery_error(
                "external provider URI scheme does not match endpoint",
            ));
        }
        super::reject_uri_credential(&url)?;
        Ok(Self::from_url(endpoint, &url))
    }

    pub(crate) fn from_url(endpoint: ProviderEndpoint, url: &ProviderUrl) -> Self {
        Self {
            scheme: endpoint.scheme.clone(),
            endpoint,
            configured_uri: url.to_string(),
            state: Mutex::new(ExternalState {
                base_dir: None,
                credentials: ProviderCredentials::new(),
                reason: None,
                base_dir_error: None,
                credentials_error: None,
                session: None,
            }),
            metadata: OnceLock::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, ExternalState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ensure_session(&self) -> Result<Arc<ProviderSession>> {
        let mut state = self.state();
        if let Some(message) = state.configuration_error() {
            return Err(discovery_error(message));
        }
        if let Some(session) = &state.session {
            if !session.is_closed() {
                return Ok(session.clone());
            }
            if let Some(stale) = state.session.take() {
                close_live_session(stale);
            }
        }
        let credentials = state
            .credentials
            .iter()
            .map(|(name, value)| (name.clone(), value.expose_secret().to_string()))
            .collect();
        let application = InitializeApplication {
            scheme: self.scheme.clone(),
            uri: self.configured_uri.clone(),
            base_dir: state
                .base_dir
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            credentials,
            reason: state.reason.clone(),
        };
        let launch = LaunchOptions {
            executable: self.endpoint.executable.clone(),
            arguments: self.endpoint.arguments.iter().map(OsString::from).collect(),
            environment: Environment::Inherit(BTreeMap::new()),
            allow_path_discovery: false,
            max_stderr_bytes: 64 * 1024,
        };
        let session = super::block_on(ProviderSession::launch(
            launch,
            Product {
                name: "secretspec".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            Limits {
                max_frame_bytes: secretspec_ipc::ABSOLUTE_MAX_FRAME_BYTES,
                max_in_flight: 16,
            },
            application,
            deadline_unix_ms_after(STARTUP_TIMEOUT),
        ))
        .map_err(ipc_error)?;
        if let Some(existing) = self.metadata.get() {
            if existing != session.metadata() {
                let _ =
                    super::block_on(session.close(deadline_unix_ms_after(Duration::from_secs(1))));
                return Err(discovery_error("provider metadata changed after reconnect"));
            }
        } else {
            let _ = self.metadata.set(session.metadata().clone());
        }
        let session = Arc::new(session);
        state.session = Some(session.clone());
        Ok(session)
    }

    /// Endpoint-reported metadata, starting the session if it has not run yet.
    ///
    /// Only for accessors that are allowed to contact the store. The identity
    /// accessors deliberately do not use this: `Secrets` reconstructs canonical
    /// URIs and storage identities from a freshly built, *uncredentialed*
    /// provider while planning, and that path is documented as touching no
    /// store. Launching an endpoint there would both break that contract and
    /// derive an identity from a session that never received its credentials.
    fn endpoint_metadata(&self) -> Option<&wire::Metadata> {
        let _ = self.ensure_session();
        self.metadata.get()
    }

    fn require(&self, method: &str) -> Result<Arc<ProviderSession>> {
        let session = self.ensure_session()?;
        if session.supports(method) {
            Ok(session)
        } else {
            Err(discovery_error(&format!(
                "external provider '{}' does not support {method}",
                self.scheme
            )))
        }
    }

    fn call<M>(&self, params: &M::Params) -> Result<M::Result>
    where
        M: wire::method::Method,
    {
        let session = self.require(M::NAME)?;
        let result = super::block_on(
            session.execute::<M>(params, deadline_unix_ms_after(OPERATION_TIMEOUT)),
        );
        if result.is_err() && session.is_closed() {
            let stale = {
                let mut state = self.state();
                if state
                    .session
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, &session))
                {
                    state.session.take()
                } else {
                    None
                }
            };
            if let Some(stale) = stale {
                close_live_session(stale);
            }
        }
        result.map_err(ipc_error)
    }

    fn resolve_remote(&self, address: Address<'_>) -> Result<NativeAddress> {
        let result = self.call::<wire::method::ResolveAddress>(&AddressParams {
            address: to_wire_address(address),
        })?;
        from_wire_coordinates(result.coordinates)
    }

    /// Optional protocol presence check, without exposing a value.
    pub fn exists(&self, address: Address<'_>) -> Result<bool> {
        // Probe the capability set once. Re-acquiring the session per branch
        // would let the capability check and the call it guards observe two
        // different endpoints if the session were replaced in between.
        let session = self.ensure_session()?;
        if session.supports(wire::method::EXISTS) {
            let result = self.call::<wire::method::Exists>(&AddressParams {
                address: to_wire_address(address),
            })?;
            Ok(result.exists)
        } else if session.supports(wire::method::GET) {
            Ok(self.get(address)?.is_some())
        } else {
            Err(discovery_error(
                "external provider cannot perform a presence check",
            ))
        }
    }

    /// Optional bounded protocol cache clear. This is deliberately not
    /// emulated through reflection.
    pub fn clear(&self, scope: wire::ClearScope) -> Result<usize> {
        let result = self.call::<wire::method::Clear>(&wire::ClearParams { scope })?;
        Ok(result.cleared)
    }
}

impl Provider for ExternalProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        self.resolve_remote(Address::Convention {
            project,
            profile,
            key,
        })
    }

    fn supports_coord(&self, name: &str) -> bool {
        self.ensure_session()
            .ok()
            .and_then(|_| self.metadata.get())
            .is_some_and(|metadata| {
                metadata
                    .supported_coordinates
                    .iter()
                    .any(|coordinate| coordinate.as_str() == name)
            })
    }

    fn supports_delete(&self) -> bool {
        self.ensure_session()
            .is_ok_and(|session| session.supports(wire::method::DELETE))
    }

    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<std::borrow::Cow<'a, NativeAddress>> {
        self.resolve_remote(addr).map(std::borrow::Cow::Owned)
    }

    fn entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, NativeAddress>> {
        self.resolve_remote(addr).map(std::borrow::Cow::Owned)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let result = self.call::<wire::method::Get>(&AddressParams {
            address: to_wire_address(addr),
        })?;
        Ok(match result {
            GetResult::Found { value } => Some(SecretString::from(value)),
            GetResult::Missing => None,
        })
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        if !self.ensure_session()?.supports(wire::method::GET_MANY) {
            return get_each(self, requests);
        }
        let params = GetManyParams {
            requests: requests
                .iter()
                .map(|(name, address)| NamedRequest {
                    name: (*name).to_string(),
                    address: to_wire_address(*address),
                })
                .collect(),
        };
        let result = self.call::<wire::method::GetMany>(&params)?;
        if result.results.len() != requests.len()
            || result
                .results
                .iter()
                .zip(requests)
                .any(|(actual, (expected, _))| actual.name != *expected)
        {
            return Err(discovery_error(
                "provider batch response did not preserve request names",
            ));
        }
        Ok(result
            .results
            .into_iter()
            .filter_map(|item| match item.outcome {
                GetResult::Found { value } => Some((item.name, SecretString::from(value))),
                GetResult::Missing => None,
            })
            .collect())
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let result = self.call::<wire::method::Set>(&SetParams {
            address: to_wire_address(addr),
            value: value.expose_secret().to_string(),
        })?;
        if result.stored {
            Ok(())
        } else {
            Err(discovery_error("provider did not confirm the write"))
        }
    }

    fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretString,
        max_age: Duration,
    ) -> Result<()> {
        if !self.ensure_session()?.supports(wire::method::SET_EXPIRING) {
            return self.set(addr, value);
        }
        self.check_writable(addr)?;
        let ttl_ms = max_age.as_millis().try_into().unwrap_or(u64::MAX);
        if ttl_ms == 0 {
            return Err(discovery_error("external provider expiry must be positive"));
        }
        let result = self.call::<wire::method::SetExpiring>(&SetExpiringParams {
            address: to_wire_address(addr),
            value: value.expose_secret().to_string(),
            ttl_ms,
        })?;
        if result.stored {
            Ok(())
        } else {
            Err(discovery_error(
                "provider did not confirm the expiring write",
            ))
        }
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        self.check_deletable(addr)?;
        let result = self.call::<wire::method::Delete>(&AddressParams {
            address: to_wire_address(addr),
        })?;
        Ok(result.deleted)
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let session = self.require(wire::method::SET)?;
        if !session.supports(wire::method::CHECK_WRITABLE) {
            return Ok(());
        }
        self.call::<wire::method::CheckWritable>(&AddressParams {
            address: to_wire_address(addr),
        })
        .map(|_| ())
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        let session = self.require(wire::method::DELETE)?;
        if !session.supports(wire::method::CHECK_DELETABLE) {
            return Ok(());
        }
        self.call::<wire::method::CheckDeletable>(&AddressParams {
            address: to_wire_address(addr),
        })
        .map(|_| ())
    }

    fn generated_value_persistence(&self) -> ProducedValuePersistence {
        self.ensure_session()
            .ok()
            .and_then(|_| self.metadata.get())
            .map_or(ProducedValuePersistence::Persist, |metadata| {
                map_persistence(metadata.generated_value_persistence)
            })
    }

    fn prompted_value_persistence(&self) -> ProducedValuePersistence {
        self.ensure_session()
            .ok()
            .and_then(|_| self.metadata.get())
            .map_or(ProducedValuePersistence::Persist, |metadata| {
                map_persistence(metadata.prompted_value_persistence)
            })
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        if self
            .ensure_session()?
            .supports(wire::method::DESCRIBE_WRITE_TARGET)
        {
            let result = self.call::<wire::method::DescribeWriteTarget>(&AddressParams {
                address: to_wire_address(addr),
            })?;
            Ok(result.description)
        } else {
            Ok(self.resolve_remote(addr)?.render())
        }
    }

    fn auth_scope_key(&self) -> Option<String> {
        Some(format!(
            "{}:{}:{}",
            self.scheme,
            self.endpoint.executable.display(),
            self.configured_uri
        ))
    }

    fn name(&self) -> &str {
        &self.scheme
    }

    // The three identity accessors below never start a session, because route
    // planning derives canonical URIs and storage identities from a freshly
    // built, uncredentialed provider and is documented as touching no store.
    // They report the endpoint's own spelling once a session exists for another
    // reason, and the configured URI until then.

    fn uri(&self) -> String {
        self.metadata
            .get()
            .map(|metadata| metadata.display_uri.clone())
            .unwrap_or_else(|| self.configured_uri.clone())
    }

    fn storage_identity(&self) -> String {
        self.metadata
            .get()
            .map(|metadata| metadata.storage_identity.clone())
            .unwrap_or_else(|| self.configured_uri.clone())
    }

    fn entry_container_identity(&self) -> String {
        self.metadata
            .get()
            .map(|metadata| metadata.entry_container_identity.clone())
            .unwrap_or_else(|| self.storage_identity())
    }

    fn physical_store_path(&self) -> Option<&Path> {
        self.endpoint_metadata()
            .and_then(|metadata| metadata.physical_store_path.as_deref())
            .map(Path::new)
    }

    fn set_reason(&self, reason: Option<String>) {
        let session = {
            let mut state = self.state();
            if state.reason == reason {
                return;
            }
            state.reason = reason;
            state.session.take()
        };
        if let Some(session) = session {
            close_live_session(session);
        }
    }

    fn with_base_dir(&mut self, base_dir: &Path) {
        let mut state = self.state();
        // These hooks cannot report an error, so a rejected value is latched
        // until the next call to the same hook. Each setter therefore owns
        // exactly one latch and clears it on success, so correcting a value
        // recovers the provider instead of poisoning it permanently.
        if base_dir.is_absolute() {
            state.base_dir = Some(base_dir.to_path_buf());
            state.base_dir_error = None;
        } else {
            state.base_dir_error =
                Some("external provider base directory is not absolute".to_string());
        }
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        let supported = self
            .endpoint
            .credential_names
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let unknown = credentials
            .keys()
            .any(|name| !supported.contains(name.as_str()));
        let mut state = self.state();
        if unknown {
            // Keep the previously accepted credentials rather than installing a
            // set the endpoint never registered for.
            state.credentials_error =
                Some("external provider received an unregistered credential".to_string());
        } else {
            state.credentials = credentials;
            state.credentials_error = None;
        }
    }

    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        let result = self.call::<wire::method::Reflect>(&ReflectParams {
            project: context.project.to_string(),
            profile: context.profile.to_string(),
        })?;
        if result.schema_version != 1 {
            return Err(discovery_error(
                "provider reflection schema version is unsupported",
            ));
        }
        result
            .declarations
            .into_iter()
            .map(|(name, declaration)| {
                let reference = from_wire_coordinates(declaration.reference)?;
                Ok((
                    name,
                    Secret {
                        description: Some(declaration.description),
                        required: Some(declaration.required),
                        reference: Some(reference),
                        ..Secret::default()
                    },
                ))
            })
            .collect()
    }
}

impl Drop for ExternalProvider {
    fn drop(&mut self) {
        if let Some(session) = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .session
            .take()
        {
            close_live_session(session);
        }
    }
}

fn close_live_session(session: Arc<ProviderSession>) {
    let _ = super::block_on(session.close(deadline_unix_ms_after(Duration::from_secs(2))));
}

fn to_wire_address(address: Address<'_>) -> wire::Address {
    match address {
        Address::Convention {
            project,
            profile,
            key,
        } => wire::Address::Convention {
            project: project.to_string(),
            profile: profile.to_string(),
            key: key.to_string(),
        },
        Address::Native(address) => wire::Address::Native {
            coordinates: wire::Coordinates {
                item: address.item.clone(),
                field: address.field.clone(),
                vault: address.vault.clone(),
                section: address.section.clone(),
                version: address.version.clone(),
            },
        },
    }
}

fn from_wire_coordinates(coordinates: wire::Coordinates) -> Result<NativeAddress> {
    coordinates.validate().map_err(ipc_error)?;
    Ok(NativeAddress {
        item: coordinates.item,
        field: coordinates.field,
        vault: coordinates.vault,
        section: coordinates.section,
        version: coordinates.version,
    })
}

fn map_persistence(value: Persistence) -> ProducedValuePersistence {
    match value {
        Persistence::Persist => ProducedValuePersistence::Persist,
        Persistence::Ephemeral => ProducedValuePersistence::Ephemeral,
    }
}

fn ipc_error(error: secretspec_ipc::Error) -> SecretSpecError {
    match error.rpc_kind() {
        Some(kind) => SecretSpecError::ProviderProtocol(kind),
        None => SecretSpecError::ProviderOperationFailed(error.stable_message().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(directory: &Path, name: &str, argument: &str) -> ProviderEndpoint {
        let executable = directory.join(name);
        std::fs::write(&executable, name).unwrap();
        ProviderEndpoint {
            schema_version: 1,
            scheme: "example".into(),
            executable,
            arguments: vec![argument.into()],
            credential_names: Vec::new(),
        }
    }

    fn write_registration(directory: &Path, endpoint: &ProviderEndpoint) {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("example.json"),
            serde_json::to_vec(endpoint).unwrap(),
        )
        .unwrap();
    }

    fn write_path_endpoint(directory: &Path) -> PathBuf {
        std::fs::create_dir_all(directory).unwrap();
        let name = if cfg!(windows) {
            "secretspec-provider-example.exe"
        } else {
            "secretspec-provider-example"
        };
        let executable = directory.join(name);
        std::fs::write(&executable, "path").unwrap();
        executable
    }

    struct AllowAll;

    impl EndpointSecurity for AllowAll {
        fn check_registration(&self, _: &Path, _: RegistrationScope) -> Result<()> {
            Ok(())
        }
        fn check_executable(&self, _: &Path, _: RegistrationScope) -> Result<()> {
            Ok(())
        }
        fn privileged(&self) -> bool {
            false
        }
    }

    struct DenyAll;

    impl EndpointSecurity for DenyAll {
        fn check_registration(&self, _: &Path, _: RegistrationScope) -> Result<()> {
            Err(discovery_error("rejected by test policy"))
        }
        fn check_executable(&self, _: &Path, _: RegistrationScope) -> Result<()> {
            Err(discovery_error("rejected by test policy"))
        }
        fn privileged(&self) -> bool {
            true
        }
    }

    #[test]
    fn discovery_precedence_and_closed_registration() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("endpoint");
        std::fs::write(&executable, "endpoint").unwrap();
        let registration_dir = directory.path().join("providers.d");
        std::fs::create_dir(&registration_dir).unwrap();
        std::fs::write(
            registration_dir.join("example.json"),
            serde_json::json!({
                "schema_version": 1,
                "scheme": "example",
                "executable": executable,
                "arguments": ["--stdio"],
                "credential_names": ["access_token"]
            })
            .to_string(),
        )
        .unwrap();
        let discovery = ProviderDiscovery {
            explicit: BTreeMap::new(),
            user_directory: Some(registration_dir.clone()),
            system_directory: None,
            allow_path: false,
        };
        let endpoint = discovery
            .resolve_with_security("example", &AllowAll)
            .unwrap()
            .unwrap();
        assert_eq!(endpoint.arguments, ["--stdio"]);

        std::fs::write(
            registration_dir.join("bad.json"),
            serde_json::json!({
                "schema_version": 1,
                "scheme": "bad",
                "executable": endpoint.executable,
                "unexpected": true
            })
            .to_string(),
        )
        .unwrap();
        assert!(discovery.resolve_with_security("bad", &AllowAll).is_err());
    }

    #[test]
    fn explicit_endpoint_precedes_user_system_and_path() {
        let root = tempfile::tempdir().unwrap();
        let explicit = endpoint(root.path(), "explicit", "explicit");
        let user = endpoint(root.path(), "user", "user");
        let system = endpoint(root.path(), "system", "system");
        let user_directory = root.path().join("user.d");
        let system_directory = root.path().join("system.d");
        let path_directory = root.path().join("bin");
        write_registration(&user_directory, &user);
        write_registration(&system_directory, &system);
        write_path_endpoint(&path_directory);
        let search_path = std::env::join_paths([&path_directory]).unwrap();
        let discovery = ProviderDiscovery {
            explicit: BTreeMap::from([("example".into(), explicit)]),
            user_directory: Some(user_directory),
            system_directory: Some(system_directory),
            allow_path: true,
        };

        let selected = discovery
            .resolve_with_security_and_search_path(
                "example",
                &AllowAll,
                Some(search_path.as_os_str()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(selected.arguments, ["explicit"]);
    }

    #[test]
    fn user_registration_precedes_system_and_path() {
        let root = tempfile::tempdir().unwrap();
        let user = endpoint(root.path(), "user", "user");
        let system = endpoint(root.path(), "system", "system");
        let user_directory = root.path().join("user.d");
        let system_directory = root.path().join("system.d");
        let path_directory = root.path().join("bin");
        write_registration(&user_directory, &user);
        write_registration(&system_directory, &system);
        write_path_endpoint(&path_directory);
        let search_path = std::env::join_paths([&path_directory]).unwrap();
        let discovery = ProviderDiscovery {
            explicit: BTreeMap::new(),
            user_directory: Some(user_directory),
            system_directory: Some(system_directory),
            allow_path: true,
        };

        let selected = discovery
            .resolve_with_security_and_search_path(
                "example",
                &AllowAll,
                Some(search_path.as_os_str()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(selected.arguments, ["user"]);
    }

    #[test]
    fn system_registration_precedes_path() {
        let root = tempfile::tempdir().unwrap();
        let system = endpoint(root.path(), "system", "system");
        let system_directory = root.path().join("system.d");
        let path_directory = root.path().join("bin");
        write_registration(&system_directory, &system);
        write_path_endpoint(&path_directory);
        let search_path = std::env::join_paths([&path_directory]).unwrap();
        let discovery = ProviderDiscovery {
            explicit: BTreeMap::new(),
            user_directory: None,
            system_directory: Some(system_directory),
            allow_path: true,
        };

        let selected = discovery
            .resolve_with_security_and_search_path(
                "example",
                &AllowAll,
                Some(search_path.as_os_str()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(selected.arguments, ["system"]);
    }

    #[test]
    fn path_discovery_requires_opt_in_and_is_disabled_when_privileged() {
        let root = tempfile::tempdir().unwrap();
        let path_directory = root.path().join("bin");
        let executable = write_path_endpoint(&path_directory);
        let search_path = std::env::join_paths([&path_directory]).unwrap();
        let mut discovery = ProviderDiscovery::default();

        assert!(
            discovery
                .resolve_with_security_and_search_path(
                    "example",
                    &AllowAll,
                    Some(search_path.as_os_str()),
                )
                .unwrap()
                .is_none()
        );
        discovery.allow_path = true;
        assert!(
            discovery
                .resolve_with_security_and_search_path(
                    "example",
                    &DenyAll,
                    Some(search_path.as_os_str()),
                )
                .unwrap()
                .is_none()
        );
        let selected = discovery
            .resolve_with_security_and_search_path(
                "example",
                &AllowAll,
                Some(search_path.as_os_str()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(selected.executable, executable.canonicalize().unwrap());
    }

    #[test]
    fn registration_change_does_not_mutate_a_resolved_endpoint() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("user.d");
        let first_endpoint = endpoint(root.path(), "first", "first");
        let second_endpoint = endpoint(root.path(), "second", "second");
        write_registration(&directory, &first_endpoint);
        let discovery = ProviderDiscovery {
            user_directory: Some(directory.clone()),
            ..ProviderDiscovery::default()
        };
        let first = discovery
            .resolve_with_security_and_search_path("example", &AllowAll, None)
            .unwrap()
            .unwrap();

        write_registration(&directory, &second_endpoint);
        let second = discovery
            .resolve_with_security_and_search_path("example", &AllowAll, None)
            .unwrap()
            .unwrap();

        assert_eq!(first.arguments, ["first"]);
        assert_eq!(second.arguments, ["second"]);
        assert_ne!(first.executable, second.executable);
    }

    #[test]
    fn dynamic_trait_surface_is_object_safe() {
        fn accepts(_: &dyn Provider) {}
        fn accepts_arc<T: Provider>(_: Arc<T>) {}

        struct DynamicName(String);
        impl Provider for DynamicName {
            fn convention_address(&self, _: &str, _: &str, key: &str) -> Result<NativeAddress> {
                Ok(NativeAddress {
                    item: key.into(),
                    ..NativeAddress::default()
                })
            }
            fn get(&self, _: Address<'_>) -> Result<Option<SecretString>> {
                Ok(None)
            }
            fn set(&self, _: Address<'_>, _: &SecretString) -> Result<()> {
                Ok(())
            }
            fn name(&self) -> &str {
                &self.0
            }
            fn uri(&self) -> String {
                format!("{}://", self.0)
            }
        }

        let direct = Arc::new(DynamicName("dynamic".into()));
        accepts(direct.as_ref());
        accepts_arc(direct);
        let boxed: Box<dyn Provider> = Box::new(DynamicName("boxed".into()));
        accepts(boxed.as_ref());
    }

    #[test]
    fn injected_security_policy_can_reject_an_explicit_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("endpoint");
        std::fs::write(&executable, "endpoint").unwrap();
        let discovery = ProviderDiscovery {
            explicit: BTreeMap::from([(
                "example".into(),
                ProviderEndpoint {
                    schema_version: 1,
                    scheme: "example".into(),
                    executable,
                    arguments: Vec::new(),
                    credential_names: Vec::new(),
                },
            )]),
            ..ProviderDiscovery::default()
        };
        assert!(
            discovery
                .resolve_with_security("example", &DenyAll)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn platform_policy_accepts_owner_only_files_and_rejects_writable_registration() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("endpoint");
        std::fs::write(&executable, "endpoint").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let registration_dir = directory.path().join("providers.d");
        std::fs::create_dir(&registration_dir).unwrap();
        std::fs::set_permissions(&registration_dir, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let registration = registration_dir.join("example.json");
        std::fs::write(
            &registration,
            serde_json::json!({
                "schema_version": 1,
                "scheme": "example",
                "executable": executable,
                "arguments": [],
                "credential_names": []
            })
            .to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&registration, std::fs::Permissions::from_mode(0o600)).unwrap();
        let discovery = ProviderDiscovery {
            user_directory: Some(registration_dir),
            ..ProviderDiscovery::default()
        };
        assert!(discovery.resolve("example").unwrap().is_some());

        std::fs::set_permissions(&registration, std::fs::Permissions::from_mode(0o622)).unwrap();
        assert!(discovery.resolve("example").is_err());
    }
}
