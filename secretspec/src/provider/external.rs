//! External provider discovery and the `secretspec.provider/1` adapter.
//!
//! Available since SecretSpec 0.21.

use super::{
    Address, DiscoveryContext, ProducedValuePersistence, Provider, ProviderCredentials,
    ProviderUrl, ProviderValue, exists_each, get_each_with,
};
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::{Result, Secret, SecretSpecError};
use secretspec_ipc::deadline_unix_ms_after;
use secretspec_ipc::error::{ErrorKind as RpcErrorKind, RpcError};
use secretspec_ipc::lifecycle::{CredentialResponder, Environment, LaunchOptions, ProviderSession};
use secretspec_ipc::protocol::callback::CredentialResult;
use secretspec_ipc::protocol::provider::{
    self as wire, AddressParams, ApplicationContext, GetManyParams, GetResult,
    InitializeApplication, NamedRequest, Persistence, ReflectParams, SetExpiringParams, SetParams,
};
use secretspec_ipc::protocol::{Limits, Product};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::Duration;

const REGISTRATION_MAX_BYTES: u64 = 64 * 1024;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Semantic credential request made by an external endpoint (0.21+).
pub use secretspec_ipc::protocol::callback::CredentialParams as ProviderCredentialRequest;

/// A resolved provider endpoint and its fixed executable identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEndpoint {
    pub scheme: String,
    pub executable: PathBuf,
    /// Explicit embedders may select a mode directly. Filesystem-discovered
    /// providers always receive the fixed `provider` argument.
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Parent environment variables the endpoint may read, beyond the base
    /// set every endpoint receives (see [`BASE_ENDPOINT_ENVIRONMENT`]). An
    /// entry is an exact name or a prefix ending in `*`, such as `VAULT_*`.
    #[serde(default)]
    pub environment: Vec<String>,
}

/// Public discovery claim written by an installed provider.
///
/// The filename supplies the scheme and the launch contract is always
/// `<executable> provider`. Unknown fields are deliberately ignored so future
/// SecretSpec releases can extend the claim without versioning this small
/// discovery document.
#[derive(Deserialize)]
struct ProviderClaim {
    executable: PathBuf,
    #[serde(default)]
    environment: Vec<String>,
}

/// Parent environment variables every endpoint receives: what a process
/// needs to find programs, locale, temporary and user directories, proxies,
/// certificate stores, and desktop or agent sessions for native
/// authentication. Anything else, including other providers' tokens, reaches
/// an endpoint only when its registration names it. Entries ending in `*`
/// are prefixes.
pub const BASE_ENDPOINT_ENVIRONMENT: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "TZ",
    "TMPDIR",
    "XDG_*",
    "SSH_AUTH_SOCK",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    // Windows
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "USERNAME",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "TEMP",
    "TMP",
];

fn validate_environment_pattern(pattern: &str) -> Result<()> {
    let name = pattern.strip_suffix('*').unwrap_or(pattern);
    if name.is_empty()
        || name
            .chars()
            .any(|c| c == '=' || c == '*' || c == '\0' || c.is_whitespace())
    {
        return Err(discovery_error(
            "provider environment entries must be variable names or name prefixes ending in '*'",
        ));
    }
    Ok(())
}

fn environment_name_matches(pattern: &str, name: &str) -> bool {
    // Windows environment names are case-insensitive.
    let (pattern, name) = if cfg!(windows) {
        (pattern.to_ascii_uppercase(), name.to_ascii_uppercase())
    } else {
        (pattern.to_string(), name.to_string())
    };
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern,
    }
}

/// Filters `parent` down to [`BASE_ENDPOINT_ENVIRONMENT`] plus the
/// endpoint's own declared `extra` entries.
pub(crate) fn endpoint_environment(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
    extra: &[String],
) -> BTreeMap<OsString, OsString> {
    parent
        .into_iter()
        .filter(|(name, _)| {
            let Some(name) = name.to_str() else {
                return false;
            };
            BASE_ENDPOINT_ENVIRONMENT
                .iter()
                .copied()
                .chain(extra.iter().map(String::as_str))
                .any(|pattern| environment_name_matches(pattern, name))
        })
        .collect()
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
            let path = directory.join(format!("{scheme}.secretspec.json"));
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
                scheme: scheme.to_string(),
                executable: path,
                arguments: vec!["provider".to_string()],
                environment: Vec::new(),
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
/// to opt into PATH discovery. Available since SecretSpec 0.21.
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
    let claim: ProviderClaim = serde_json::from_slice(&bytes)
        .map_err(|_| discovery_error("invalid provider registration"))?;
    let expected_filename = format!("{scheme}.secretspec.json");
    if path.file_name().and_then(|value| value.to_str()) != Some(&expected_filename) {
        return Err(discovery_error(
            "provider registration filename does not match its scheme",
        ));
    }
    validate_endpoint(
        ProviderEndpoint {
            scheme: scheme.to_string(),
            executable: claim.executable,
            arguments: vec!["provider".to_string()],
            environment: claim.environment,
        },
        scheme,
        scope,
        security,
    )
}

fn validate_endpoint(
    mut endpoint: ProviderEndpoint,
    expected_scheme: &str,
    scope: RegistrationScope,
    security: &dyn EndpointSecurity,
) -> Result<ProviderEndpoint> {
    if endpoint.scheme != expected_scheme {
        return Err(discovery_error(
            "provider registration scheme does not match",
        ));
    }
    validate_scheme(&endpoint.scheme)?;
    for pattern in &endpoint.environment {
        validate_environment_pattern(pattern)?;
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

/// Sticky directories are safe ancestors even when world-writable: the bit
/// stops anyone but the owner renaming or deleting an entry, so `/tmp` cannot
/// be used to swap out a subtree that belongs to someone else.
#[cfg(unix)]
const STICKY_BIT: u32 = 0o1000;

#[cfg(unix)]
fn owner_is_trusted(uid: u32, scope: RegistrationScope) -> bool {
    match scope {
        RegistrationScope::System => uid == 0,
        RegistrationScope::Explicit | RegistrationScope::User | RegistrationScope::Path => {
            uid == effective_uid() || uid == 0
        }
    }
}

#[cfg(unix)]
fn check_file_security(path: &Path, scope: RegistrationScope, executable: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // Resolve first, then inspect the resolved path with `symlink_metadata`.
    // Plain `metadata` follows symlinks silently, so what it validated was the
    // target while the registration named something else entirely.
    let resolved = std::fs::canonicalize(path).map_err(discovery_io)?;
    let metadata = std::fs::symlink_metadata(&resolved).map_err(discovery_io)?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 {
        return Err(discovery_error(if executable {
            "provider executable is group- or world-writable"
        } else {
            "provider registration is group- or world-writable"
        }));
    }
    if !owner_is_trusted(metadata.uid(), scope) {
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
    // Every directory above the endpoint, not just the immediate parent: one
    // writable ancestor lets an attacker swap a component for a symlink to any
    // executable that already satisfies the checks below it.
    //
    // The walk runs over the canonical path, so a symlinked component is
    // validated as the chain it actually resolves to rather than refused
    // outright. Refusing symlinks would break the common cases where they are
    // how software is installed: Nix store paths and macOS's /var.
    let resolved = std::fs::canonicalize(path).map_err(discovery_io)?;
    let mut checked_any = false;
    for ancestor in resolved.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(discovery_io)?;
        if !metadata.is_dir() {
            return Err(discovery_error(
                "provider endpoint path component is not a directory",
            ));
        }
        let mode = metadata.mode();
        if mode & 0o022 != 0 && mode & STICKY_BIT == 0 {
            return Err(discovery_error(
                "provider endpoint directory is group- or world-writable",
            ));
        }
        if !owner_is_trusted(metadata.uid(), scope) {
            return Err(discovery_error(
                "provider endpoint directory ownership is outside the trust domain",
            ));
        }
        checked_any = true;
    }
    if !checked_any {
        return Err(discovery_error("provider endpoint has no parent directory"));
    }
    Ok(())
}

#[cfg(windows)]
fn check_file_security(path: &Path, _scope: RegistrationScope, _executable: bool) -> Result<()> {
    if !path.is_file() {
        return Err(discovery_error("provider endpoint is not a regular file"));
    }
    let system_scope = _scope == RegistrationScope::System;
    match crate::windows_security::path_acl_is_trusted(
        path,
        crate::windows_security::AclObjectKind::File,
        system_scope,
    ) {
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
    check_windows_parent_security_with(
        path,
        _scope == RegistrationScope::System,
        |ancestor, system_scope| {
            crate::windows_security::path_acl_is_trusted(
                ancestor,
                crate::windows_security::AclObjectKind::Directory,
                system_scope,
            )
        },
    )
}

#[cfg(windows)]
fn check_windows_parent_security_with<F>(
    path: &Path,
    system_scope: bool,
    mut acl_is_trusted: F,
) -> Result<()>
where
    F: FnMut(&Path, bool) -> std::io::Result<bool>,
{
    // A trusted endpoint and immediate directory are not enough: write or
    // FILE_DELETE_CHILD access on any higher directory lets an attacker
    // replace the protected subtree after validation. Walk the canonical path
    // so junctions and other reparse points are checked where they resolve.
    let resolved = std::fs::canonicalize(path).map_err(discovery_io)?;
    let mut checked_any = false;
    for ancestor in resolved.ancestors().skip(1) {
        if !ancestor.is_dir() {
            return Err(discovery_error(
                "provider endpoint path component is not a directory",
            ));
        }
        match acl_is_trusted(ancestor, system_scope) {
            Ok(true) => {}
            Ok(false) => {
                return Err(discovery_error(
                    "provider endpoint directory ACL is outside the trust domain",
                ));
            }
            Err(_) => {
                return Err(discovery_error(
                    "provider endpoint directory ACL could not be validated",
                ));
            }
        }
        checked_any = true;
    }
    if checked_any {
        Ok(())
    } else {
        Err(discovery_error("provider endpoint has no parent directory"))
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

/// The host-selected provider instance a credential request belongs to
/// (0.21+).
///
/// Both parts come from SecretSpec, never from the endpoint: the discovered
/// scheme and the configured provider URI, which cannot carry a password. Two
/// aliases of one scheme that select different accounts or stores are
/// therefore distinct principals even when their endpoint reports the same
/// `scope`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderCredentialPrincipal {
    scheme: String,
    uri: String,
}

impl ProviderCredentialPrincipal {
    pub fn new(scheme: impl Into<String>, uri: impl Into<String>) -> Self {
        Self {
            scheme: scheme.into(),
            uri: uri.into(),
        }
    }

    /// The discovered provider scheme.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The configured provider URI, as SecretSpec normalized it.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub(crate) fn from_url(url: &ProviderUrl) -> Self {
        Self::new(url.scheme(), url.to_string())
    }
}

/// Resolves credentials requested by one already-discovered external provider.
///
/// The host-selected principal is supplied separately from the
/// endpoint-controlled request and MUST be part of the backing-store
/// namespace. Implementations return `None` for an ordinary miss and must
/// never place a value in an error. A broker must not call back into the
/// provider instance that requested the credential: that instance is still
/// starting and is waiting for this answer.
pub trait ProviderCredentialBroker: Send + Sync + 'static {
    fn get(
        &self,
        principal: &ProviderCredentialPrincipal,
        request: &ProviderCredentialRequest,
    ) -> Result<Option<SecretBytes>>;

    /// Whether answering may wait for a person. Requests to an endpoint using
    /// an interactive broker get the longest deadline the protocol allows, so
    /// a prompt is not cut off by the machine startup or operation budget.
    fn interactive(&self) -> bool {
        false
    }
}

#[derive(Default)]
pub(crate) struct KeyringCredentialBroker;

impl ProviderCredentialBroker for KeyringCredentialBroker {
    fn get(
        &self,
        principal: &ProviderCredentialPrincipal,
        request: &ProviderCredentialRequest,
    ) -> Result<Option<SecretBytes>> {
        #[cfg(feature = "keyring")]
        {
            use crate::provider::keyring::{KeyringConfig, KeyringProvider};

            let provider = KeyringProvider::new(KeyringConfig::default());
            let address = brokered_credential_address(principal, &request.scope, &request.name);
            match provider.get(Address::Native(&address)) {
                // An optional broker lookup must not prevent the endpoint from
                // using its native environment, agent, or workload identity merely
                // because this machine has no usable keyring service.
                Err(_) if !request.required => Ok(None),
                result => result,
            }
        }
        #[cfg(not(feature = "keyring"))]
        {
            let _ = (principal, request);
            Ok(None)
        }
    }
}

/// Stable, provider-private keyring address for a dynamically requested
/// credential. The hash covers the host-selected provider URI and the
/// endpoint-controlled scope, so aliases selecting different accounts never
/// share a slot even when their endpoint reports one scope. Length-prefixing
/// each part keeps separators from collapsing two namespaces, and hashing
/// keeps the name within platform keyring limits; the scheme and semantic
/// name remain visible for diagnostics and keyring UIs.
pub(crate) fn brokered_credential_address(
    principal: &ProviderCredentialPrincipal,
    scope: &str,
    name: &str,
) -> NativeAddress {
    let mut hasher = Sha256::new();
    for part in [principal.uri(), scope] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut namespace = String::with_capacity(digest.len() * 2);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(namespace, "{byte:02x}");
    }
    NativeAddress {
        item: format!(
            "secretspec/provider-credentials/{}/{namespace}/{name}",
            principal.scheme()
        ),
        ..NativeAddress::default()
    }
}

pub(crate) fn store_brokered_credential(
    principal: &ProviderCredentialPrincipal,
    scope: &str,
    name: &str,
    value: &SecretBytes,
) -> Result<String> {
    #[cfg(feature = "keyring")]
    {
        use crate::provider::keyring::{KeyringConfig, KeyringProvider};

        let provider = KeyringProvider::new(KeyringConfig::default());
        let address = brokered_credential_address(principal, scope, name);
        provider.set(Address::Native(&address), value)?;
        Ok(format!("keyring at {}", address.render()))
    }
    #[cfg(not(feature = "keyring"))]
    {
        let _ = (principal, scope, name, value);
        Err(SecretSpecError::ProviderOperationFailed(
            "this SecretSpec build has no system-keyring support".into(),
        ))
    }
}

struct ExternalCredentialResponder {
    principal: ProviderCredentialPrincipal,
    explicit: ProviderCredentials,
    broker: Arc<dyn ProviderCredentialBroker>,
    names: Mutex<HashSet<(String, String)>>,
    broker_error: Arc<Mutex<Option<String>>>,
}

#[async_trait::async_trait]
impl CredentialResponder for ExternalCredentialResponder {
    async fn credential(
        &self,
        request: ProviderCredentialRequest,
    ) -> std::result::Result<CredentialResult, RpcError> {
        // Bound the authority surface independently from frame size. Repeated
        // requests for the same credential remain valid for token refresh.
        let identity = (request.scope.clone(), request.name.clone());
        {
            let mut names = self
                .names
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !names.contains(&identity) && names.len() >= 64 {
                return Err(RpcError::new(RpcErrorKind::InvalidParams));
            }
            names.insert(identity);
        }
        let value = match self.explicit.get(&request.name).cloned() {
            Some(value) => Some(value),
            None => {
                let broker = self.broker.clone();
                let principal = self.principal.clone();
                let result = tokio::task::spawn_blocking(move || broker.get(&principal, &request))
                    .await
                    .map_err(|_| RpcError::new(RpcErrorKind::OperationFailed))?;
                match result {
                    Ok(value) => value,
                    Err(error) => {
                        *self
                            .broker_error
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                            Some(error.to_string());
                        return Err(RpcError::new(RpcErrorKind::OperationFailed));
                    }
                }
            }
        };
        Ok(match value {
            Some(value) if !value.expose_secret().is_empty() => CredentialResult::Found {
                value: value
                    .try_as_utf8()
                    .map_err(|_| RpcError::new(RpcErrorKind::OperationFailed))?
                    .to_owned(),
            },
            _ => CredentialResult::Missing,
        })
    }
}

struct ExternalState {
    project: Option<String>,
    profile: Option<String>,
    base_dir: Option<PathBuf>,
    credentials: ProviderCredentials,
    credential_broker: Arc<dyn ProviderCredentialBroker>,
    credential_error: Arc<Mutex<Option<String>>>,
    reason: Option<String>,
    requested_authorization_duration: Option<std::time::Duration>,
    /// Latched rejection from the last `with_base_dir`, cleared when a later
    /// call supplies an acceptable value.
    base_dir_error: Option<String>,
    session: Option<Arc<ProviderSession>>,
    /// Bumped whenever initialization inputs change, so a startup that ran
    /// without this lock can tell its snapshot went stale.
    generation: u64,
}

impl ExternalState {
    /// The configuration rejection that must block session startup, if any.
    fn configuration_error(&self) -> Option<&str> {
        self.base_dir_error.as_deref()
    }

    /// Records a change to initialization inputs and detaches the session
    /// that was initialized with the previous ones.
    fn invalidate(&mut self) -> Option<Arc<ProviderSession>> {
        self.generation = self.generation.wrapping_add(1);
        self.session.take()
    }
}

/// A core provider backed by one `secretspec.provider/1` endpoint.
///
/// Endpoint startup is lazy so project/profile context, `with_base_dir`, the
/// credential broker, and the initial `set_reason` are applied to immutable
/// initialization state first.
pub struct ExternalProvider {
    endpoint: ProviderEndpoint,
    scheme: String,
    configured_uri: String,
    state: Mutex<ExternalState>,
    /// Serializes endpoint startup. Held instead of `state` while an endpoint
    /// initializes, because initialization may wait on a credential prompt.
    launch: Mutex<()>,
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
                project: None,
                profile: None,
                base_dir: None,
                credentials: ProviderCredentials::new(),
                credential_broker: Arc::new(KeyringCredentialBroker),
                credential_error: Arc::new(Mutex::new(None)),
                reason: None,
                requested_authorization_duration: None,
                base_dir_error: None,
                session: None,
                generation: 0,
            }),
            launch: Mutex::new(()),
            metadata: OnceLock::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, ExternalState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Replaces the default system-keyring broker before the endpoint starts.
    /// Embedders can use this to enforce their own credential policy (0.21+).
    pub fn with_credential_broker(&mut self, broker: Arc<dyn ProviderCredentialBroker>) {
        let session = {
            let mut state = self.state();
            state.credential_broker = broker;
            state
                .credential_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            state.invalidate()
        };
        if let Some(session) = session {
            close_live_session(session);
        }
    }

    #[cfg(any(feature = "cli", test))]
    pub(crate) fn initialize(&self) -> Result<()> {
        self.ensure_session().map(|_| ())
    }

    /// The absolute deadline for a request that may trigger credential
    /// callbacks. An interactive broker may wait for a person, so it gets the
    /// longest horizon the protocol allows instead of a machine budget.
    fn request_deadline(&self, interactive: bool, budget: Duration) -> u64 {
        deadline_unix_ms_after(if interactive {
            secretspec_ipc::deadline::MAX_DEADLINE_HORIZON
        } else {
            budget
        })
    }

    fn ensure_session(&self) -> Result<Arc<ProviderSession>> {
        if let Some(session) = self.live_session()? {
            return Ok(session);
        }
        // Serialize startup under a dedicated lock so `state` stays free while
        // the endpoint initializes: initialization may wait on a credential
        // prompt, and setters or other accessors must not block behind it.
        let _launch = self
            .launch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            // Another caller may have finished starting the endpoint while
            // this one waited for the launch lock.
            if let Some(session) = self.live_session()? {
                return Ok(session);
            }
            if let Some(session) = self.launch_session()? {
                return Ok(session);
            }
            // Initialization inputs changed while the endpoint started, so
            // the session it produced was closed. Start again with the new
            // inputs.
        }
    }

    /// The current usable session, detaching one that has closed.
    fn live_session(&self) -> Result<Option<Arc<ProviderSession>>> {
        let stale = {
            let mut state = self.state();
            if let Some(message) = state.configuration_error() {
                return Err(discovery_error(message));
            }
            match &state.session {
                Some(session) if !session.is_closed() => return Ok(Some(session.clone())),
                Some(_) => state.session.take(),
                None => None,
            }
        };
        if let Some(stale) = stale {
            close_live_session(stale);
        }
        Ok(None)
    }

    /// Starts one endpoint from a snapshot of the initialization inputs.
    /// Returns `None` when those inputs changed during startup.
    fn launch_session(&self) -> Result<Option<Arc<ProviderSession>>> {
        let state = self.state();
        let generation = state.generation;
        let interactive = state.credential_broker.interactive();
        let credential_error = state.credential_error.clone();
        let application = InitializeApplication {
            scheme: self.scheme.clone(),
            uri: self.configured_uri.clone(),
            context: ApplicationContext {
                project: state.project.clone(),
                profile: state.profile.clone(),
                base_dir: state
                    .base_dir
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
                reason: state.reason.clone(),
                requested_authorization_duration_ms: state
                    .requested_authorization_duration
                    .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
            },
        };
        let responder = Arc::new(ExternalCredentialResponder {
            principal: ProviderCredentialPrincipal::new(&self.scheme, &self.configured_uri),
            explicit: state.credentials.clone(),
            broker: state.credential_broker.clone(),
            names: Mutex::new(HashSet::new()),
            broker_error: credential_error.clone(),
        });
        drop(state);
        let launch = self.launch_options(std::env::vars_os());
        let launched = super::block_on(ProviderSession::launch_with_credential_broker(
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
            self.request_deadline(interactive, STARTUP_TIMEOUT),
            Some(responder.clone()),
        ));
        let session = match launched {
            Ok(session) => session,
            Err(error) => {
                if let Some(message) = credential_error
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    return Err(SecretSpecError::ProviderOperationFailed(message));
                }
                return Err(ipc_error(error));
            }
        };
        // An endpoint may deliberately catch a failed optional lookup and use
        // native authentication instead. Do not let that handled failure leak
        // into a later operation on the healthy session.
        credential_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let session = Arc::new(session);
        {
            let mut state = self.state();
            if state.generation == generation {
                if let Some(existing) = self.metadata.get() {
                    if existing != session.metadata() {
                        drop(state);
                        close_live_session(session);
                        return Err(discovery_error("provider metadata changed after reconnect"));
                    }
                } else {
                    let _ = self.metadata.set(session.metadata().clone());
                }
                state.session = Some(session.clone());
                return Ok(Some(session));
            }
        }
        close_live_session(session);
        Ok(None)
    }

    /// Launch options for this endpoint, with the child environment filtered
    /// from `parent` so other providers' tokens never reach it.
    fn launch_options(
        &self,
        parent: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> LaunchOptions {
        LaunchOptions {
            executable: self.endpoint.executable.clone(),
            arguments: self.endpoint.arguments.iter().map(OsString::from).collect(),
            environment: Environment::Replace(endpoint_environment(
                parent,
                &self.endpoint.environment,
            )),
            allow_path_discovery: false,
            max_stderr_bytes: 64 * 1024,
        }
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
        // Endpoints may request a credential again mid-operation, for example
        // to refresh a token, so an interactive broker widens this deadline too.
        let interactive = self.state().credential_broker.interactive();
        let result = super::block_on(session.execute::<M>(
            params,
            self.request_deadline(interactive, OPERATION_TIMEOUT),
        ));
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
        match result {
            Ok(value) => {
                self.state()
                    .credential_error
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
                Ok(value)
            }
            Err(error) => {
                if let Some(message) = self
                    .state()
                    .credential_error
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    Err(SecretSpecError::ProviderOperationFailed(message))
                } else {
                    Err(ipc_error(error))
                }
            }
        }
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

    fn supports_read(&self) -> bool {
        // Initialization errors must surface from the attempted operation, not
        // be misreported by core workflows as a healthy write-only endpoint.
        // Until negotiation succeeds, preserve the trait's readable default.
        self.ensure_session().map_or(true, |session| {
            session.supports(wire::method::GET) || session.supports(wire::method::GET_MANY)
        })
    }

    fn exists(&self, addr: Address<'_>) -> Result<bool> {
        ExternalProvider::exists(self, addr)
    }

    fn supports_delete(&self) -> bool {
        self.ensure_session()
            .is_ok_and(|session| session.supports(wire::method::DELETE))
    }

    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<std::borrow::Cow<'a, NativeAddress>> {
        self.resolve_remote(addr).map(std::borrow::Cow::Owned)
    }

    /// Planning compares entries before any cache hit and must not start the
    /// endpoint (which may prompt for credentials). A native address is
    /// already the endpoint's coordinates. A convention address is compiled
    /// only by the endpoint, so without contacting it the address is
    /// identified by its logical coordinates under a marker no native `item`
    /// can contain.
    fn configured_entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, NativeAddress>> {
        Ok(match addr {
            Address::Native(native) => std::borrow::Cow::Borrowed(native),
            Address::Convention {
                project,
                profile,
                key,
            } => std::borrow::Cow::Owned(NativeAddress {
                item: format!("\0convention\0{project}\0{profile}\0{key}"),
                ..NativeAddress::default()
            }),
        })
    }

    fn entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, NativeAddress>> {
        self.resolve_remote(addr).map(std::borrow::Cow::Owned)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        self.get_with_metadata(addr)
            .map(|value| value.map(|value| value.value))
    }

    fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        let result = self.call::<wire::method::Get>(&AddressParams {
            address: to_wire_address(addr),
        })?;
        Ok(match result {
            GetResult::Found {
                value,
                expires_at_unix_ms,
                revision,
            } => Some(
                ProviderValue::new(SecretBytes::from_utf8(value), expires_at_unix_ms)
                    .with_revision(revision),
            ),
            GetResult::Missing => None,
        })
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        self.get_many_with_metadata(requests).map(|values| {
            values
                .into_iter()
                .map(|(name, value)| (name, value.value))
                .collect()
        })
    }

    fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        if !self.ensure_session()?.supports(wire::method::GET_MANY) {
            return get_each_with(requests, |address| self.get_with_metadata(address));
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
                GetResult::Found {
                    value,
                    expires_at_unix_ms,
                    revision,
                } => Some((
                    item.name,
                    ProviderValue::new(SecretBytes::from_utf8(value), expires_at_unix_ms)
                        .with_revision(revision),
                )),
                GetResult::Missing => None,
            })
            .collect())
    }

    fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        if self.ensure_session()?.supports(wire::method::EXISTS) {
            return exists_each(self, requests);
        }
        self.get_many(requests)
            .map(|values| values.into_keys().collect())
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        self.check_writable(addr)?;
        let result = self.call::<wire::method::Set>(&SetParams {
            address: to_wire_address(addr),
            value: value
                .try_as_utf8_for(match addr {
                    Address::Convention { key, .. } => key,
                    Address::Native(native) => &native.item,
                })?
                .to_owned(),
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
        value: &SecretBytes,
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
            value: value
                .try_as_utf8_for(match addr {
                    Address::Convention { key, .. } => key,
                    Address::Native(native) => &native.item,
                })?
                .to_owned(),
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

    /// Known only from the endpoint, so planning sees it once a session has
    /// reported it and otherwise compares configured identities.
    fn configured_physical_store_path(&self) -> Option<&Path> {
        self.metadata
            .get()
            .and_then(|metadata| metadata.physical_store_path.as_deref())
            .map(Path::new)
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
            state.invalidate()
        };
        if let Some(session) = session {
            close_live_session(session);
        }
    }

    fn set_requested_authorization_duration(&self, duration: Option<std::time::Duration>) {
        let session = {
            let mut state = self.state();
            if state.requested_authorization_duration == duration {
                return;
            }
            state.requested_authorization_duration = duration;
            state.invalidate()
        };
        if let Some(session) = session {
            close_live_session(session);
        }
    }

    fn set_project(&self, project: &str) {
        let session = {
            let mut state = self.state();
            if state.project.as_deref() == Some(project) {
                return;
            }
            state.project = Some(project.to_string());
            state.invalidate()
        };
        if let Some(session) = session {
            close_live_session(session);
        }
    }

    fn set_profile(&self, profile: &str) {
        let session = {
            let mut state = self.state();
            if state.profile.as_deref() == Some(profile) {
                return;
            }
            state.profile = Some(profile.to_string());
            state.invalidate()
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
        let session = {
            let mut state = self.state();
            state.credentials = credentials;
            state
                .credential_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            state.invalidate()
        };
        if let Some(session) = session {
            close_live_session(session);
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
                let secret = if declaration.required {
                    Secret::required(declaration.description)
                } else {
                    Secret::optional(declaration.description)
                }
                .reference(reference);
                Ok((name, secret))
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
    run_to_completion_or_detach(async move {
        let _ = session
            .close(deadline_unix_ms_after(Duration::from_secs(2)))
            .await;
    });
}

/// Runs cleanup that must never panic, including from `Drop`.
///
/// `block_on` enters `block_in_place`, which panics on a current-thread
/// runtime, and a panic in `Drop` while unwinding aborts the process. There
/// the cleanup moves to a helper thread instead of blocking the only runtime
/// worker; elsewhere it completes before returning.
fn run_to_completion_or_detach<F>(cleanup: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let current_thread = tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread
    });
    if current_thread {
        // The helper thread has no ambient runtime, so `block_on` uses the
        // shared provider runtime there.
        std::thread::spawn(move || super::block_on(cleanup));
    } else {
        super::block_on(cleanup);
    }
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
    match error {
        secretspec_ipc::Error::Remote(error) => SecretSpecError::ProviderProtocol {
            kind: error.data.kind,
            interaction: error.data.interaction,
        },
        error => match error.rpc_kind() {
            Some(kind) => SecretSpecError::ProviderProtocol {
                kind,
                interaction: None,
            },
            None => SecretSpecError::ProviderOperationFailed(error.stable_message().to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(directory: &Path, name: &str, argument: &str) -> ProviderEndpoint {
        let executable = directory.join(name);
        std::fs::write(&executable, name).unwrap();
        ProviderEndpoint {
            scheme: "example".into(),
            executable,
            arguments: vec![argument.into()],
            environment: Vec::new(),
        }
    }

    fn write_registration(directory: &Path, endpoint: &ProviderEndpoint) {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("example.secretspec.json"),
            serde_json::to_vec(&serde_json::json!({
                "executable": endpoint.executable,
            }))
            .unwrap(),
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
    fn discovery_precedence_and_extensible_registration() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("endpoint");
        std::fs::write(&executable, "endpoint").unwrap();
        let registration_dir = directory.path().join("providers.d");
        std::fs::create_dir(&registration_dir).unwrap();
        std::fs::write(
            registration_dir.join("example.secretspec.json"),
            serde_json::json!({
                "executable": executable,
                "future_field": true
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
        assert_eq!(endpoint.arguments, ["provider"]);

        std::fs::write(
            registration_dir.join("bad.secretspec.json"),
            serde_json::json!({
                "executable": "relative/provider"
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
        assert_eq!(selected.arguments, ["provider"]);
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
        assert_eq!(selected.arguments, ["provider"]);
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

        assert_eq!(first.arguments, ["provider"]);
        assert_eq!(second.arguments, ["provider"]);
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
            fn get(&self, _: Address<'_>) -> Result<Option<SecretBytes>> {
                Ok(None)
            }
            fn set(&self, _: Address<'_>, _: &SecretBytes) -> Result<()> {
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
                    scheme: "example".into(),
                    executable,
                    arguments: Vec::new(),
                    environment: Vec::new(),
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
        let registration = registration_dir.join("example.secretspec.json");
        std::fs::write(
            &registration,
            serde_json::json!({
                "executable": executable
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

    /// Builds a discoverable registration whose endpoint lives at `executable`.
    #[cfg(unix)]
    fn registration_for(directory: &Path, executable: &Path) -> ProviderDiscovery {
        use std::os::unix::fs::PermissionsExt;
        let registration_dir = directory.join("providers.d");
        std::fs::create_dir_all(&registration_dir).unwrap();
        std::fs::set_permissions(&registration_dir, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let registration = registration_dir.join("example.secretspec.json");
        std::fs::write(
            &registration,
            serde_json::json!({
                "executable": executable
            })
            .to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&registration, std::fs::Permissions::from_mode(0o600)).unwrap();
        ProviderDiscovery {
            user_directory: Some(registration_dir),
            ..ProviderDiscovery::default()
        }
    }

    #[cfg(unix)]
    fn owner_only_executable(at: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(at, "endpoint").unwrap();
        std::fs::set_permissions(at, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// A tight parent is not enough: anyone who can write to a directory above
    /// it can replace the parent wholesale.
    #[cfg(unix)]
    #[test]
    fn a_writable_ancestor_above_a_tight_parent_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let loose = directory.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        let bin = loose.join("bin");
        let executable = bin.join("endpoint");
        owner_only_executable(&executable);
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let discovery = registration_for(directory.path(), &executable);

        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(discovery.resolve("example").unwrap().is_some());

        // Only the ancestor changes; the parent and the executable stay tight.
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = discovery.resolve("example").unwrap_err().to_string();
        assert!(error.contains("group- or world-writable"), "{error}");
    }

    /// A world-writable ancestor is safe when it is sticky, which is what makes
    /// a build or temporary directory under /tmp usable.
    #[cfg(unix)]
    #[test]
    fn a_sticky_world_writable_ancestor_is_accepted() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let sticky = directory.path().join("sticky");
        std::fs::create_dir(&sticky).unwrap();
        let bin = sticky.join("bin");
        let executable = bin.join("endpoint");
        owner_only_executable(&executable);
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let discovery = registration_for(directory.path(), &executable);
        std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(discovery.resolve("example").unwrap().is_some());
    }

    /// A symlinked component is validated as the chain it resolves to, so a
    /// redirect into a writable location is refused rather than followed.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_component_is_validated_through_to_its_target() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        let executable = real.join("bin").join("endpoint");
        owner_only_executable(&executable);
        std::fs::set_permissions(
            executable.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();

        // The registration names a symlinked spelling of the same endpoint.
        let linked = directory.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let discovery = registration_for(directory.path(), &linked.join("bin").join("endpoint"));
        assert!(discovery.resolve("example").unwrap().is_some());

        // Loosening the resolved target is caught through the link.
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = discovery.resolve("example").unwrap_err().to_string();
        assert!(error.contains("group- or world-writable"), "{error}");
    }

    /// The Windows ACL walk must not stop after the immediate parent. Keeping
    /// the ACL lookup injectable makes the traversal deterministic even when
    /// the hosted runner's temporary and drive-root ACLs differ.
    #[cfg(windows)]
    #[test]
    fn windows_rejects_an_untrusted_higher_executable_ancestor() {
        let directory = tempfile::tempdir().unwrap();
        let higher = directory.path().join("higher");
        let parent = higher.join("bin");
        std::fs::create_dir_all(&parent).unwrap();
        let executable = parent.join("endpoint.exe");
        std::fs::write(&executable, "endpoint").unwrap();
        let higher = higher.canonicalize().unwrap();
        let parent = parent.canonicalize().unwrap();
        let mut checked = Vec::new();

        let error = check_windows_parent_security_with(&executable, false, |ancestor, _| {
            checked.push(ancestor.to_path_buf());
            Ok(ancestor != higher)
        })
        .unwrap_err()
        .to_string();

        assert_eq!(checked.first(), Some(&parent));
        assert!(
            checked.contains(&higher),
            "higher ancestor was never checked"
        );
        assert!(error.contains("outside the trust domain"), "{error}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_accepts_a_trusted_chain_through_the_volume_root() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("bin");
        std::fs::create_dir(&parent).unwrap();
        let executable = parent.join("endpoint.exe");
        std::fs::write(&executable, "endpoint").unwrap();
        let resolved = executable.canonicalize().unwrap();
        let resolved_parent = resolved.parent().unwrap().to_path_buf();
        let volume_root = resolved.ancestors().last().unwrap().to_path_buf();
        let mut checked = Vec::new();

        check_windows_parent_security_with(&executable, false, |ancestor, _| {
            checked.push(ancestor.to_path_buf());
            // The directory ACL tests model the root's only untrusted effective
            // right as FILE_ADD_SUBDIRECTORY, which is safe for existing paths.
            Ok(true)
        })
        .unwrap();

        assert_eq!(checked.first(), Some(&resolved_parent));
        assert_eq!(checked.last(), Some(&volume_root));
    }

    #[cfg(windows)]
    #[test]
    fn windows_checks_the_resolved_target_of_a_directory_link() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        let parent = real.join("bin");
        std::fs::create_dir_all(&parent).unwrap();
        let executable = parent.join("endpoint.exe");
        std::fs::write(&executable, "endpoint").unwrap();
        let linked = directory.path().join("linked");
        if let Err(error) = std::os::windows::fs::symlink_dir(&real, &linked) {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("failed to create directory link: {error}");
        }
        let linked_executable = linked.join("bin").join("endpoint.exe");
        let resolved_real = real.canonicalize().unwrap();
        let mut checked = Vec::new();

        check_windows_parent_security_with(&linked_executable, false, |ancestor, _| {
            checked.push(ancestor.to_path_buf());
            Ok(ancestor != resolved_real)
        })
        .unwrap_err();

        assert!(
            checked.contains(&resolved_real),
            "resolved target was never checked: {checked:?}"
        );
        assert!(
            !checked.contains(&linked),
            "unresolved link spelling was checked: {checked:?}"
        );
    }

    fn vars(names: &[&str]) -> Vec<(OsString, OsString)> {
        names
            .iter()
            .map(|name| (OsString::from(name), OsString::from("value")))
            .collect()
    }

    fn names(environment: &BTreeMap<OsString, OsString>) -> Vec<&str> {
        environment
            .keys()
            .map(|name| name.to_str().unwrap())
            .collect()
    }

    #[test]
    fn endpoint_environment_keeps_the_base_set_and_declared_entries_only() {
        let parent = vars(&[
            "PATH",
            "LC_ALL",
            "XDG_RUNTIME_DIR",
            "VAULT_TOKEN",
            "VAULT_ADDR",
            "OP_SERVICE_ACCOUNT_TOKEN",
            "EXAMPLE_TOKEN",
            "EXAMPLE_TOKENIZER",
        ]);
        let base = endpoint_environment(parent.clone(), &[]);
        assert_eq!(names(&base), ["LC_ALL", "PATH", "XDG_RUNTIME_DIR"]);

        let declared = endpoint_environment(parent, &["EXAMPLE_TOKEN".into(), "VAULT_*".into()]);
        assert_eq!(
            names(&declared),
            [
                "EXAMPLE_TOKEN",
                "LC_ALL",
                "PATH",
                "VAULT_ADDR",
                "VAULT_TOKEN",
                "XDG_RUNTIME_DIR"
            ]
        );
    }

    #[test]
    fn launch_options_replace_the_parent_environment() {
        let directory = tempfile::tempdir().unwrap();
        let provider = ExternalProvider::from_url(
            endpoint(directory.path(), "endpoint", "provider"),
            &ProviderUrl::new(url::Url::parse("example://team-a").unwrap()),
        );
        let options = provider.launch_options(vars(&["PATH", "VAULT_TOKEN"]));
        match options.environment {
            Environment::Replace(environment) => assert_eq!(names(&environment), ["PATH"]),
            Environment::Inherit(_) => panic!("endpoints must not inherit the environment"),
        }
    }

    #[test]
    fn registration_environment_entries_are_validated() {
        for valid in ["VAULT_TOKEN", "VAULT_*"] {
            validate_environment_pattern(valid).unwrap();
        }
        for invalid in ["", "*", "A=B", "A*B", "A B", "A\0"] {
            assert!(
                validate_environment_pattern(invalid).is_err(),
                "{invalid:?} was accepted"
            );
        }

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("endpoint");
        std::fs::write(&executable, "endpoint").unwrap();
        let registration_dir = directory.path().join("providers.d");
        std::fs::create_dir(&registration_dir).unwrap();
        let discovery = ProviderDiscovery {
            user_directory: Some(registration_dir.clone()),
            ..ProviderDiscovery::default()
        };
        let register = |environment: serde_json::Value| {
            std::fs::write(
                registration_dir.join("example.secretspec.json"),
                serde_json::json!({ "executable": executable, "environment": environment })
                    .to_string(),
            )
            .unwrap();
        };
        register(serde_json::json!(["VAULT_*"]));
        let endpoint = discovery
            .resolve_with_security("example", &AllowAll)
            .unwrap()
            .unwrap();
        assert_eq!(endpoint.environment, ["VAULT_*"]);

        register(serde_json::json!(["*"]));
        assert!(
            discovery
                .resolve_with_security("example", &AllowAll)
                .is_err()
        );
    }

    /// The child really starts with the filtered environment: a variable the
    /// test process has but the base set excludes never reaches it.
    #[cfg(unix)]
    #[test]
    fn a_launched_endpoint_does_not_see_undeclared_parent_variables() {
        use std::os::unix::fs::PermissionsExt;
        // Cargo sets both for the test process. One is excluded; the other is
        // declared by the endpoint and must pass through.
        let (Some(_), Some(_)) = (
            std::env::var_os("CARGO_MANIFEST_DIR"),
            std::env::var_os("CARGO_PKG_NAME"),
        ) else {
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("environment");
        let executable = directory.path().join("endpoint");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nexport -p > '{}'\n", output.display()),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = ExternalProvider::from_url(
            ProviderEndpoint {
                scheme: "example".into(),
                executable,
                arguments: vec!["provider".into()],
                environment: vec!["CARGO_PKG_*".into()],
            },
            &ProviderUrl::new(url::Url::parse("example://team-a").unwrap()),
        );
        provider.with_credential_broker(Arc::new(NoCredentials));
        assert!(
            provider.initialize().is_err(),
            "the script is not an endpoint"
        );

        let exported = std::fs::read_to_string(&output).unwrap();
        let exported: HashSet<&str> = exported
            .lines()
            .filter_map(|line| {
                line.strip_prefix("export ")
                    .or_else(|| line.strip_prefix("declare -x "))
            })
            .map(|rest| rest.split('=').next().unwrap())
            .collect();
        assert!(exported.contains("CARGO_PKG_NAME"), "{exported:?}");
        assert!(!exported.contains("CARGO_MANIFEST_DIR"), "{exported:?}");
    }

    struct NoCredentials;
    impl ProviderCredentialBroker for NoCredentials {
        fn get(
            &self,
            _: &ProviderCredentialPrincipal,
            _: &ProviderCredentialRequest,
        ) -> Result<Option<SecretBytes>> {
            Ok(None)
        }
    }

    #[test]
    fn brokered_credentials_are_scoped_by_the_configured_uri() {
        let team_a = ProviderCredentialPrincipal::new("example", "example://team-a");
        let team_b = ProviderCredentialPrincipal::new("example", "example://team-b");
        let address = |principal: &ProviderCredentialPrincipal, scope: &str| {
            brokered_credential_address(principal, scope, "token").item
        };
        // An endpoint reporting one constant scope for every account.
        assert_ne!(address(&team_a, ""), address(&team_b, ""));
        assert_eq!(address(&team_a, ""), address(&team_a, ""));
        assert_ne!(address(&team_a, "one"), address(&team_a, "two"));
        // Moving bytes between the URI and scope cannot alias a slot.
        assert_ne!(
            address(&ProviderCredentialPrincipal::new("example", "ab"), "c"),
            address(&ProviderCredentialPrincipal::new("example", "a"), "bc"),
        );
        let item = address(&team_a, "");
        assert!(
            item.starts_with("secretspec/provider-credentials/example/")
                && item.ends_with("/token"),
            "{item}"
        );
    }

    /// Cache planning compares configured entries before any cache hit and
    /// must not start the endpoint, which may prompt for credentials.
    #[cfg(unix)]
    #[test]
    fn configured_entry_comparison_never_launches_the_endpoint() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("launched");
        let executable = directory.path().join("endpoint");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\n: > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let provider = ExternalProvider::from_url(
            ProviderEndpoint {
                scheme: "example".into(),
                executable,
                arguments: vec!["provider".into()],
                environment: Vec::new(),
            },
            &ProviderUrl::new(url::Url::parse("example://team-a").unwrap()),
        );
        let convention = |key| Address::Convention {
            project: "app",
            profile: "default",
            key,
        };
        let native = NativeAddress {
            item: "db".into(),
            ..NativeAddress::default()
        };
        let same = |left: Address<'_>, right: Address<'_>| {
            crate::provider::same_configured_entries(&provider, left, &provider, right).unwrap()
        };

        assert!(same(convention("DB"), convention("DB")));
        assert!(!same(convention("DB"), convention("API")));
        assert!(same(Address::Native(&native), Address::Native(&native)));
        assert!(!marker.exists(), "planning started the endpoint");
    }

    /// `Drop` closes a live session with this helper. On a current-thread
    /// runtime `block_in_place` would panic, aborting a process that is
    /// already unwinding.
    #[tokio::test(flavor = "current_thread")]
    async fn session_cleanup_does_not_block_in_place_on_a_current_thread_runtime() {
        let (sender, receiver) = std::sync::mpsc::channel();
        run_to_completion_or_detach(async move {
            sender.send(()).unwrap();
        });
        receiver.recv().unwrap();
    }

    #[test]
    fn session_cleanup_completes_before_returning_outside_a_runtime() {
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = completed.clone();
        run_to_completion_or_detach(async move {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    }
}
