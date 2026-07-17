//! # Provider System
//!
//! The provider module implements a trait-based plugin architecture for managing secrets
//! across different storage backends. Providers handle the actual storage and retrieval
//! of secrets, supporting everything from local files to cloud-based secret managers.
//!
//! ## Architecture
//!
//! The provider system is built around the [`Provider`] trait, which defines a common
//! interface for all storage backends. Each provider implementation handles:
//!
//! - Profile-aware storage (e.g., development vs production secrets)
//! - Project isolation (secrets are namespaced by project)
//! - Optional write support (some providers are read-only)
//!
//! ## Available Providers
//!
//! - [`KeyringProvider`]: System keyring integration (default)
//! - [`DotEnvProvider`]: `.env` file support
//! - [`EnvProvider`]: Environment variables (read-only)
//! - [`OnePasswordProvider`]: OnePassword integration
//! - [`LastPassProvider`]: LastPass integration
//! - [`AkvProvider`]: Azure Key Vault integration
//!
//! ## URI-Based Configuration
//!
//! Providers support URI-based configuration for flexibility:
//!
//! ```text
//! keyring://
//! dotenv://.env.production
//! onepassword://vault
//! lastpass://folder
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use secretspec::provider::{Address, Provider};
//! use std::convert::TryFrom;
//!
//! // Create a provider from a URI string
//! let provider = Box::<dyn Provider>::try_from("keyring://")?;
//!
//! let addr = Address::convention("myproject", "production", "API_KEY");
//!
//! // Store a secret
//! provider.set(addr, &"secret123".to_string().into())?;
//!
//! // Retrieve a secret
//! if let Some(value) = provider.get(addr)? {
//!     println!("API_KEY retrieved");
//! }
//! ```

use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, percent_encode};
use secrecy::{ExposeSecret, SecretString};
use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use url::Url;

/// Credentials handed to a provider at construction.
///
/// Maps semantic provider-specific names (for example `access_token`) to
/// secret values. Providers may retain environment-variable fallback for
/// standalone compatibility, but environment names are not part of this API.
pub(crate) type ProviderCredentials = HashMap<String, SecretString>;

/// Resolves a semantic provider credential, falling back to the provider's
/// conventional environment variable when no explicit credential was supplied.
pub(crate) fn credential_or_env(
    credentials: &ProviderCredentials,
    name: &str,
    env_var: &str,
) -> Option<String> {
    credentials
        .get(name)
        .map(|secret| secret.expose_secret().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var(env_var)
                .ok()
                .filter(|value| !value.is_empty())
        })
}

/// Characters that are invalid in URI hosts but might appear in provider config
/// values like vault names (e.g., 1Password vault "Home Lab").
/// Structural URI delimiters (@, /, :, ?, #) are intentionally excluded so they
/// are preserved during encoding.
pub(crate) const URI_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b']')
    .add(b'|')
    .add(b'^')
    .add(b'\\');

/// Like [`URI_ENCODE_SET`] but also encodes `:`. Used for Windows absolute paths
/// (e.g. `C:\path`) where the drive-letter colon would otherwise be read as a
/// `host:port` separator and fail parsing with "invalid port number".
const WINDOWS_PATH_ENCODE_SET: &AsciiSet = &URI_ENCODE_SET.add(b':');

/// Like [`URI_ENCODE_SET`] but also encodes the characters that are structurally
/// significant inside a URI query string. Query *values* (e.g. the `V` in
/// `?key=V`) are read back with `application/x-www-form-urlencoded` semantics via
/// [`ProviderUrl::query_pairs`], which treats `&` as a pair separator, `+` as a
/// space and `%` as an escape, while `#` ends the query at the URL level. Leaving
/// those unencoded (as plain [`URI_ENCODE_SET`] does) makes a value like
/// `/a&b` or `/a+b` decode to something different on the way back. Encoding them
/// makes [`ProviderUrl::encode_query`] a true inverse of that parsing, so query
/// values round-trip. Path and host components keep using [`URI_ENCODE_SET`].
const QUERY_ENCODE_SET: &AsciiSet = &URI_ENCODE_SET.add(b'%').add(b'#').add(b'&').add(b'+');

/// Detects a Windows-style absolute path such as `C:\path` or `C:/path`.
fn is_windows_abs_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// A URL wrapper that automatically percent-decodes all accessors.
///
/// Providers receive `&ProviderUrl` instead of `&Url`, ensuring they always
/// get decoded values (e.g., `"Home Lab"` instead of `"Home%20Lab"`).
///
/// **Limitation:** Structural URI delimiters (`@`, `/`, `:`, `?`, `#`) are
/// never encoded, so they cannot appear literally in provider config values
/// like vault or folder names. For example, a vault named `"My@Vault"` would
/// be misinterpreted as a username/host separator.
pub(crate) struct ProviderUrl(Url);

impl ProviderUrl {
    pub fn new(url: Url) -> Self {
        Self(url)
    }

    pub fn scheme(&self) -> &str {
        self.0.scheme()
    }

    pub fn host(&self) -> Option<String> {
        self.0
            .host_str()
            .map(|h| percent_decode_str(h).decode_utf8_lossy().into_owned())
    }

    pub fn username(&self) -> String {
        percent_decode_str(self.0.username())
            .decode_utf8_lossy()
            .into_owned()
    }

    pub fn password(&self) -> Option<String> {
        self.0
            .password()
            .map(|p| percent_decode_str(p).decode_utf8_lossy().into_owned())
    }

    pub fn path(&self) -> String {
        percent_decode_str(self.0.path())
            .decode_utf8_lossy()
            .into_owned()
    }

    #[cfg(any(feature = "vault", test))]
    pub fn port(&self) -> Option<u16> {
        self.0.port()
    }

    #[cfg(any(feature = "awssm", feature = "vault", test))]
    pub fn query_pairs(&self) -> url::form_urlencoded::Parse<'_> {
        self.0.query_pairs()
    }

    /// Returns the value of the first `key=value` query pair matching `key`,
    /// treating an empty value as absent. The owned `String` is the inverse of
    /// [`encode_query`](Self::encode_query).
    pub fn query_value(&self, key: &str) -> Option<String> {
        self.0
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
            .filter(|v| !v.is_empty())
    }

    /// Percent-encode a value for use in a URI path or host component (e.g., in
    /// `uri()` methods).
    pub fn encode(value: &str) -> String {
        percent_encode(value.as_bytes(), URI_ENCODE_SET).to_string()
    }

    /// Percent-encode a value for use as a URI query-string value (the `V` in
    /// `?key=V`). Unlike [`encode`](Self::encode), this also escapes the
    /// characters that `application/x-www-form-urlencoded` parsing treats
    /// specially, so the value survives a round-trip through
    /// [`query_pairs`](Self::query_pairs).
    pub fn encode_query(value: &str) -> String {
        percent_encode(value.as_bytes(), QUERY_ENCODE_SET).to_string()
    }
}

/// Executes an async future in a blocking context.
///
/// If already inside a tokio runtime, uses `block_in_place` with the
/// existing runtime handle. Otherwise, creates a new runtime.
#[allow(dead_code)]
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
            .block_on(future),
    }
}

#[cfg(feature = "akv")]
pub mod akv;
#[cfg(feature = "awssm")]
pub mod awssm;
#[cfg(feature = "bws")]
pub mod bws;
pub mod dotenv;
pub mod env;
#[cfg(feature = "gcsm")]
pub mod gcsm;
pub mod gopass;
#[cfg(feature = "keyring")]
pub mod keyring;
pub mod lastpass;
pub mod onepassword;
pub mod pass;
pub mod protonpass;
#[cfg(feature = "vault")]
pub mod vault;
#[macro_use]
pub mod macros;

#[cfg(test)]
pub(crate) mod tests;

/// Information about a secret storage provider.
///
/// Contains metadata used for displaying available providers to users,
/// including the provider's name, description, and example URIs.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// The canonical name of the provider (e.g., "keyring", "1password").
    pub name: &'static str,
    /// A human-readable description of what the provider does.
    #[cfg_attr(not(any(feature = "cli", test)), allow(dead_code))]
    pub description: &'static str,
    /// Example URIs showing how to configure this provider.
    #[cfg_attr(not(any(feature = "cli", test)), allow(dead_code))]
    pub examples: &'static [&'static str],
}

impl ProviderInfo {
    /// Formats the provider information for display, including examples if available.
    ///
    /// # Returns
    ///
    /// A formatted string in one of two formats:
    /// - Without examples: "name: description"
    /// - With examples: "name: description (e.g., example1, example2)"
    ///
    /// # Example
    ///
    /// ```ignore
    /// let info = ProviderInfo {
    ///     name: "onepassword",
    ///     description: "OnePassword password manager",
    ///     examples: &["onepassword://vault", "onepassword://work@Production"],
    /// };
    /// assert_eq!(
    ///     info.display_with_examples(),
    ///     "onepassword: OnePassword password manager (e.g., onepassword://vault, onepassword://work@Production)"
    /// );
    /// ```
    #[cfg(any(feature = "cli", test))]
    pub fn display_with_examples(&self) -> String {
        if self.examples.is_empty() {
            format!("{}: {}", self.name, self.description)
        } else {
            format!(
                "{}: {} (e.g., {})",
                self.name,
                self.description,
                self.examples.join(", ")
            )
        }
    }
}

/// How a provider operation addresses a secret.
///
/// Every read and write names its secret one of two ways:
///
/// - [`Convention`](Address::Convention): SecretSpec's own naming scheme. The
///   provider maps `(project, profile, key)` into its namespace, by default
///   `{provider}/{project}/{profile}/{key}` or the provider's configured
///   format string.
/// - [`Native`](Address::Native): explicit coordinates from a secret's `ref`
///   field, naming one externally managed secret in the provider's own terms
///   (item, field, ...). The provider translates the coordinates and rejects
///   any it has no equivalent for.
///
/// Which stores are consulted is decided entirely by provider resolution
/// (chains, overrides, defaults); the address only supplies the name to look
/// up in each.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address<'a> {
    /// SecretSpec's `{project}/{profile}/{key}` naming convention.
    Convention {
        project: &'a str,
        profile: &'a str,
        key: &'a str,
    },
    /// Native coordinates of one externally managed secret (a `ref`).
    Native(&'a NativeAddress),
}

impl<'a> Address<'a> {
    /// Convention-scheme constructor, in the enum's own field order.
    pub fn convention(project: &'a str, profile: &'a str, key: &'a str) -> Self {
        Address::Convention {
            project,
            profile,
            key,
        }
    }
}

/// Rejects native-address coordinates a provider has no equivalent for.
///
/// Enforced once for every address inside the default
/// [`resolve_coords`](Provider::resolve_coords), against the provider's
/// declared [`supported_coords`](Provider::supported_coords): a coordinate the
/// provider does not name produces an error that names the coordinate, the ref
/// it came from, and how to fix it, so a `ref` written for one store fails
/// loudly when routing points it at a store that cannot honor those
/// coordinates, instead of silently resolving something else.
fn reject_unsupported_coords(
    provider: &str,
    addr: &NativeAddress,
    supported: &[&str],
) -> Result<()> {
    for (name, value) in addr.coordinates() {
        // `item` is the one coordinate every provider consumes.
        if name == "item" || value.is_none() {
            continue;
        }
        if !supported.contains(&name) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "the {provider} provider does not support the `{name}` coordinate. \
                 Drop `{name}` from the ref for `{item}`.",
                item = addr.item
            )));
        }
    }
    Ok(())
}

/// Resolves an address for flat stores whose secrets have no sub-components:
/// any address, convention or `ref`, names the entry via `item` alone, every
/// other coordinate having been rejected by the provider's empty
/// [`supported_coords`](Provider::supported_coords).
pub(crate) fn flat_item<'a, P: Provider + ?Sized>(
    provider: &P,
    addr: Address<'a>,
) -> Result<Cow<'a, str>> {
    match provider.resolve_coords(addr)? {
        Cow::Borrowed(native) => Ok(Cow::Borrowed(native.item.as_str())),
        Cow::Owned(native) => Ok(Cow::Owned(native.item)),
    }
}

/// Macro support types
pub use macros::{PROVIDER_REGISTRY, ProviderRegistration};

/// Returns a list of all available providers with their metadata.
///
/// This includes the provider name, description, and example URIs for each
/// supported provider type.
///
/// # Returns
///
/// A vector of `ProviderInfo` structs containing metadata for each provider.
#[cfg(feature = "cli")]
pub fn providers() -> Vec<ProviderInfo> {
    PROVIDER_REGISTRY
        .iter()
        .map(|reg| reg.info.clone())
        .collect()
}

/// Splits a provider spec at the first `:` into its scheme token and the rest
/// (empty for a bare provider name). The one definition of "the scheme",
/// shared by the `TryFrom<&str>` URI parser and [`spec_names_known_provider`],
/// so the two cannot disagree on how a spec is split.
fn split_spec(spec: &str) -> (&str, &str) {
    match spec.find(':') {
        Some(pos) => (&spec[..pos], &spec[pos + 1..]),
        None => (spec, ""),
    }
}

/// The registry entry whose schemes contain `scheme`. The one definition of
/// "which registration a scheme resolves to", shared by every lookup below and
/// by [`provider_from_url`], so they cannot drift on the matching rule.
fn registration_for_scheme(scheme: &str) -> Option<&'static ProviderRegistration> {
    PROVIDER_REGISTRY
        .iter()
        .find(|reg| reg.schemes.contains(&scheme))
}

/// Whether `spec` names a registered provider: a bare name (`keyring`), a
/// `scheme:path` shorthand (`dotenv:.env.production`), or a full URI. Checks
/// the leading scheme token against the registry without constructing a
/// provider, so alias resolution can tell a valid provider spec apart from an
/// undefined alias.
///
/// The common `1password` misspelling of `onepassword` errors with its
/// corrective "use `onepassword` instead" message. Both the `TryFrom<&str>`
/// URI parser and alias resolution gate specs through here, so the correction
/// fires in one place no matter which path first sees the spec.
pub(crate) fn spec_names_known_provider(spec: &str) -> Result<bool> {
    let (scheme, _) = split_spec(spec);
    if scheme == "1password" {
        return Err(SecretSpecError::ProviderOperationFailed(
            "Invalid scheme '1password'. Use 'onepassword' instead (e.g., onepassword://vault)"
                .to_string(),
        ));
    }
    Ok(registration_for_scheme(scheme).is_some())
}

/// The semantic credential names accepted by the provider named by `spec`, or
/// an empty slice for an unknown scheme. Lets alias validation reject a
/// declaration the provider would silently ignore.
pub(crate) fn credential_names_for_spec(spec: &str) -> &'static [&'static str] {
    let (scheme, _) = split_spec(spec);
    registration_for_scheme(scheme).map_or(&[], |reg| reg.credential_names)
}

/// The registered display name for the provider `spec` names, falling back to
/// the spec's scheme token. Pure registry lookup: lets callers show which
/// provider a spec routes to without constructing it (construction now fetches
/// provider credentials, so a display-only build could fail or do I/O).
pub(crate) fn provider_display_name_for_spec(spec: &str) -> String {
    let (scheme, _) = split_spec(spec);
    registration_for_scheme(scheme)
        .map(|reg| reg.info.name.to_string())
        .unwrap_or_else(|| scheme.to_string())
}

/// Trait defining the interface for secret storage providers.
///
/// All secret storage backends must implement this trait to integrate with SecretSpec.
/// The trait is designed to be flexible enough to support various storage mechanisms
/// while maintaining a consistent interface.
///
/// # Thread Safety
///
/// Providers must be `Send + Sync` as they may be used across thread boundaries
/// in multi-threaded applications.
///
/// # Profile Support
///
/// Providers should support profile-based secret isolation, allowing different values
/// for the same key across environments (e.g., development, staging, production).
///
/// # Implementation Guidelines
///
/// - Providers should handle their own error cases and return appropriate `Result` types
/// - Storage paths should follow the pattern: `{provider}/{project}/{profile}/{key}`
/// - Providers may choose to be read-only by overriding [`check_writable`](Provider::check_writable)
/// - Provider names should be lowercase and descriptive
pub trait Provider: Send + Sync {
    /// Compiles SecretSpec's `{project}/{profile}/{key}` naming convention into
    /// this store's native coordinates: the same address space a secret's
    /// `ref` uses.
    ///
    /// This is the single owner of the provider's convention layout (format
    /// strings, path shapes, default vaults); the operation methods resolve
    /// every address through [`resolve_coords`](Provider::resolve_coords) and
    /// never re-derive names. Pure naming, no I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the convention inputs cannot form a valid name in
    /// this store (e.g. empty components, length limits).
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress>;

    /// The optional [`NativeAddress`] coordinates this store can honor, beyond
    /// the universally consumed `item` (e.g. `["field"]`).
    ///
    /// Declared as data rather than checked per operation: the default
    /// [`resolve_coords`](Provider::resolve_coords) rejects every coordinate a
    /// provider does not name here, so a store whose secrets have no
    /// sub-components gets the correct behavior from the empty default without
    /// writing any validation.
    fn supported_coords(&self) -> &'static [&'static str] {
        &[]
    }

    /// Resolves any [`Address`] to this store's native coordinates: a `ref`'s
    /// coordinates pass through as-is, a convention address is compiled via
    /// [`convention_address`](Provider::convention_address). Coordinates
    /// outside [`supported_coords`](Provider::supported_coords) are rejected,
    /// so every operation that resolves an address inherits the check.
    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        let coords = match addr {
            Address::Native(native) => Cow::Borrowed(native),
            Address::Convention {
                project,
                profile,
                key,
            } => Cow::Owned(self.convention_address(project, profile, key)?),
        };
        reject_unsupported_coords(self.name(), &coords, self.supported_coords())?;
        Ok(coords)
    }

    /// Retrieves the secret named by `addr`.
    ///
    /// See [`Address`] for the two naming schemes. A provider that cannot
    /// interpret a [`Native`](Address::Native) coordinate (e.g. a `field` on a
    /// store whose secrets have no sub-components) returns an error naming the
    /// coordinate rather than guessing.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(value))` if the secret exists
    /// - `Ok(None)` if the secret doesn't exist
    /// - `Err` if there was an error accessing the provider
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let addr = Address::Convention { project: "myapp", profile: "production", key: "DATABASE_URL" };
    /// match provider.get(addr)? {
    ///     Some(url) => println!("Database URL: {}", url),
    ///     None => println!("DATABASE_URL not found"),
    /// }
    /// ```
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>>;

    /// Stores a secret value at `addr`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the secret was successfully stored
    /// - `Err` if there was an error or the address is read-only
    ///
    /// # Errors
    ///
    /// This method should return an error whenever
    /// [`check_writable`](Provider::check_writable) does, for the same address.
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()>;

    /// Reports whether this provider can write to `addr`, and why not when it
    /// cannot.
    ///
    /// Callers use this to refuse a write before prompting for a value, so the
    /// error must be the same one [`set`](Provider::set) would return: state
    /// the policy here and have `set` call this method, rather than writing the
    /// rule twice.
    ///
    /// By default, providers are assumed to support writing. Read-only
    /// providers (like environment variables) reject every address; providers
    /// that can write their own layout but not externally managed secrets
    /// reject only [`Native`](Address::Native) addresses, and say so — a
    /// generic "provider is read-only" would be untrue of the store as a whole.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// provider.check_writable(addr)?;
    /// provider.set(addr, &value)?;
    /// ```
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let _ = addr;
        Ok(())
    }

    /// Identifies the shared authentication state this instance's preflight
    /// check probes, when that state outlives the instance.
    ///
    /// Instances of the same provider returning equal keys share one probe
    /// result process-wide. This matters because a secret's `providers` chain
    /// builds a fresh provider instance per (secret, URI) pair — without a
    /// scope key, N secrets would run N identical auth probes (each typically a
    /// CLI round-trip). The default `None` keeps the probe per-instance.
    fn auth_scope_key(&self) -> Option<String> {
        None
    }

    /// Returns the name of this provider.
    ///
    /// This should match the name registered with the provider macro.
    fn name(&self) -> &'static str;

    /// Returns the full URI representation of this provider.
    ///
    /// This includes any configuration like vault names, paths, etc.
    /// For example: "onepassword://VaultName" or "dotenv://.env.production"
    ///
    /// # Contract: the returned URI must be credential-free
    ///
    /// The audit log records this URI and the fallback-chain warnings print it,
    /// so it must never contain a secret the user embedded in the source URI
    /// (e.g. a `:password` or service-account token). Reconstruct the URI from
    /// non-secret attribution only — account, profile, namespace, host, path —
    /// and drop any credential, which authentication resolves from the
    /// environment or a token field instead. This contract is enforced for every
    /// registered scheme by `uri_never_echoes_a_userinfo_password` in
    /// `provider::tests`.
    fn uri(&self) -> String;

    /// Records a human-readable reason for the secrets access happening in this
    /// session (e.g. "secretspec run: deploy"), set via [`Secrets::with_reason`].
    ///
    /// Providers that support audit logging use this; for example the Proton Pass
    /// provider forwards it to `pass-cli` agent sessions, which require a reason
    /// for every audited item operation. The default implementation ignores it.
    ///
    /// Takes `&self` (relying on interior mutability) so it can be applied after
    /// the provider is wrapped in an `Arc` (as preflight-enabled providers are).
    ///
    /// [`Secrets::with_reason`]: crate::Secrets::with_reason
    fn set_reason(&self, _reason: Option<String>) {}

    /// Rebases any relative filesystem paths the provider holds against
    /// `base_dir`, the directory containing the `secretspec.toml` that
    /// configured it.
    ///
    /// File-backed providers (e.g. `dotenv`) take paths from the config or its
    /// provider aliases. Those paths must resolve relative to the project root,
    /// not the process's current working directory — otherwise running from a
    /// subdirectory with `--file ../secretspec.toml` looks for the `.env` file
    /// in the wrong place. [`Secrets`] calls this once at construction, before
    /// the provider performs any I/O. The default implementation does nothing,
    /// which is correct for providers that hold no relative paths.
    ///
    /// [`Secrets`]: crate::Secrets
    fn with_base_dir(&mut self, _base_dir: &std::path::Path) {}

    /// Hands semantic credentials to the provider.
    ///
    /// Called once inside the registration factory, on the concrete provider
    /// value *before* any `Arc`/`Box` wrapping. This must not be a
    /// post-construction call on a `Box<dyn Provider>`: like [`with_base_dir`],
    /// a `&mut self` hook cannot be forwarded through the blanket
    /// `impl Provider for Arc<T>` (an `Arc` gives no `&mut` access to its
    /// inner value), so a preflight provider — wrapped as `Box<Arc<P>>` — would
    /// silently receive the default no-op. The default implementation ignores
    /// the values, which is correct for providers that need no credentials.
    ///
    /// [`with_base_dir`]: Provider::with_base_dir
    fn with_credentials(&mut self, _credentials: ProviderCredentials) {}

    /// Discovers and returns all secrets available in this provider.
    ///
    /// This method is used to introspect the provider and find all available secrets.
    /// It's particularly useful for importing secrets from external sources.
    ///
    /// # Returns
    ///
    /// A HashMap where keys are secret names and values are `Secret` configurations.
    /// The default implementation returns an empty map, indicating the provider
    /// doesn't support reflection.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let secrets = provider.reflect()?;
    /// for (name, secret) in secrets {
    ///     println!("Found secret: {} = {:?}", name, secret);
    /// }
    /// ```
    fn reflect(&self) -> Result<HashMap<String, crate::config::Secret>> {
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Provider '{}' does not support reflection",
            self.name()
        )))
    }

    /// Retrieves multiple secrets in one batch operation.
    ///
    /// Each request pairs a secret name (the key of the returned map) with the
    /// [`Address`] to fetch it from, so a batch mixes convention secrets and
    /// `ref` secrets freely. Secrets that don't exist are omitted from the
    /// result.
    ///
    /// # Contract
    ///
    /// Requests naming identical addresses (several secrets sharing one `ref`)
    /// must be fetched once and share the value.
    ///
    /// # Default Implementation
    ///
    /// The default deduplicates identical addresses and fetches each unique
    /// address once, concurrently. Providers with a real batch surface (one
    /// listing, a bulk API) should override this to cut round-trips further.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        get_each(self, requests)
    }
}

/// Shared fallback used by the default [`Provider::get_many`] and by batch
/// overrides for the part of a request set their bulk surface cannot serve:
/// deduplicates identical addresses and fetches each unique address once,
/// concurrently, mirroring the per-item threading batch overrides do.
pub(crate) fn get_each<P: Provider + ?Sized>(
    provider: &P,
    requests: &[(&str, Address<'_>)],
) -> Result<HashMap<String, SecretString>> {
    let mut groups: HashMap<Address<'_>, Vec<&str>> = HashMap::new();
    for (name, addr) in requests {
        groups.entry(*addr).or_default().push(name);
    }

    // One address is the common case (a single secret, or several sharing a
    // `ref`); fetching it on this thread skips the scope and the spawn.
    let fetched: Vec<(Vec<&str>, Result<Option<SecretString>>)> = if groups.len() <= 1 {
        groups
            .into_iter()
            .map(|(addr, names)| (names, provider.get(addr)))
            .collect()
    } else {
        std::thread::scope(|scope| {
            let handles: Vec<_> = groups
                .into_iter()
                .map(|(addr, names)| (names, scope.spawn(move || provider.get(addr))))
                .collect();
            handles
                .into_iter()
                .map(|(names, handle)| {
                    (
                        names,
                        handle.join().expect("get_many fetch thread panicked"),
                    )
                })
                .collect()
        })
    };

    let mut results = HashMap::new();
    for (names, result) in fetched {
        if let Some(value) = result? {
            for name in names {
                results.insert(name.to_string(), value.clone());
            }
        }
    }
    Ok(results)
}

impl<T: Provider> Provider for std::sync::Arc<T> {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        (**self).convention_address(project, profile, key)
    }
    fn supported_coords(&self) -> &'static [&'static str] {
        (**self).supported_coords()
    }
    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        (**self).resolve_coords(addr)
    }
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        (**self).get(addr)
    }
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        (**self).set(addr, value)
    }
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        (**self).check_writable(addr)
    }
    fn auth_scope_key(&self) -> Option<String> {
        (**self).auth_scope_key()
    }
    fn name(&self) -> &'static str {
        (**self).name()
    }
    fn uri(&self) -> String {
        (**self).uri()
    }
    fn set_reason(&self, reason: Option<String>) {
        (**self).set_reason(reason);
    }
    fn reflect(&self) -> Result<HashMap<String, crate::config::Secret>> {
        (**self).reflect()
    }
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        (**self).get_many(requests)
    }
}

/// Return type from provider factories that pairs a provider with an
/// optional preflight check (e.g. authentication verification).
pub(crate) struct ProviderWithPreflight {
    pub provider: Box<dyn Provider>,
    pub preflight: Option<Box<dyn Fn() -> Result<()> + Send + Sync>>,
}

/// Process-wide deduplication of provider auth probes.
///
/// Caching the preflight check per provider *instance* was enough when one
/// instance served every secret, but a secret's `providers` fallback chain
/// builds a fresh instance per (secret, URI) pair, so N secrets would run N
/// identical auth probes (each a CLI round-trip). Providers whose auth state is
/// shared across instances advertise that via [`Provider::auth_scope_key`], and
/// [`PreflightGuard`] keys their probe here instead: the first caller per key
/// runs it, concurrent callers block on the same cell, and later callers
/// reuse the result.
///
/// Failures are returned to every caller waiting on the in-flight probe but
/// are not cached beyond that: the user may fix auth mid-process (e.g. unlock
/// the desktop app in a long-lived SDK process), so the next check re-probes.
type AuthCheckResult = std::result::Result<(), String>;
type AuthCheckCell = Arc<OnceLock<AuthCheckResult>>;

pub(crate) struct AuthCheckCache<K> {
    cells: Mutex<HashMap<K, AuthCheckCell>>,
}

impl<K> Default for AuthCheckCache<K> {
    fn default() -> Self {
        Self {
            cells: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: std::hash::Hash + Eq + Clone> AuthCheckCache<K> {
    pub(crate) fn check(
        &self,
        key: K,
        probe: impl FnOnce() -> std::result::Result<(), String>,
    ) -> std::result::Result<(), String> {
        let cell = self
            .cells
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_default()
            .clone();
        let result = cell.get_or_init(probe).clone();
        if result.is_err() {
            // Drop the failed cell so a later retry re-probes, but only if it
            // is still ours: another thread may have already replaced it.
            let mut cells = self.cells.lock().unwrap();
            if let Some(existing) = cells.get(&key)
                && Arc::ptr_eq(existing, &cell)
            {
                cells.remove(&key);
            }
        }
        result
    }
}

/// Auth probes shared across provider instances (see
/// [`Provider::auth_scope_key`]), keyed by provider name plus scope.
static PREFLIGHT_AUTH_CACHE: LazyLock<AuthCheckCache<(&'static str, String)>> =
    LazyLock::new(AuthCheckCache::default);

/// Wrapper that runs a preflight check exactly once before any provider
/// operation, caching the result for all subsequent calls.
struct PreflightGuard {
    inner: Box<dyn Provider>,
    preflight: Option<Box<dyn Fn() -> Result<()> + Send + Sync>>,
    result: OnceLock<std::result::Result<(), String>>,
}

impl PreflightGuard {
    fn new(pwp: ProviderWithPreflight) -> Self {
        Self {
            inner: pwp.provider,
            preflight: pwp.preflight,
            result: OnceLock::new(),
        }
    }

    fn check(&self) -> Result<()> {
        let Some(f) = &self.preflight else {
            return Ok(());
        };
        // A provider with a shared auth scope dedupes the probe process-wide
        // in PREFLIGHT_AUTH_CACHE, so the per-instance providers that a
        // secret's `providers` chain creates all reuse one probe.
        if let Some(scope) = self.inner.auth_scope_key() {
            return PREFLIGHT_AUTH_CACHE
                .check((self.inner.name(), scope), || {
                    f().map_err(|e| e.to_string())
                })
                .map_err(SecretSpecError::ProviderOperationFailed);
        }
        let result = self.result.get_or_init(|| f().map_err(|e| e.to_string()));
        match result {
            Ok(()) => Ok(()),
            Err(msg) => Err(SecretSpecError::ProviderOperationFailed(msg.clone())),
        }
    }
}

impl Provider for PreflightGuard {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        // Pure naming, no I/O: needs no auth preflight.
        self.inner.convention_address(project, profile, key)
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        self.inner.supported_coords()
    }

    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        // Pure naming, no I/O: needs no auth preflight.
        self.inner.resolve_coords(addr)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        self.check()?;
        self.inner.get(addr)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check()?;
        self.inner.set(addr, value)
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.inner.check_writable(addr)
    }

    fn auth_scope_key(&self) -> Option<String> {
        self.inner.auth_scope_key()
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn uri(&self) -> String {
        self.inner.uri()
    }

    fn set_reason(&self, reason: Option<String>) {
        self.inner.set_reason(reason);
    }

    fn with_base_dir(&mut self, base_dir: &std::path::Path) {
        self.inner.with_base_dir(base_dir);
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.inner.with_credentials(credentials);
    }

    fn reflect(&self) -> Result<HashMap<String, crate::config::Secret>> {
        self.check()?;
        self.inner.reflect()
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        self.check()?;
        self.inner.get_many(requests)
    }
}

impl TryFrom<String> for Box<dyn Provider> {
    type Error = SecretSpecError;

    /// Creates a provider instance from a URI string.
    ///
    /// This function handles various URI formats and normalizes them before parsing.
    /// It supports both full URIs and shorthand notations.
    ///
    /// # URI Formats
    ///
    /// - **Full URI**: `scheme://authority/path` (e.g., `onepassword://Production`)
    ///
    /// # Special Cases
    ///
    /// - **1password**: Will error suggesting to use `onepassword` instead
    /// - **Bare provider names**: Automatically converted to `provider://`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::convert::TryFrom;
    ///
    /// // Simple provider name
    /// let provider = Box::<dyn Provider>::try_from("keyring".to_string())?;
    ///
    /// // Full URI with configuration
    /// let provider = Box::<dyn Provider>::try_from("onepassword://Production".to_string())?;
    ///
    /// // Dotenv with path
    /// let provider = Box::<dyn Provider>::try_from("dotenv:.env.production".to_string())?;
    /// ```
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(&s as &str)
    }
}

impl TryFrom<&str> for Box<dyn Provider> {
    type Error = SecretSpecError;

    fn try_from(s: &str) -> Result<Self> {
        provider_from_spec(s, ProviderCredentials::new())
    }
}

/// Builds a boxed provider from a spec string (a bare name, `scheme:...`
/// shorthand, or full URI), handing it the supplied credentials. The shared
/// body of the string `TryFrom` impls: construction funnels here so URL
/// normalization and credential injection have exactly one home.
pub(crate) fn provider_from_spec(
    s: &str,
    credentials: ProviderCredentials,
) -> Result<Box<dyn Provider>> {
    // Parse the scheme from the input string
    let (scheme, rest) = split_spec(s);

    // Reject the `1password` misspelling (with its corrective error) and
    // check the scheme against the registry, through the same gate alias
    // resolution uses.
    if !spec_names_known_provider(s)? {
        // Check if it's a known provider name to give a better error
        if PROVIDER_REGISTRY.iter().any(|reg| reg.info.name == scheme) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Provider '{}' exists but URI parsing failed",
                scheme
            )));
        } else {
            return Err(SecretSpecError::ProviderNotFound(scheme.to_string()));
        }
    }

    // Build a proper URL with the correct scheme.
    //
    // Windows absolute paths (e.g. `dotenv://C:\path\.env`) need special care:
    // the drive-letter colon looks like a `host:port` separator and parsing
    // fails with "invalid port number". Encode the whole path (drive colon and
    // backslashes included) into an opaque host so it round-trips back out via
    // `ProviderUrl::host()`. A Unix absolute path stays in the authority-less
    // `scheme:///abs/path` form, which already parses cleanly.
    let path_candidate = rest.trim_start_matches('/');
    let url_string = if is_windows_abs_path(path_candidate) {
        format!(
            "{}://{}",
            scheme,
            percent_encode(path_candidate.as_bytes(), WINDOWS_PATH_ENCODE_SET)
        )
    } else {
        let url_string = match rest {
            // Just scheme name (e.g., "keyring")
            "" | ":" => format!("{}://", scheme),
            // Standard URI format already has // (e.g., "onepassword://vault")
            s if s.starts_with("//") => format!("{}:{}", scheme, s),
            // Path only format (e.g., "dotenv:/path/to/.env")
            s if s.starts_with('/') => format!("{}://{}", scheme, s),
            // Everything else - assume it's a host or path component
            s => format!("{}://{}", scheme, s),
        };

        // Percent-encode characters that are invalid in URIs but might appear in
        // provider config values (e.g., spaces in 1Password vault names like "Home Lab")
        let scheme_end = url_string.find("://").unwrap() + 3;
        let (prefix, rest) = url_string.split_at(scheme_end);
        format!(
            "{}{}",
            prefix,
            percent_encode(rest.as_bytes(), URI_ENCODE_SET)
        )
    };

    let proper_url = Url::parse(&url_string).map_err(|e| {
        SecretSpecError::ProviderOperationFailed(format!(
            "Invalid provider specification '{}': {}",
            s, e
        ))
    })?;

    provider_from_url(&ProviderUrl::new(proper_url), credentials)
}

impl TryFrom<&Url> for Box<dyn Provider> {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> Result<Self> {
        provider_from_url(&ProviderUrl::new(url.clone()), ProviderCredentials::new())
    }
}

pub(crate) fn provider_from_url(
    url: &ProviderUrl,
    credentials: ProviderCredentials,
) -> Result<Box<dyn Provider>> {
    let scheme = url.scheme();

    let registration = registration_for_scheme(scheme)
        .ok_or_else(|| SecretSpecError::ProviderNotFound(scheme.to_string()))?;

    let pwp = (registration.factory)(url, credentials)?;
    if pwp.preflight.is_some() {
        Ok(Box::new(PreflightGuard::new(pwp)))
    } else {
        Ok(pwp.provider)
    }
}

#[cfg(test)]
mod auth_cache_tests {
    use super::AuthCheckCache;
    use std::cell::Cell;

    #[test]
    fn success_probes_once_per_key() {
        let cache = AuthCheckCache::default();
        let probes = Cell::new(0);
        for _ in 0..3 {
            let result = cache.check("key", || {
                probes.set(probes.get() + 1);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
        assert_eq!(probes.get(), 1);
    }

    #[test]
    fn failure_is_not_cached() {
        let cache = AuthCheckCache::default();
        assert_eq!(
            cache.check("key", || Err("not signed in".to_string())),
            Err("not signed in".to_string())
        );
        // A later check re-probes and can observe recovered auth
        // (e.g. after `op signin`).
        assert_eq!(cache.check("key", || Ok(())), Ok(()));
        // ...and the recovery is then cached.
        let probes = Cell::new(0);
        assert_eq!(
            cache.check("key", || {
                probes.set(probes.get() + 1);
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(probes.get(), 0);
    }

    #[test]
    fn keys_are_independent() {
        let cache = AuthCheckCache::default();
        assert_eq!(cache.check("a", || Ok(())), Ok(()));
        assert_eq!(
            cache.check("b", || Err("nope".to_string())),
            Err("nope".to_string())
        );
        // "a" stays cached despite "b" failing.
        assert_eq!(cache.check("a", || Err("unused".to_string())), Ok(()));
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;
    use std::collections::HashMap;
    use url::Url;

    fn url(s: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(s).unwrap())
    }

    #[test]
    fn host_and_path_are_percent_decoded() {
        let u = url("keyring://Home%20Lab/My%20Path");
        assert_eq!(u.host().as_deref(), Some("Home Lab"));
        assert_eq!(u.path(), "/My Path");
    }

    #[test]
    fn username_and_password_are_percent_decoded() {
        let u = url("onepassword://work%40acct:tok%20en@Vault");
        assert_eq!(u.username(), "work@acct");
        assert_eq!(u.password().as_deref(), Some("tok en"));
        assert_eq!(u.host().as_deref(), Some("Vault"));
    }

    #[test]
    fn missing_password_and_port_are_none() {
        let u = url("keyring://host");
        assert_eq!(u.password(), None);
        assert_eq!(u.port(), None);
        assert_eq!(u.username(), "");
    }

    #[test]
    fn port_is_parsed_when_present() {
        assert_eq!(url("https://example.com:8200/").port(), Some(8200));
    }

    #[test]
    fn detects_windows_absolute_paths() {
        assert!(is_windows_abs_path(r"C:\Users\foo"));
        assert!(is_windows_abs_path("C:/Users/foo"));
        assert!(is_windows_abs_path(r"d:\x"));
        // Not absolute Windows paths:
        assert!(!is_windows_abs_path("/tmp/foo"));
        assert!(!is_windows_abs_path("relative/path"));
        assert!(!is_windows_abs_path("C:"));
        assert!(!is_windows_abs_path("vault"));
    }

    #[test]
    fn windows_dotenv_path_parses_instead_of_failing_on_port() {
        // The drive-letter colon must not be read as a `host:port` separator.
        let provider = Box::<dyn Provider>::try_from(r"dotenv://C:\Users\foo\.env");
        assert!(
            provider.is_ok(),
            "Windows dotenv path should parse, got {:?}",
            provider.err()
        );
    }

    #[test]
    fn query_pairs_are_decoded() {
        let u = url("keyring://h/p?prefix=a%20b&kv=v2");
        let pairs: HashMap<String, String> = u
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(pairs.get("prefix").map(String::as_str), Some("a b"));
        assert_eq!(pairs.get("kv").map(String::as_str), Some("v2"));
    }

    #[test]
    fn encode_escapes_spaces_but_keeps_plain() {
        assert_eq!(ProviderUrl::encode("plain"), "plain");
        assert_eq!(ProviderUrl::encode("Home Lab"), "Home%20Lab");
    }

    #[test]
    fn windows_drive_paths_parse_as_provider_specs() {
        // "C:" must not be treated as host:port ("invalid port number").
        for spec in [
            r"dotenv://C:\Users\me\.env",
            r"dotenv://C:/Users/me/.env",
            r"dotenv:C:\Users\me\.env",
        ] {
            assert!(
                Box::<dyn Provider>::try_from(spec).is_ok(),
                "should parse: {}",
                spec
            );
        }
        // Unix and relative forms are unaffected.
        assert!(Box::<dyn Provider>::try_from("dotenv:///tmp/.env").is_ok());
        assert!(Box::<dyn Provider>::try_from("dotenv://.env").is_ok());
    }

    #[test]
    fn encode_query_escapes_query_significant_chars() {
        // Unlike `encode`, the query encoder must escape the bytes that
        // form-urlencoded parsing treats specially, so values round-trip through
        // `query_pairs`. Path separators stay readable.
        assert_eq!(ProviderUrl::encode_query("/a/b"), "/a/b");
        assert_eq!(ProviderUrl::encode_query("a&b"), "a%26b");
        assert_eq!(ProviderUrl::encode_query("a+b"), "a%2Bb");
        assert_eq!(ProviderUrl::encode_query("a#b"), "a%23b");
        assert_eq!(ProviderUrl::encode_query("a%b"), "a%25b");
        assert_eq!(ProviderUrl::encode_query("a b"), "a%20b");

        // Round-trips back through form-urlencoded parsing.
        let value = "/srv/a&b+c#d%e f";
        let encoded = ProviderUrl::encode_query(value);
        let u = url(&format!("keyring://?store_dir={encoded}"));
        let decoded = u
            .query_pairs()
            .find(|(k, _)| k == "store_dir")
            .map(|(_, v)| v.into_owned());
        assert_eq!(decoded.as_deref(), Some(value));
    }

    #[test]
    fn provider_info_display_with_and_without_examples() {
        let with = ProviderInfo {
            name: "onepassword",
            description: "OnePassword",
            examples: &["onepassword://vault", "onepassword://work@Production"],
        };
        assert_eq!(
            with.display_with_examples(),
            "onepassword: OnePassword (e.g., onepassword://vault, onepassword://work@Production)"
        );

        let without = ProviderInfo {
            name: "env",
            description: "Environment variables",
            examples: &[],
        };
        assert_eq!(
            without.display_with_examples(),
            "env: Environment variables"
        );
    }
}

#[cfg(test)]
mod provider_credentials_tests {
    use super::{ProviderCredentials, credential_or_env};
    use crate::tests::EnvVarGuard;
    use secrecy::SecretString;

    fn credentials(name: &str, value: &str) -> ProviderCredentials {
        let mut credentials = ProviderCredentials::new();
        credentials.insert(name.to_string(), SecretString::new(value.into()));
        credentials
    }

    #[test]
    fn explicit_credential_wins_over_environment() {
        // The lock guard serializes all env mutation across the test binary;
        // the var guard restores the previous value even if an assert panics.
        let _lock = crate::tests::scrub_resolution_env();
        const NAME: &str = "access_token";
        const ENV_VAR: &str = "SECRETSPEC_TEST_PROVIDER_CREDENTIAL";
        let _var = EnvVarGuard::set(ENV_VAR, "from-env");

        assert_eq!(
            credential_or_env(&credentials(NAME, "explicit"), NAME, ENV_VAR).as_deref(),
            Some("explicit"),
        );
    }

    #[test]
    fn environment_is_a_fallback() {
        let _lock = crate::tests::scrub_resolution_env();
        const NAME: &str = "access_token";
        const ENV_VAR: &str = "SECRETSPEC_TEST_PROVIDER_CREDENTIAL_FALLBACK";
        let _var = EnvVarGuard::set(ENV_VAR, "from-env");

        // With no explicit credential, the provider's conventional environment
        // variable remains available as a fallback.
        assert_eq!(
            credential_or_env(&ProviderCredentials::new(), NAME, ENV_VAR).as_deref(),
            Some("from-env"),
        );
        // Empty explicit values are ignored and fall through as well.
        assert_eq!(
            credential_or_env(&credentials(NAME, ""), NAME, ENV_VAR).as_deref(),
            Some("from-env"),
        );
    }
}

/// Property tests for the URI encoding every provider's `uri()` runs through.
///
/// `QUERY_ENCODE_SET` states its own contract: it "makes `ProviderUrl::encode_query`
/// a true inverse of that parsing, so query values round-trip". That is a claim
/// about every string, checked today against one hand-written value in one
/// provider's tests. These quantify it.
#[cfg(test)]
mod encoding_properties {
    use super::*;
    use proptest::prelude::*;

    /// Reads a query value back the way a provider's `TryFrom` does.
    fn query_value_of(uri: &str, key: &str) -> Option<String> {
        let url = ProviderUrl::new(Url::parse(uri).ok()?);
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    proptest! {
        /// A query value survives `encode_query` -> parse unchanged.
        ///
        /// The characters that break this are the ones form-urlencoded parsing
        /// claims: `&` splits a pair, `+` becomes a space, `%` starts an escape,
        /// `#` ends the query. Each silently truncates or mangles a value rather
        /// than failing, so the store a provider ends up talking to is not the
        /// one the URI named.
        #[test]
        fn encode_query_round_trips(value in ".*") {
            let uri = format!("keyring://?v={}", ProviderUrl::encode_query(&value));
            let decoded = query_value_of(&uri, "v");
            prop_assert_eq!(
                decoded.as_deref(),
                Some(value.as_str()),
                "value {:?} did not survive the round-trip through {:?}",
                value,
                uri,
            );
        }

        /// Encoding is deterministic: the same value always encodes the same
        /// way, so a `uri()` rendering is stable across runs (it lands in audit
        /// records, which are compared).
        #[test]
        fn encode_query_is_deterministic(value in ".*") {
            prop_assert_eq!(
                ProviderUrl::encode_query(&value),
                ProviderUrl::encode_query(&value),
            );
        }

        /// An encoded value never carries a character that would end the query
        /// or start a new pair, whatever went in.
        #[test]
        fn encoded_values_are_query_safe(value in ".*") {
            let encoded = ProviderUrl::encode_query(&value);
            prop_assert!(
                !encoded.contains('&') && !encoded.contains('#') && !encoded.contains('+'),
                "encoded {encoded:?} still carries a query-structural character",
            );
        }
    }
}
