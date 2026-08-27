use super::address::unsupported_coord_error;
use super::{Address, ProviderCredentials};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// Context supplied when a provider discovers secret declarations.
///
/// Available starting with SecretSpec 0.18. Hierarchical providers use the
/// project and profile to render a bounded namespace before listing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiscoveryContext<'a> {
    pub project: &'a str,
    pub profile: &'a str,
}

impl<'a> DiscoveryContext<'a> {
    pub const fn new(project: &'a str, profile: &'a str) -> Self {
        Self { project, profile }
    }
}

/// Whether a value SecretSpec produces after a provider miss is written back
/// to the primary provider.
///
/// This capability is available since SecretSpec 0.19. It is deliberately
/// separate from read and write support: a provider may reject ordinary writes
/// while explicitly allowing SecretSpec to return a generated or prompted
/// value for the current resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducedValuePersistence {
    /// Store the produced value through [`Provider::set`] and reuse it on
    /// subsequent resolutions. This is the default for storage providers.
    Persist,
    /// Return the produced value only from the current materializing
    /// resolution. No provider write or cache refresh is performed.
    Ephemeral,
}

/// A provider value with an optional authoritative validity bound.
///
/// `expires_at_unix_ms` is when the secret itself expires according to the
/// provider. `None` means no bound is known. Resolver cache freshness is
/// separate metadata and must never be placed here.
#[derive(Clone)]
pub struct ProviderValue {
    pub value: SecretString,
    pub expires_at_unix_ms: Option<u64>,
}

impl ProviderValue {
    pub fn new(value: SecretString, expires_at_unix_ms: Option<u64>) -> Self {
        Self {
            value,
            expires_at_unix_ms,
        }
    }
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

    /// Returns whether this provider understands an optional native-address
    /// coordinate. Available since SecretSpec 0.20.
    ///
    /// Static providers inherit the existing slice-based behavior. External
    /// providers override this hook because their coordinate list is selected
    /// during protocol initialization and is therefore owned by the instance.
    fn supports_coord(&self, name: &str) -> bool {
        self.supported_coords().contains(&name)
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
        for (name, value) in coords.coordinates() {
            if name == "item" || value.is_none() {
                continue;
            }
            if !self.supports_coord(name) {
                return Err(unsupported_coord_error(self.name(), &coords, name));
            }
        }
        Ok(coords)
    }

    /// Resolves the canonical coordinates an operation uses to identify one
    /// physical entry. Available since SecretSpec 0.19.
    ///
    /// The default is the validated address returned by
    /// [`resolve_coords`](Provider::resolve_coords). Providers that interpret
    /// an omitted coordinate as a concrete default must override this method
    /// and fill that default, so destructive preflight compares the same
    /// identity that `get`, `set`, and `delete` operate on.
    fn entry_coordinates<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        self.resolve_coords(addr)
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

    /// Retrieves a value together with its provider-reported validity bound.
    ///
    /// Available starting with SecretSpec 0.20. Existing providers inherit a
    /// compatibility implementation with unknown expiry. Providers issuing or
    /// reading time-bounded credentials override this method; callers use it in
    /// preference to [`get`](Provider::get) when they can preserve metadata.
    fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        self.get(addr)
            .map(|value| value.map(|value| ProviderValue::new(value, None)))
    }

    /// Whether this provider can return plaintext values through
    /// [`get`](Provider::get) or [`get_many`](Provider::get_many).
    ///
    /// Available starting with SecretSpec 0.20. Write-only stores override this
    /// to return `false`; callers that only need presence can then use
    /// [`exists`](Provider::exists) without accidentally attempting a value
    /// read. This capability check never returns a secret value.
    fn supports_read(&self) -> bool {
        true
    }

    /// Tests whether one addressed secret exists without requiring its value.
    ///
    /// Available starting with SecretSpec 0.20. Readable providers inherit the
    /// compatibility implementation. Write-only providers must override it with
    /// a value-free backend operation.
    fn exists(&self, addr: Address<'_>) -> Result<bool> {
        Ok(self.get(addr)?.is_some())
    }

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

    /// Writes a secret at `addr` that need not outlive `max_age`. Available
    /// since SecretSpec 0.17.
    ///
    /// The default ignores the hint and writes a plain value, which is always
    /// correct: SecretSpec's own cache envelope carries the expiration time and
    /// remains the freshness authority. A provider whose store can drop a value
    /// on its own overrides this, so a cached secret stops existing even if
    /// SecretSpec never runs again — a store-side bound on how long a copy of
    /// someone else's secret sits there.
    ///
    /// A provider that cannot apply the expiry it was asked for must return an
    /// error rather than write an unexpiring value: the caller asked for a
    /// bounded copy, and silently storing an unbounded one is worse than not
    /// caching at all.
    fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretString,
        max_age: std::time::Duration,
    ) -> Result<()> {
        let _ = max_age;
        self.set(addr, value)
    }

    /// Deletes a secret at `addr`. Available since SecretSpec 0.17.
    ///
    /// Providers opt into deletion explicitly. This is used by cache
    /// invalidation and, starting in SecretSpec 0.18, by `secretspec delete`
    /// and `secretspec import --delete-source`. It defaults to a clear
    /// unsupported-operation error so adding the method does not silently make
    /// destructive behavior available to every provider.
    ///
    /// Deleting is idempotent: an address that holds nothing is `Ok(false)`,
    /// not an error. The `bool` reports whether an entry was actually removed,
    /// so callers can tell a real invalidation from a no-op instead of counting
    /// addresses they merely asked about.
    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let _ = addr;
        Err(self.deletion_unsupported())
    }

    /// Whether this provider implements [`delete`](Provider::delete) at all.
    ///
    /// Defaults to `false`, matching the default `delete`. A provider that
    /// overrides `delete` must override this too, so that
    /// [`check_deletable`](Provider::check_deletable) can answer the coarse
    /// question — *can this provider delete anything?* — without performing a
    /// deletion to find out.
    ///
    /// This is deliberately separate from `check_deletable`: that method
    /// answers whether one specific address is deletable, which a provider may
    /// refuse for reasons of its own, while this one reports a static property
    /// of the implementation.
    fn supports_delete(&self) -> bool {
        false
    }

    /// The error both `delete` and `check_deletable` report for a provider that
    /// cannot delete. Shared so the preflight and the operation cannot disagree
    /// about the reason.
    fn deletion_unsupported(&self) -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(format!(
            "provider '{}' does not support deleting secrets",
            self.name()
        ))
    }

    /// Reports whether this provider can delete `addr`, without changing the
    /// store. Available since SecretSpec 0.19.
    ///
    /// Destructive multi-secret operations use this during preflight so an
    /// unsupported native address cannot be discovered only after earlier
    /// source entries have already been removed. Providers with deletion
    /// policies beyond coordinate support must override this method and have
    /// [`delete`](Provider::delete) enforce the same policy.
    ///
    /// The default first rejects providers that cannot delete at all. Without
    /// that, every provider inheriting the default `delete` — which errors —
    /// still passed preflight, because resolving coordinates says nothing about
    /// whether the store can be written to. `import --delete-source` then
    /// aborted in its deletion phase, after the copy phase had already mutated
    /// the destination, which is the late discovery this method exists to
    /// prevent.
    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        if !self.supports_delete() {
            return Err(self.deletion_unsupported());
        }
        self.resolve_coords(addr).map(|_| ())
    }

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

    /// Controls whether SecretSpec persists a value produced by a declaration's
    /// `generate` configuration after this provider's read route misses.
    /// Available since SecretSpec 0.19.
    ///
    /// [`ProducedValuePersistence::Ephemeral`] affects only automatic
    /// generation. Ordinary [`set`](Provider::set), deletion, imports, and
    /// provider reads keep their usual behavior. The capability must be pure:
    /// callers may inspect it without running authentication preflight or other
    /// provider I/O.
    fn generated_value_persistence(&self) -> ProducedValuePersistence {
        ProducedValuePersistence::Persist
    }

    /// Controls whether a value entered for a `prompt = true` declaration is
    /// stored after the provider's read route misses. Available since
    /// SecretSpec 0.19.
    ///
    /// The default persists the answer through [`Provider::set`], making the
    /// prompt a first-use provisioning step. A provider that cannot or must not
    /// retain values can return [`ProducedValuePersistence::Ephemeral`] so the
    /// answer is used only by the current `run` resolution.
    fn prompted_value_persistence(&self) -> ProducedValuePersistence {
        ProducedValuePersistence::Persist
    }

    /// Describes the provider-native destination that a write to `addr` will
    /// change. Available since SecretSpec 0.19.
    ///
    /// The description is intended for a pre-write CLI preview and must not
    /// contain credentials. Providers with file-backed or otherwise structured
    /// storage should override this when their URI plus native coordinates do
    /// not identify the resolved file/container and selector clearly. The
    /// default renders the provider-native coordinates.
    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        Ok(self.resolve_coords(addr)?.render())
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
    fn name(&self) -> &str;

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

    /// Returns a credential-free identity for the physical store this provider
    /// addresses.
    ///
    /// Unlike [`Self::uri`], this value is not user-facing attribution. It is
    /// used when SecretSpec must decide whether two differently configured
    /// providers can read and write the same storage location, such as when
    /// ensuring a cache is distinct from its authoritative sources. Authentication
    /// choices that do not change the store must therefore not change this
    /// identity, and protocol-compatible provider names should return the same
    /// identity when they target the same store.
    ///
    /// Most providers have one public spelling for a store, so the default uses
    /// their canonical URI. Providers with equivalent spellings or compatible
    /// identities should override this method.
    fn storage_identity(&self) -> String {
        self.uri()
    }

    /// Returns the identity of the container holding a resolved secret entry.
    /// Available since SecretSpec 0.18.
    ///
    /// This differs from [`Self::storage_identity`] only for providers whose
    /// public URI contains an addressing template. Cache routing must retain
    /// that template so sibling address spaces remain distinct, while
    /// destructive operations compare the template's resolved native
    /// coordinates separately and need the identity of the underlying
    /// container here.
    fn entry_container_identity(&self) -> String {
        self.storage_identity()
    }

    /// Returns whether `self` and `other` resolve `addr` to the same physical
    /// secret entry. Available since SecretSpec 0.18.
    ///
    /// This compatibility method applies one address to both providers. New
    /// cross-endpoint operations should use [`Self::same_entries`] when source
    /// and destination can have independent refs.
    fn same_entry(&self, other: &dyn Provider, addr: Address<'_>) -> Result<bool> {
        self.same_entries(addr, other, addr)
    }

    /// Returns whether `self` and `other` resolve their respective addresses to
    /// the same physical secret entry. Available since SecretSpec 0.19.
    ///
    /// Destructive cross-provider operations must use this instead of comparing
    /// [`uri`](Provider::uri) strings: one store may have multiple equivalent
    /// spellings, and provider URIs can include convention templates that are
    /// only meaningful after resolving a concrete address. The physical store
    /// and the resolved native coordinates must both match before an entry is
    /// considered shared.
    fn same_entries(
        &self,
        self_addr: Address<'_>,
        other: &dyn Provider,
        other_addr: Address<'_>,
    ) -> Result<bool> {
        if !same_storage_container(self, other) {
            return Ok(false);
        }

        Ok(self.entry_coordinates(self_addr)? == other.entry_coordinates(other_addr)?)
    }

    /// Returns the path that identifies a filesystem-backed store, if any.
    /// Available since SecretSpec 0.18.
    ///
    /// The path is compared using filesystem identity when it exists, catching
    /// lexical aliases, symlinks, and hard links. Providers that are not backed
    /// by one path keep the default and are identified by
    /// [`storage_identity`](Provider::storage_identity).
    fn physical_store_path(&self) -> Option<&std::path::Path> {
        None
    }

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

    /// Records the app-requested authorization lifetime for approval surfaces.
    /// Available starting with SecretSpec 0.20.
    ///
    /// This is an untrusted default: the provider and user decide the actual
    /// grant lifetime. The default implementation ignores it.
    fn set_requested_authorization_duration(&self, _duration: Option<std::time::Duration>) {}

    /// Records structured context about the software integration invoking
    /// SecretSpec, such as `git` performing `credential_get` for `github.com`.
    ///
    /// This metadata is distinct from the user-supplied access reason and never
    /// satisfies `require_reason`. Providers may use it for their own audit or
    /// approval surfaces. The default implementation ignores it.
    ///
    /// Takes `&self` for the same reason as [`Provider::set_reason`]: SecretSpec
    /// applies it after providers may have been wrapped in `Arc`.
    ///
    /// Available since SecretSpec 0.20.
    fn set_caller(&self, _caller: Option<crate::CallerContext>) {}

    /// Records the declared project for this provider session. Available
    /// starting with SecretSpec 0.20.
    ///
    /// This is resolver-declared context for provider policy, audit, and
    /// approval surfaces. It is not an authenticated application identity and
    /// must not be used as one. Convention addresses carry the same project;
    /// native addresses need this session context because their coordinates do
    /// not.
    fn set_project(&self, _project: &str) {}

    /// Records the profile this session resolves under. Available starting with
    /// SecretSpec 0.20.
    ///
    /// A [`Convention`](Address::Convention) address carries the profile, so a
    /// provider whose namespace varies by profile reads it there. A
    /// [`Native`](Address::Native) address carries coordinates only, and a
    /// provider that needs the profile for something the coordinates do not name
    /// — Infisical's environment, say — would otherwise have to reject every
    /// native address. Such a provider keeps this as a fallback, behind whatever
    /// its URI states explicitly.
    ///
    /// This is context, not naming: it must not change
    /// [`uri`](Provider::uri) or
    /// [`storage_identity`](Provider::storage_identity), or one store would take
    /// a different identity under each profile and invalidate its own cache
    /// entries.
    ///
    /// Takes `&self` (relying on interior mutability) so it can be applied after
    /// the provider is wrapped in an `Arc` (as preflight-enabled providers are).
    /// The default implementation ignores it, which is correct for providers
    /// whose addresses already carry everything they need.
    fn set_profile(&self, _profile: &str) {}

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

    /// Discovers declarations using the project and profile that the new
    /// manifest will contain. Available starting with SecretSpec 0.18.
    ///
    /// Providers whose namespace does not depend on that context can ignore
    /// it. Hierarchical providers should use it so discovery stays inside the
    /// same namespace as [`convention_address`](Provider::convention_address).
    /// The default implementation returns an unsupported-operation error.
    /// Implementations return the public declaration [`Secret`](crate::Secret),
    /// built with constructors such as [`Secret::required`](crate::Secret::required),
    /// rather than the raw configuration document type used before 0.20.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let context = DiscoveryContext::new("payments", "production");
    /// let mut secrets = HashMap::new();
    /// secrets.insert(
    ///     "DATABASE_URL".to_string(),
    ///     Secret::required("Database connection URL"),
    /// );
    /// # let _ = context;
    /// ```
    fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, crate::Secret>> {
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

    /// Batch form of [`get_with_metadata`](Provider::get_with_metadata).
    ///
    /// Existing providers retain their optimized `get_many` implementation and
    /// report unknown expiry. A provider with per-value lifetime metadata must
    /// override this method as well as the single-value form.
    fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        self.get_many(requests).map(|values| {
            values
                .into_iter()
                .map(|(name, value)| (name, ProviderValue::new(value, None)))
                .collect()
        })
    }

    /// Tests a batch of addressed secrets for presence, returning the request
    /// names that exist.
    ///
    /// Available starting with SecretSpec 0.20. Readable providers reuse their
    /// batch read surface. Write-only providers use bounded concurrent
    /// [`exists`](Provider::exists) calls unless they override this with a native
    /// listing operation.
    fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        if self.supports_read() {
            return self
                .get_many(requests)
                .map(|values| values.into_keys().collect());
        }
        exists_each(self, requests)
    }
}

/// Returns a stable lexical identity for a filesystem store that may not exist
/// yet. Canonicalizing the parent resolves symlink aliases without requiring
/// the destination file itself to exist.
fn comparable_missing_file_path(path: &std::path::Path) -> std::path::PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let Some(parent) = absolute.parent() else {
        return absolute;
    };
    let Some(file_name) = absolute.file_name() else {
        return absolute;
    };

    std::fs::canonicalize(parent)
        .map(|parent| parent.join(file_name))
        .unwrap_or(absolute)
}

/// Returns whether two providers address the same physical storage container,
/// without comparing any one secret's resolved coordinates.
///
/// This is the store half of [`Provider::same_entries`]. Keeping it here lets
/// non-destructive diagnostics use exactly the same filesystem and provider
/// identity rules as destructive import preflight, including symlinks, hard
/// links, missing file paths, and provider-specific container identities.
pub(crate) fn same_storage_container<L, R>(left: &L, right: &R) -> bool
where
    L: Provider + ?Sized,
    R: Provider + ?Sized,
{
    match (left.physical_store_path(), right.physical_store_path()) {
        (Some(left), Some(right)) => same_file::is_same_file(left, right).unwrap_or_else(|_| {
            let left = comparable_missing_file_path(left);
            let right = comparable_missing_file_path(right);
            left == right
        }),
        (None, None) => left.entry_container_identity() == right.entry_container_identity(),
        _ => false,
    }
}

/// Default max concurrent unique-address fetches in [`get_each`].
///
/// Providers that open one TCP connection per concurrent `get` (cold HTTP
/// clients, reverse proxies in front of Vault/OpenBao, rate-limited APIs) can
/// drop part of an unbounded burst. A modest default keeps resolution fast
/// without stampeding the store. Override with [`get_each_concurrency`].
const DEFAULT_GET_EACH_CONCURRENCY: usize = 8;

/// Env var that caps concurrent unique-address fetches in [`get_each`].
///
/// Must parse as an integer ≥ 1; invalid or missing values fall back to
/// [`DEFAULT_GET_EACH_CONCURRENCY`].
pub(crate) const GET_EACH_CONCURRENCY_ENV: &str = "SECRETSPEC_PROVIDER_CONCURRENCY";

/// Resolved concurrency limit for [`get_each`].
pub(crate) fn get_each_concurrency() -> usize {
    std::env::var(GET_EACH_CONCURRENCY_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(DEFAULT_GET_EACH_CONCURRENCY)
}

/// Applies `map` in bounded, thread-scoped waves while preserving input order.
///
/// Shared by provider batch reads and higher-level fallback-chain reads so both
/// honor [`GET_EACH_CONCURRENCY_ENV`] without an additional thread-pool
/// dependency.
pub(crate) fn map_concurrently<T, R, F>(items: &[T], concurrency: usize, map: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let concurrency = concurrency.max(1);
    if items.len() <= 1 || concurrency == 1 {
        return items.iter().map(map).collect();
    }

    let mut mapped = Vec::with_capacity(items.len());
    for chunk in items.chunks(concurrency) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunk.iter().map(|item| scope.spawn(|| map(item))).collect();
            mapped.extend(
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("concurrent map thread panicked")),
            );
        });
    }
    mapped
}

/// Shared fallback used by the default [`Provider::get_many`] and by batch
/// overrides for the part of a request set their bulk surface cannot serve:
/// deduplicates identical addresses and fetches each unique address once,
/// concurrently (capped), mirroring the per-item threading batch overrides do.
pub(crate) fn get_each<P: Provider + ?Sized>(
    provider: &P,
    requests: &[(&str, Address<'_>)],
) -> Result<HashMap<String, SecretString>> {
    get_each_with(requests, |addr| provider.get(addr))
}

/// Bounded, deduplicating fallback for write-only providers that expose only a
/// single-address presence operation.
pub(crate) fn exists_each<P: Provider + ?Sized>(
    provider: &P,
    requests: &[(&str, Address<'_>)],
) -> Result<HashSet<String>> {
    let mut groups: HashMap<Address<'_>, Vec<&str>> = HashMap::new();
    for (name, addr) in requests {
        groups.entry(*addr).or_default().push(name);
    }
    let groups: Vec<(Address<'_>, Vec<&str>)> = groups.into_iter().collect();
    let checked: Vec<(Vec<&str>, Result<bool>)> =
        map_concurrently(&groups, get_each_concurrency(), |(addr, names)| {
            (names.clone(), provider.exists(*addr))
        });

    let mut present = HashSet::new();
    for (names, result) in checked {
        if result? {
            present.extend(names.into_iter().map(str::to_string));
        }
    }
    Ok(present)
}

/// [`get_each`] with an operation-scoped fetch function.
///
/// Providers can use this when the per-address reads need to share state that
/// belongs to exactly one `get_many` call, such as a short-lived login token.
pub(crate) fn get_each_with<'a, F, T>(
    requests: &[(&str, Address<'a>)],
    fetch: F,
) -> Result<HashMap<String, T>>
where
    F: Fn(Address<'a>) -> Result<Option<T>> + Sync,
    T: Clone + Send,
{
    let mut groups: HashMap<Address<'_>, Vec<&str>> = HashMap::new();
    for (name, addr) in requests {
        groups.entry(*addr).or_default().push(name);
    }

    // Stable vec so we can process in concurrency-sized waves. HashMap
    // iteration order is irrelevant: each address is independent.
    let groups: Vec<(Address<'_>, Vec<&str>)> = groups.into_iter().collect();

    // One address is the common case (a single secret, or several sharing a
    // `ref`); `map_concurrently` keeps it on this thread. Larger sets fan out in
    // capped waves so they do not stampede a provider.
    let fetched: Vec<(Vec<&str>, Result<Option<T>>)> =
        map_concurrently(&groups, get_each_concurrency(), |(addr, names)| {
            (names.clone(), fetch(*addr))
        });

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
    fn supports_coord(&self, name: &str) -> bool {
        (**self).supports_coord(name)
    }
    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        (**self).resolve_coords(addr)
    }
    fn entry_coordinates<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        (**self).entry_coordinates(addr)
    }
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        (**self).get(addr)
    }
    fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        (**self).get_with_metadata(addr)
    }
    fn supports_read(&self) -> bool {
        (**self).supports_read()
    }
    fn exists(&self, addr: Address<'_>) -> Result<bool> {
        (**self).exists(addr)
    }
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        (**self).set(addr, value)
    }
    fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretString,
        max_age: std::time::Duration,
    ) -> Result<()> {
        (**self).set_expiring(addr, value, max_age)
    }
    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        (**self).delete(addr)
    }
    fn supports_delete(&self) -> bool {
        (**self).supports_delete()
    }
    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        (**self).check_deletable(addr)
    }
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        (**self).check_writable(addr)
    }
    fn generated_value_persistence(&self) -> ProducedValuePersistence {
        (**self).generated_value_persistence()
    }
    fn prompted_value_persistence(&self) -> ProducedValuePersistence {
        (**self).prompted_value_persistence()
    }
    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        (**self).describe_write_target(addr)
    }
    fn auth_scope_key(&self) -> Option<String> {
        (**self).auth_scope_key()
    }
    fn name(&self) -> &str {
        (**self).name()
    }
    fn uri(&self) -> String {
        (**self).uri()
    }
    fn same_entry(&self, other: &dyn Provider, addr: Address<'_>) -> Result<bool> {
        (**self).same_entry(other, addr)
    }
    fn same_entries(
        &self,
        self_addr: Address<'_>,
        other: &dyn Provider,
        other_addr: Address<'_>,
    ) -> Result<bool> {
        (**self).same_entries(self_addr, other, other_addr)
    }
    fn storage_identity(&self) -> String {
        (**self).storage_identity()
    }
    fn entry_container_identity(&self) -> String {
        (**self).entry_container_identity()
    }
    fn physical_store_path(&self) -> Option<&std::path::Path> {
        (**self).physical_store_path()
    }
    fn set_reason(&self, reason: Option<String>) {
        (**self).set_reason(reason);
    }
    fn set_requested_authorization_duration(&self, duration: Option<std::time::Duration>) {
        (**self).set_requested_authorization_duration(duration);
    }
    fn set_caller(&self, caller: Option<crate::CallerContext>) {
        (**self).set_caller(caller);
    }
    fn set_project(&self, project: &str) {
        (**self).set_project(project);
    }
    fn set_profile(&self, profile: &str) {
        (**self).set_profile(profile);
    }
    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, crate::Secret>> {
        (**self).reflect(context)
    }
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        (**self).get_many(requests)
    }
    fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        (**self).get_many_with_metadata(requests)
    }
    fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        (**self).exists_many(requests)
    }
}
