//! Shared configuration and identity for provider backends and adapters.
use super::address::unsupported_coord_error;
use super::{Address, ProducedValuePersistence, ProviderCredentials};
use crate::{NativeAddress, Result, SecretSpecError};
use std::borrow::Cow;

/// Configuration, capabilities, and identity shared by provider adapters (0.22+).
///
/// Implement this alongside `AsyncProvider`. Existing synchronous `Provider`
/// implementations keep their interface and are forwarded by `AsyncProviderAdapter`.
/// Configuration and identity accessors must not fetch secrets. In particular,
/// configured entry coordinates and configured physical paths must not perform I/O.
pub trait ProviderBase: Send + Sync {
    /// Whether sync capability accessors need async initialization first.
    /// Native async accessors always report already cached capabilities.
    fn requires_initialization(&self) -> bool {
        false
    }
    /// Configures the shared retry policy (0.22+). Called before first I/O.
    fn set_retry_policy(&mut self, _policy: super::RetryPolicy) {}

    /// Native SDK/session retry owners must not receive an outer retry loop (0.22+).
    fn retry_ownership(&self) -> super::RetryOwnership {
        super::RetryOwnership::Shared
    }

    /// Whether a mutation may be repeated without changing its observable result (0.22+).
    /// Reads are always handled independently. Mutations require explicit opt-in.
    fn retry_safe(&self, _operation: super::RetryOperation, _addr: Address<'_>) -> bool {
        false
    }

    /// Compiles SecretSpec's `{project}/{profile}/{key}` naming convention into
    /// this store's native coordinates: the same address space a secret's
    /// `ref` uses.
    ///
    /// This is the single owner of the provider's convention layout (format
    /// strings, path shapes, default vaults); the operation methods resolve
    /// every address through [`resolve_coords`](super::Provider::resolve_coords) and
    /// never re-derive names. Pure naming, no I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the convention inputs cannot form a valid name in
    /// this store (e.g. empty components, length limits).
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        _key: &str,
    ) -> Result<NativeAddress> {
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "provider '{}' does not support convention addresses",
            self.name()
        )))
    }

    /// The optional [`NativeAddress`] coordinates this store can honor, beyond
    /// the universally consumed `item` (e.g. `["field"]`).
    ///
    /// Declared as data rather than checked per operation: the default
    /// [`resolve_coords`](super::Provider::resolve_coords) rejects every coordinate a
    /// provider does not name here, so a store whose secrets have no
    /// sub-components gets the correct behavior from the empty default without
    /// writing any validation.
    fn supported_coords(&self) -> &'static [&'static str] {
        &[]
    }

    /// Returns whether this provider understands an optional native-address
    /// coordinate. Available since SecretSpec 0.21.
    ///
    /// Static providers inherit the existing slice-based behavior. External
    /// providers override this hook because their coordinate list is selected
    /// during protocol initialization and is therefore owned by the instance.
    fn supports_coord(&self, name: &str) -> bool {
        self.supported_coords().contains(&name)
    }

    /// Resolves any [`Address`] to this store's native coordinates: a `ref`'s
    /// coordinates pass through as-is, a convention address is compiled via
    /// [`convention_address`](super::Provider::convention_address). Coordinates
    /// outside [`supported_coords`](super::Provider::supported_coords) are rejected,
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

    /// Resolves entry coordinates using only configuration and address defaults.
    /// Available since SecretSpec 0.21.
    ///
    /// This must not read provider storage or invoke a provider CLI. Planning
    /// uses it before consulting the cache. Providers should fill in implicit
    /// coordinates here; aliases that require a lookup, such as an item title
    /// and UUID, are resolved only by [`Self::entry_coordinates`].
    fn configured_entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<Cow<'a, NativeAddress>> {
        self.resolve_coords(addr)
    }

    /// Whether this provider can return plaintext values through
    /// [`get`](super::Provider::get) or [`get_many`](super::Provider::get_many).
    ///
    /// Available starting with SecretSpec 0.21. Write-only stores override this
    /// to return `false`; callers that only need presence can then use
    /// [`exists`](super::Provider::exists) without accidentally attempting a value
    /// read. This capability check never returns a secret value.
    fn supports_read(&self) -> bool {
        true
    }

    /// Whether this provider implements [`delete`](super::Provider::delete) at all.
    ///
    /// Defaults to `false`, matching the default `delete`. A provider that
    /// overrides `delete` must override this too, so that
    /// [`check_deletable`](super::Provider::check_deletable) can answer the coarse
    /// question, *can this provider delete anything?*, without performing a
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

    /// Controls whether SecretSpec persists a value produced by a declaration's
    /// `generate` configuration after this provider's read route misses.
    /// Available since SecretSpec 0.19.
    ///
    /// [`ProducedValuePersistence::Ephemeral`] affects only automatic
    /// generation. Ordinary [`set`](super::Provider::set), deletion, imports, and
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
    /// The default persists the answer through [`super::Provider::set`], making the
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
    /// builds a fresh provider instance per (secret, URI) pair; without a
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
    /// non-secret attribution only (account, profile, namespace, host, path)
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

    /// Returns the path that identifies a filesystem-backed store, if any.
    /// Available since SecretSpec 0.18.
    ///
    /// The path is compared using filesystem identity when it exists, catching
    /// lexical aliases, symlinks, and hard links. Providers that are not backed
    /// by one path keep the default and are identified by
    /// [`storage_identity`](super::Provider::storage_identity).
    fn physical_store_path(&self) -> Option<&std::path::Path> {
        None
    }

    /// [`Self::physical_store_path`] as known from configuration alone.
    /// Available since SecretSpec 0.21.
    ///
    /// Like [`Self::configured_entry_coordinates`], this must not contact the
    /// store; planning compares containers before consulting the cache.
    /// Providers that only learn their path from the store report what they
    /// already know, or `None`.
    fn configured_physical_store_path(&self) -> Option<&std::path::Path> {
        self.physical_store_path()
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
    /// Available starting with SecretSpec 0.21.
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
    /// Takes `&self` for the same reason as [`super::Provider::set_reason`]: SecretSpec
    /// applies it after providers may have been wrapped in `Arc`.
    ///
    /// Available since SecretSpec 0.20.
    fn set_caller(&self, _caller: Option<crate::CallerContext>) {}

    /// Records the declared project for this provider session. Available
    /// starting with SecretSpec 0.21.
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
    /// (Infisical's environment, for example) would otherwise have to reject every
    /// native address. Such a provider keeps this as a fallback, behind whatever
    /// its URI states explicitly.
    ///
    /// This is context, not naming: it must not change
    /// [`uri`](super::Provider::uri) or
    /// [`storage_identity`](super::Provider::storage_identity), or one store would take
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
    /// not the process's current working directory; otherwise running from a
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
    /// inner value), so a preflight provider wrapped as `Box<Arc<P>>` would
    /// silently receive the default no-op. The default implementation ignores
    /// the values, which is correct for providers that need no credentials.
    ///
    /// [`with_base_dir`]: Provider::with_base_dir
    fn with_credentials(&mut self, _credentials: ProviderCredentials) {}
}

impl<T: ProviderBase + ?Sized> ProviderBase for Box<T> {
    fn requires_initialization(&self) -> bool {
        (**self).requires_initialization()
    }

    fn set_retry_policy(&mut self, _policy: super::RetryPolicy) {
        (**self).set_retry_policy(_policy);
    }

    fn retry_ownership(&self) -> super::RetryOwnership {
        (**self).retry_ownership()
    }

    fn retry_safe(&self, _operation: super::RetryOperation, _addr: Address<'_>) -> bool {
        (**self).retry_safe(_operation, _addr)
    }

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

    fn configured_entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<Cow<'a, NativeAddress>> {
        (**self).configured_entry_coordinates(addr)
    }

    fn supports_read(&self) -> bool {
        (**self).supports_read()
    }

    fn supports_delete(&self) -> bool {
        (**self).supports_delete()
    }

    fn deletion_unsupported(&self) -> SecretSpecError {
        (**self).deletion_unsupported()
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

    fn storage_identity(&self) -> String {
        (**self).storage_identity()
    }

    fn entry_container_identity(&self) -> String {
        (**self).entry_container_identity()
    }

    fn physical_store_path(&self) -> Option<&std::path::Path> {
        (**self).physical_store_path()
    }

    fn configured_physical_store_path(&self) -> Option<&std::path::Path> {
        (**self).configured_physical_store_path()
    }

    fn set_reason(&self, _reason: Option<String>) {
        (**self).set_reason(_reason)
    }

    fn set_requested_authorization_duration(&self, _duration: Option<std::time::Duration>) {
        (**self).set_requested_authorization_duration(_duration)
    }

    fn set_caller(&self, _caller: Option<crate::CallerContext>) {
        (**self).set_caller(_caller)
    }

    fn set_project(&self, _project: &str) {
        (**self).set_project(_project)
    }

    fn set_profile(&self, _profile: &str) {
        (**self).set_profile(_profile)
    }

    fn with_base_dir(&mut self, _base_dir: &std::path::Path) {
        (**self).with_base_dir(_base_dir);
    }

    fn with_credentials(&mut self, _credentials: ProviderCredentials) {
        (**self).with_credentials(_credentials);
    }
}
