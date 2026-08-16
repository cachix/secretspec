//! HashiCorp Vault provider.
//!
//! This provider stores and retrieves secrets through the Vault KV (Key-Value)
//! secrets engine, version 1 or 2.
//!
//! # Authentication
//!
//! Select one of three methods with the `auth` query parameter:
//!
//! - Token (default) -- reads the `token` provider credential, `VAULT_TOKEN`,
//!   or `~/.vault-token`, in that order.
//! - AppRole (`?auth=approle`) -- exchanges the required `role_id` and optional
//!   `secret_id` provider credentials, or `VAULT_ROLE_ID` and
//!   `VAULT_SECRET_ID`, for a client token. Starting with SecretSpec 0.18, the
//!   SecretID may be omitted when the AppRole has `bind_secret_id=false`.
//! - JWT/OIDC (SecretSpec 0.17+, `?auth=jwt`) -- logs in using `VAULT_JWT` or a
//!   short-lived GitHub Actions / Forgejo Actions OIDC token. Starting with
//!   SecretSpec 0.18, the role may be omitted when the auth mount has a
//!   `default_role`.
//!
//! # URI format
//!
//! `vault://[namespace@]host[:port][/mount][?key=value&...]`
//!
//! Query parameters:
//!
//! - `auth` -- `token` (default), `approle`, or `jwt` (0.17+)
//! - `kv` -- KV engine version: `1` or `2` (default)
//! - `tls` -- `true` (default) or `false`; the latter is intended for dev mode
//! - `auth_mount` -- non-default AppRole or JWT mount beneath `/v1/auth`
//!   (SecretSpec 0.18+)
//! - `role` -- Vault role for JWT auth, falling back to `VAULT_JWT_ROLE`;
//!   optional with a server-configured `default_role` (SecretSpec 0.18+)
//! - `audience` -- audience requested from the CI OIDC issuer, falling back to
//!   `VAULT_JWT_AUDIENCE` (0.17+)
//!
//! Examples:
//!
//! - `vault://vault.example.com:8200/secret` -- KV v2 with token auth
//! - `vault://vault.example.com:8200/secret?auth=approle` -- AppRole auth
//! - `vault://vault.example.com:8200/secret?auth=approle&auth_mount=platform-approle`
//!   -- custom AppRole mount (SecretSpec 0.18+)
//! - `vault://vault.example.com:8200/secret?auth=jwt&role=ci` -- JWT auth
//! - `vault://vault.example.com:8200/secret?auth=jwt` -- JWT auth using the
//!   mount's `default_role` (SecretSpec 0.18+)
//! - `vault://team-a@vault.example.com:8200/secret` -- Vault namespace
//! - `vault://127.0.0.1:8200/secret?kv=1&tls=false` -- local KV v1 server
//!
//! With no URI host, `VAULT_ADDR` supplies the endpoint. With no URI username,
//! `VAULT_NAMESPACE` supplies the namespace.
//!
//! # Secret naming
//!
//! Convention-addressed secrets live at
//! `secretspec/{project}/{profile}/{key}` under the configured KV mount. Each
//! entry is a map whose `value` field contains the SecretSpec value. Native
//! references name a KV path with `item` and select a map entry with `field`;
//! they are read-only so changing one field cannot overwrite its siblings.
//!
//! ```bash
//! secretspec set DATABASE_URL --provider vault://vault.example.com:8200/secret
//! secretspec check --provider vault://team-a@vault.example.com:8200/secret
//! ```

use super::vault_common::{KvConfig, KvProvider, Product, ROLE_ID, SECRET_ID, TOKEN};
use super::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use secrecy::SecretString;

/// HashiCorp Vault provider configuration.
///
/// Parsing is intentionally product-specific even though the resulting KV
/// coordinates are compatible with OpenBao. This keeps Vault's URI and
/// environment contract from acquiring OpenBao-only behavior.
#[derive(Debug, Clone, Default)]
pub struct VaultConfig(KvConfig);

impl TryFrom<&ProviderUrl> for VaultConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        KvConfig::parse(url, Product::Vault).map(Self)
    }
}

/// HashiCorp Vault KV provider.
///
/// The wrapper owns Vault's public identity and delegates compatible protocol
/// operations to [`KvProvider`].
pub struct VaultProvider {
    core: KvProvider,
}

crate::register_provider! {
    struct: VaultProvider,
    config: VaultConfig,
    name: "vault",
    description: "HashiCorp Vault secret management",
    schemes: ["vault"],
    examples: ["vault://vault.example.com:8200/secret"],
    credential_names: [ROLE_ID, SECRET_ID, TOKEN],
    deletes: true,
}

impl VaultProvider {
    /// Creates a Vault provider with the parsed product-specific configuration.
    pub fn new(config: VaultConfig) -> Self {
        Self {
            core: KvProvider::new(config.0, Product::Vault),
        }
    }
}

impl Provider for VaultProvider {
    /// Convention secrets use one KV path per secret and the `value` map field.
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        self.core.convention_address(project, profile, key)
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.core.with_credentials(credentials);
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        self.core.uri()
    }

    fn storage_identity(&self) -> String {
        self.core.storage_identity()
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        self.core.supported_coords()
    }

    /// A native reference must identify the field inside the KV entry's map.
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        self.core.get(&coords)
    }

    /// Reuses one operation-scoped login across the batch while retaining the
    /// default address deduplication and concurrency cap.
    fn get_many(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<std::collections::HashMap<String, SecretString>> {
        self.core.get_many(requests)
    }

    /// Only convention addresses are writable; see [`Self::check_writable`].
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_coords(addr)?;
        self.core.set(&coords, value)
    }

    /// KV v2 expires the written version through the path's
    /// `delete_version_after` metadata, so a cached copy of another store's
    /// secret disappears on its own.
    fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretString,
        max_age: std::time::Duration,
    ) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_coords(addr)?;
        self.core.set_expiring(&coords, value, max_age)
    }

    /// Deletes the whole KV path, so it is confined to entries SecretSpec owns;
    /// see [`Self::check_writable`] for the same reasoning about `ref`s.
    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        self.core.check_deletable(addr)?;
        let coords = self.resolve_coords(addr)?;
        self.core.delete(&coords)
    }

    fn supports_delete(&self) -> bool {
        true
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.core.check_deletable(addr)
    }

    /// Refuses native writes because replacing a KV entry to change one field
    /// would silently discard every sibling field.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.core.check_writable(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn config(spec: &str) -> VaultConfig {
        VaultConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap())).unwrap()
    }

    #[test]
    fn field_query_is_rejected_in_favour_of_a_ref() {
        let err = VaultConfig::try_from(&ProviderUrl::new(
            Url::parse("vault://vault.example.com:8200/secret?field=x").unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("ref = { item ="), "{err}");
    }

    #[test]
    fn convention_address_is_the_writable_value_field() {
        let provider = VaultProvider::new(config("vault://vault.example.com:8200/secret"));
        let address = provider
            .resolve_coords(Address::convention("app", "prod", "DATABASE_URL"))
            .unwrap();
        assert_eq!(address.item, "secretspec/app/prod/DATABASE_URL");
        assert_eq!(address.field.as_deref(), Some("value"));
        assert!(
            provider
                .check_writable(Address::convention("app", "prod", "DATABASE_URL"))
                .is_ok()
        );
    }

    #[test]
    fn native_address_requires_a_field() {
        let provider = VaultProvider::new(config("vault://vault.example.com:8200/secret"));
        let address = NativeAddress {
            item: "myapp/config".into(),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&address)).unwrap_err();
        assert!(error.to_string().contains("need a `field`"), "{error}");
    }

    #[test]
    fn native_address_is_read_only() {
        let provider = VaultProvider::new(config("vault://vault.example.com:8200/secret"));
        let address = NativeAddress {
            item: "myapp/config".into(),
            field: Some("db_password".into()),
            ..Default::default()
        };
        let refusal = provider
            .check_writable(Address::Native(&address))
            .unwrap_err();
        assert!(refusal.to_string().contains("read-only"), "{refusal}");
        let error = provider
            .set(Address::Native(&address), &SecretString::new("v".into()))
            .unwrap_err();
        assert_eq!(error.to_string(), refusal.to_string());
    }

    #[test]
    fn native_address_rejects_version() {
        let provider = VaultProvider::new(config("vault://vault.example.com:8200/secret"));
        let address = NativeAddress {
            item: "myapp/config".into(),
            field: Some("db_password".into()),
            version: Some("3".into()),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&address)).unwrap_err();
        assert!(error.to_string().contains("`version`"), "{error}");
    }
}
