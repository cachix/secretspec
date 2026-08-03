//! OpenBao provider (SecretSpec 0.17+).
//!
//! This provider stores and retrieves secrets through the OpenBao KV
//! (Key-Value) secrets engine, version 1 or 2. It has a separate identity from
//! HashiCorp Vault even where their current HTTP APIs remain compatible.
//!
//! # Authentication
//!
//! Select one of three methods with the `auth` query parameter:
//!
//! - Token (default) -- reads the `token` provider credential, `BAO_TOKEN`, or
//!   the compatibility fallback `VAULT_TOKEN`. It then reads the path selected
//!   by `BAO_TOKEN_PATH` / `VAULT_TOKEN_PATH`, or the OpenBao CLI's default
//!   `~/.vault-token`.
//! - AppRole (`?auth=approle`) -- exchanges the `role_id` and `secret_id`
//!   provider credentials, or SecretSpec's `BAO_ROLE_ID` and `BAO_SECRET_ID`
//!   inputs, for a client token. The corresponding `VAULT_*` names remain
//!   compatibility fallbacks.
//! - JWT/OIDC (`?auth=jwt`) -- logs in using SecretSpec's `BAO_JWT` input
//!   (falling back to `VAULT_JWT`) or a short-lived GitHub Actions / Forgejo
//!   Actions OIDC token. Starting with SecretSpec 0.18, the role may be omitted
//!   when the auth mount has a `default_role`.
//!
//! For environment variables defined by the OpenBao CLI -- address, namespace,
//! token, and token path -- `BAO_*` takes precedence and the corresponding
//! `VAULT_*` name remains a compatibility fallback. The AppRole and JWT names
//! are SecretSpec provider inputs rather than variables consumed by the
//! OpenBao CLI itself.
//!
//! # URI format
//!
//! `openbao://[namespace@]host[:port][/mount][?key=value&...]`
//!
//! Query parameters:
//!
//! - `auth` -- `token` (default), `approle`, or `jwt`
//! - `kv` -- KV engine version: `1` or `2` (default)
//! - `tls` -- `true` (default) or `false`; the latter is intended for dev mode
//! - `auth_mount` -- non-default AppRole or JWT mount beneath `/v1/auth`
//!   (SecretSpec 0.18+)
//! - `role` -- role for JWT auth, falling back through `BAO_JWT_ROLE` and
//!   `VAULT_JWT_ROLE`; optional with a server-configured `default_role`
//!   (SecretSpec 0.18+)
//! - `audience` -- audience requested from the CI OIDC issuer, falling back
//!   through `BAO_JWT_AUDIENCE` and `VAULT_JWT_AUDIENCE`
//!
//! Examples:
//!
//! - `openbao://bao.example.com:8200/secret` -- KV v2 with token auth
//! - `openbao://bao.example.com:8200/secret?auth=approle` -- AppRole auth
//! - `openbao://bao.example.com:8200/secret?auth=approle&auth_mount=platform-approle`
//!   -- custom AppRole mount (SecretSpec 0.18+)
//! - `openbao://bao.example.com:8200/secret?auth=jwt&role=ci` -- JWT auth
//! - `openbao://bao.example.com:8200/secret?auth=jwt` -- JWT auth using the
//!   mount's `default_role` (SecretSpec 0.18+)
//! - `openbao://team-a@bao.example.com:8200/secret` -- OpenBao namespace
//! - `openbao://127.0.0.1:8200/secret?kv=1&tls=false` -- local KV v1 server
//!
//! With no URI host, `BAO_ADDR` then `VAULT_ADDR` supplies the endpoint. With
//! no URI username, `BAO_NAMESPACE` then `VAULT_NAMESPACE` supplies the
//! namespace.
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
//! secretspec set DATABASE_URL --provider openbao://bao.example.com:8200/secret
//! secretspec check --provider openbao://team-a@bao.example.com:8200/secret
//! ```

use super::vault_common::{KvConfig, KvProvider, Product, ROLE_ID, SECRET_ID, TOKEN};
use super::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use secrecy::SecretString;

/// OpenBao provider configuration.
///
/// Parsing is intentionally product-specific even though the resulting KV
/// coordinates are compatible with Vault. This is where the documented
/// OpenBao CLI environment precedence and future OpenBao-only options belong.
#[derive(Debug, Clone, Default)]
pub struct OpenBaoConfig(KvConfig);

impl TryFrom<&ProviderUrl> for OpenBaoConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        KvConfig::parse(url, Product::OpenBao).map(Self)
    }
}

/// OpenBao KV provider.
///
/// The wrapper owns OpenBao's public identity and delegates compatible protocol
/// operations to [`KvProvider`].
pub struct OpenBaoProvider {
    core: KvProvider,
}

crate::register_provider! {
    struct: OpenBaoProvider,
    config: OpenBaoConfig,
    name: "openbao",
    description: "OpenBao secret management (0.17+)",
    schemes: ["openbao"],
    examples: ["openbao://bao.example.com:8200/secret"],
    credential_names: [ROLE_ID, SECRET_ID, TOKEN],
    deletes: true,
}

impl OpenBaoProvider {
    /// Creates an OpenBao provider with the parsed product-specific configuration.
    pub fn new(config: OpenBaoConfig) -> Self {
        Self {
            core: KvProvider::new(config.0, Product::OpenBao),
        }
    }
}

impl Provider for OpenBaoProvider {
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

    fn config(spec: &str) -> OpenBaoConfig {
        OpenBaoConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap())).unwrap()
    }

    #[test]
    fn has_an_independent_identity_and_uri() {
        let provider = OpenBaoProvider::new(config("openbao://bao.example.com:8200/team"));
        assert_eq!(provider.name(), "openbao");
        assert_eq!(provider.uri(), "openbao://bao.example.com:8200/team");
    }

    #[test]
    fn rejects_the_vault_scheme() {
        let error = OpenBaoConfig::try_from(&ProviderUrl::new(
            Url::parse("vault://vault.example.com:8200/secret").unwrap(),
        ))
        .unwrap_err();
        assert!(error.to_string().contains("Expected 'openbao'"), "{error}");
    }

    #[test]
    fn convention_address_is_the_writable_value_field() {
        let provider = OpenBaoProvider::new(config("openbao://bao.example.com:8200/secret"));
        let address = provider
            .resolve_coords(Address::convention("app", "prod", "DATABASE_URL"))
            .unwrap();
        assert_eq!(address.item, "secretspec/app/prod/DATABASE_URL");
        assert_eq!(address.field.as_deref(), Some("value"));
    }

    #[test]
    fn native_address_requires_a_field() {
        let provider = OpenBaoProvider::new(config("openbao://bao.example.com:8200/secret"));
        let address = NativeAddress {
            item: "myapp/config".into(),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&address)).unwrap_err();
        assert!(error.to_string().contains("need a `field`"), "{error}");
        assert!(error.to_string().contains("openbao"), "{error}");
    }

    #[test]
    fn native_address_is_read_only_with_an_openbao_error() {
        let provider = OpenBaoProvider::new(config("openbao://bao.example.com:8200/secret"));
        let address = NativeAddress {
            item: "myapp/config".into(),
            field: Some("db_password".into()),
            ..Default::default()
        };
        let error = provider
            .check_writable(Address::Native(&address))
            .unwrap_err();
        assert!(error.to_string().contains("openbao"), "{error}");
        assert!(error.to_string().contains("read-only"), "{error}");
    }
}
