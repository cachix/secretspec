//! Azure Key Vault provider
//!
//! This provider integrates with Azure Key Vault to store and retrieve secrets.
//!
//! # Authentication
//!
//! Unlike the AWS and GCP SDKs, the Rust Azure SDK does not (yet) ship a single
//! "try everything" default credential, so the authentication method is chosen
//! explicitly via the `auth` query parameter:
//!
//! - `auth=env` (default) -- reads a service principal from the `tenant_id`,
//!   `client_id`, and `client_secret` provider credentials, falling back to
//!   the matching `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
//!   `AZURE_CLIENT_SECRET` environment variables. All three must be supplied
//!   together; if none are available, this falls back to the signed-in Azure
//!   CLI / Azure Developer CLI session (equivalent to `auth=cli`), so local
//!   development works out of the box after `az login`. A partial set is an
//!   error rather than a silent fallback to a different identity.
//! - `auth=cli` -- only the Azure CLI / Azure Developer CLI session.
//! - `auth=managed_identity` -- the VM/App Service/AKS system-assigned managed
//!   identity.
//! - `auth=workload_identity` -- AKS workload identity federation, via the
//!   `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_FEDERATED_TOKEN_FILE`
//!   environment variables injected by AKS.
//!
//! # URI Format
//!
//! `akv://<vault-name>[?auth=env|cli|managed_identity|workload_identity][&suffix=<dns-suffix>]`
//!
//! - `akv://myvault` -- `https://myvault.vault.azure.net/`
//! - `akv://myvault?auth=managed_identity` -- authenticate via managed identity
//! - `akv://myvault.vault.azure.cn` -- a host containing a dot is used verbatim
//!   as the vault's DNS name, for sovereign clouds (China, US Gov, Germany)
//!   whose Key Vault suffix is not `.vault.azure.net`
//! - `akv://myvault?suffix=vault.azure.cn` -- an explicit, first-class way to
//!   address a sovereign cloud without needing to spell out the full DNS name
//!
//! # Secret Naming
//!
//! Azure Key Vault secret names may only contain ASCII letters, digits and
//! hyphens (`^[0-9a-zA-Z-]+$`, 1-127 characters), and Key Vault compares object
//! identifiers case-insensitively. Convention secrets are therefore named
//! `secretspec--{base32(project)}--{base32(profile)}--{base32(key)}`. Encoding
//! each component as lowercase, unpadded Base32 preserves case and punctuation
//! distinctions while producing only Azure-compatible characters. It also
//! keeps the `--` separators unambiguous because encoded components contain no
//! hyphens.
//!
//! Native `ref` addresses (naming a secret that already exists in the vault)
//! are validated against this same charset but never rewritten: silently
//! rewriting characters in a user-specified `ref` could silently point at a
//! different secret than the one they named.
//!
//! # Example
//!
//! ```bash
//! # Set a secret (reads AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET,
//! # or falls back to `az login`)
//! secretspec set DATABASE_URL --provider akv://myvault
//!
//! # Use a managed identity (e.g. from a VM or App Service)
//! secretspec check --provider akv://myvault?auth=managed_identity
//! ```

use super::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env};
use crate::SecretBytes;
use crate::{Result, SecretSpecError};
use azure_core::credentials::{Secret, TokenCredential};
use azure_core::http::StatusCode;
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    WorkloadIdentityCredential,
};
use azure_security_keyvault_secrets::{
    SecretClient,
    models::{SecretClientGetSecretOptions, SetSecretParameters},
};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

/// Serializes a client's first request while Azure Key Vault discovers its
/// authentication scope through a 401 challenge.
///
/// The Azure bearer-token policy caches tokens with single-flight refreshes,
/// but the scope starts empty. If a cold client sends a batch concurrently,
/// every request first receives a 401 and can invalidate a token another
/// request just acquired, spawning the Azure CLI more than once. Once one
/// request completes successfully, the client has both its scope and token and
/// later requests can safely fan out.
#[derive(Default)]
pub(crate) struct InitialRequestGate {
    ready: AtomicBool,
    lock: Mutex<()>,
}

impl InitialRequestGate {
    pub(crate) fn run<T, F>(&self, request: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        if self.ready.load(Ordering::Acquire) {
            return request();
        }

        let guard = self.lock.lock().unwrap();
        if self.ready.load(Ordering::Acquire) {
            drop(guard);
            return request();
        }

        let result = request();
        if result.is_ok() {
            self.ready.store(true, Ordering::Release);
        }
        result
    }
}

/// Authentication method for the Azure Key Vault provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuthMethod {
    /// Service principal via env vars, falling back to the Azure CLI / azd session.
    #[default]
    Env,
    /// Azure CLI / Azure Developer CLI session only (`az login`).
    Cli,
    /// VM / App Service / AKS system-assigned managed identity.
    ManagedIdentity,
    /// AKS workload identity federation.
    WorkloadIdentity,
}

impl AuthMethod {
    /// The `?auth=` query-string spelling of this auth method.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Env => "env",
            AuthMethod::Cli => "cli",
            AuthMethod::ManagedIdentity => "managed_identity",
            AuthMethod::WorkloadIdentity => "workload_identity",
        }
    }
}

impl std::str::FromStr for AuthMethod {
    type Err = SecretSpecError;

    /// The inverse of [`AuthMethod::as_str`] -- kept as a single pair so the
    /// two directions can't drift out of sync.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "env" => Ok(AuthMethod::Env),
            "cli" => Ok(AuthMethod::Cli),
            "managed_identity" => Ok(AuthMethod::ManagedIdentity),
            "workload_identity" => Ok(AuthMethod::WorkloadIdentity),
            other => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Unknown auth method '{}'. Expected 'env', 'cli', 'managed_identity', \
                 or 'workload_identity'.",
                other
            ))),
        }
    }
}

/// Configuration for the Azure Key Vault provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkvConfig {
    /// The vault name (short form) or full DNS name (sovereign clouds).
    pub vault_host: String,
    /// The full `https://...` base URL derived from `vault_host`.
    pub vault_url: String,
    /// Authentication method (default: Env).
    pub auth: AuthMethod,
    /// Explicit Key Vault DNS suffix override for a bare `vault_host`, given
    /// via `?suffix=`. `None` when `vault_host` is already a full DNS name
    /// (contains a dot) or the default public suffix was used, so `uri()`
    /// only emits `suffix` when it was actually given.
    pub suffix: Option<String>,
}

/// The public-cloud Key Vault DNS suffix. Sovereign clouds (China, US Gov,
/// Germany) use a different suffix and must be addressed by their full DNS
/// name (a host containing a `.`) or an explicit `?suffix=`, since there is
/// no single suffix that works for all of them.
const DEFAULT_SUFFIX: &str = "vault.azure.net";

impl AkvConfig {
    /// Builds Key Vault configuration from a full vault DNS host that the
    /// caller has already validated.
    pub(crate) fn from_validated_vault_host(vault_host: String, auth: AuthMethod) -> Self {
        Self {
            vault_url: format!("https://{vault_host}/"),
            vault_host,
            auth,
            suffix: None,
        }
    }
}

impl TryFrom<&ProviderUrl> for AkvConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "akv" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for akv provider. Expected 'akv'.",
                url.scheme()
            )));
        }

        let vault_host = url.host().filter(|s| !s.is_empty()).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Azure Key Vault name is required. Use format: akv://myvault".to_string(),
            )
        })?;

        // A host containing a dot is already a full DNS name (sovereign
        // clouds); a bare name gets the public-cloud suffix, or an explicit
        // `?suffix=` override, appended.
        let (vault_url, suffix) = if vault_host.contains('.') {
            (format!("https://{}/", vault_host), None)
        } else {
            match url.query_value("suffix") {
                Some(suffix) => (format!("https://{}.{}/", vault_host, suffix), Some(suffix)),
                None => (format!("https://{}.{}/", vault_host, DEFAULT_SUFFIX), None),
            }
        };

        let auth = url
            .query_value("auth")
            .map(|v| v.parse::<AuthMethod>())
            .transpose()?
            .unwrap_or_default();

        // The path/field reference form from other providers is rejected here
        // too: akv URIs take no path, secrets are addressed via `ref` instead.
        let path = url.path();
        let trimmed = path.trim_start_matches('/');
        if !trimmed.is_empty() {
            let hint = crate::config::ref_table_hint(None, trimmed, None, None);
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "akv URIs take no path: address the secret with {hint} on the secret instead"
            )));
        }

        Ok(Self {
            vault_host,
            vault_url,
            auth,
            suffix,
        })
    }
}

/// Azure Key Vault provider.
///
/// Stores and retrieves secrets from an Azure Key Vault instance.
pub struct AkvProvider {
    config: AkvConfig,
    /// Service-principal credentials supplied by the provider alias.
    credentials: ProviderCredentials,
    /// An externally resolved credential shared with another Azure provider.
    credential: Option<Arc<dyn TokenCredential>>,
    /// One client per provider, so a batch shares the credential's token cache
    /// instead of authenticating per secret. Every `DeveloperToolsCredential`
    /// starts with an empty cache, and under `auth=cli` filling it spawns the
    /// Azure CLI.
    client: OnceLock<SecretClient>,
    /// Keeps a cold client's challenge-based authentication to one request, so
    /// a concurrent batch cannot launch several Azure CLI processes.
    initial_request: InitialRequestGate,
}

const TENANT_ID: &str = "tenant_id";
const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";
const AZURE_TENANT_ID_ENV: &str = "AZURE_TENANT_ID";
const AZURE_CLIENT_ID_ENV: &str = "AZURE_CLIENT_ID";
const AZURE_CLIENT_SECRET_ENV: &str = "AZURE_CLIENT_SECRET";

/// Resolves the Azure identity modes shared by Azure-backed providers.
pub(crate) fn resolve_azure_credential(
    auth: AuthMethod,
    credentials: &ProviderCredentials,
) -> Result<Arc<dyn TokenCredential>> {
    match auth {
        AuthMethod::Cli => Ok(DeveloperToolsCredential::new(None).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create Azure CLI / azd credential: {}",
                crate::error::display_error_chain(&e)
            ))
        })? as Arc<dyn TokenCredential>),
        AuthMethod::ManagedIdentity => Ok(ManagedIdentityCredential::new(None).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create managed identity credential: {}",
                crate::error::display_error_chain(&e)
            ))
        })? as Arc<dyn TokenCredential>),
        AuthMethod::WorkloadIdentity => Ok(WorkloadIdentityCredential::new(None).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create workload identity credential: {}\n\n\
                 Requires the AZURE_TENANT_ID, AZURE_CLIENT_ID, and \
                 AZURE_FEDERATED_TOKEN_FILE environment variables that AKS \
                 injects automatically for workload-identity-enabled pods.",
                crate::error::display_error_chain(&e)
            ))
        })? as Arc<dyn TokenCredential>),
        AuthMethod::Env => {
            let (tenant_id, client_id, client_secret) = service_principal_inputs(credentials);

            match classify_env_credentials(tenant_id, client_id, client_secret)? {
                Some((tenant_id, client_id, client_secret)) => Ok(ClientSecretCredential::new(
                    &tenant_id,
                    client_id,
                    Secret::new(client_secret),
                    None,
                )
                .map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to create service principal credential from \
                         AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET: {}",
                        crate::error::display_error_chain(&e)
                    ))
                })?
                    as Arc<dyn TokenCredential>),
                None => Ok(DeveloperToolsCredential::new(None).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "No AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET set, and \
                         failed to fall back to the Azure CLI / azd session: {}\n\n\
                         Either set those three environment variables, or run `az login`.",
                        crate::error::display_error_chain(&e)
                    ))
                })? as Arc<dyn TokenCredential>),
            }
        }
    }
}

fn service_principal_inputs(
    credentials: &ProviderCredentials,
) -> (Option<String>, Option<String>, Option<String>) {
    (
        credential_or_env(credentials, TENANT_ID, AZURE_TENANT_ID_ENV),
        credential_or_env(credentials, CLIENT_ID, AZURE_CLIENT_ID_ENV),
        credential_or_env(credentials, CLIENT_SECRET, AZURE_CLIENT_SECRET_ENV),
    )
}

fn classify_env_credentials(
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Result<Option<(String, String, String)>> {
    match (tenant_id, client_id, client_secret) {
        (Some(t), Some(c), Some(s)) => Ok(Some((t, c, s))),
        (None, None, None) => Ok(None),
        (tenant_id, client_id, client_secret) => {
            let missing: Vec<String> = [
                (TENANT_ID, AZURE_TENANT_ID_ENV, tenant_id.is_none()),
                (CLIENT_ID, AZURE_CLIENT_ID_ENV, client_id.is_none()),
                (
                    CLIENT_SECRET,
                    AZURE_CLIENT_SECRET_ENV,
                    client_secret.is_none(),
                ),
            ]
            .into_iter()
            .filter(|(_, _, is_missing)| *is_missing)
            .map(|(credential, env, _)| format!("{credential} / {env}"))
            .collect();
            Err(SecretSpecError::ProviderOperationFailed(format!(
                "Partial service principal configuration: the tenant_id, client_id, and \
                 client_secret provider credentials (or the AZURE_TENANT_ID, AZURE_CLIENT_ID, \
                 and AZURE_CLIENT_SECRET environment variables) must all be supplied together, \
                 or none of them (to fall back to `az login`). Missing: {}.",
                missing.join(", ")
            )))
        }
    }
}

crate::register_provider! {
    struct: AkvProvider,
    config: AkvConfig,
    metadata: &super::catalog::AKV,
}

impl AkvProvider {
    /// Creates a new AkvProvider with the given configuration.
    pub fn new(config: AkvConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            credential: None,
            client: OnceLock::new(),
            initial_request: InitialRequestGate::default(),
        }
    }

    /// Creates a provider that reuses a credential resolved by another Azure
    /// provider.
    pub(crate) fn with_token_credential(
        config: AkvConfig,
        credential: Arc<dyn TokenCredential>,
    ) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            credential: Some(credential),
            client: OnceLock::new(),
            initial_request: InitialRequestGate::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_client(config: AkvConfig, client: SecretClient) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            credential: None,
            client: OnceLock::from(client),
            initial_request: InitialRequestGate::default(),
        }
    }

    /// Validates a convention-name component before encoding it.
    fn validate_name_component(name: &str, component: &str) -> Result<()> {
        if component.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} cannot be empty",
                name
            )));
        }
        for c in component.chars() {
            if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} contains invalid character '{}'. \
                    Only alphanumeric characters, underscores, and hyphens are allowed",
                    name, c
                )));
            }
        }
        Ok(())
    }

    /// Encodes a component into a lowercase, Azure-compatible and injective
    /// representation. Lowercasing the Base32 output is safe because Base32's
    /// alphabet is case-insensitive, while the encoded bytes preserve the
    /// original component's case. The output contains no hyphens, so it cannot
    /// consume or shift the `--` delimiter between components.
    fn encode_name_component(component: &str) -> String {
        BASE32_NOPAD
            .encode(component.as_bytes())
            .to_ascii_lowercase()
    }

    /// Formats and validates the secret name for Azure Key Vault.
    ///
    /// Converts the SecretSpec path format to an Azure-compatible name:
    /// `secretspec--{base32(project)}--{base32(profile)}--{base32(key)}`.
    /// Lowercase, unpadded Base32 avoids both Key Vault's case-insensitive
    /// identifier comparisons and ambiguity with the `--` component delimiter.
    fn format_secret_name(project: &str, profile: &str, key: &str) -> Result<String> {
        Self::validate_name_component("project", project)?;
        Self::validate_name_component("profile", profile)?;
        Self::validate_name_component("key", key)?;

        let secret_name = format!(
            "secretspec--{}--{}--{}",
            Self::encode_name_component(project),
            Self::encode_name_component(profile),
            Self::encode_name_component(key)
        );

        if secret_name.len() > 127 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Secret name too long: {} characters (max 127)",
                secret_name.len()
            )));
        }

        Ok(secret_name)
    }

    /// Resolves an address to a validated Azure Key Vault secret name.
    ///
    /// Convention addresses are already Azure-legal by construction
    /// (`format_secret_name` validates and rewrites them). Native `ref`
    /// addresses name a secret that already exists in the vault, so they are
    /// validated but never rewritten -- silently rewriting characters in a
    /// user-specified `ref` could silently point at a different secret than
    /// the one they named.
    fn resolve_address<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::config::NativeAddress>> {
        let coords = self.resolve_coords(addr)?;
        let item = &coords.item;
        let valid = !item.is_empty()
            && item.len() <= 127
            && item.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !valid {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "'{item}' is not a valid Azure Key Vault secret name: only ASCII letters, \
                 digits, and hyphens are allowed (1-127 characters). Azure Key Vault has no \
                 underscores; if this `ref` names a real secret, use the vault's actual name."
            )));
        }
        // Azure emits 32-character object versions; reject other shapes before authentication.
        if let Some(version) = coords.version.as_deref()
            && (version.len() != 32 || !version.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "'{version}' is not a valid Azure Key Vault secret version: expected a \
                 32-character ASCII alphanumeric version identifier"
            )));
        }

        Ok(coords)
    }

    /// Resolves the token credential for the configured auth method.
    fn resolve_credential(&self) -> Result<Arc<dyn TokenCredential>> {
        match &self.credential {
            Some(credential) => Ok(Arc::clone(credential)),
            None => resolve_azure_credential(self.config.auth, &self.credentials),
        }
    }

    /// Creates a SecretClient for the configured vault.
    fn create_client(&self) -> Result<SecretClient> {
        let credential = self.resolve_credential()?;
        SecretClient::new(&self.config.vault_url, credential, None).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create Azure Key Vault client for {}: {}",
                self.config.vault_url,
                crate::error::display_error_chain(&e)
            ))
        })
    }

    /// Returns the shared client, building it on first use.
    ///
    /// Concurrent callers may each build one and discard all but the first,
    /// which costs an extra construction rather than being incorrect.
    fn client(&self) -> Result<&SecretClient> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let created = self.create_client()?;
        Ok(self.client.get_or_init(|| created))
    }

    /// Checks whether an error indicates the secret was not found, via the
    /// typed HTTP status code rather than string-matching the error's
    /// `Display` output (a genuine 404's message is the service's plain-text
    /// description, e.g. "A secret with (name) was not found in this key
    /// vault" -- it does not contain the literal text "SecretNotFound" or
    /// "404", so matching on those strings misses real not-found responses).
    fn is_not_found_error(e: &azure_core::Error) -> bool {
        e.http_status() == Some(StatusCode::NotFound)
    }

    /// Retrieves one version of a secret by name, or its latest version when
    /// `version` is absent, mapping "not found" to `None`.
    async fn get_secret_async(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<SecretBytes>> {
        let client = self.client()?;
        let options = version.map(|version| SecretClientGetSecretOptions {
            secret_version: Some(version.to_string()),
            ..Default::default()
        });
        match client.get_secret(name, options).await {
            Ok(response) => {
                let secret = response.into_model().map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to read secret '{}' from Azure Key Vault: {}",
                        name,
                        crate::error::display_error_chain(&e)
                    ))
                })?;
                Ok(secret.value.map(|v| SecretBytes::new(v.into())))
            }
            Err(e) => {
                if Self::is_not_found_error(&e) {
                    Ok(None)
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to get secret '{}' from Azure Key Vault: {}",
                        name,
                        crate::error::display_error_chain(&e)
                    )))
                }
            }
        }
    }

    /// Sets a secret's value by name. Azure Key Vault's SET operation always
    /// creates a new version if the secret already exists, so create and
    /// update share this one call.
    async fn set_secret_async(&self, name: &str, value: &SecretBytes) -> Result<()> {
        let value = super::require_utf8("akv", value)?;
        let client = self.client()?;
        let params = SetSecretParameters {
            value: Some(value.to_string()),
            ..Default::default()
        };
        client
            .set_secret(
                name,
                params.try_into().map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to build set-secret request for '{}': {}",
                        name,
                        crate::error::display_error_chain(&e)
                    ))
                })?,
                None,
            )
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to set secret '{}' in Azure Key Vault: {}",
                    name,
                    crate::error::display_error_chain(&e)
                ))
            })?;
        Ok(())
    }
}

impl Provider for AkvProvider {
    /// Convention names use lowercase Base32 components so they remain
    /// injective despite Azure Key Vault's restricted, case-insensitive names.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: Self::format_secret_name(project, profile, key)?,
            ..Default::default()
        })
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = format!("akv://{}", self.config.vault_host);
        let mut params = Vec::new();
        if self.config.auth != AuthMethod::default() {
            params.push(format!("auth={}", self.config.auth.as_str()));
        }
        if let Some(suffix) = &self.config.suffix {
            params.push(format!("suffix={suffix}"));
        }
        if !params.is_empty() {
            uri.push('?');
            uri.push_str(&params.join("&"));
        }
        uri
    }

    fn storage_identity(&self) -> String {
        self.config.vault_url.clone()
    }

    /// An optional `version` pins the secret version to read.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["version"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let coords = self.resolve_address(addr)?;
        self.initial_request
            .run(|| super::block_on(self.get_secret_async(&coords.item, coords.version.as_deref())))
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_address(addr)?;
        self.initial_request
            .run(|| super::block_on(self.set_secret_async(&coords.item, value)))
    }

    /// Native addresses are read-only: they name a secret managed outside
    /// SecretSpec, and writing would mint a new version of it.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention { .. } => Ok(()),
            Address::Native(_) => Err(SecretSpecError::ProviderOperationFailed(
                "akv secret references are read-only and cannot be written".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::EnvVarGuard;
    use azure_core::error::ErrorKind;
    use azure_core::http::{
        AsyncRawResponse, ClientOptions, HttpClient, Request, StatusCode as HttpStatusCode,
        Transport, headers::Headers,
    };
    use azure_security_keyvault_secrets::SecretClientOptions;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::{thread, time::Duration};
    use url::Url;

    fn config(s: &str) -> AkvConfig {
        AkvConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    fn credentials(entries: &[(&str, &str)]) -> ProviderCredentials {
        entries
            .iter()
            .map(|(name, value)| {
                (
                    (*name).to_string(),
                    SecretBytes::new((*value).to_string().into()),
                )
            })
            .collect()
    }

    #[derive(Debug, Default)]
    struct RecordingHttpClient {
        paths: Mutex<Vec<String>>,
    }

    impl HttpClient for RecordingHttpClient {
        fn execute_request<'life0, 'life1, 'async_trait>(
            &'life0 self,
            request: &'life1 Request,
        ) -> Pin<Box<dyn Future<Output = azure_core::Result<AsyncRawResponse>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.paths.lock().unwrap().push(request.url().path().into());
            Box::pin(async {
                Ok(AsyncRawResponse::from_bytes(
                    HttpStatusCode::Ok,
                    Headers::new(),
                    r#"{"value":"secret-value"}"#,
                ))
            })
        }
    }

    #[test]
    fn initial_request_gate_allows_only_one_cold_request() {
        const CALLERS: usize = 8;
        let gate = Arc::new(InitialRequestGate::default());
        let start = Arc::new(Barrier::new(CALLERS));
        let first_finished = Arc::new(AtomicBool::new(false));
        let cold_requests = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..CALLERS)
            .map(|_| {
                let gate = Arc::clone(&gate);
                let start = Arc::clone(&start);
                let first_finished = Arc::clone(&first_finished);
                let cold_requests = Arc::clone(&cold_requests);
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                thread::spawn(move || {
                    start.wait();
                    gate.run(|| {
                        if !first_finished.load(Ordering::SeqCst) {
                            cold_requests.fetch_add(1, Ordering::SeqCst);
                        }
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(30));
                        active.fetch_sub(1, Ordering::SeqCst);
                        first_finished.store(true, Ordering::SeqCst);
                        Ok(())
                    })
                })
            })
            .collect();

        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        assert_eq!(cold_requests.load(Ordering::SeqCst), 1);
        assert!(
            peak.load(Ordering::SeqCst) >= 2,
            "requests stayed serialized after the client was warm"
        );
        assert!(gate.ready.load(Ordering::Acquire));
    }

    #[test]
    fn initial_request_gate_retries_after_failure() {
        let gate = InitialRequestGate::default();
        let failed = gate.run(|| {
            Err::<(), _>(SecretSpecError::ProviderOperationFailed(
                "authentication unavailable".into(),
            ))
        });
        assert!(failed.is_err());
        assert!(!gate.ready.load(Ordering::Acquire));

        assert!(gate.run(|| Ok(())).is_ok());
        assert!(gate.ready.load(Ordering::Acquire));
    }

    #[test]
    fn test_format_secret_name() {
        let name = AkvProvider::format_secret_name("myapp", "prod", "DB_URL").unwrap();
        assert_eq!(name, "secretspec--nv4wc4dq--obzg6za--irbf6vksjq");
    }

    #[test]
    fn test_format_secret_name_rejects_invalid_chars() {
        assert!(AkvProvider::format_secret_name("my/app", "prod", "DB_URL").is_err());
        assert!(AkvProvider::format_secret_name("myapp", "prod", "DB URL").is_err());
    }

    #[test]
    fn test_format_secret_name_too_long() {
        let long_key = "A".repeat(127);
        let result = AkvProvider::format_secret_name("myapp", "prod", &long_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_secret_name_preserves_case_distinctions() {
        let upper = AkvProvider::format_secret_name("app", "prod", "API_KEY").unwrap();
        let lower = AkvProvider::format_secret_name("app", "prod", "api_key").unwrap();
        assert_ne!(upper, lower);
        assert_eq!(upper, upper.to_ascii_lowercase());
        assert_eq!(lower, lower.to_ascii_lowercase());
    }

    #[test]
    fn test_format_secret_name_prevents_boundary_delimiter_collision() {
        let trailing = AkvProvider::format_secret_name("a", "b-", "C").unwrap();
        let leading = AkvProvider::format_secret_name("a", "b", "_C").unwrap();
        assert_ne!(trailing, leading);
    }

    #[test]
    fn test_format_secret_name_encodes_internal_delimiters() {
        let left = AkvProvider::format_secret_name("a", "b__c", "d").unwrap();
        let right = AkvProvider::format_secret_name("a", "b", "c__d").unwrap();
        assert_ne!(left, right);
    }

    #[test]
    fn test_classify_env_credentials_all_set() {
        let result = classify_env_credentials(
            Some("t".to_string()),
            Some("c".to_string()),
            Some("s".to_string()),
        );
        assert_eq!(
            result.unwrap(),
            Some(("t".to_string(), "c".to_string(), "s".to_string()))
        );
    }

    #[test]
    fn test_classify_env_credentials_none_set() {
        let result = classify_env_credentials(None, None, None);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_classify_env_credentials_partial_errors() {
        let err = classify_env_credentials(Some("t".to_string()), None, None).unwrap_err();
        assert!(err.to_string().contains("AZURE_CLIENT_ID"), "{err}");
        assert!(err.to_string().contains("AZURE_CLIENT_SECRET"), "{err}");
        // The message must also name the semantic provider credentials, so a user
        // who configured the alias `credentials` map (not env vars) knows which
        // input to supply.
        assert!(err.to_string().contains("client_id"), "{err}");
        assert!(err.to_string().contains("client_secret"), "{err}");
    }

    #[test]
    fn service_principal_credentials_override_environment_individually() {
        let _lock = crate::tests::scrub_resolution_env();
        let _tenant = EnvVarGuard::set(AZURE_TENANT_ID_ENV, "tenant-from-env");
        let _client = EnvVarGuard::set(AZURE_CLIENT_ID_ENV, "client-from-env");
        let _secret = EnvVarGuard::set(AZURE_CLIENT_SECRET_ENV, "secret-from-env");
        let mut provider = AkvProvider::new(config("akv://myvault"));
        provider.with_credentials(credentials(&[
            (TENANT_ID, "tenant-from-provider"),
            (CLIENT_SECRET, "secret-from-provider"),
        ]));

        assert_eq!(
            service_principal_inputs(&provider.credentials),
            (
                Some("tenant-from-provider".to_string()),
                Some("client-from-env".to_string()),
                Some("secret-from-provider".to_string()),
            )
        );
    }

    #[test]
    fn registration_advertises_service_principal_credentials() {
        assert_eq!(
            crate::provider::credential_names_for_spec("akv://myvault"),
            &[TENANT_ID, CLIENT_ID, CLIENT_SECRET]
        );
    }

    #[test]
    fn test_is_not_found_error_uses_http_status_not_string_matching() {
        let not_found = azure_core::Error::from(ErrorKind::HttpResponse {
            status: StatusCode::NotFound,
            error_code: Some("SecretNotFound".to_string()),
            raw_response: None,
        });
        assert!(AkvProvider::is_not_found_error(&not_found));

        // A real 404's Display is the service's plain-text message, which
        // does not necessarily contain "SecretNotFound" or "404" -- the old
        // string-matching check would have missed this.
        let plain_message_404 = azure_core::Error::with_message(
            ErrorKind::HttpResponse {
                status: StatusCode::NotFound,
                error_code: None,
                raw_response: None,
            },
            "A secret with (name) was not found in this key vault",
        );
        assert!(AkvProvider::is_not_found_error(&plain_message_404));

        let forbidden = azure_core::Error::from(ErrorKind::HttpResponse {
            status: StatusCode::Forbidden,
            error_code: None,
            raw_response: None,
        });
        assert!(!AkvProvider::is_not_found_error(&forbidden));

        let other = azure_core::Error::with_message(ErrorKind::Other, "boom");
        assert!(!AkvProvider::is_not_found_error(&other));
    }

    #[test]
    fn test_vault_url_appends_public_suffix_for_bare_name() {
        let c = config("akv://myvault");
        assert_eq!(c.vault_url, "https://myvault.vault.azure.net/");
        assert_eq!(c.suffix, None);
    }

    #[test]
    fn test_vault_url_uses_fqdn_verbatim_for_sovereign_clouds() {
        let c = config("akv://myvault.vault.azure.cn");
        assert_eq!(c.vault_url, "https://myvault.vault.azure.cn/");
        assert_eq!(c.suffix, None);
    }

    #[test]
    fn test_vault_url_suffix_query_param_overrides_default() {
        let c = config("akv://myvault?suffix=vault.azure.cn");
        assert_eq!(c.vault_url, "https://myvault.vault.azure.cn/");
        assert_eq!(c.suffix.as_deref(), Some("vault.azure.cn"));
    }

    #[test]
    fn test_uri_roundtrips_suffix() {
        let p = AkvProvider::new(config("akv://myvault?suffix=vault.azure.cn"));
        assert_eq!(p.uri(), "akv://myvault?suffix=vault.azure.cn");
    }

    #[test]
    fn test_uri_roundtrips_auth_and_suffix() {
        let p = AkvProvider::new(config(
            "akv://myvault?auth=managed_identity&suffix=vault.azure.cn",
        ));
        assert_eq!(
            p.uri(),
            "akv://myvault?auth=managed_identity&suffix=vault.azure.cn"
        );
    }

    #[test]
    fn storage_identity_uses_effective_vault_url_without_auth() {
        let public = AkvProvider::new(config("akv://myvault"));
        let cli = AkvProvider::new(config("akv://myvault?auth=cli"));
        let sovereign = AkvProvider::new(config("akv://myvault?suffix=vault.azure.cn"));
        let sovereign_fqdn = AkvProvider::new(config("akv://myvault.vault.azure.cn"));

        assert_eq!(public.storage_identity(), cli.storage_identity());
        assert_eq!(
            sovereign.storage_identity(),
            sovereign_fqdn.storage_identity()
        );
        assert_ne!(public.storage_identity(), sovereign.storage_identity());
    }

    #[test]
    fn validated_vault_host_and_injected_credential_are_reused() {
        let config = AkvConfig::from_validated_vault_host(
            "shared.vault.azure.net".to_string(),
            AuthMethod::ManagedIdentity,
        );
        assert_eq!(config.vault_url, "https://shared.vault.azure.net/");
        assert_eq!(config.vault_host, "shared.vault.azure.net");

        let credential: Arc<dyn TokenCredential> = DeveloperToolsCredential::new(None).unwrap();
        let provider = AkvProvider::with_token_credential(config, Arc::clone(&credential));
        assert!(Arc::ptr_eq(
            &credential,
            &provider.resolve_credential().unwrap()
        ));
    }

    #[test]
    fn test_default_auth_is_env() {
        let c = config("akv://myvault");
        assert_eq!(c.auth, AuthMethod::Env);
    }

    #[test]
    fn test_auth_query_param() {
        let c = config("akv://myvault?auth=managed_identity");
        assert_eq!(c.auth, AuthMethod::ManagedIdentity);
    }

    #[test]
    fn test_unknown_auth_method_errors() {
        assert!(
            AkvConfig::try_from(&ProviderUrl::new(
                Url::parse("akv://myvault?auth=bogus").unwrap()
            ))
            .is_err()
        );
    }

    #[test]
    fn test_convention_address() {
        let p = AkvProvider::new(config("akv://myvault"));
        let coords = p.convention_address("proj", "default", "A").unwrap();
        assert_eq!(coords.item, "secretspec--obzg62q--mrswmylvnr2a--ie");
        assert_eq!(coords.field, None);
    }

    #[test]
    fn version_coordinate_is_supported_and_distinguishes_entries() {
        let p = AkvProvider::new(config("akv://myvault"));
        assert_eq!(p.supported_coords(), &["version"]);

        let first = crate::config::NativeAddress {
            item: "existing-secret".into(),
            version: Some("0123456789abcdef0123456789abcdef".into()),
            ..Default::default()
        };
        let second = crate::config::NativeAddress {
            version: Some("fedcba9876543210fedcba9876543210".into()),
            ..first.clone()
        };
        assert!(
            !p.same_entries(Address::Native(&first), &p, Address::Native(&second))
                .unwrap()
        );
        assert!(
            !p.same_entries(
                Address::Native(&first),
                &p,
                Address::Native(&crate::config::NativeAddress {
                    version: None,
                    ..first.clone()
                }),
            )
            .unwrap()
        );
    }

    #[test]
    fn native_reads_request_pinned_or_latest_version() {
        let transport = Arc::new(RecordingHttpClient::default());
        let credential = DeveloperToolsCredential::new(None).unwrap();
        let client = SecretClient::new(
            "https://myvault.vault.azure.net/",
            credential,
            Some(SecretClientOptions {
                client_options: ClientOptions {
                    transport: Some(Transport::new(transport.clone())),
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .unwrap();
        let provider = AkvProvider::with_client(config("akv://myvault"), client);
        let pinned_version = "0123456789abcdef0123456789abcdef";

        let pinned = crate::config::NativeAddress {
            item: "existing-secret".into(),
            version: Some(pinned_version.into()),
            ..Default::default()
        };
        let value = provider.get(Address::Native(&pinned)).unwrap().unwrap();
        assert_eq!(value.expose_secret(), b"secret-value");

        let latest = crate::config::NativeAddress {
            version: None,
            ..pinned
        };
        let value = provider.get(Address::Native(&latest)).unwrap().unwrap();
        assert_eq!(value.expose_secret(), b"secret-value");

        assert_eq!(
            *transport.paths.lock().unwrap(),
            [
                format!("/secrets/existing-secret/{pinned_version}"),
                "/secrets/existing-secret/".to_string(),
            ]
        );
    }

    #[test]
    fn native_address_rejects_invalid_version_before_client_creation() {
        let p = AkvProvider::new(config("akv://myvault"));
        for version in [
            "",
            "3",
            "--------------------------------",
            "0123456789abcdef0123456789abcde/",
        ] {
            let addr = crate::config::NativeAddress {
                item: "existing-secret".into(),
                version: Some(version.into()),
                ..Default::default()
            };
            let error = p.get(Address::Native(&addr)).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("not a valid Azure Key Vault secret version"),
                "{version:?}: {error}"
            );
            assert!(p.client.get().is_none());
        }
    }

    /// Native addresses are read-only: they name secrets managed outside
    /// SecretSpec.
    #[test]
    fn native_address_is_read_only() {
        let p = AkvProvider::new(config("akv://myvault"));
        let addr = crate::config::NativeAddress {
            item: "existing-secret".into(),
            version: Some("0123456789abcdef0123456789abcdef".into()),
            ..Default::default()
        };
        let refusal = p.check_writable(Address::Native(&addr)).unwrap_err();
        assert!(refusal.to_string().contains("read-only"), "{refusal}");
        let err = p
            .set(Address::Native(&addr), &crate::SecretBytes::new("v".into()))
            .unwrap_err();
        assert_eq!(err.to_string(), refusal.to_string());
    }

    /// Azure Key Vault secrets have no sub-fields; the coordinate is rejected
    /// before any network I/O.
    #[test]
    fn native_address_rejects_field() {
        let p = AkvProvider::new(config("akv://myvault"));
        let addr = crate::config::NativeAddress {
            item: "existing-secret".into(),
            field: Some("x".into()),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }

    /// A native `ref` item with characters Azure Key Vault doesn't allow is
    /// rejected up front (and never silently rewritten), before any network
    /// I/O.
    #[test]
    fn native_address_rejects_invalid_azure_chars() {
        let p = AkvProvider::new(config("akv://myvault"));
        let addr = crate::config::NativeAddress {
            item: "existing_secret".into(),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(
            err.to_string()
                .contains("not a valid Azure Key Vault secret name"),
            "{err}"
        );
    }

    #[test]
    fn test_path_is_rejected_with_ref_hint() {
        let err = AkvConfig::try_from(&ProviderUrl::new(
            Url::parse("akv://myvault/some/path").unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("ref"), "{err}");
    }
}

/// Property tests for the invariants `format_secret_name` is built on.
///
/// The example-based tests above pin the counterexamples already found --
/// `b__c`/`c__d`, `b-`/`_C`, `API_KEY`/`api_key`. These quantify over the whole
/// component domain, so the *next* collision fails a test rather than a user's
/// `get`.
#[cfg(test)]
mod name_properties {
    use super::*;
    use proptest::prelude::*;

    /// A component Azure will accept: non-empty, alphanumeric/`_`/`-` only --
    /// exactly the domain `validate_name_component` admits. Kept short so a
    /// failure shrinks to a minimal, readable counterexample.
    ///
    /// The second arm is deliberate. Every collision this scheme has ever had
    /// lived in `_`/`-` against the `--` delimiter, and a uniform alphanumeric
    /// generator reaches that region far too rarely to find one: sampled against
    /// the old `_`->`-` mapping, an unbiased generator reports no collision at
    /// all. Weighting short delimiter-only components finds one immediately.
    fn component() -> impl Strategy<Value = String> {
        prop_oneof!["[A-Za-z0-9_-]{1,8}", "[_-]{1,3}"]
    }

    fn triple() -> impl Strategy<Value = (String, String, String)> {
        (component(), component(), component())
    }

    /// Recovers the triple a name was built from.
    ///
    /// Injectivity is stated over pairs, but sampling pairs is a poor way to
    /// look for a collision: two independently generated triples almost never
    /// collide by chance, so such a test passes happily against a scheme that is
    /// provably not injective. A left inverse is the stronger and cheaper claim
    /// -- if every name decodes back to exactly one triple, no two triples can
    /// share a name -- and every generated case exercises it.
    fn decode_secret_name(name: &str) -> Option<(String, String, String)> {
        let body = name.strip_prefix("secretspec--")?;
        let parts: Vec<&str> = body.split("--").collect();
        let [project, profile, key] = parts.as_slice() else {
            return None;
        };
        let decode = |part: &str| {
            let bytes = BASE32_NOPAD
                .decode(part.to_ascii_uppercase().as_bytes())
                .ok()?;
            String::from_utf8(bytes).ok()
        };
        Some((decode(project)?, decode(profile)?, decode(key)?))
    }

    proptest! {
        /// A name decodes back to the exact triple that built it.
        ///
        /// This is injectivity with teeth: it fails on the first generated case
        /// under a lossy scheme. The `_`->`-` mapping this replaced fails here
        /// immediately -- `-` and `_` both encode to `-`, so the original is
        /// unrecoverable and two triples can reach one name.
        #[test]
        fn a_name_decodes_to_the_triple_that_built_it((project, profile, key) in triple()) {
            let name = AkvProvider::format_secret_name(&project, &profile, &key)
                .expect("a valid component must format");
            prop_assert_eq!(
                decode_secret_name(&name),
                Some((project, profile, key)),
                "name {:?} did not decode back to its triple",
                name,
            );
        }

        /// No two triples in a batch share a name.
        ///
        /// Weaker than the left inverse above and kept deliberately: it states
        /// the guarantee in the form the module claims it ("injective"), and it
        /// would catch a collision introduced somewhere other than the encoding
        /// -- a changed delimiter, say, which decoding alone would not notice.
        #[test]
        fn distinct_triples_never_collide(triples in prop::collection::vec(triple(), 2..24)) {
            let mut seen: std::collections::HashMap<String, (String, String, String)> =
                std::collections::HashMap::new();
            for triple in triples {
                let name = AkvProvider::format_secret_name(&triple.0, &triple.1, &triple.2)
                    .expect("a valid component must format");
                if let Some(previous) = seen.insert(name.clone(), triple.clone()) {
                    prop_assert_eq!(
                        &previous,
                        &triple,
                        "distinct triples {:?} and {:?} both produced {:?}",
                        previous,
                        triple,
                        name,
                    );
                }
            }
        }

        /// Every formatted name is one Azure will accept: Key Vault permits
        /// alphanumerics and hyphens only.
        #[test]
        fn formatted_names_are_azure_legal((project, profile, key) in triple()) {
            let name = AkvProvider::format_secret_name(&project, &profile, &key)
                .expect("a valid component must format");
            prop_assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "name {name:?} contains a character Azure rejects",
            );
        }

        /// Names are already lowercase, so Azure's case-insensitive comparison
        /// changes nothing. Case distinctions survive in the encoded bytes
        /// rather than in the name's case, which is what lets `API_KEY` and
        /// `api_key` coexist.
        #[test]
        fn formatted_names_are_lowercase((project, profile, key) in triple()) {
            let name = AkvProvider::format_secret_name(&project, &profile, &key)
                .expect("a valid component must format");
            prop_assert_eq!(name.clone(), name.to_ascii_lowercase());
        }
    }
}
