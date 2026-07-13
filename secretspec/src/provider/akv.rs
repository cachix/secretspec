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
//! - `auth=env` (default) -- reads a service principal from the `AZURE_TENANT_ID`,
//!   `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` environment variables. If those
//!   are not set, falls back to the signed-in Azure CLI / Azure Developer CLI
//!   session (equivalent to `auth=cli`), so local development works out of the
//!   box after `az login`.
//! - `auth=cli` -- only the Azure CLI / Azure Developer CLI session.
//! - `auth=managed_identity` -- the VM/App Service/AKS system-assigned managed
//!   identity.
//! - `auth=workload_identity` -- AKS workload identity federation, via the
//!   `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_FEDERATED_TOKEN_FILE`
//!   environment variables injected by AKS.
//!
//! # URI Format
//!
//! `akv://<vault-name>[?auth=env|cli|managed_identity|workload_identity]`
//!
//! - `akv://myvault` -- `https://myvault.vault.azure.net/`
//! - `akv://myvault?auth=managed_identity` -- authenticate via managed identity
//! - `akv://myvault.vault.azure.cn` -- a host containing a dot is used verbatim
//!   as the vault's DNS name, for sovereign clouds (China, US Gov, Germany)
//!   whose Key Vault suffix is not `.vault.azure.net`
//!
//! # Secret Naming
//!
//! Azure Key Vault secret names may only contain ASCII letters, digits and
//! hyphens (`^[0-9a-zA-Z-]+$`, 1-127 characters) -- notably, unlike every other
//! cloud provider in this codebase, *not* underscores or slashes. Convention
//! secrets are named `secretspec--{project}--{profile}--{key}`, with each
//! component's underscores rewritten to hyphens to fit that charset. This is
//! lossy: `FOO_BAR` and `FOO-BAR` map to the same Key Vault secret name. Prefer
//! hyphens over underscores in project/profile/key names if that matters to you.
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

use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use azure_core::credentials::TokenCredential;
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    WorkloadIdentityCredential,
};
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

/// Configuration for the Azure Key Vault provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkvConfig {
    /// The vault name (short form) or full DNS name (sovereign clouds).
    pub vault_host: String,
    /// The full `https://...` base URL derived from `vault_host`.
    pub vault_url: String,
    /// Authentication method (default: Env).
    pub auth: AuthMethod,
}

/// The public-cloud Key Vault DNS suffix. Sovereign clouds (China, US Gov,
/// Germany) use a different suffix and must be addressed by their full DNS
/// name (a host containing a `.`), since there is no single suffix that works
/// for all of them.
const DEFAULT_SUFFIX: &str = "vault.azure.net";

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
        // clouds); a bare name gets the public-cloud suffix appended.
        let vault_url = if vault_host.contains('.') {
            format!("https://{}/", vault_host)
        } else {
            format!("https://{}.{}/", vault_host, DEFAULT_SUFFIX)
        };

        let auth = url
            .query_value("auth")
            .map(|v| match v.as_str() {
                "env" => Ok(AuthMethod::Env),
                "cli" => Ok(AuthMethod::Cli),
                "managed_identity" => Ok(AuthMethod::ManagedIdentity),
                "workload_identity" => Ok(AuthMethod::WorkloadIdentity),
                other => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Unknown auth method '{}'. Expected 'env', 'cli', 'managed_identity', \
                     or 'workload_identity'.",
                    other
                ))),
            })
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
        })
    }
}

/// Azure Key Vault provider.
///
/// Stores and retrieves secrets from an Azure Key Vault instance.
pub struct AkvProvider {
    config: AkvConfig,
}

crate::register_provider! {
    struct: AkvProvider,
    config: AkvConfig,
    name: "akv",
    description: "Azure Key Vault",
    schemes: ["akv"],
    examples: ["akv://myvault", "akv://myvault?auth=managed_identity"],
}

impl AkvProvider {
    /// Creates a new AkvProvider with the given configuration.
    pub fn new(config: AkvConfig) -> Self {
        Self { config }
    }

    /// Validates a secret name component against the characters Azure Key
    /// Vault allows once mapped (alphanumeric, underscore, hyphen -- the
    /// underscore is rewritten to a hyphen by the caller, everything else is
    /// rejected up front rather than silently dropped).
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

    /// Formats and validates the secret name for Azure Key Vault.
    ///
    /// Converts the SecretSpec path format to an Azure-compatible name:
    /// `secretspec--{project}--{profile}--{key}`, with underscores in each
    /// component rewritten to hyphens (Azure Key Vault secret names may only
    /// contain `[0-9a-zA-Z-]`, 1-127 characters).
    fn format_secret_name(project: &str, profile: &str, key: &str) -> Result<String> {
        Self::validate_name_component("project", project)?;
        Self::validate_name_component("profile", profile)?;
        Self::validate_name_component("key", key)?;

        let sanitize = |s: &str| s.replace('_', "-");
        let secret_name = format!(
            "secretspec--{}--{}--{}",
            sanitize(project),
            sanitize(profile),
            sanitize(key)
        );

        if secret_name.len() > 127 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Secret name too long: {} characters (max 127)",
                secret_name.len()
            )));
        }

        Ok(secret_name)
    }

    /// Resolves the token credential for the configured auth method.
    fn resolve_credential(&self) -> Result<Arc<dyn TokenCredential>> {
        match self.config.auth {
            AuthMethod::Cli => Ok(DeveloperToolsCredential::new(None).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to create Azure CLI / azd credential: {}",
                    e
                ))
            })? as Arc<dyn TokenCredential>),
            AuthMethod::ManagedIdentity => {
                Ok(ManagedIdentityCredential::new(None).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to create managed identity credential: {}",
                        e
                    ))
                })? as Arc<dyn TokenCredential>)
            }
            AuthMethod::WorkloadIdentity => {
                Ok(WorkloadIdentityCredential::new(None).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to create workload identity credential: {}\n\n\
                        Requires the AZURE_TENANT_ID, AZURE_CLIENT_ID, and \
                        AZURE_FEDERATED_TOKEN_FILE environment variables that AKS \
                        injects automatically for workload-identity-enabled pods.",
                        e
                    ))
                })? as Arc<dyn TokenCredential>)
            }
            AuthMethod::Env => {
                let tenant_id = std::env::var("AZURE_TENANT_ID").ok();
                let client_id = std::env::var("AZURE_CLIENT_ID").ok();
                let client_secret = std::env::var("AZURE_CLIENT_SECRET").ok();

                if let (Some(tenant_id), Some(client_id), Some(client_secret)) =
                    (tenant_id, client_id, client_secret)
                {
                    // NOTE: `azure_identity` is a very new (v1.0), fast-moving
                    // crate; verify this constructor's exact parameter types
                    // with `cargo check --features akv` before relying on it,
                    // in case the secret parameter type has changed.
                    Ok(ClientSecretCredential::new(
                        tenant_id,
                        client_id,
                        SecretString::new(client_secret.into()),
                        None,
                    )
                    .map_err(|e| {
                        SecretSpecError::ProviderOperationFailed(format!(
                            "Failed to create service principal credential from \
                            AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET: {}",
                            e
                        ))
                    })? as Arc<dyn TokenCredential>)
                } else {
                    // No service principal env vars: fall back to the signed-in
                    // Azure CLI / azd session so local development works after
                    // `az login` without any extra configuration.
                    Ok(DeveloperToolsCredential::new(None).map_err(|e| {
                        SecretSpecError::ProviderOperationFailed(format!(
                            "No AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET set, and \
                            failed to fall back to the Azure CLI / azd session: {}\n\n\
                            Either set those three environment variables, or run `az login`.",
                            e
                        ))
                    })? as Arc<dyn TokenCredential>)
                }
            }
        }
    }

    /// Creates a SecretClient for the configured vault.
    fn create_client(&self) -> Result<SecretClient> {
        let credential = self.resolve_credential()?;
        SecretClient::new(&self.config.vault_url, credential, None).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create Azure Key Vault client for {}: {}",
                self.config.vault_url, e
            ))
        })
    }

    /// Checks whether an error indicates the secret was not found.
    fn is_not_found_error(e: &impl std::error::Error) -> bool {
        let s = e.to_string();
        s.contains("SecretNotFound") || s.contains("404")
    }

    /// Retrieves a secret's current value by name, mapping "not found" to `None`.
    async fn get_secret_async(&self, name: &str) -> Result<Option<SecretString>> {
        let client = self.create_client()?;
        match client.get_secret(name, None).await {
            Ok(response) => {
                let secret = response.into_model().map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to read secret '{}' from Azure Key Vault: {}",
                        name, e
                    ))
                })?;
                Ok(secret.value.map(|v| SecretString::new(v.into())))
            }
            Err(e) => {
                if Self::is_not_found_error(&e) {
                    Ok(None)
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to get secret '{}' from Azure Key Vault: {}",
                        name, e
                    )))
                }
            }
        }
    }

    /// Sets a secret's value by name. Azure Key Vault's SET operation always
    /// creates a new version if the secret already exists, so create and
    /// update share this one call.
    async fn set_secret_async(&self, name: &str, value: &SecretString) -> Result<()> {
        let client = self.create_client()?;
        let params = SetSecretParameters {
            value: Some(value.expose_secret().to_string()),
            ..Default::default()
        };
        client
            .set_secret(
                name,
                params.try_into().map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to build set-secret request for '{}': {}",
                        name, e
                    ))
                })?,
                None,
            )
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to set secret '{}' in Azure Key Vault: {}",
                    name, e
                ))
            })?;
        Ok(())
    }
}

impl Provider for AkvProvider {
    /// Convention secrets are named `secretspec--{project}--{profile}--{key}`
    /// (Azure Key Vault secret names cannot contain underscores or slashes).
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

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = format!("akv://{}", self.config.vault_host);
        if self.config.auth != AuthMethod::default() {
            let auth = match self.config.auth {
                AuthMethod::Env => "env",
                AuthMethod::Cli => "cli",
                AuthMethod::ManagedIdentity => "managed_identity",
                AuthMethod::WorkloadIdentity => "workload_identity",
            };
            uri.push_str("?auth=");
            uri.push_str(auth);
        }
        uri
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        super::block_on(self.get_secret_async(&coords.item))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_coords(addr)?;
        super::block_on(self.set_secret_async(&coords.item, value))
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
    use url::Url;

    fn config(s: &str) -> AkvConfig {
        AkvConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    #[test]
    fn test_format_secret_name() {
        let name = AkvProvider::format_secret_name("myapp", "prod", "DB_URL").unwrap();
        assert_eq!(name, "secretspec--myapp--prod--DB-URL");
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
    fn test_vault_url_appends_public_suffix_for_bare_name() {
        let c = config("akv://myvault");
        assert_eq!(c.vault_url, "https://myvault.vault.azure.net/");
    }

    #[test]
    fn test_vault_url_uses_fqdn_verbatim_for_sovereign_clouds() {
        let c = config("akv://myvault.vault.azure.cn");
        assert_eq!(c.vault_url, "https://myvault.vault.azure.cn/");
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
        assert!(AkvConfig::try_from(&ProviderUrl::new(
            Url::parse("akv://myvault?auth=bogus").unwrap()
        ))
        .is_err());
    }

    #[test]
    fn test_convention_address() {
        let p = AkvProvider::new(config("akv://myvault"));
        let coords = p.convention_address("proj", "default", "A").unwrap();
        assert_eq!(coords.item, "secretspec--proj--default--A");
        assert_eq!(coords.field, None);
    }

    /// Native addresses are read-only: they name secrets managed outside
    /// SecretSpec.
    #[test]
    fn native_address_is_read_only() {
        let p = AkvProvider::new(config("akv://myvault"));
        let addr = crate::config::NativeAddress {
            item: "existing-secret".into(),
            ..Default::default()
        };
        let refusal = p.check_writable(Address::Native(&addr)).unwrap_err();
        assert!(refusal.to_string().contains("read-only"), "{refusal}");
        let err = p
            .set(
                Address::Native(&addr),
                &secrecy::SecretString::new("v".into()),
            )
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

    #[test]
    fn test_path_is_rejected_with_ref_hint() {
        let err = AkvConfig::try_from(&ProviderUrl::new(
            Url::parse("akv://myvault/some/path").unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("ref"), "{err}");
    }
}
