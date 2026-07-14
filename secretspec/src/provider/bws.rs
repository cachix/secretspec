//! Bitwarden Secrets Manager (BWS) provider
//!
//! This provider integrates with Bitwarden Secrets Manager to store and retrieve secrets.
//!
//! # Authentication
//!
//! Uses a machine account access token via the `BWS_ACCESS_TOKEN` environment variable.
//! Generate access tokens from the Bitwarden Secrets Manager web interface.
//!
//! # URI Format
//!
//! `bws://[server-base@]project-uuid`
//!
//! Server Base is a hostname pointing to the bitwarden vault instance.
//! Defaults to bitwarden.com
//!
//! The UUID identifies the Bitwarden Secrets Manager project where secrets are stored.
//! This provides namespace isolation — different projects use different BWS project IDs.
//!
//! # Secret Naming
//!
//! Secrets are stored with flat key names matching the secret key directly (e.g., `DATABASE_URL`).
//! The BWS project ID in the URI provides namespace isolation, so project/profile parameters
//! from the Provider trait are ignored for lookup purposes.
//!
//! # Example
//!
//! ```bash
//! # Set up authentication
//! export BWS_ACCESS_TOKEN="0.your-access-token..."
//!
//! # Set a secret
//! secretspec set DATABASE_URL --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c
//!
//! # Check secrets from BWS
//! secretspec check --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c
//! ```

use super::{Address, BootstrapEnv, Provider, ProviderUrl, env_or_overlay_var};
use crate::{Result, SecretSpecError};
use bitwarden::auth::login::AccessTokenLoginRequest;
use bitwarden::secrets_manager::ClientSecretsExt;
use bitwarden::secrets_manager::secrets::{
    SecretCreateRequest, SecretIdentifiersByProjectRequest, SecretPutRequest, SecretResponse,
    SecretsGetRequest,
};
use bitwarden::{Client, ClientSettings};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Configuration for the Bitwarden Secrets Manager provider.
///
/// Contains the BWS project UUID where secrets are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwsConfig {
    /// The BWS project UUID (e.g., "a9230ec4-5507-4870-b8b5-b3f500587e4c")
    pub project_id: uuid::Uuid,

    /// The Bitwarden instance base URL (e.g., "https://vault.bitwarden.eu")
    pub server_base: Option<String>,
}

impl TryFrom<&ProviderUrl> for BwsConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "bws" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for bws provider. Expected 'bws'.",
                url.scheme()
            )));
        }

        // Extract project ID from host portion: bws://project-uuid
        let project_id_str = url.host().filter(|s| !s.is_empty()).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "BWS project ID is required. Use format: bws://project-uuid".to_string(),
            )
        })?;

        let project_id = uuid::Uuid::parse_str(&project_id_str).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Invalid BWS project UUID '{}': {}. Use format: bws://a9230ec4-5507-4870-b8b5-b3f500587e4c",
                project_id_str, e
            ))
        })?;

        // Extract server base URL from the username: bws://[server-base@]project-uuid
        let server_base = if !url.username().is_empty() {
            Some(url.username())
        } else {
            None
        };

        Ok(Self {
            project_id,
            server_base,
        })
    }
}

/// Bitwarden Secrets Manager provider.
///
/// This provider stores and retrieves secrets from Bitwarden Secrets Manager using
/// a machine account access token for authentication. Secrets are namespaced by
/// the BWS project ID specified in the provider URI.
pub struct BwsProvider {
    config: BwsConfig,
    client: OnceLock<Client>,
    secrets_cache: OnceLock<Vec<SecretResponse>>,
    /// Bootstrap-credential overlay consulted after the process environment.
    bootstrap_env: BootstrapEnv,
}

crate::register_provider! {
    struct: BwsProvider,
    config: BwsConfig,
    name: "bws",
    description: "Bitwarden Secrets Manager",
    schemes: ["bws"],
    examples: ["bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"],
}

impl BwsProvider {
    /// Creates a new BwsProvider with the given configuration.
    pub fn new(config: BwsConfig) -> Self {
        Self {
            config,
            client: OnceLock::new(),
            secrets_cache: OnceLock::new(),
            bootstrap_env: BootstrapEnv::new(),
        }
    }

    /// Resolves the BWS access token from the environment or bootstrap overlay.
    fn access_token(&self) -> Option<String> {
        env_or_overlay_var(&self.bootstrap_env, "BWS_ACCESS_TOKEN")
    }

    /// Strips the BWS access token from error messages to avoid leaking credentials.
    fn sanitize_error(&self, message: &str) -> String {
        if let Some(token) = self.access_token() {
            if !token.is_empty() {
                return message.replace(&token, "[REDACTED]");
            }
        }
        message.to_string()
    }

    /// Returns a reference to the authenticated Client, creating it if needed.
    ///
    /// Reads `BWS_ACCESS_TOKEN` from the environment and authenticates on first call.
    /// Subsequent calls return the cached client.
    async fn ensure_client(&self) -> Result<&Client> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }

        let token = self.access_token().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "BWS_ACCESS_TOKEN environment variable is not set. \
                 Generate an access token from the Bitwarden Secrets Manager web interface \
                 and set it as BWS_ACCESS_TOKEN."
                    .to_string(),
            )
        })?;

        if token.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "BWS_ACCESS_TOKEN environment variable is empty. \
                 Generate an access token from the Bitwarden Secrets Manager web interface."
                    .to_string(),
            ));
        }

        // The bitwarden crate uses rustls for TLS but doesn't install a crypto
        // provider. Install the aws-lc-rs provider (already a transitive dependency)
        // before creating the client. ok() ignores if already installed.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Set the API and Identity URLs based on server base URL if set
        let settings = self.config.server_base.as_ref().map(|it| ClientSettings {
            identity_url: format!("https://{it}/identity"),
            api_url: format!("https://{it}/api"),
            ..Default::default()
        });

        let client = Client::new(settings);

        client
            .auth()
            .login_access_token(&AccessTokenLoginRequest {
                access_token: token,
                state_file: None,
            })
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(self.sanitize_error(&format!(
                    "Failed to authenticate with Bitwarden Secrets Manager: {}",
                    e
                )))
            })?;

        Ok(self.client.get_or_init(|| client))
    }

    /// Returns a reference to the cached list of secrets in the project, fetching if needed.
    ///
    /// Uses a two-step process: first lists secret identifiers by project (which only returns
    /// IDs and key names), then fetches full secret values by IDs.
    async fn ensure_secrets(&self) -> Result<&Vec<SecretResponse>> {
        if let Some(secrets) = self.secrets_cache.get() {
            return Ok(secrets);
        }

        let secrets = self.fetch_secrets().await?;
        Ok(self.secrets_cache.get_or_init(|| secrets))
    }

    /// Fetches all secrets from the BWS project (always makes API calls, no caching).
    async fn fetch_secrets(&self) -> Result<Vec<SecretResponse>> {
        let client = self.ensure_client().await?;

        // Step 1: List secret identifiers in the project
        let identifiers = client
            .secrets()
            .list_by_project(&SecretIdentifiersByProjectRequest {
                project_id: self.config.project_id,
            })
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(self.sanitize_error(&format!(
                    "Failed to list secrets in BWS project '{}': {}",
                    self.config.project_id, e
                )))
            })?;

        if identifiers.data.is_empty() {
            return Ok(Vec::new());
        }

        // Step 2: Fetch full secret values by IDs
        let ids: Vec<uuid::Uuid> = identifiers.data.iter().map(|s| s.id).collect();
        let secrets = client
            .secrets()
            .get_by_ids(SecretsGetRequest { ids })
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(self.sanitize_error(&format!(
                    "Failed to fetch secret values from BWS project '{}': {}",
                    self.config.project_id, e
                )))
            })?;

        Ok(secrets.data)
    }

    /// Retrieves a secret value from BWS by its resolved key name.
    async fn get_secret_async(&self, target: &str) -> Result<Option<SecretString>> {
        let secrets = self.ensure_secrets().await?;

        // BWS uses flat key names -- match directly.
        for secret in secrets {
            if secret.key == target {
                return Ok(Some(SecretString::new(secret.value.clone().into())));
            }
        }

        Ok(None)
    }

    /// Creates or updates a secret in BWS at its resolved key name.
    async fn set_secret_async(&self, key: &str, value: &SecretString) -> Result<()> {
        let client = self.ensure_client().await?;

        // get_access_token_organization() is not part of the public stable API surface
        // of bitwarden-core, but it is the only way to retrieve the organization ID
        // from the access token after authentication.
        // See: https://github.com/bitwarden/sdk-sm/issues/944
        let org_id = client
            .internal
            .get_access_token_organization()
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "Failed to determine organization ID from BWS access token. \
                     Ensure the access token is valid."
                        .to_string(),
                )
            })?;

        // Fetch fresh secrets list (not cached) to avoid stale data when writing
        let fresh_secrets = self.fetch_secrets().await?;

        // Look for an existing secret with the same key name
        let existing = fresh_secrets.iter().find(|s| s.key == key);

        if let Some(existing_secret) = existing {
            // Update existing secret
            client
                .secrets()
                .update(&SecretPutRequest {
                    id: existing_secret.id,
                    organization_id: org_id.into(),
                    key: key.to_string(),
                    value: value.expose_secret().to_string(),
                    note: existing_secret.note.clone(),
                    project_ids: existing_secret.project_id.map(|id| vec![id]),
                })
                .await
                .map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(self.sanitize_error(&format!(
                        "Failed to update secret '{}' in BWS: {}",
                        key, e
                    )))
                })?;
        } else {
            // Create new secret
            client
                .secrets()
                .create(&SecretCreateRequest {
                    organization_id: org_id.into(),
                    key: key.to_string(),
                    value: value.expose_secret().to_string(),
                    note: String::new(),
                    project_ids: Some(vec![self.config.project_id]),
                })
                .await
                .map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(self.sanitize_error(&format!(
                        "Failed to create secret '{}' in BWS: {}",
                        key, e
                    )))
                })?;
        }

        Ok(())
    }
}

impl Provider for BwsProvider {
    /// Convention names map straight to the BWS key named after the secret;
    /// the project UUID in the URI provides namespace isolation instead.
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: key.to_string(),
            ..Default::default()
        })
    }

    fn with_bootstrap_env(&mut self, env: BootstrapEnv) {
        self.bootstrap_env = env;
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        match self.config.server_base {
            Some(ref server_base) => format!("bws://{server_base}@{}", self.config.project_id),
            None => format!("bws://{}", self.config.project_id),
        }
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let target = super::flat_item(self, addr)?;
        super::block_on(self.get_secret_async(&target))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let target = super::flat_item(self, addr)?;
        super::block_on(self.set_secret_async(&target, value))
    }

    /// Serves every request, convention or `ref`, from one cached listing of
    /// the project's secrets.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }
        let mut targets = Vec::with_capacity(requests.len());
        for (name, addr) in requests {
            targets.push((*name, super::flat_item(self, *addr)?));
        }

        let secrets = super::block_on(self.ensure_secrets())?;
        let by_key: HashMap<&str, &str> = secrets
            .iter()
            .map(|s| (s.key.as_str(), s.value.as_str()))
            .collect();

        let mut results = HashMap::new();
        for (name, target) in targets {
            if let Some(value) = by_key.get(&*target) {
                results.insert(
                    name.to_string(),
                    SecretString::new((*value).to_string().into()),
                );
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn provider_url(s: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(s).unwrap())
    }

    #[test]
    fn test_bws_config_valid_uuid() {
        let url = provider_url("bws://a9230ec4-5507-4870-b8b5-b3f500587e4c");
        let config = BwsConfig::try_from(&url).unwrap();
        assert_eq!(
            config.project_id,
            uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap()
        );
    }

    #[test]
    fn test_bws_config_missing_project_id() {
        let url = provider_url("bws://");
        let result = BwsConfig::try_from(&url);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("project ID is required"),
            "Error should mention project ID is required, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_bws_config_read_server_base() {
        let url = provider_url("bws://bw.home.internal@a9230ec4-5507-4870-b8b5-b3f500587e4c");
        let result = BwsConfig::try_from(&url).unwrap();

        assert_eq!(result.server_base, Some("bw.home.internal".to_string()));
    }

    #[test]
    fn test_bws_config_invalid_uuid() {
        let url = provider_url("bws://not-a-valid-uuid");
        let result = BwsConfig::try_from(&url);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid BWS project UUID"),
            "Error should mention invalid UUID, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_bws_config_wrong_scheme() {
        let url = provider_url("gcsm://a9230ec4-5507-4870-b8b5-b3f500587e4c");
        let result = BwsConfig::try_from(&url);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid scheme"),
            "Error should mention invalid scheme, got: {}",
            err_msg
        );
    }

    /// A native address names the BWS key directly via `item`.
    #[test]
    fn native_address_names_the_key() {
        let config =
            BwsConfig::try_from(&provider_url("bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"))
                .unwrap();
        let p = BwsProvider::new(config);
        let addr = crate::config::NativeAddress {
            item: "prod-db-url".into(),
            ..Default::default()
        };
        assert_eq!(
            crate::provider::flat_item(&p, Address::Native(&addr)).unwrap(),
            "prod-db-url"
        );
    }

    #[test]
    fn test_bws_provider_metadata() {
        let config = BwsConfig {
            project_id: uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap(),
            server_base: Some("vault.bitwarden.com".to_string()),
        };
        let provider = BwsProvider::new(config);

        assert_eq!(provider.name(), "bws");
        assert_eq!(
            provider.uri(),
            "bws://vault.bitwarden.com@a9230ec4-5507-4870-b8b5-b3f500587e4c"
        );
        assert!(
            provider
                .check_writable(Address::convention("proj", "default", "KEY"))
                .is_ok()
        );

        let config = BwsConfig {
            project_id: uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap(),
            server_base: None,
        };
        let provider = BwsProvider::new(config);

        assert_eq!(provider.name(), "bws");
        assert_eq!(provider.uri(), "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c");
        assert!(
            provider
                .check_writable(Address::convention("proj", "default", "KEY"))
                .is_ok()
        );
    }

    #[test]
    fn test_bws_access_token_missing_produces_clear_error() {
        if std::env::var("BWS_ACCESS_TOKEN").is_ok() {
            return;
        }

        let config = BwsConfig {
            project_id: uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap(),
            server_base: None,
        };
        let provider = BwsProvider::new(config);

        let result = provider.get(Address::convention("test_project", "default", "TEST_KEY"));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("BWS_ACCESS_TOKEN"),
            "Error should mention BWS_ACCESS_TOKEN, got: {}",
            err_msg
        );
    }

    /// BWS secrets are flat key/value pairs; a `field` coordinate is rejected.
    #[test]
    fn native_address_rejects_field() {
        let config =
            BwsConfig::try_from(&provider_url("bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"))
                .unwrap();
        let p = BwsProvider::new(config);
        let addr = crate::config::NativeAddress {
            item: "prod-db-url".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let err = crate::provider::flat_item(&p, Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }
}
