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
//! `bws://project-uuid`
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

use super::{Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use bitwarden::Client;
use bitwarden::auth::login::AccessTokenLoginRequest;
use bitwarden::secrets_manager::ClientSecretsExt;
use bitwarden::secrets_manager::secrets::{
    SecretCreateRequest, SecretIdentifiersByProjectRequest, SecretPutRequest, SecretResponse,
    SecretsGetRequest,
};
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

        Ok(Self { project_id })
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
        }
    }

    /// Strips the BWS access token from error messages to avoid leaking credentials.
    fn sanitize_error(message: &str) -> String {
        if let Ok(token) = std::env::var("BWS_ACCESS_TOKEN") {
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

        let token = std::env::var("BWS_ACCESS_TOKEN").map_err(|_| {
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

        let client = Client::new(None);

        client
            .auth()
            .login_access_token(&AccessTokenLoginRequest {
                access_token: token,
                state_file: None,
            })
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(Self::sanitize_error(&format!(
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
                SecretSpecError::ProviderOperationFailed(Self::sanitize_error(&format!(
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
                SecretSpecError::ProviderOperationFailed(Self::sanitize_error(&format!(
                    "Failed to fetch secret values from BWS project '{}': {}",
                    self.config.project_id, e
                )))
            })?;

        Ok(secrets.data)
    }

    /// Retrieves a secret value from BWS by key name.
    async fn get_secret_async(
        &self,
        _project: &str,
        key: &str,
        _profile: &str,
    ) -> Result<Option<SecretString>> {
        let secrets = self.ensure_secrets().await?;

        // BWS uses flat key names -- match directly on the key
        for secret in secrets {
            if secret.key == key {
                return Ok(Some(SecretString::new(secret.value.clone().into())));
            }
        }

        Ok(None)
    }

    /// Creates or updates a secret in BWS.
    async fn set_secret_async(
        &self,
        _project: &str,
        key: &str,
        value: &SecretString,
        _profile: &str,
    ) -> Result<()> {
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
                    SecretSpecError::ProviderOperationFailed(Self::sanitize_error(&format!(
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
                    SecretSpecError::ProviderOperationFailed(Self::sanitize_error(&format!(
                        "Failed to create secret '{}' in BWS: {}",
                        key, e
                    )))
                })?;
        }

        Ok(())
    }

    /// Retrieves multiple secrets in a single batch using the cached secrets list.
    async fn get_batch_async(
        &self,
        _project: &str,
        keys: &[&str],
        _profile: &str,
    ) -> Result<HashMap<String, SecretString>> {
        let secrets = self.ensure_secrets().await?;
        let mut results = HashMap::new();

        for secret in secrets {
            if keys.contains(&secret.key.as_str()) {
                results.insert(
                    secret.key.clone(),
                    SecretString::new(secret.value.clone().into()),
                );
            }
        }

        Ok(results)
    }
}

impl Provider for BwsProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        format!("bws://{}", self.config.project_id)
    }

    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        super::block_on(self.get_secret_async(project, key, profile))
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        super::block_on(self.set_secret_async(project, key, value, profile))
    }

    fn allows_set(&self) -> bool {
        true
    }

    fn get_batch(
        &self,
        project: &str,
        keys: &[&str],
        profile: &str,
    ) -> Result<HashMap<String, SecretString>> {
        super::block_on(self.get_batch_async(project, keys, profile))
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

    #[test]
    fn test_bws_provider_metadata() {
        let config = BwsConfig {
            project_id: uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap(),
        };
        let provider = BwsProvider::new(config);

        assert_eq!(provider.name(), "bws");
        assert_eq!(provider.uri(), "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c");
        assert!(provider.allows_set());
    }
}
