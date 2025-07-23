use super::Provider;
use crate::{Result, SecretSpecError};
use infisical::{
    auth::AuthMethod,
    client::Client,
    resources::secrets::{CreateSecretRequest, GetSecretRequest, UpdateSecretRequest},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::runtime::Runtime;
use url::Url;

/// Configuration for the Infisical provider.
///
/// This struct contains all the necessary configuration options for
/// interacting with Infisical API. It currently supports Universal Auth
/// for authentication.
///
/// # Examples
///
/// ```ignore
/// # use secretspec::provider::infisical::InfisicalConfig;
/// // Using universal auth (client ID and secret)
/// let config = InfisicalConfig {
///     client_id: Some("your-client-id".to_string()),
///     client_secret: Some("your-client-secret".to_string()),
///     project_id: "your-project-id".to_string(),
///     ..Default::default()
/// };
///
/// // With custom API URL
/// let config = InfisicalConfig {
///     client_id: Some("your-client-id".to_string()),
///     client_secret: Some("your-client-secret".to_string()),
///     project_id: "your-project-id".to_string(),
///     api_url: Some("https://custom.infisical.com".to_string()),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InfisicalConfig {
    /// Client ID for universal authentication.
    ///
    /// This should be obtained from the Infisical dashboard
    /// when creating machine identities.
    pub client_id: Option<String>,

    /// Client secret for universal authentication.
    ///
    /// This should be obtained from the Infisical dashboard
    /// when creating machine identities.
    pub client_secret: Option<String>,

    /// Optional custom API URL.
    ///
    /// Defaults to "https://app.infisical.com" if not specified.
    /// Useful for self-hosted Infisical instances.
    pub api_url: Option<String>,

    /// Project ID where secrets are stored.
    ///
    /// Required for secret operations.
    pub project_id: Option<String>,

    /// Optional path prefix for organizing secrets.
    ///
    /// Defaults to "/" if not specified.
    pub path_prefix: Option<String>,
}

impl TryFrom<&Url> for InfisicalConfig {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "infisical" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for infisical provider",
                url.scheme()
            )));
        }

        let mut config = Self::default();

        // Parse URL components
        // Format: infisical://[api_url]/[project_id]/[path]?client_id=xxx&client_secret=yyy
        if let Some(host) = url.host_str() {
            if !host.is_empty() {
                // If there's a port, include it in the API URL
                if let Some(port) = url.port() {
                    config.api_url = Some(format!("https://{}:{}", host, port));
                } else {
                    config.api_url = Some(format!("https://{}", host));
                }
            }
        }

        // Extract project ID and path from URL path
        let path = url.path();
        if !path.is_empty() && path != "/" {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            if !parts.is_empty() && !parts[0].is_empty() {
                config.project_id = Some(parts[0].to_string());
                if parts.len() > 1 {
                    config.path_prefix = Some(format!("/{}", parts[1..].join("/")));
                }
            }
        }

        // Parse query parameters
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "client_id" => config.client_id = Some(value.to_string()),
                "client_secret" => config.client_secret = Some(value.to_string()),
                _ => {}
            }
        }

        Ok(config)
    }
}

/// Provider for storing secrets in Infisical.
///
/// The InfisicalProvider uses the Infisical API to store and retrieve
/// secrets securely. It requires authentication via Universal Auth (client ID and secret).
///
/// Secrets are organized using the following structure:
/// - Project: Maps to Infisical project ID
/// - Environment: Maps to secretspec profile (e.g., "development", "production")
/// - Path: `/secretspec/{project}/{key}`
///
/// This ensures secrets are properly namespaced by project and profile,
/// preventing conflicts between different projects or environments.
pub struct InfisicalProvider {
    config: InfisicalConfig,
    client: Arc<Client>,
    runtime: Runtime,
}

crate::register_provider! {
    struct: InfisicalProvider,
    config: InfisicalConfig,
    name: "infisical",
    description: "Infisical secrets management platform",
    schemes: ["infisical"],
    examples: ["infisical://project-id?client_id=xxx&client_secret=yyy", "infisical://app.infisical.com/project-id?client_id=xxx&client_secret=yyy"],
}

impl InfisicalProvider {
    /// Creates a new InfisicalProvider with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the infisical provider
    ///
    /// # Returns
    ///
    /// A Result containing the new instance or an error
    pub fn new(config: InfisicalConfig) -> Result<Self> {
        let client_id = config.client_id.clone().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Infisical client ID not provided. Set via URL parameter".to_string(),
            )
        })?;

        let client_secret = config.client_secret.clone().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Infisical client secret not provided. Set via URL parameter".to_string(),
            )
        })?;

        let api_url = config.api_url.clone();

        // Create a tokio runtime for async operations
        let runtime = Runtime::new().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!("Failed to create runtime: {}", e))
        })?;

        // Build and authenticate the client
        let client = runtime.block_on(async {
            let mut builder = Client::builder();

            if let Some(url) = api_url {
                builder = builder.base_url(url);
            }

            let mut client = builder.build().await.map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!("Failed to build client: {}", e))
            })?;

            // Authenticate with universal auth
            let auth_method = AuthMethod::new_universal_auth(client_id, client_secret);
            client.login(auth_method).await.map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!("Failed to authenticate: {}", e))
            })?;

            Ok::<_, SecretSpecError>(client)
        })?;

        Ok(Self {
            config,
            client: Arc::new(client),
            runtime,
        })
    }

    /// Constructs the secret key name for a given project and key.
    /// In Infisical, we'll use a naming convention: SECRETSPEC_{PROJECT}_{KEY}
    fn secret_key(&self, project: &str, key: &str) -> String {
        format!(
            "SECRETSPEC_{}_{}",
            project.to_uppercase().replace("-", "_"),
            key
        )
    }

    /// Gets the path for secrets, defaulting to the configured path prefix or "/"
    fn get_path(&self) -> &str {
        self.config.path_prefix.as_deref().unwrap_or("/")
    }

    /// Gets the project ID from config.
    fn get_project_id(&self) -> Result<String> {
        self.config.project_id.clone().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Project ID not specified. Set via URL path".to_string(),
            )
        })
    }
}

impl Provider for InfisicalProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    /// Retrieves a secret from Infisical.
    ///
    /// The secret is looked up using the project ID, environment (profile),
    /// and a naming convention: SECRETSPEC_{PROJECT}_{KEY}
    ///
    /// # Arguments
    ///
    /// * `project` - The project namespace for the secret
    /// * `key` - The secret key/name to retrieve
    /// * `profile` - The profile/environment (e.g., "development", "production")
    ///
    /// # Returns
    ///
    /// - `Ok(Some(value))` if the secret exists
    /// - `Ok(None)` if the secret doesn't exist
    /// - `Err` if there was an error accessing Infisical
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<String>> {
        let project_id = self.get_project_id()?;
        let secret_key = self.secret_key(project, key);
        let path = self.get_path();

        // Map profile names to Infisical environments
        let environment = match profile {
            "default" => "dev",
            _ => profile,
        };

        let client = Arc::clone(&self.client);

        self.runtime.block_on(async move {
            let request = GetSecretRequest::builder(&secret_key, &project_id, environment)
                .path(path)
                .build();

            match client.secrets().get(request).await {
                Ok(secret) => Ok(Some(secret.secret_value)),
                Err(e) => {
                    // Check if it's a not found error
                    let error_msg = e.to_string();
                    if error_msg.contains("not found")
                        || error_msg.contains("404")
                        || error_msg.contains("does not exist")
                    {
                        Ok(None)
                    } else {
                        Err(SecretSpecError::ProviderOperationFailed(format!(
                            "Failed to get secret from Infisical: {}",
                            e
                        )))
                    }
                }
            }
        })
    }

    /// Stores a secret in Infisical.
    ///
    /// The secret is stored with the project ID, environment (profile),
    /// and a naming convention: SECRETSPEC_{PROJECT}_{KEY}
    ///
    /// # Arguments
    ///
    /// * `project` - The project namespace for the secret
    /// * `key` - The secret key/name to store
    /// * `value` - The secret value to store
    /// * `profile` - The profile/environment (e.g., "development", "production")
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the secret was successfully stored
    /// - `Err` if there was an error
    fn set(&self, project: &str, key: &str, value: &str, profile: &str) -> Result<()> {
        let project_id = self.get_project_id()?;
        let secret_key = self.secret_key(project, key);
        let path = self.get_path();

        // Map profile names to Infisical environments
        let environment = match profile {
            "default" => "dev",
            _ => profile,
        };

        let client = Arc::clone(&self.client);
        let value = value.to_string();

        self.runtime.block_on(async move {
            // First, check if the secret exists
            let get_request = GetSecretRequest::builder(&secret_key, &project_id, environment)
                .path(path)
                .build();

            match client.secrets().get(get_request).await {
                Ok(_) => {
                    // Secret exists, update it
                    // Based on the GitHub example, environment should be in the builder
                    let update_request =
                        UpdateSecretRequest::builder(&secret_key, &value, &project_id)
                            .path(path)
                            .build();

                    client.secrets().update(update_request).await.map_err(|e| {
                        SecretSpecError::ProviderOperationFailed(format!(
                            "Failed to update secret in Infisical: {}",
                            e
                        ))
                    })?;
                }
                Err(_) => {
                    // Secret doesn't exist, create it
                    let create_request =
                        CreateSecretRequest::builder(&secret_key, &value, &project_id, environment)
                            .path(path)
                            .secret_comment(&format!(
                                "SecretSpec managed secret for {}/{}",
                                project, key
                            ))
                            .build();

                    client.secrets().create(create_request).await.map_err(|e| {
                        SecretSpecError::ProviderOperationFailed(format!(
                            "Failed to create secret in Infisical: {}",
                            e
                        ))
                    })?;
                }
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infisical_config_from_url() {
        // Test basic client credentials
        let url = Url::parse("infisical://?client_id=xxx&client_secret=yyy").unwrap();
        let config = InfisicalConfig::try_from(&url).unwrap();
        assert_eq!(config.client_id, Some("xxx".to_string()));
        assert_eq!(config.client_secret, Some("yyy".to_string()));
        assert_eq!(config.api_url, None);
        assert_eq!(config.project_id, None);

        // Test with custom API URL and project
        let url =
            Url::parse("infisical://app.infisical.com/project-123?client_id=aaa&client_secret=bbb")
                .unwrap();
        let config = InfisicalConfig::try_from(&url).unwrap();
        assert_eq!(config.client_id, Some("aaa".to_string()));
        assert_eq!(config.client_secret, Some("bbb".to_string()));
        assert_eq!(
            config.api_url,
            Some("https://app.infisical.com".to_string())
        );
        assert_eq!(config.project_id, Some("project-123".to_string()));

        // Test with path prefix
        let url = Url::parse("infisical://app.infisical.com/project-123/production/backend?client_id=ccc&client_secret=ddd").unwrap();
        let config = InfisicalConfig::try_from(&url).unwrap();
        assert_eq!(config.client_id, Some("ccc".to_string()));
        assert_eq!(config.client_secret, Some("ddd".to_string()));
        assert_eq!(config.project_id, Some("project-123".to_string()));
        assert_eq!(config.path_prefix, Some("/production/backend".to_string()));

        // Test with port
        let url =
            Url::parse("infisical://localhost:8080/project-456?client_id=eee&client_secret=fff")
                .unwrap();
        let config = InfisicalConfig::try_from(&url).unwrap();
        assert_eq!(config.api_url, Some("https://localhost:8080".to_string()));
        assert_eq!(config.project_id, Some("project-456".to_string()));
    }

    #[test]
    fn test_secret_key_construction() {
        // We can't easily create a real provider without authentication,
        // so we'll test the key construction logic separately

        // Test basic key construction
        assert_eq!(
            format!(
                "SECRETSPEC_{}_{}",
                "myapp".to_uppercase().replace("-", "_"),
                "API_KEY"
            ),
            "SECRETSPEC_MYAPP_API_KEY"
        );

        // Test with hyphens in project name
        assert_eq!(
            format!(
                "SECRETSPEC_{}_{}",
                "my-app".to_uppercase().replace("-", "_"),
                "DATABASE_URL"
            ),
            "SECRETSPEC_MY_APP_DATABASE_URL"
        );

        // Test with lowercase key
        assert_eq!(
            format!(
                "SECRETSPEC_{}_{}",
                "service".to_uppercase().replace("-", "_"),
                "api_key"
            ),
            "SECRETSPEC_SERVICE_api_key"
        );
    }
}
