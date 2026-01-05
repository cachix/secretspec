//! Google Cloud Secret Manager provider
//!
//! This provider integrates with Google Cloud Secret Manager to store and retrieve secrets.
//!
//! # Authentication
//!
//! Uses Application Default Credentials (ADC). Set up via:
//! - `gcloud auth application-default login` for local development
//! - Service account with `GOOGLE_APPLICATION_CREDENTIALS` environment variable
//! - Workload Identity for GKE environments
//!
//! # URI Format
//!
//! `gcsm://project-id`
//!
//! # Secret Naming
//!
//! Secrets are stored with the naming pattern: `secretspec-{project}-{profile}-{key}`
//!
//! # Example
//!
//! ```bash
//! # Set up authentication
//! gcloud auth application-default login
//!
//! # Set a secret
//! secretspec set DATABASE_URL --provider gcsm://my-gcp-project
//!
//! # Check secrets from GCP
//! secretspec check --provider gcsm://my-gcp-project
//! ```

use super::Provider;
use crate::{Result, SecretSpecError};
use google_cloud_secretmanager_v1::client::SecretManagerService;
use google_cloud_secretmanager_v1::model::{Replication, Secret, SecretPayload, replication};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::future::Future;
use url::Url;

/// Configuration for the Google Cloud Secret Manager provider.
///
/// Contains the GCP project ID where secrets are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsmConfig {
    /// The GCP project ID (e.g., "my-gcp-project")
    pub project_id: String,
}

/// Validates a GCP project ID format.
///
/// GCP project IDs must:
/// - Be 6-30 characters long
/// - Start with a lowercase letter
/// - Contain only lowercase letters, digits, and hyphens
/// - Not end with a hyphen
fn validate_gcp_project_id(project_id: &str) -> std::result::Result<(), SecretSpecError> {
    let len = project_id.len();
    if len < 6 || len > 30 {
        return Err(SecretSpecError::ProviderOperationFailed(format!(
            "GCP project ID must be 6-30 characters, got {}",
            len
        )));
    }

    let mut chars = project_id.chars().peekable();

    // First character must be a lowercase letter
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => {
            return Err(SecretSpecError::ProviderOperationFailed(
                "GCP project ID must start with a lowercase letter".to_string(),
            ));
        }
    }

    // Check remaining characters
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "GCP project ID contains invalid character '{}'. \
                Only lowercase letters, digits, and hyphens are allowed",
                c
            )));
        }
    }

    // Cannot end with a hyphen
    if project_id.ends_with('-') {
        return Err(SecretSpecError::ProviderOperationFailed(
            "GCP project ID cannot end with a hyphen".to_string(),
        ));
    }

    Ok(())
}

impl TryFrom<&Url> for GcsmConfig {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "gcsm" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for gcsm provider. Expected 'gcsm'.",
                url.scheme()
            )));
        }

        // Extract project ID from host portion: gcsm://project-id
        let project_id = url
            .host_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "GCP project ID is required. Use format: gcsm://project-id".to_string(),
                )
            })?
            .to_string();

        // Validate project ID format
        validate_gcp_project_id(&project_id)?;

        Ok(Self { project_id })
    }
}

impl TryFrom<Url> for GcsmConfig {
    type Error = SecretSpecError;

    fn try_from(url: Url) -> std::result::Result<Self, Self::Error> {
        (&url).try_into()
    }
}

/// Google Cloud Secret Manager provider.
///
/// This provider stores and retrieves secrets from Google Cloud Secret Manager using
/// Application Default Credentials for authentication.
pub struct GcsmProvider {
    config: GcsmConfig,
}

crate::register_provider! {
    struct: GcsmProvider,
    config: GcsmConfig,
    name: "gcsm",
    description: "Google Cloud Secret Manager",
    schemes: ["gcsm"],
    examples: ["gcsm://my-gcp-project"],
}

impl GcsmProvider {
    /// Creates a new GcsmProvider with the given configuration.
    pub fn new(config: GcsmConfig) -> Self {
        Self { config }
    }

    /// Validates a secret name component for GCP Secret Manager.
    ///
    /// Components must contain only alphanumeric characters, underscores, and hyphens.
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

    /// Formats and validates the secret name for GCP Secret Manager.
    ///
    /// Converts the SecretSpec path format to GCP-compatible name:
    /// `secretspec-{project}-{profile}-{key}`
    ///
    /// GCP Secret Manager secret IDs must:
    /// - Be 1-255 characters long
    /// - Contain only alphanumeric characters, hyphens, and underscores
    fn format_secret_name(&self, project: &str, profile: &str, key: &str) -> Result<String> {
        // Validate each component
        Self::validate_name_component("project", project)?;
        Self::validate_name_component("profile", profile)?;
        Self::validate_name_component("key", key)?;

        let secret_name = format!("secretspec-{}-{}-{}", project, profile, key);

        // GCP secret IDs must be 1-255 characters
        if secret_name.len() > 255 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Secret name too long: {} characters (max 255)",
                secret_name.len()
            )));
        }

        Ok(secret_name)
    }

    /// Checks if an error indicates the resource was not found.
    fn is_not_found_error(e: &impl std::error::Error) -> bool {
        let s = e.to_string();
        s.contains("NOT_FOUND") || s.contains("notFound")
    }

    /// Checks if an error indicates the resource already exists.
    fn is_already_exists_error(e: &impl std::error::Error) -> bool {
        let s = e.to_string();
        s.contains("ALREADY_EXISTS") || s.contains("alreadyExists")
    }

    /// Executes an async future in a blocking context.
    ///
    /// Creates a new tokio runtime for each operation. While this has some
    /// overhead, it ensures compatibility with SecretSpec's synchronous
    /// Provider trait.
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
            .block_on(future)
    }

    /// Creates a SecretManagerService client.
    async fn create_client(&self) -> Result<SecretManagerService> {
        SecretManagerService::builder().build().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create GCP Secret Manager client: {}\n\n\
                Ensure Application Default Credentials are configured:\n  \
                - Local development: Run 'gcloud auth application-default login'\n  \
                - Service account: Set GOOGLE_APPLICATION_CREDENTIALS environment variable\n  \
                - GKE: Configure Workload Identity",
                e
            ))
        })
    }

    /// Retrieves a secret value from GCP Secret Manager.
    async fn get_secret_async(
        &self,
        project: &str,
        key: &str,
        profile: &str,
    ) -> Result<Option<SecretString>> {
        let secret_name = self.format_secret_name(project, profile, key)?;
        let secret_version_path = format!(
            "projects/{}/secrets/{}/versions/latest",
            self.config.project_id, secret_name
        );

        let client = self.create_client().await?;

        match client
            .access_secret_version()
            .set_name(&secret_version_path)
            .send()
            .await
        {
            Ok(response) => {
                if let Some(payload) = response.payload {
                    let data = String::from_utf8(payload.data.to_vec()).map_err(|e| {
                        SecretSpecError::ProviderOperationFailed(format!(
                            "Secret data is not valid UTF-8: {}",
                            e
                        ))
                    })?;
                    Ok(Some(SecretString::new(data.into())))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                // Check if the error is "not found" (secret doesn't exist)
                if Self::is_not_found_error(&e) {
                    Ok(None)
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to access secret '{}': {}",
                        secret_name, e
                    )))
                }
            }
        }
    }

    /// Creates or updates a secret in GCP Secret Manager.
    ///
    /// Always attempts to create the secret first (idempotent operation), then adds a new version.
    /// This avoids TOCTOU race conditions by not checking existence before creation.
    async fn set_secret_async(
        &self,
        project: &str,
        key: &str,
        value: &SecretString,
        profile: &str,
    ) -> Result<()> {
        let secret_name = self.format_secret_name(project, profile, key)?;
        let client = self.create_client().await?;

        // Always try to create the secret first (idempotent - ALREADY_EXISTS is expected for existing secrets)
        let create_result = client
            .create_secret()
            .set_parent(format!("projects/{}", self.config.project_id))
            .set_secret_id(&secret_name)
            .set_secret(Secret::default().set_replication(
                Replication::default().set_automatic(replication::Automatic::default()),
            ))
            .send()
            .await;

        // Only fail on errors OTHER than ALREADY_EXISTS
        if let Err(e) = create_result {
            if !Self::is_already_exists_error(&e) {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to create secret '{}': {}",
                    secret_name, e
                )));
            }
            // ALREADY_EXISTS is expected for existing secrets, continue to add version
        }

        // Add a new version with the secret data
        client
            .add_secret_version()
            .set_parent(format!(
                "projects/{}/secrets/{}",
                self.config.project_id, secret_name
            ))
            .set_payload(
                SecretPayload::default().set_data(value.expose_secret().as_bytes().to_vec()),
            )
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to add secret version for '{}': {}",
                    secret_name, e
                ))
            })?;

        Ok(())
    }
}

impl Provider for GcsmProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        format!("gcsm://{}", self.config.project_id)
    }

    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        self.block_on(self.get_secret_async(project, key, profile))
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        self.block_on(self.set_secret_async(project, key, value, profile))
    }

    fn allows_set(&self) -> bool {
        true
    }
}
