//! AWS Secrets Manager provider
//!
//! This provider integrates with AWS Secrets Manager to store and retrieve secrets.
//!
//! # Authentication
//!
//! Uses the standard AWS SDK credential chain:
//! - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
//! - Shared credentials file (`~/.aws/credentials`)
//! - IAM roles (EC2 instance profiles, ECS task roles)
//! - AWS SSO
//!
//! # URI Format
//!
//! `awssm://[aws-profile@]region`
//!
//! - `awssm://us-east-1` — use SDK default credentials in us-east-1
//! - `awssm://production@us-east-1` — use the "production" AWS profile in us-east-1
//! - `awssm://` — use SDK defaults for both profile and region
//!
//! # Secret Naming
//!
//! Secrets are stored with the naming pattern: `secretspec/{project}/{profile}/{key}`
//!
//! # Example
//!
//! ```bash
//! # Set a secret
//! secretspec set DATABASE_URL --provider awssm://us-east-1
//!
//! # Use a specific AWS profile
//! secretspec check --provider awssm://production@us-east-1
//! ```

use super::Provider;
use crate::{Result, SecretSpecError};
use aws_sdk_secretsmanager::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::future::Future;
use url::Url;

/// Configuration for the AWS Secrets Manager provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwssmConfig {
    /// The AWS region (e.g., "us-east-1"). If None, uses the SDK default.
    pub region: Option<String>,
    /// The AWS profile name from `~/.aws/credentials`. If None, uses the SDK default chain.
    pub aws_profile: Option<String>,
}

impl TryFrom<&Url> for AwssmConfig {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "awssm" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for awssm provider. Expected 'awssm'.",
                url.scheme()
            )));
        }

        // Parse AWS profile from username position: awssm://profile@region
        let aws_profile = {
            let username = url.username();
            if username.is_empty() {
                None
            } else {
                Some(username.to_string())
            }
        };

        let region = url
            .host_str()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        Ok(Self {
            region,
            aws_profile,
        })
    }
}

impl TryFrom<Url> for AwssmConfig {
    type Error = SecretSpecError;

    fn try_from(url: Url) -> std::result::Result<Self, Self::Error> {
        (&url).try_into()
    }
}

/// AWS Secrets Manager provider.
///
/// This provider stores and retrieves secrets from AWS Secrets Manager using
/// the standard AWS SDK credential chain for authentication.
pub struct AwssmProvider {
    config: AwssmConfig,
}

crate::register_provider! {
    struct: AwssmProvider,
    config: AwssmConfig,
    name: "awssm",
    description: "AWS Secrets Manager",
    schemes: ["awssm"],
    examples: ["awssm://us-east-1", "awssm://production@us-east-1"],
}

impl AwssmProvider {
    /// Creates a new AwssmProvider with the given configuration.
    pub fn new(config: AwssmConfig) -> Self {
        Self { config }
    }

    /// Formats the secret name for AWS Secrets Manager.
    ///
    /// Uses the pattern: `secretspec/{project}/{profile}/{key}`
    fn format_secret_name(project: &str, profile: &str, key: &str) -> Result<String> {
        if project.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "project cannot be empty".to_string(),
            ));
        }
        if profile.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "profile cannot be empty".to_string(),
            ));
        }
        if key.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "key cannot be empty".to_string(),
            ));
        }

        let secret_name = format!("secretspec/{}/{}/{}", project, profile, key);

        // AWS secret names can be up to 512 characters
        if secret_name.len() > 512 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Secret name too long: {} characters (max 512)",
                secret_name.len()
            )));
        }

        Ok(secret_name)
    }

    /// Executes an async future in a blocking context.
    ///
    /// If already inside a tokio runtime, uses `block_in_place` with the
    /// existing runtime handle. Otherwise, creates a new runtime.
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime")
                .block_on(future),
        }
    }

    /// Creates an AWS Secrets Manager client.
    async fn create_client(&self) -> Result<Client> {
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

        if let Some(region) = &self.config.region {
            config_loader = config_loader.region(aws_config::Region::new(region.clone()));
        }

        if let Some(profile) = &self.config.aws_profile {
            config_loader = config_loader.profile_name(profile);
        }

        let sdk_config = config_loader.load().await;
        Ok(Client::new(&sdk_config))
    }

    /// Retrieves a secret value from AWS Secrets Manager.
    async fn get_secret_async(
        &self,
        project: &str,
        key: &str,
        profile: &str,
    ) -> Result<Option<SecretString>> {
        let secret_name = Self::format_secret_name(project, profile, key)?;
        let client = self.create_client().await?;

        match client
            .get_secret_value()
            .secret_id(&secret_name)
            .send()
            .await
        {
            Ok(output) => {
                if let Some(value) = output.secret_string() {
                    Ok(Some(SecretString::new(value.to_string().into())))
                } else {
                    Ok(None)
                }
            }
            Err(err) => {
                let service_err = err.into_service_error();
                if service_err.is_resource_not_found_exception() {
                    Ok(None)
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to get secret '{}': {}",
                        secret_name, service_err
                    )))
                }
            }
        }
    }

    /// Creates or updates a secret in AWS Secrets Manager.
    async fn set_secret_async(
        &self,
        project: &str,
        key: &str,
        value: &SecretString,
        profile: &str,
    ) -> Result<()> {
        let secret_name = Self::format_secret_name(project, profile, key)?;
        let client = self.create_client().await?;

        // Try to create the secret first
        let create_result = client
            .create_secret()
            .name(&secret_name)
            .secret_string(value.expose_secret())
            .send()
            .await;

        match create_result {
            Ok(_) => Ok(()),
            Err(err) => {
                let service_err = err.into_service_error();
                if service_err.is_resource_exists_exception() {
                    // Secret already exists, update it
                    client
                        .put_secret_value()
                        .secret_id(&secret_name)
                        .secret_string(value.expose_secret())
                        .send()
                        .await
                        .map_err(|e| {
                            SecretSpecError::ProviderOperationFailed(format!(
                                "Failed to update secret '{}': {}",
                                secret_name,
                                e.into_service_error()
                            ))
                        })?;
                    Ok(())
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to create secret '{}': {}",
                        secret_name, service_err
                    )))
                }
            }
        }
    }
}

impl Provider for AwssmProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        match (&self.config.aws_profile, &self.config.region) {
            (Some(profile), Some(region)) => format!("awssm://{}@{}", profile, region),
            (None, Some(region)) => format!("awssm://{}", region),
            (_, None) => "awssm".to_string(),
        }
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
