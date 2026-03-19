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
use std::collections::HashMap;
use url::Url;

/// Maximum number of secrets per BatchGetSecretValue API call.
const AWS_BATCH_GET_MAX_SECRETS: usize = 20;

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

    /// Builds the full AWS secret names and a reverse map back to the original keys.
    fn build_batch_request_names(
        project: &str,
        keys: &[&str],
        profile: &str,
    ) -> Result<(Vec<String>, HashMap<String, String>)> {
        let mut secret_names = Vec::with_capacity(keys.len());
        let mut name_to_key = HashMap::with_capacity(keys.len());
        for key in keys {
            let name = Self::format_secret_name(project, profile, key)?;
            name_to_key.insert(name.clone(), key.to_string());
            secret_names.push(name);
        }
        Ok((secret_names, name_to_key))
    }

    /// Fetches multiple secrets in batches of 20 using the BatchGetSecretValue API.
    async fn get_batch_async(
        &self,
        project: &str,
        keys: &[&str],
        profile: &str,
    ) -> Result<HashMap<String, SecretString>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }

        let client = self.create_client().await?;
        let (secret_names, name_to_key) = Self::build_batch_request_names(project, keys, profile)?;
        let mut results = HashMap::new();

        for chunk in secret_names.chunks(AWS_BATCH_GET_MAX_SECRETS) {
            let mut request = client.batch_get_secret_value();
            for name in chunk {
                request = request.secret_id_list(name.clone());
            }

            let response = request.send().await.map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BatchGetSecretValue failed: {}",
                    e.into_service_error()
                ))
            })?;

            // Process successful values
            for secret in response.secret_values() {
                if let (Some(name), Some(value)) = (secret.name(), secret.secret_string())
                    && let Some(key) = name_to_key.get(name)
                {
                    results.insert(key.clone(), SecretString::new(value.to_string().into()));
                }
            }

            // Handle per-secret errors
            for error in response.errors() {
                let error_code = error.error_code().unwrap_or("Unknown");
                if error_code != "ResourceNotFoundException" {
                    let secret_id = error.secret_id().unwrap_or("unknown");
                    let message = error.message().unwrap_or("no message");
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to get secret '{}': {} - {}",
                        secret_id, error_code, message
                    )));
                }
                // ResourceNotFoundException: secret not present, omit from results
            }
        }

        Ok(results)
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

    #[test]
    fn test_format_secret_name() {
        let name = AwssmProvider::format_secret_name("myapp", "prod", "DB_URL").unwrap();
        assert_eq!(name, "secretspec/myapp/prod/DB_URL");
    }

    #[test]
    fn test_format_secret_name_too_long() {
        let long_key = "A".repeat(500);
        let result = AwssmProvider::format_secret_name("myapp", "prod", &long_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_secret_name_empty_inputs() {
        assert!(AwssmProvider::format_secret_name("", "prod", "KEY").is_err());
        assert!(AwssmProvider::format_secret_name("proj", "", "KEY").is_err());
        assert!(AwssmProvider::format_secret_name("proj", "prod", "").is_err());
    }

    #[test]
    fn test_build_batch_request_names() {
        let keys: Vec<&str> = vec!["A", "B", "C"];
        let (secret_names, name_to_key) =
            AwssmProvider::build_batch_request_names("proj", &keys, "default").unwrap();

        assert_eq!(secret_names.len(), 3);
        assert_eq!(name_to_key.len(), 3);
        assert_eq!(secret_names[0], "secretspec/proj/default/A");
        assert_eq!(name_to_key["secretspec/proj/default/A"], "A");
        assert_eq!(name_to_key["secretspec/proj/default/B"], "B");
        assert_eq!(name_to_key["secretspec/proj/default/C"], "C");
    }

    #[test]
    fn test_build_batch_request_names_empty() {
        let keys: Vec<&str> = vec![];
        let (secret_names, name_to_key) =
            AwssmProvider::build_batch_request_names("proj", &keys, "default").unwrap();
        assert!(secret_names.is_empty());
        assert!(name_to_key.is_empty());
    }

    #[test]
    fn test_build_batch_request_names_chunking() {
        let keys: Vec<String> = (0..45).map(|i| format!("SECRET_{}", i)).collect();
        let key_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();

        let (secret_names, name_to_key) =
            AwssmProvider::build_batch_request_names("proj", &key_refs, "default").unwrap();

        assert_eq!(secret_names.len(), 45);
        assert_eq!(name_to_key.len(), 45);

        let chunks: Vec<&[String]> = secret_names.chunks(AWS_BATCH_GET_MAX_SECRETS).collect();
        assert_eq!(chunks.len(), 3); // 20 + 20 + 5
        assert_eq!(chunks[0].len(), 20);
        assert_eq!(chunks[1].len(), 20);
        assert_eq!(chunks[2].len(), 5);

        // Verify reverse mapping is correct for all keys
        for key in &key_refs {
            let name = AwssmProvider::format_secret_name("proj", "default", key).unwrap();
            assert_eq!(name_to_key[&name], *key);
        }
    }
}
