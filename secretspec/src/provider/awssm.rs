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
//! `awssm://[aws-profile@]region[?prefix=PREFIX]`
//!
//! - `awssm://us-east-1` — use SDK default credentials in us-east-1
//! - `awssm://production@us-east-1` — use the "production" AWS profile in us-east-1
//! - `awssm://us-east-1?prefix=myteam` — prefix all secret names with `myteam/`
//! - `awssm://` — use SDK defaults for both profile and region
//!
//! # Secret Naming
//!
//! Secrets are stored with the naming pattern: `[prefix/]secretspec/{project}/{profile}/{key}`
//!
//! When a `prefix` query parameter is set, it is prepended to the secret name,
//! allowing IAM policies to scope access (e.g. `arn:aws:secretsmanager:*:*:secret:myteam/*`).
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

use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use aws_sdk_secretsmanager::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum number of secrets per BatchGetSecretValue API call.
const AWS_BATCH_GET_MAX_SECRETS: usize = 20;

/// Configuration for the AWS Secrets Manager provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwssmConfig {
    /// The AWS region (e.g., "us-east-1"). If None, uses the SDK default.
    pub region: Option<String>,
    /// The AWS profile name from `~/.aws/credentials`. If None, uses the SDK default chain.
    pub aws_profile: Option<String>,
    /// Optional prefix prepended to all secret names (e.g., "myteam" →
    /// `myteam/secretspec/{project}/{profile}/{key}`).
    /// Useful for scoping IAM policies by prefix.
    pub prefix: Option<String>,
}

impl TryFrom<&ProviderUrl> for AwssmConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
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
                Some(username)
            }
        };

        let region = url.host().filter(|s| !s.is_empty());

        let prefix = url.query_value("prefix");

        // The path reference form from earlier iterations is rejected with a
        // pointer at the `ref` table, instead of being silently ignored and
        // reading the conventional layout.
        let name = url.path().trim_start_matches('/').to_string();
        if !name.is_empty() {
            let hint = crate::config::ref_table_hint(None, &name, None, None);
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "awssm URIs take no path: address the secret with \
                 {hint} on the secret instead \
                 (add field = \"<json-key>\" to extract one JSON key)"
            )));
        }

        Ok(Self {
            region,
            aws_profile,
            prefix,
        })
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
    examples: ["awssm://us-east-1", "awssm://production@us-east-1", "awssm://us-east-1?prefix=myteam"],
}

impl AwssmProvider {
    /// Creates a new AwssmProvider with the given configuration.
    pub fn new(config: AwssmConfig) -> Self {
        Self { config }
    }

    /// Formats the secret name for AWS Secrets Manager.
    ///
    /// Uses the pattern: `[prefix/]secretspec/{project}/{profile}/{key}`
    fn format_secret_name(
        prefix: Option<&str>,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<String> {
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

        let secret_name = match prefix {
            Some(p) => format!("{}/secretspec/{}/{}/{}", p, project, profile, key),
            None => format!("secretspec/{}/{}/{}", project, profile, key),
        };

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

    /// Extracts one key from a JSON secret value.
    fn extract_json_key(name: &str, value: &str, json_key: &str) -> Result<Option<SecretString>> {
        let json: serde_json::Value = serde_json::from_str(value).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "secret '{}' is not JSON, cannot extract key '{}': {}",
                name, json_key, e
            ))
        })?;
        match json.get(json_key) {
            Some(serde_json::Value::String(s)) => Ok(Some(SecretString::new(s.clone().into()))),
            // Non-string JSON values (numbers, bools) are rendered as-is.
            Some(other) => Ok(Some(SecretString::new(other.to_string().into()))),
            None => Ok(None),
        }
    }

    /// Retrieves a secret by its full name/ARN, optionally extracting one key
    /// from a JSON secret value.
    async fn get_coords_async(
        &self,
        name: &str,
        json_key: Option<&str>,
    ) -> Result<Option<SecretString>> {
        let client = self.create_client().await?;
        let output = match client.get_secret_value().secret_id(name).send().await {
            Ok(output) => output,
            Err(err) => {
                let service_err = err.into_service_error();
                return if service_err.is_resource_not_found_exception() {
                    Ok(None)
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to get secret '{}': {}",
                        name, service_err
                    )))
                };
            }
        };

        let Some(value) = output.secret_string() else {
            return Ok(None);
        };

        match json_key {
            None => Ok(Some(SecretString::new(value.to_string().into()))),
            Some(json_key) => Self::extract_json_key(name, value, json_key),
        }
    }

    /// Fetches every request in batches of 20 via the BatchGetSecretValue API:
    /// each unique secret name/ARN is fetched once, then per-request `field`
    /// coordinates extract their JSON key from the shared value.
    async fn get_many_async(
        &self,
        resolved: &[(&str, crate::config::NativeAddress)],
    ) -> Result<HashMap<String, SecretString>> {
        let client = self.create_client().await?;

        let mut unique: Vec<&str> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (_, coords) in resolved {
            if seen.insert(coords.item.as_str()) {
                unique.push(coords.item.as_str());
            }
        }

        // Fetched values keyed by both name and ARN, so requests addressing
        // the secret either way find their value.
        let mut fetched: HashMap<String, String> = HashMap::new();
        for chunk in unique.chunks(AWS_BATCH_GET_MAX_SECRETS) {
            let mut request = client.batch_get_secret_value();
            for name in chunk {
                request = request.secret_id_list(*name);
            }

            let response = request.send().await.map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BatchGetSecretValue failed: {}",
                    e.into_service_error()
                ))
            })?;

            for secret in response.secret_values() {
                if let Some(value) = secret.secret_string() {
                    if let Some(name) = secret.name() {
                        fetched.insert(name.to_string(), value.to_string());
                    }
                    if let Some(arn) = secret.arn() {
                        fetched.insert(arn.to_string(), value.to_string());
                    }
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

        let mut results = HashMap::new();
        for (name, coords) in resolved {
            let Some(value) = fetched.get(coords.item.as_str()) else {
                continue;
            };
            let secret = match coords.field.as_deref() {
                None => Some(SecretString::new(value.clone().into())),
                Some(json_key) => Self::extract_json_key(&coords.item, value, json_key)?,
            };
            if let Some(secret) = secret {
                results.insert((*name).to_string(), secret);
            }
        }
        Ok(results)
    }

    /// Creates or updates a secret at its full name in AWS Secrets Manager.
    async fn set_secret_async(&self, secret_name: &str, value: &SecretString) -> Result<()> {
        let client = self.create_client().await?;

        // Try to create the secret first
        let create_result = client
            .create_secret()
            .name(secret_name)
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
                        .secret_id(secret_name)
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
    /// Convention secrets are named `[{prefix}/]secretspec/{project}/{profile}/{key}`.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: Self::format_secret_name(self.config.prefix.as_deref(), project, profile, key)?,
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let base = match (&self.config.aws_profile, &self.config.region) {
            (Some(profile), Some(region)) => format!("awssm://{}@{}", profile, region),
            (None, Some(region)) => format!("awssm://{}", region),
            (_, None) => "awssm".to_string(),
        };
        match &self.config.prefix {
            Some(prefix) => {
                let sep = if base.contains("://") { "?" } else { "://?" };
                format!(
                    "{}{}prefix={}",
                    base,
                    sep,
                    ProviderUrl::encode_query(prefix)
                )
            }
            None => base,
        }
    }

    /// An optional `field` extracts one key from a JSON secret value.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        // `item` is the secret name or ARN.
        let coords = self.resolve_coords(addr)?;
        super::block_on(self.get_coords_async(&coords.item, coords.field.as_deref()))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_coords(addr)?;
        super::block_on(self.set_secret_async(&coords.item, value))
    }

    /// Native addresses are read-only: they name a secret managed outside
    /// SecretSpec (and a JSON-key write could not happen without clobbering
    /// the other keys).
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention { .. } => Ok(()),
            Address::Native(_) => Err(SecretSpecError::ProviderOperationFailed(
                "awssm secret references are read-only and cannot be written".to_string(),
            )),
        }
    }

    /// Batches every request, convention or `ref`, through
    /// BatchGetSecretValue.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }
        let mut resolved = Vec::with_capacity(requests.len());
        for (name, addr) in requests {
            resolved.push((*name, self.resolve_coords(*addr)?.into_owned()));
        }
        super::block_on(self.get_many_async(&resolved))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_secret_name() {
        let name = AwssmProvider::format_secret_name(None, "myapp", "prod", "DB_URL").unwrap();
        assert_eq!(name, "secretspec/myapp/prod/DB_URL");
    }

    #[test]
    fn test_format_secret_name_with_prefix() {
        let name =
            AwssmProvider::format_secret_name(Some("myteam"), "myapp", "prod", "DB_URL").unwrap();
        assert_eq!(name, "myteam/secretspec/myapp/prod/DB_URL");
    }

    #[test]
    fn test_format_secret_name_with_nested_prefix() {
        let name =
            AwssmProvider::format_secret_name(Some("org/team"), "myapp", "prod", "DB_URL").unwrap();
        assert_eq!(name, "org/team/secretspec/myapp/prod/DB_URL");
    }

    #[test]
    fn test_format_secret_name_too_long() {
        let long_key = "A".repeat(500);
        let result = AwssmProvider::format_secret_name(None, "myapp", "prod", &long_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_secret_name_empty_inputs() {
        assert!(AwssmProvider::format_secret_name(None, "", "prod", "KEY").is_err());
        assert!(AwssmProvider::format_secret_name(None, "proj", "", "KEY").is_err());
        assert!(AwssmProvider::format_secret_name(None, "proj", "prod", "").is_err());
    }

    #[test]
    fn test_convention_address() {
        let p = AwssmProvider::new(config("awssm://us-east-1"));
        let coords = p.convention_address("proj", "default", "A").unwrap();
        assert_eq!(coords.item, "secretspec/proj/default/A");
        assert_eq!(coords.field, None);
    }

    #[test]
    fn test_convention_address_with_prefix() {
        let p = AwssmProvider::new(config("awssm://us-east-1?prefix=myteam"));
        let coords = p.convention_address("proj", "default", "A").unwrap();
        assert_eq!(coords.item, "myteam/secretspec/proj/default/A");
    }

    #[test]
    fn test_batch_chunking() {
        let names: Vec<String> = (0..45).map(|i| format!("SECRET_{}", i)).collect();
        let chunks: Vec<&[String]> = names.chunks(AWS_BATCH_GET_MAX_SECRETS).collect();
        assert_eq!(chunks.len(), 3); // 20 + 20 + 5
        assert_eq!(chunks[0].len(), 20);
        assert_eq!(chunks[1].len(), 20);
        assert_eq!(chunks[2].len(), 5);
    }

    fn config(s: &str) -> AwssmConfig {
        use url::Url;
        AwssmConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    /// Native addresses are read-only: they name secrets managed outside
    /// SecretSpec.
    #[test]
    fn native_address_is_read_only() {
        let p = AwssmProvider::new(config("awssm://us-east-1"));
        let addr = crate::config::NativeAddress {
            item: "prod/db-credentials".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let refusal = p.check_writable(Address::Native(&addr)).unwrap_err();
        assert!(refusal.to_string().contains("read-only"), "{refusal}");
        // `set` refuses with the same reason, so the pre-check cannot drift.
        let err = p
            .set(
                Address::Native(&addr),
                &secrecy::SecretString::new("v".into()),
            )
            .unwrap_err();
        assert_eq!(err.to_string(), refusal.to_string());
    }

    /// AWS secrets have no sections; the coordinate is rejected before any
    /// network I/O.
    #[test]
    fn native_address_rejects_section() {
        let p = AwssmProvider::new(config("awssm://us-east-1"));
        let addr = crate::config::NativeAddress {
            item: "prod/db-credentials".into(),
            section: Some("x".into()),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`section`"), "{err}");
    }

    // The `field` coordinate extracts one key from a JSON secret value. This
    // is the whole point of `field` on AWS, and the only ref path that carries
    // logic (JSON parsing) rather than a live API call, so it is unit-tested
    // directly rather than only through the network path.

    #[test]
    fn extract_json_key_returns_string_value() {
        let value = r#"{"username": "admin", "password": "s3cret"}"#;
        let got = AwssmProvider::extract_json_key("db", value, "password").unwrap();
        assert_eq!(got.unwrap().expose_secret(), "s3cret");
    }

    #[test]
    fn extract_json_key_renders_non_string_values_verbatim() {
        // Numbers and bools are rendered as-is, not quoted like strings.
        let value = r#"{"port": 5432, "tls": true}"#;
        assert_eq!(
            AwssmProvider::extract_json_key("db", value, "port")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "5432"
        );
        assert_eq!(
            AwssmProvider::extract_json_key("db", value, "tls")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "true"
        );
    }

    #[test]
    fn extract_json_key_missing_key_is_none() {
        let value = r#"{"username": "admin"}"#;
        assert!(
            AwssmProvider::extract_json_key("db", value, "password")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn extract_json_key_on_non_json_value_errors() {
        let err = AwssmProvider::extract_json_key("db", "plain-string", "password").unwrap_err();
        let msg = err.to_string();
        // The error names both the secret and the key so the user can locate it.
        assert!(msg.contains("is not JSON"), "{msg}");
        assert!(msg.contains("db") && msg.contains("password"), "{msg}");
    }
}
