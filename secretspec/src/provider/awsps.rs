//! AWS Systems Manager Parameter Store provider
//!
//! Available starting with SecretSpec 0.18.
//!
//! This provider stores SecretSpec values as encrypted `SecureString`
//! parameters in AWS Systems Manager Parameter Store.
//!
//! # URI Format
//!
//! `awsps://[aws-profile@]region[?prefix=PREFIX][&kms_key_id=KEY][&tier=TIER]`
//!
//! - `awsps://us-east-1` — use SDK default credentials in us-east-1
//! - `awsps://production@us-east-1` — use the "production" AWS profile
//! - `awsps://us-east-1?prefix=/myteam` — store parameters below `/myteam`
//! - `awsps://us-east-1?kms_key_id=alias/my-key&tier=advanced`
//! - `awsps://` — use SDK defaults for both profile and region
//!
//! # Parameter Naming
//!
//! Parameters use the path
//! `[/prefix]/secretspec/{project}/{profile}/{key}`.

use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::{ParameterTier, ParameterType};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Maximum number of names accepted by one `GetParameters` request.
const AWS_GET_PARAMETERS_MAX_NAMES: usize = 10;

/// Parameter Store tier requested for writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AwspsTier {
    Standard,
    Advanced,
    IntelligentTiering,
}

impl AwspsTier {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "standard" => Ok(Self::Standard),
            "advanced" => Ok(Self::Advanced),
            "intelligent-tiering" => Ok(Self::IntelligentTiering),
            other => Err(SecretSpecError::ProviderOperationFailed(format!(
                "invalid awsps tier '{other}': expected standard, advanced, or \
                 intelligent-tiering"
            ))),
        }
    }

    fn as_uri_value(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Advanced => "advanced",
            Self::IntelligentTiering => "intelligent-tiering",
        }
    }

    fn as_sdk_value(self) -> ParameterTier {
        match self {
            Self::Standard => ParameterTier::Standard,
            Self::Advanced => ParameterTier::Advanced,
            Self::IntelligentTiering => ParameterTier::IntelligentTiering,
        }
    }
}

/// Configuration for the AWS Systems Manager Parameter Store provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AwspsConfig {
    /// AWS region. `None` uses the SDK default region chain.
    pub region: Option<String>,
    /// AWS shared-config profile. `None` uses the SDK default credential chain.
    pub aws_profile: Option<String>,
    /// Optional hierarchy placed before `/secretspec`.
    pub prefix: Option<String>,
    /// Optional customer-managed KMS key for `SecureString` writes.
    pub kms_key_id: Option<String>,
    /// Optional Parameter Store tier for writes.
    pub tier: Option<AwspsTier>,
}

impl TryFrom<&ProviderUrl> for AwspsConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        if url.scheme() != "awsps" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for awsps provider. Expected 'awsps'.",
                url.scheme()
            )));
        }

        let aws_profile = {
            let username = url.username();
            (!username.is_empty()).then_some(username)
        };
        let region = url.host().filter(|value| !value.is_empty());
        let prefix = url
            .query_value("prefix")
            .map(|value| value.trim_matches('/').to_string())
            .filter(|value| !value.is_empty());
        let kms_key_id = url.query_value("kms_key_id");
        let tier = url
            .query_value("tier")
            .map(|value| AwspsTier::parse(&value))
            .transpose()?;

        let path = url.path();
        let item = path.trim_start_matches('/');
        if !item.is_empty() {
            let hint = crate::config::ref_table_hint(None, item, None, None);
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "awsps URIs take no path: address the parameter with {hint} on \
                 the secret instead"
            )));
        }

        Ok(Self {
            region,
            aws_profile,
            prefix,
            kms_key_id,
            tier,
        })
    }
}

/// AWS Systems Manager Parameter Store provider, available in SecretSpec 0.18+.
pub struct AwspsProvider {
    config: AwspsConfig,
}

crate::register_provider! {
    struct: AwspsProvider,
    config: AwspsConfig,
    name: "awsps",
    description: "AWS Systems Manager Parameter Store (0.18+)",
    schemes: ["awsps"],
    examples: [
        "awsps://us-east-1",
        "awsps://production@us-east-1",
        "awsps://us-east-1?prefix=/myteam",
        "awsps://us-east-1?kms_key_id=alias/my-key&tier=advanced",
    ],
}

impl AwspsProvider {
    pub fn new(config: AwspsConfig) -> Self {
        Self { config }
    }

    /// Builds and validates the convention hierarchy.
    fn format_parameter_name(
        prefix: Option<&str>,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<String> {
        for (name, value) in [("project", project), ("profile", profile), ("key", key)] {
            if value.is_empty() {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{name} cannot be empty"
                )));
            }
        }

        let prefix = prefix.unwrap_or_default().trim_matches('/');
        let parameter_name = if prefix.is_empty() {
            format!("/secretspec/{project}/{profile}/{key}")
        } else {
            format!("/{prefix}/secretspec/{project}/{profile}/{key}")
        };
        Self::validate_parameter_name(&parameter_name)?;
        Ok(parameter_name)
    }

    /// Applies the Parameter Store naming constraints that can be checked
    /// without knowing the caller's AWS partition, account, and region.
    fn validate_parameter_name(name: &str) -> Result<()> {
        if name.len() > 1011 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Parameter name too long: {} characters (maximum 1011 before \
                 AWS applies its ARN-specific limit)",
                name.len()
            )));
        }

        let path = name.trim_start_matches('/');
        let mut parts = path.split('/');
        let Some(first) = parts.next().filter(|part| !part.is_empty()) else {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Parameter name cannot be empty".to_string(),
            ));
        };
        let first_lower = first.to_ascii_lowercase();
        if first_lower.starts_with("aws") || first_lower.starts_with("ssm") {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Parameter name '{name}' cannot start with the reserved prefix \
                 'aws' or 'ssm'"
            )));
        }

        let parts: Vec<&str> = std::iter::once(first).chain(parts).collect();
        if parts.len() > 15 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Parameter hierarchy has {} levels (maximum 15)",
                parts.len()
            )));
        }
        if parts.iter().any(|part| part.is_empty()) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Parameter name '{name}' contains an empty hierarchy level"
            )));
        }
        if let Some(character) = path
            .chars()
            .find(|character| !character.is_ascii_alphanumeric() && !"_.-/".contains(*character))
        {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Parameter name '{name}' contains invalid character '{character}'"
            )));
        }

        Ok(())
    }

    async fn create_client(&self) -> Client {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &self.config.region {
            loader = loader.region(aws_config::Region::new(region.clone()));
        }
        if let Some(profile) = &self.config.aws_profile {
            loader = loader.profile_name(profile);
        }
        Client::new(&loader.load().await)
    }

    /// Parameter Store selects a version or label by appending it to the name.
    fn selected_name(item: &str, version: Option<&str>) -> String {
        match version {
            Some(version) => format!("{item}:{version}"),
            None => item.to_string(),
        }
    }

    async fn get_parameter_async(&self, name: &str) -> Result<Option<SecretString>> {
        let client = self.create_client().await;
        let output = match client
            .get_parameter()
            .name(name)
            .with_decryption(true)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let service_error = error.into_service_error();
                return if service_error.is_parameter_not_found() {
                    Ok(None)
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to get Parameter Store parameter '{name}': {service_error}"
                    )))
                };
            }
        };

        Ok(output
            .parameter()
            .and_then(|parameter| parameter.value())
            .map(|value| SecretString::new(value.to_string().into())))
    }

    /// Indexes a returned parameter by the name and ARN forms accepted in the
    /// request, preserving a version or label selector when one was used.
    fn index_parameter(
        values: &mut HashMap<String, String>,
        parameter: &aws_sdk_ssm::types::Parameter,
    ) {
        let Some(value) = parameter.value() else {
            return;
        };
        let selector = parameter.selector().map_or_else(String::new, |selector| {
            if selector.starts_with(':') {
                selector.to_string()
            } else {
                format!(":{selector}")
            }
        });
        for identity in [parameter.name(), parameter.arn()].into_iter().flatten() {
            values.insert(format!("{identity}{selector}"), value.to_string());
        }
    }

    async fn get_many_async(
        &self,
        resolved: &[(&str, crate::config::NativeAddress)],
    ) -> Result<HashMap<String, SecretString>> {
        let client = self.create_client().await;
        let mut unique_names = Vec::new();
        let mut seen = HashSet::new();
        for (_, coordinates) in resolved {
            let name = Self::selected_name(&coordinates.item, coordinates.version.as_deref());
            if seen.insert(name.clone()) {
                unique_names.push(name);
            }
        }

        let mut values = HashMap::new();
        for names in unique_names.chunks(AWS_GET_PARAMETERS_MAX_NAMES) {
            let output = client
                .get_parameters()
                .set_names(Some(names.to_vec()))
                .with_decryption(true)
                .send()
                .await
                .map_err(|error| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "GetParameters failed: {}",
                        error.into_service_error()
                    ))
                })?;
            for parameter in output.parameters() {
                Self::index_parameter(&mut values, parameter);
            }
            // Parameter Store reports absent names in `invalid_parameters`;
            // like every other provider, absent secrets are omitted.
        }

        let mut results = HashMap::new();
        for (secret_name, coordinates) in resolved {
            let name = Self::selected_name(&coordinates.item, coordinates.version.as_deref());
            if let Some(value) = values.get(&name) {
                results.insert(
                    (*secret_name).to_string(),
                    SecretString::new(value.clone().into()),
                );
            }
        }
        Ok(results)
    }

    async fn set_parameter_async(&self, name: &str, value: &SecretString) -> Result<()> {
        let client = self.create_client().await;
        let mut request = client
            .put_parameter()
            .name(name)
            .value(value.expose_secret())
            .r#type(ParameterType::SecureString)
            .overwrite(true);
        if let Some(kms_key_id) = &self.config.kms_key_id {
            request = request.key_id(kms_key_id);
        }
        if let Some(tier) = self.config.tier {
            request = request.tier(tier.as_sdk_value());
        }
        request.send().await.map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to write Parameter Store parameter '{name}': {}",
                error.into_service_error()
            ))
        })?;
        Ok(())
    }
}

impl Provider for AwspsProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: Self::format_parameter_name(
                self.config.prefix.as_deref(),
                project,
                profile,
                key,
            )?,
            ..Default::default()
        })
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        &["version"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coordinates = self.resolve_coords(addr)?;
        let name = Self::selected_name(&coordinates.item, coordinates.version.as_deref());
        super::block_on(self.get_parameter_async(&name))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let coordinates = self.resolve_coords(addr)?;
        super::block_on(self.set_parameter_async(&coordinates.item, value))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention { .. } => Ok(()),
            Address::Native(_) => Err(SecretSpecError::ProviderOperationFailed(
                "awsps parameter references are read-only and cannot be written".to_string(),
            )),
        }
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let base = match (&self.config.aws_profile, &self.config.region) {
            (Some(profile), Some(region)) => format!(
                "awsps://{}@{}",
                ProviderUrl::encode(profile),
                ProviderUrl::encode(region)
            ),
            (None, Some(region)) => format!("awsps://{}", ProviderUrl::encode(region)),
            (_, None) => "awsps".to_string(),
        };

        let mut parameters = Vec::new();
        if let Some(prefix) = &self.config.prefix {
            parameters.push(format!(
                "prefix={}",
                ProviderUrl::encode_query(&format!("/{prefix}"))
            ));
        }
        if let Some(kms_key_id) = &self.config.kms_key_id {
            parameters.push(format!(
                "kms_key_id={}",
                ProviderUrl::encode_query(kms_key_id)
            ));
        }
        if let Some(tier) = self.config.tier {
            parameters.push(format!("tier={}", tier.as_uri_value()));
        }

        if parameters.is_empty() {
            base
        } else {
            let separator = if self.config.region.is_some() {
                "?"
            } else {
                "://?"
            };
            format!("{base}{separator}{}", parameters.join("&"))
        }
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }
        let mut resolved = Vec::with_capacity(requests.len());
        for (name, address) in requests {
            resolved.push((*name, self.resolve_coords(*address)?.into_owned()));
        }
        super::block_on(self.get_many_async(&resolved))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(uri: &str) -> AwspsConfig {
        let url = url::Url::parse(uri).unwrap();
        AwspsConfig::try_from(&ProviderUrl::new(url)).unwrap()
    }

    #[test]
    fn convention_uses_parameter_hierarchy() {
        let provider = AwspsProvider::new(config("awsps://us-east-1"));
        let address = provider
            .convention_address("myapp", "production", "DATABASE_URL")
            .unwrap();
        assert_eq!(address.item, "/secretspec/myapp/production/DATABASE_URL");
    }

    #[test]
    fn convention_accepts_normalized_prefix() {
        for prefix in ["myteam", "/myteam", "/myteam/"] {
            let name =
                AwspsProvider::format_parameter_name(Some(prefix), "app", "prod", "TOKEN").unwrap();
            assert_eq!(name, "/myteam/secretspec/app/prod/TOKEN");
        }
    }

    #[test]
    fn convention_rejects_invalid_names() {
        assert!(AwspsProvider::format_parameter_name(None, "", "prod", "KEY").is_err());
        assert!(AwspsProvider::format_parameter_name(None, "app", "", "KEY").is_err());
        assert!(AwspsProvider::format_parameter_name(None, "app", "prod", "").is_err());

        let error =
            AwspsProvider::format_parameter_name(None, "my app", "prod", "KEY").unwrap_err();
        assert!(error.to_string().contains("invalid character"), "{error}");

        let error = AwspsProvider::format_parameter_name(Some("/aws/team"), "app", "prod", "KEY")
            .unwrap_err();
        assert!(error.to_string().contains("reserved prefix"), "{error}");
    }

    #[test]
    fn convention_rejects_hierarchies_deeper_than_fifteen_levels() {
        let prefix = (0..12)
            .map(|number| format!("p{number}"))
            .collect::<Vec<_>>()
            .join("/");
        let error =
            AwspsProvider::format_parameter_name(Some(&prefix), "app", "prod", "KEY").unwrap_err();
        assert!(error.to_string().contains("maximum 15"), "{error}");
    }

    #[test]
    fn parses_profile_region_and_options() {
        let parsed = config(
            "awsps://production@us-east-1?prefix=/team/platform&kms_key_id=alias/team&tier=advanced",
        );
        assert_eq!(parsed.aws_profile.as_deref(), Some("production"));
        assert_eq!(parsed.region.as_deref(), Some("us-east-1"));
        assert_eq!(parsed.prefix.as_deref(), Some("team/platform"));
        assert_eq!(parsed.kms_key_id.as_deref(), Some("alias/team"));
        assert_eq!(parsed.tier, Some(AwspsTier::Advanced));
    }

    #[test]
    fn rejects_invalid_tier() {
        let url = url::Url::parse("awsps://us-east-1?tier=free").unwrap();
        let error = AwspsConfig::try_from(&ProviderUrl::new(url)).unwrap_err();
        assert!(error.to_string().contains("invalid awsps tier"), "{error}");
    }

    #[test]
    fn uri_round_trips_all_options() {
        let provider = AwspsProvider::new(config(
            "awsps://production@us-east-1?prefix=/team/platform&kms_key_id=alias/team&tier=intelligent-tiering",
        ));
        let uri = provider.uri();
        assert_eq!(
            uri,
            "awsps://production@us-east-1?prefix=/team/platform&kms_key_id=alias/team&tier=intelligent-tiering"
        );
        let reparsed = config(&uri);
        assert_eq!(reparsed.prefix.as_deref(), Some("team/platform"));
        assert_eq!(reparsed.tier, Some(AwspsTier::IntelligentTiering));
    }

    #[test]
    fn uri_without_region_uses_bare_provider_name() {
        assert_eq!(AwspsProvider::new(config("awsps://")).uri(), "awsps");
        assert_eq!(
            AwspsProvider::new(config("awsps://?prefix=/team")).uri(),
            "awsps://?prefix=/team"
        );
    }

    #[test]
    fn path_is_rejected_in_favor_of_ref() {
        let url = url::Url::parse("awsps://us-east-1/existing/parameter").unwrap();
        let error = AwspsConfig::try_from(&ProviderUrl::new(url)).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("URIs take no path"), "{message}");
        assert!(message.contains("ref = { item ="), "{message}");
    }

    #[test]
    fn native_ref_supports_version_or_label_selector() {
        assert_eq!(
            AwspsProvider::selected_name("/prod/token", Some("7")),
            "/prod/token:7"
        );
        assert_eq!(
            AwspsProvider::selected_name("/prod/token", Some("current")),
            "/prod/token:current"
        );
    }

    #[test]
    fn batch_response_preserves_selector_and_arn_forms() {
        let parameter = aws_sdk_ssm::types::Parameter::builder()
            .name("/prod/token")
            .arn("arn:aws:ssm:us-east-1:123456789012:parameter/prod/token")
            .selector(":7")
            .value("secret")
            .build();
        let mut values = HashMap::new();
        AwspsProvider::index_parameter(&mut values, &parameter);

        assert_eq!(values["/prod/token:7"], "secret");
        assert_eq!(
            values["arn:aws:ssm:us-east-1:123456789012:parameter/prod/token:7"],
            "secret"
        );
        assert!(!values.contains_key("/prod/token"));
    }

    #[test]
    fn native_ref_is_read_only() {
        let provider = AwspsProvider::new(config("awsps://us-east-1"));
        let reference = crate::config::NativeAddress {
            item: "/prod/token".to_string(),
            version: Some("3".to_string()),
            ..Default::default()
        };
        let error = provider
            .check_writable(Address::Native(&reference))
            .unwrap_err();
        assert!(error.to_string().contains("read-only"), "{error}");
    }

    #[test]
    fn native_ref_rejects_field_before_network_access() {
        let provider = AwspsProvider::new(config("awsps://us-east-1"));
        let reference = crate::config::NativeAddress {
            item: "/prod/token".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        };
        let error = provider
            .resolve_coords(Address::Native(&reference))
            .unwrap_err();
        assert!(error.to_string().contains("`field`"), "{error}");
    }

    #[test]
    fn batch_limit_is_ten_names() {
        let names: Vec<_> = (0..23).collect();
        let chunks: Vec<_> = names.chunks(AWS_GET_PARAMETERS_MAX_NAMES).collect();
        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            [10, 10, 3]
        );
    }
}
