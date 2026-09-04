//! AWS Systems Manager Parameter Store provider
//!
//! Available starting with SecretSpec 0.18.
//!
//! This provider stores SecretSpec values as encrypted `SecureString`
//! parameters in AWS Systems Manager Parameter Store.
//!
//! # URI Format
//!
//! `awsps://[aws-profile@]region[?prefix=PREFIX][&template=TEMPLATE][&kms_key_id=KEY][&tier=TIER]`
//!
//! - `awsps://us-east-1` — use SDK default credentials in us-east-1
//! - `awsps://production@us-east-1` — use the "production" AWS profile
//! - `awsps://us-east-1?prefix=/myteam` — store parameters below `/myteam`
//! - `awsps://us-east-1?template=/{profile}/{project}/{key}` — use a custom hierarchy
//! - `awsps://us-east-1?kms_key_id=alias/my-key&tier=advanced`
//! - `awsps://` — use SDK defaults for both profile and region
//!
//! # Parameter Naming
//!
//! Parameters use the path `[/prefix]/secretspec/{project}/{profile}/{key}` by
//! default. `template` replaces that complete layout.

use super::{Address, DiscoveryContext, Provider, ProviderUrl};
use crate::SecretBytes;
use crate::{Result, SecretSpecError};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_ssm::types::{ParameterTier, ParameterType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Debug;

/// Maximum number of names accepted by one `GetParameters` request.
const AWS_GET_PARAMETERS_MAX_NAMES: usize = 10;
const DEFAULT_PARAMETER_TEMPLATE: &str = "/secretspec/{project}/{profile}/{key}";

/// Formats an AWS SDK error without collapsing non-service failures into a
/// generated operation error's opaque `unhandled error` variant.
fn format_aws_error<E, R>(error: &SdkError<E, R>) -> String
where
    E: Error + ProvideErrorMetadata + 'static,
    R: Debug + 'static,
{
    if let Some(service_error) = error.as_service_error() {
        return match (service_error.code(), service_error.message()) {
            (Some(code), Some(message)) => format!("{code}: {message}"),
            (Some(code), None) => code.to_string(),
            (None, Some(message)) => message.to_string(),
            (None, None) => crate::error::display_error_chain(service_error),
        };
    }

    crate::error::display_error_chain(error)
}

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
    /// Optional complete convention layout. Must end in `/{key}` so discovery
    /// can map one bounded hierarchy back to declaration names.
    pub template: Option<String>,
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
        let template = url.query_value("template");
        if prefix.is_some() && template.is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "awsps `prefix` and `template` are mutually exclusive: `prefix` prepends the \
                 default layout, while `template` replaces it"
                    .to_string(),
            ));
        }
        if let Some(template) = &template {
            AwspsProvider::validate_template(template)?;
        }
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
            template,
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
    metadata: &super::catalog::AWSPS,
}

impl AwspsProvider {
    pub fn new(config: AwspsConfig) -> Self {
        Self { config }
    }

    fn effective_template(prefix: Option<&str>, template: Option<&str>) -> Result<String> {
        if prefix.is_some() && template.is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "awsps `prefix` and `template` are mutually exclusive: `prefix` prepends the \
                 default layout, while `template` replaces it"
                    .to_string(),
            ));
        }
        if let Some(template) = template {
            return Ok(template.to_string());
        }

        let prefix = prefix.unwrap_or_default().trim_matches('/');
        if prefix.is_empty() {
            Ok(DEFAULT_PARAMETER_TEMPLATE.to_string())
        } else {
            Ok(format!("/{prefix}{DEFAULT_PARAMETER_TEMPLATE}"))
        }
    }

    fn validate_template(template: &str) -> Result<()> {
        if !template.starts_with('/') {
            return Err(SecretSpecError::ProviderOperationFailed(
                "awsps template must start with `/`".to_string(),
            ));
        }

        let mut rest = template;
        let mut key_count = 0;
        while let Some(open) = rest.find('{') {
            if rest[..open].contains('}') {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "awsps template '{template}' contains an unmatched `}}`"
                )));
            }
            let after_open = &rest[open + 1..];
            let Some(close) = after_open.find('}') else {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "awsps template '{template}' contains an unmatched `{{`"
                )));
            };
            let placeholder = &after_open[..close];
            match placeholder {
                "project" | "profile" => {}
                "key" => key_count += 1,
                _ => {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "unknown awsps template placeholder '{{{placeholder}}}': expected \
                         {{project}}, {{profile}}, or {{key}}"
                    )));
                }
            }
            rest = &after_open[close + 1..];
        }
        if rest.contains('}') {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "awsps template '{template}' contains an unmatched `}}`"
            )));
        }
        if key_count != 1 || !template.ends_with("/{key}") {
            return Err(SecretSpecError::ProviderOperationFailed(
                "awsps template must contain `{key}` exactly once as its final path segment"
                    .to_string(),
            ));
        }
        if template == "/{key}" {
            return Err(SecretSpecError::ProviderOperationFailed(
                "awsps template must include a bounded parent path before `/{key}`".to_string(),
            ));
        }

        let sample = template
            .replace("{project}", "project")
            .replace("{profile}", "profile")
            .replace("{key}", "KEY");
        Self::validate_parameter_name(&sample)
    }

    /// Builds and validates the convention hierarchy.
    fn format_parameter_name(
        prefix: Option<&str>,
        template: Option<&str>,
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

        let template = Self::effective_template(prefix, template)?;
        Self::validate_template(&template)?;
        let parameter_name = template
            .replace("{project}", project)
            .replace("{profile}", profile)
            .replace("{key}", key);
        Self::validate_parameter_name(&parameter_name)?;
        Ok(parameter_name)
    }

    /// Renders the exact parent hierarchy that reflection may enumerate.
    fn discovery_path(
        prefix: Option<&str>,
        template: Option<&str>,
        context: DiscoveryContext<'_>,
    ) -> Result<String> {
        for (name, value) in [("project", context.project), ("profile", context.profile)] {
            if value.is_empty() {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "discovery {name} cannot be empty"
                )));
            }
        }

        let template = Self::effective_template(prefix, template)?;
        Self::validate_template(&template)?;
        let rendered = template
            .replace("{project}", context.project)
            .replace("{profile}", context.profile);
        let path = rendered
            .strip_suffix("/{key}")
            .expect("validated template ends in /{key}")
            .to_string();
        Self::validate_parameter_name(&path)?;
        Ok(path)
    }

    fn declaration_from_parameter(
        path: &str,
        name: &str,
    ) -> Result<Option<(String, crate::Secret)>> {
        let Some(key) = name.strip_prefix(&format!("{path}/")) else {
            return Ok(None);
        };
        if key.is_empty() || key.contains('/') {
            return Ok(None);
        }
        if !crate::config::is_valid_identifier(key) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Parameter Store parameter '{name}' maps to invalid SecretSpec name '{key}': \
                 names must be alphanumeric and underscores and cannot start with a number"
            )));
        }

        Ok(Some((
            key.to_string(),
            crate::Secret::required(format!("{key} secret")),
        )))
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

    async fn get_parameter_async(&self, name: &str) -> Result<Option<SecretBytes>> {
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
                return if error
                    .as_service_error()
                    .is_some_and(|service_error| service_error.is_parameter_not_found())
                {
                    Ok(None)
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to get Parameter Store parameter '{name}': {}",
                        format_aws_error(&error)
                    )))
                };
            }
        };

        Ok(output
            .parameter()
            .and_then(|parameter| parameter.value())
            .map(|value| SecretBytes::new(value.to_string().into())))
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
    ) -> Result<HashMap<String, SecretBytes>> {
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
                        format_aws_error(&error)
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
                    SecretBytes::new(value.clone().into()),
                );
            }
        }
        Ok(results)
    }

    async fn set_parameter_async(&self, name: &str, value: &SecretBytes) -> Result<()> {
        let value = super::require_utf8("awsps", value)?;
        let client = self.create_client().await;
        let mut request = client
            .put_parameter()
            .name(name)
            .value(value)
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
                format_aws_error(&error)
            ))
        })?;
        Ok(())
    }

    async fn reflect_async(
        &self,
        context: DiscoveryContext<'_>,
    ) -> Result<HashMap<String, crate::Secret>> {
        let path = Self::discovery_path(
            self.config.prefix.as_deref(),
            self.config.template.as_deref(),
            context,
        )?;
        let client = self.create_client().await;
        let mut declarations = HashMap::new();
        let mut next_token = None;

        loop {
            let mut request = client
                .get_parameters_by_path()
                .path(&path)
                .recursive(false)
                .with_decryption(false);
            if let Some(token) = next_token {
                request = request.next_token(token);
            }
            let output = request.send().await.map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to discover Parameter Store parameters under '{path}': {}",
                    format_aws_error(&error)
                ))
            })?;

            for parameter in output.parameters() {
                if let Some(name) = parameter.name()
                    && let Some((key, declaration)) = Self::declaration_from_parameter(&path, name)?
                {
                    declarations.insert(key, declaration);
                }
            }

            next_token = output.next_token().map(str::to_string);
            if next_token.is_none() {
                break;
            }
        }

        Ok(declarations)
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
                self.config.template.as_deref(),
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

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let coordinates = self.resolve_coords(addr)?;
        let name = Self::selected_name(&coordinates.item, coordinates.version.as_deref());
        super::block_on(self.get_parameter_async(&name))
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        self.check_writable(addr)?;
        let coordinates = self.resolve_coords(addr)?;
        super::block_on(self.set_parameter_async(&coordinates.item, value))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Native(native) if native.item.starts_with("arn:") => {
                Err(SecretSpecError::ProviderOperationFailed(
                    "awsps refs using a parameter ARN are read-only: use the parameter's name to \
                     write it in the provider's configured account and region."
                        .to_string(),
                ))
            }
            Address::Native(native) if native.version.is_some() => {
                Err(SecretSpecError::ProviderOperationFailed(
                    "awsps refs pinning a `version` are read-only: a Parameter Store version or \
                     label cannot be overwritten. Drop `version` to write a new latest version."
                        .to_string(),
                ))
            }
            _ => self
                .resolve_coords(addr)
                .and_then(|coordinates| Self::validate_parameter_name(&coordinates.item)),
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
        if let Some(template) = &self.config.template {
            parameters.push(format!("template={}", ProviderUrl::encode_query(template)));
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

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }
        let mut resolved = Vec::with_capacity(requests.len());
        for (name, address) in requests {
            resolved.push((*name, self.resolve_coords(*address)?.into_owned()));
        }
        super::block_on(self.get_many_async(&resolved))
    }

    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, crate::Secret>> {
        super::block_on(self.reflect_async(context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ssm::operation::get_parameters::GetParametersError;

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
                AwspsProvider::format_parameter_name(Some(prefix), None, "app", "prod", "TOKEN")
                    .unwrap();
            assert_eq!(name, "/myteam/secretspec/app/prod/TOKEN");
        }
    }

    #[test]
    fn convention_rejects_invalid_names() {
        assert!(AwspsProvider::format_parameter_name(None, None, "", "prod", "KEY").is_err());
        assert!(AwspsProvider::format_parameter_name(None, None, "app", "", "KEY").is_err());
        assert!(AwspsProvider::format_parameter_name(None, None, "app", "prod", "").is_err());

        let error =
            AwspsProvider::format_parameter_name(None, None, "my app", "prod", "KEY").unwrap_err();
        assert!(error.to_string().contains("invalid character"), "{error}");

        let error =
            AwspsProvider::format_parameter_name(Some("/aws/team"), None, "app", "prod", "KEY")
                .unwrap_err();
        assert!(error.to_string().contains("reserved prefix"), "{error}");
    }

    #[test]
    fn convention_rejects_hierarchies_deeper_than_fifteen_levels() {
        let prefix = (0..12)
            .map(|number| format!("p{number}"))
            .collect::<Vec<_>>()
            .join("/");
        let error = AwspsProvider::format_parameter_name(Some(&prefix), None, "app", "prod", "KEY")
            .unwrap_err();
        assert!(error.to_string().contains("maximum 15"), "{error}");
    }

    #[test]
    fn custom_template_replaces_default_hierarchy() {
        let provider = AwspsProvider::new(config(
            "awsps://us-east-1?template=/{profile}/{project}/{key}",
        ));
        let address = provider
            .convention_address("payments", "production", "DATABASE_URL")
            .unwrap();
        assert_eq!(address.item, "/production/payments/DATABASE_URL");
    }

    #[test]
    fn template_requires_a_bounded_reversible_key_path() {
        for template in [
            "relative/{key}",
            "/{key}",
            "/prod/static",
            "/prod/{key}/nested",
            "/prod/{unknown}/{key}",
            "/prod/{key}/{key}",
        ] {
            let uri = format!("awsps://us-east-1?template={template}");
            let url = url::Url::parse(&uri).unwrap();
            assert!(
                AwspsConfig::try_from(&ProviderUrl::new(url)).is_err(),
                "expected invalid template: {template}"
            );
        }
    }

    #[test]
    fn prefix_and_template_are_mutually_exclusive() {
        let url =
            url::Url::parse("awsps://us-east-1?prefix=/team&template=/{profile}/{project}/{key}")
                .unwrap();
        let error = AwspsConfig::try_from(&ProviderUrl::new(url)).unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"), "{error}");
    }

    #[test]
    fn discovery_renders_the_same_bounded_parent_as_the_convention() {
        let context = DiscoveryContext::new("payments", "production");
        assert_eq!(
            AwspsProvider::discovery_path(None, None, context).unwrap(),
            "/secretspec/payments/production"
        );
        assert_eq!(
            AwspsProvider::discovery_path(None, Some("/{profile}/{project}/{key}"), context,)
                .unwrap(),
            "/production/payments"
        );
    }

    #[test]
    fn discovery_maps_only_direct_valid_children_to_declarations() {
        let path = "/production/payments";
        let (key, declaration) =
            AwspsProvider::declaration_from_parameter(path, "/production/payments/DATABASE_URL")
                .unwrap()
                .unwrap();
        assert_eq!(key, "DATABASE_URL");
        assert_eq!(declaration.required_setting(), Some(true));
        assert!(
            AwspsProvider::declaration_from_parameter(path, "/production/payments/nested/TOKEN")
                .unwrap()
                .is_none()
        );

        let error = AwspsProvider::declaration_from_parameter(path, "/production/payments/api-key")
            .unwrap_err();
        assert!(
            error.to_string().contains("invalid SecretSpec name"),
            "{error}"
        );
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
    fn uri_round_trips_template() {
        let provider = AwspsProvider::new(config(
            "awsps://production@us-east-1?template=/{profile}/{project}/{key}",
        ));
        let uri = provider.uri();
        assert_eq!(
            uri,
            "awsps://production@us-east-1?template=/{profile}/{project}/{key}"
        );
        let reparsed = config(&uri);
        assert_eq!(
            reparsed.template.as_deref(),
            Some("/{profile}/{project}/{key}")
        );
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
    fn unversioned_native_name_ref_is_writable() {
        let provider = AwspsProvider::new(config("awsps://us-east-1"));
        let reference = crate::config::NativeAddress {
            item: "/prod/token".to_string(),
            ..Default::default()
        };
        provider
            .check_writable(Address::Native(&reference))
            .unwrap();
    }

    #[test]
    fn versioned_native_ref_is_read_only() {
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
    fn native_arn_ref_is_read_only() {
        let provider = AwspsProvider::new(config("awsps://us-east-1"));
        let reference = crate::config::NativeAddress {
            item: "arn:aws:ssm:us-east-1:123456789012:parameter/prod/token".to_string(),
            ..Default::default()
        };
        let error = provider
            .check_writable(Address::Native(&reference))
            .unwrap_err();
        assert!(error.to_string().contains("ARN"), "{error}");
        assert!(error.to_string().contains("read-only"), "{error}");
    }

    #[test]
    fn versioned_native_arn_ref_reports_arn_remediation() {
        let provider = AwspsProvider::new(config("awsps://us-east-1"));
        let reference = crate::config::NativeAddress {
            item: "arn:aws:ssm:us-east-1:123456789012:parameter/prod/token".to_string(),
            version: Some("3".to_string()),
            ..Default::default()
        };
        let error = provider
            .check_writable(Address::Native(&reference))
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("ARN"), "{message}");
        assert!(!message.contains("Drop `version`"), "{message}");
    }

    #[test]
    fn native_ref_rejects_unsupported_coordinates_during_writability_check() {
        let provider = AwspsProvider::new(config("awsps://us-east-1"));
        let references = [
            (
                "field",
                crate::config::NativeAddress {
                    item: "/prod/token".to_string(),
                    field: Some("password".to_string()),
                    ..Default::default()
                },
            ),
            (
                "vault",
                crate::config::NativeAddress {
                    item: "/prod/token".to_string(),
                    vault: Some("production".to_string()),
                    ..Default::default()
                },
            ),
            (
                "section",
                crate::config::NativeAddress {
                    item: "/prod/token".to_string(),
                    section: Some("credentials".to_string()),
                    ..Default::default()
                },
            ),
        ];

        for (coordinate, reference) in references {
            let error = provider
                .check_writable(Address::Native(&reference))
                .unwrap_err();
            assert!(error.to_string().contains(coordinate), "{error}");
        }
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

    #[test]
    fn aws_error_includes_unmodeled_service_code_and_message() {
        let service_error = GetParametersError::generic(
            aws_sdk_ssm::error::ErrorMetadata::builder()
                .code("AccessDeniedException")
                .message("not authorized to read these parameters")
                .build(),
        );
        let sdk_error = SdkError::service_error(service_error, ());

        assert_eq!(
            format_aws_error(&sdk_error),
            "AccessDeniedException: not authorized to read these parameters"
        );
    }

    #[test]
    fn aws_error_includes_non_service_cause() {
        let sdk_error: SdkError<GetParametersError, ()> =
            SdkError::construction_failure(std::io::Error::other("invalid AWS endpoint"));

        assert_eq!(
            format_aws_error(&sdk_error),
            "failed to construct request: invalid AWS endpoint"
        );
    }
}
