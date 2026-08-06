//! BeyondTrust Password Safe provider.
//!
//! This module provides a first-pass adapter for the BeyondTrust Password Safe
//! API flow shown in the example: it signs into the service with a
//! PS-Auth header, handles the initial 401 challenge, requests a managed
//! account, creates a request, reads the credentials response, and signs out.
//! The implementation is intentionally practical rather than exhaustive and is
//! meant to be a starting point for further integration.

use crate::config::NativeAddress;
use crate::provider::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env};
use crate::{Result, SecretSpecError};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Configuration for the BeyondTrust Password Safe provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BtPwsConfig {
    /// Optional host or tenant identifier used to derive the base URL.
    pub vault: Option<String>,
    /// Optional base URL for the Password Safe REST API.
    pub base_url: Option<String>,
    /// Optional tenant identifier to include in the auth context.
    pub tenant_id: Option<String>,
    /// Optional API key used for the PS-Auth header.
    pub auth_key: Option<String>,
    /// Optional account or user identity passed with PS-Auth.
    pub runas: Option<String>,
    /// Optional system name used when the secret ref does not include one.
    pub default_system_name: Option<String>,
    /// Optional API version or endpoint variant.
    pub api_version: Option<String>,
}

impl TryFrom<&ProviderUrl> for BtPwsConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "bt-pws" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for BeyondTrust Password Safe provider",
                url.scheme()
            )));
        }

        let mut config = Self::default();

        if let Some(host) = url.host().filter(|host| !host.is_empty()) {
            config.vault = Some(host);
        }

        if !url.path().is_empty() && url.path() != "/" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "BeyondTrust Password Safe secrets are addressed with a secret ref, not via the provider URI path: {}",
                url.path()
            )));
        }

        config.base_url = url.query_value("base_url");
        config.tenant_id = url.query_value("tenant_id");
        config.auth_key = url.query_value("auth_key");
        config.runas = url.query_value("runas");
        config.default_system_name = url.query_value("system_name");
        config.api_version = url.query_value("api_version");

        Ok(config)
    }
}

/// Minimal provider implementation for the Password Safe API.
pub struct BtPwsProvider {
    config: BtPwsConfig,
    credentials: ProviderCredentials,
}

crate::register_provider! {
    struct: BtPwsProvider,
    config: BtPwsConfig,
    name: "bt-pws",
    description: "BeyondTrust Password Safe API integration",
    schemes: ["bt-pws"],
    examples: ["bt-pws://", "bt-pws://pbps.example.com?auth_key=...&runas=..."],
    credential_names: ["auth_key", "runas"],
}

impl BtPwsProvider {
    pub fn new(config: BtPwsConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
        }
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn base_url(&self) -> String {
        if let Some(base_url) = self.config.base_url.as_deref() {
            return base_url.trim_end_matches('/').to_string();
        }

        if let Some(host) = self.config.vault.as_deref() {
            return format!("https://{host}/BeyondTrust/api/public/v3");
        }

        "https://localhost/BeyondTrust/api/public/v3".to_string()
    }

    fn auth_values(&self) -> Result<(String, String)> {
        let auth_key = self
            .config
            .auth_key
            .clone()
            .or_else(|| credential_or_env(&self.credentials, "auth_key", "BTPWS_AUTH_KEY"))
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "BeyondTrust Password Safe auth key missing; set auth_key in the provider config or BTPWS_AUTH_KEY".to_string(),
                )
            })?;

        let runas = self
            .config
            .runas
            .clone()
            .or_else(|| credential_or_env(&self.credentials, "runas", "BTPWS_RUNAS"))
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "BeyondTrust Password Safe runas value missing; set runas in the provider config or BTPWS_RUNAS".to_string(),
                )
            })?;

        Ok((auth_key, runas))
    }

    fn auth_headers(&self, challenge: Option<&str>) -> Result<HeaderMap> {
        let (auth_key, runas) = self.auth_values()?;
        let mut headers = HeaderMap::new();
        let mut value = format!("PS-Auth key={auth_key}; runas={runas};");
        if let Some(challenge) = challenge.filter(|value| !value.is_empty()) {
            value.push_str(&format!(" challenge={challenge};"));
        }
        headers.insert(AUTHORIZATION, value.parse().map_err(|err| {
            SecretSpecError::ProviderOperationFailed(format!(
                "invalid BeyondTrust auth header: {err}"
            ))
        })?);
        Ok(headers)
    }

    fn challenge_from_header(value: &str) -> Option<&str> {
        value
            .split_whitespace()
            .find_map(|token| token.strip_prefix("challenge=").map(|value| value.trim_matches(['"', ';'])))
    }

    fn sign_in(&self) -> Result<Client> {
        let client = Client::builder().build().map_err(|err| {
            SecretSpecError::ProviderOperationFailed(format!(
                "failed to build BeyondTrust HTTP client: {err}"
            ))
        })?;
        let base_url = self.base_url();
        let first = client
            .post(format!("{base_url}/Auth/SignAppin"))
            .headers(self.auth_headers(None)?)
            .json(&json!({}))
            .send()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BeyondTrust sign-in request failed: {err}"
                ))
            })?;

        if first.status().is_success() {
            return Ok(client);
        }

        let challenge = first
            .headers()
            .get("WWW-Authenticate-2FA")
            .and_then(|value| value.to_str().ok())
            .and_then(Self::challenge_from_header);

        if first.status().as_u16() == 401 {
            let second = client
                .post(format!("{base_url}/Auth/SignAppin"))
                .headers(self.auth_headers(challenge.as_deref())?)
                .json(&json!({}))
                .send()
                .map_err(|err| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "BeyondTrust challenge-response sign-in failed: {err}"
                    ))
                })?;
            if second.status().is_success() {
                return Ok(client);
            }
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "BeyondTrust sign-in failed with status {}: {}",
                second.status(),
                second.text().unwrap_or_default()
            )));
        }

        Err(SecretSpecError::ProviderOperationFailed(format!(
            "BeyondTrust sign-in failed with status {}: {}",
            first.status(),
            first.text().unwrap_or_default()
        )))
    }

    fn sign_out(&self, client: &Client) -> Result<()> {
        let base_url = self.base_url();
        let response = client
            .post(format!("{base_url}/Auth/Signout"))
            .headers(self.auth_headers(None)?)
            .json(&json!({}))
            .send()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BeyondTrust sign-out failed: {err}"
                ))
            })?;
        if !response.status().is_success() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "BeyondTrust sign-out failed with status {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            )));
        }
        Ok(())
    }

    fn request_password(&self, client: &Client, account_name: &str, system_name: &str) -> Result<String> {
        let base_url = self.base_url();
        let managed_accounts = client
            .get(format!("{base_url}/ManagedAccounts"))
            .headers(self.auth_headers(None)?)
            .query(&[("accountName", account_name), ("systemName", system_name)])
            .send()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BeyondTrust managed-account lookup failed: {err}"
                ))
            })?;

        if !managed_accounts.status().is_success() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "BeyondTrust managed-account lookup failed with status {}: {}",
                managed_accounts.status(),
                managed_accounts.text().unwrap_or_default()
            )));
        }

        #[derive(Debug, Deserialize)]
        struct ManagedAccount {
            #[allow(dead_code)]
            system_id: Option<i64>,
            #[allow(dead_code)]
            account_id: Option<i64>,
        }

        let account: ManagedAccount = managed_accounts.json().map_err(|err| {
            SecretSpecError::ProviderOperationFailed(format!(
                "failed to parse BeyondTrust managed-account response: {err}"
            ))
        })?;

        let request_body = json!({
            "SystemId": account.system_id,
            "AccountId": account.account_id,
            "DurationMinutes": 5,
            "Reason": "SecretSpec",
            "AccessType": "View",
            "ConflictOption": "reuse"
        });

        let request_response = client
            .post(format!("{base_url}/Requests"))
            .headers(self.auth_headers(None)?)
            .json(&request_body)
            .send()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BeyondTrust request creation failed: {err}"
                ))
            })?;

        if !request_response.status().is_success() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "BeyondTrust request creation failed with status {}: {}",
                request_response.status(),
                request_response.text().unwrap_or_default()
            )));
        }

        let request_id = request_response.text().map_err(|err| {
            SecretSpecError::ProviderOperationFailed(format!(
                "failed to read BeyondTrust request id: {err}"
            ))
        })?;

        let credentials = client
            .get(format!("{base_url}/Credentials/{request_id}/"))
            .headers(self.auth_headers(None)?)
            .send()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BeyondTrust credential retrieval failed: {err}"
                ))
            })?;

        if !credentials.status().is_success() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "BeyondTrust credential retrieval failed with status {}: {}",
                credentials.status(),
                credentials.text().unwrap_or_default()
            )));
        }

        Ok(credentials.text().unwrap_or_default().trim().to_string())
    }
}

impl Provider for BtPwsProvider {
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: format!("{project}/{profile}/{key}"),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        match &self.config.vault {
            Some(vault) => format!("bt-pws://{vault}"),
            None => "bt-pws://".to_string(),
        }
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        let account_name = coords.item.as_str();
        let system_name = coords.field.as_deref().unwrap_or_else(|| {
            self.config.default_system_name.as_deref().unwrap_or_default()
        });

        let client = self.sign_in()?;
        let password = self.request_password(&client, account_name, system_name)?;
        let _ = self.sign_out(&client);

        if password.is_empty() {
            Ok(None)
        } else {
            Ok(Some(SecretString::new(password.into())))
        }
    }

    fn set(&self, addr: Address<'_>, _value: &SecretString) -> Result<()> {
        let _ = addr;
        Err(SecretSpecError::ProviderOperationFailed(
            "BeyondTrust Password Safe provider currently implements read-only secret retrieval".to_string(),
        ))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let _ = addr;
        Err(SecretSpecError::ProviderOperationFailed(
            "BeyondTrust Password Safe provider does not implement writes yet".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn parses_basic_query_values() {
        let url = ProviderUrl::new(Url::parse("bt-pws://vault?tenant_id=tenant-a&api_version=v2").unwrap());
        let config: BtPwsConfig = (&url).try_into().unwrap();

        assert_eq!(config.vault.as_deref(), Some("vault"));
        assert_eq!(config.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(config.api_version.as_deref(), Some("v2"));
    }
}
