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
use std::io::IsTerminal;

const AUTH_KEY: &str = "auth_key";
const RUNAS: &str = "runas";
const PERSONAL_ACCESS_TOKEN: &str = "personal_access_token";
const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";

const AUTH_KEY_ENV: &str = "BTPWS_AUTH_KEY";
const RUNAS_ENV: &str = "BTPWS_RUNAS";
const PERSONAL_ACCESS_TOKEN_ENV: &str = "BTPWS_PERSONAL_ACCESS_TOKEN";
const CLIENT_ID_ENV: &str = "BTPWS_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "BTPWS_CLIENT_SECRET";

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
    /// Optional personal access token passed in the PS-Auth password field.
    pub personal_access_token: Option<String>,
    /// Optional OAuth client ID.
    pub client_id: Option<String>,
    /// Optional OAuth client secret.
    pub client_secret: Option<String>,
    /// Optional system name used when the secret ref does not include one.
    pub default_system_name: Option<String>,
    /// Optional API version or endpoint variant.
    pub api_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ManagedAccount {
    system_id: Option<i64>,
    account_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct OAuthToken {
    access_token: String,
}

enum AuthMethod {
    PsAuth {
        auth_key: String,
        runas: String,
        personal_access_token: Option<String>,
    },
    OAuth {
        client_id: String,
        client_secret: String,
    },
}

struct AuthenticatedClient {
    client: Client,
    headers: HeaderMap,
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
        config.auth_key = url.query_value(AUTH_KEY);
        config.runas = url.query_value(RUNAS);
        config.personal_access_token = url.query_value(PERSONAL_ACCESS_TOKEN);
        config.client_id = url.query_value(CLIENT_ID);
        config.client_secret = url.query_value(CLIENT_SECRET);
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
    examples: ["bt-pws://", "bt-pws://pbps.example.com"],
    credential_names: [AUTH_KEY, RUNAS, PERSONAL_ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET],
}

impl BtPwsProvider {
    pub fn new(config: BtPwsConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
        }
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

    fn credential(&self, config: &Option<String>, name: &str, env_var: &str) -> Option<String> {
        config
            .clone()
            .or_else(|| credential_or_env(&self.credentials, name, env_var))
    }

    fn auth_method(&self) -> Result<AuthMethod> {
        let client_id = self.credential(&self.config.client_id, CLIENT_ID, CLIENT_ID_ENV);
        let client_secret =
            self.credential(&self.config.client_secret, CLIENT_SECRET, CLIENT_SECRET_ENV);

        match (client_id, client_secret) {
            (Some(client_id), Some(client_secret)) => {
                return Ok(AuthMethod::OAuth {
                    client_id,
                    client_secret,
                });
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "BeyondTrust OAuth authentication requires both client_id and client_secret"
                        .to_string(),
                ));
            }
            (None, None) => {}
        }

        let auth_key = self
            .credential(&self.config.auth_key, AUTH_KEY, AUTH_KEY_ENV)
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "BeyondTrust Password Safe auth key missing; set auth_key or BTPWS_AUTH_KEY"
                        .to_string(),
                )
            })?;
        let runas = self
            .credential(&self.config.runas, RUNAS, RUNAS_ENV)
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "BeyondTrust Password Safe runas value missing; set runas or BTPWS_RUNAS"
                        .to_string(),
                )
            })?;
        let personal_access_token = self.credential(
            &self.config.personal_access_token,
            PERSONAL_ACCESS_TOKEN,
            PERSONAL_ACCESS_TOKEN_ENV,
        );

        Ok(AuthMethod::PsAuth {
            auth_key,
            runas,
            personal_access_token,
        })
    }

    fn ps_auth_headers(
        auth_key: &str,
        runas: &str,
        personal_access_token: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        let mut value = format!("PS-Auth key={auth_key}; runas={runas};");
        if let Some(personal_access_token) = personal_access_token.filter(|value| !value.is_empty())
        {
            value.push_str(&format!(" pwd=[{personal_access_token}];"));
        }
        if let Some(challenge) = challenge.filter(|value| !value.is_empty()) {
            value.push_str(&format!(" challenge={challenge};"));
        }
        headers.insert(
            AUTHORIZATION,
            value.parse().map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "invalid BeyondTrust auth header: {err}"
                ))
            })?,
        );
        Ok(headers)
    }

    fn bearer_headers(access_token: &str) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {access_token}").parse().map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "invalid BeyondTrust bearer token: {err}"
                ))
            })?,
        );
        Ok(headers)
    }

    fn oauth_headers(
        &self,
        client: &Client,
        client_id: &str,
        client_secret: &str,
    ) -> Result<HeaderMap> {
        let response = client
            .post(format!("{}/auth/connect/token", self.base_url()))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BeyondTrust OAuth token request failed: {err}"
                ))
            })?;

        if !response.status().is_success() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "BeyondTrust OAuth token request failed with status {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            )));
        }

        let token: OAuthToken = response.json().map_err(|err| {
            SecretSpecError::ProviderOperationFailed(format!(
                "failed to parse BeyondTrust OAuth token response: {err}"
            ))
        })?;
        Self::bearer_headers(&token.access_token)
    }

    fn prompt_mfa_challenge(&self, instruction: &str) -> Result<String> {
        if !std::io::stdin().is_terminal() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "BeyondTrust MFA is required, but standard input is not a terminal".to_string(),
            ));
        }

        inquire::Password::new(&format!("BeyondTrust MFA required ({instruction})"))
            .without_confirmation()
            .prompt()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "failed to read BeyondTrust MFA challenge response: {err}"
                ))
            })
    }

    fn sign_in(&self) -> Result<AuthenticatedClient> {
        let client = Client::builder()
            .cookie_store(true)
            .build()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "failed to build BeyondTrust HTTP client: {err}"
                ))
            })?;
        let base_url = self.base_url();
        let auth_method = self.auth_method()?;
        let headers = match &auth_method {
            AuthMethod::PsAuth {
                auth_key,
                runas,
                personal_access_token,
            } => Self::ps_auth_headers(auth_key, runas, personal_access_token.as_deref(), None)?,
            AuthMethod::OAuth {
                client_id,
                client_secret,
            } => self.oauth_headers(&client, client_id, client_secret)?,
        };
        let first = client
            .post(format!("{base_url}/Auth/SignAppin"))
            .headers(headers.clone())
            .json(&json!({}))
            .send()
            .map_err(|err| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "BeyondTrust sign-in request failed: {err}"
                ))
            })?;

        if first.status().is_success() {
            return Ok(AuthenticatedClient { client, headers });
        }

        let challenge_instruction = first
            .headers()
            .get("WWW-Authenticate-2FA")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("enter the one-time password");

        if first.status().as_u16() == 401 {
            let AuthMethod::PsAuth {
                auth_key,
                runas,
                personal_access_token,
            } = auth_method
            else {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "BeyondTrust sign-in failed with status {}: {}",
                    first.status(),
                    first.text().unwrap_or_default()
                )));
            };
            let challenge = self.prompt_mfa_challenge(challenge_instruction)?;
            let headers = Self::ps_auth_headers(
                &auth_key,
                &runas,
                personal_access_token.as_deref(),
                Some(&challenge),
            )?;
            let second = client
                .post(format!("{base_url}/Auth/SignAppin"))
                .headers(headers.clone())
                .json(&json!({}))
                .send()
                .map_err(|err| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "BeyondTrust challenge-response sign-in failed: {err}"
                    ))
                })?;
            if second.status().is_success() {
                return Ok(AuthenticatedClient { client, headers });
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

    fn sign_out(&self, session: &AuthenticatedClient) -> Result<()> {
        let base_url = self.base_url();
        let response = session
            .client
            .post(format!("{base_url}/Auth/Signout"))
            .headers(session.headers.clone())
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

    fn request_password(
        &self,
        session: &AuthenticatedClient,
        account_name: &str,
        system_name: &str,
    ) -> Result<String> {
        let base_url = self.base_url();
        let managed_accounts = session
            .client
            .get(format!("{base_url}/ManagedAccounts"))
            .headers(session.headers.clone())
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

        let request_response = session
            .client
            .post(format!("{base_url}/Requests"))
            .headers(session.headers.clone())
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

        let credentials = session
            .client
            .get(format!("{base_url}/Credentials/{request_id}/"))
            .headers(session.headers.clone())
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
            self.config
                .default_system_name
                .as_deref()
                .unwrap_or_default()
        });

        let session = self.sign_in()?;
        let password = self.request_password(&session, account_name, system_name)?;
        let _ = self.sign_out(&session);

        if password.is_empty() {
            Ok(None)
        } else {
            Ok(Some(SecretString::new(password.into())))
        }
    }

    fn set(&self, addr: Address<'_>, _value: &SecretString) -> Result<()> {
        let _ = addr;
        Err(SecretSpecError::ProviderOperationFailed(
            "BeyondTrust Password Safe provider currently implements read-only secret retrieval"
                .to_string(),
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
        let url = ProviderUrl::new(
            Url::parse("bt-pws://vault?tenant_id=tenant-a&api_version=v2").unwrap(),
        );
        let config: BtPwsConfig = (&url).try_into().unwrap();

        assert_eq!(config.vault.as_deref(), Some("vault"));
        assert_eq!(config.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(config.api_version.as_deref(), Some("v2"));
    }

    #[test]
    fn parses_pascal_case_managed_account_ids() {
        let account: ManagedAccount =
            serde_json::from_str(r#"{"SystemId":429,"AccountId":75,"SystemName":"PRWNRDWW02"}"#)
                .unwrap();

        assert_eq!(account.system_id, Some(429));
        assert_eq!(account.account_id, Some(75));
    }

    #[test]
    fn ps_auth_header_includes_pat_and_mfa_challenge() {
        let headers = BtPwsProvider::ps_auth_headers(
            "api-key",
            "user@example.com",
            Some("personal-access-token"),
            Some("one-time-password"),
        )
        .unwrap();

        assert_eq!(
            headers[AUTHORIZATION].to_str().unwrap(),
            "PS-Auth key=api-key; runas=user@example.com; pwd=[personal-access-token]; challenge=one-time-password;"
        );
    }

    #[test]
    fn parses_oauth_access_token() {
        let token: OAuthToken = serde_json::from_str(r#"{"access_token":"token-value"}"#).unwrap();

        assert_eq!(token.access_token, "token-value");
    }
}
