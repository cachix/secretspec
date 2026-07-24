//! Scaleway Secret Manager provider.
//!
//! Stores and retrieves secrets through Scaleway's Secret Manager
//! (`v1beta1`) REST API.
//!
//! # Authentication
//!
//! Requests are authenticated with an API secret key sent in the
//! `X-Auth-Token` header. It is read from the `secret_key` provider credential
//! or the `SCW_SECRET_KEY` environment variable.
//!
//! # URI format
//!
//! `scaleway://[region][?project_id=UUID][&path=/folder]`
//!
//! - `scaleway://fr-par` — Paris region, project from `SCW_DEFAULT_PROJECT_ID`
//! - `scaleway://nl-ams?project_id=11111111-2222-3333-4444-555555555555`
//! - `scaleway://fr-par?project_id=…&path=/myteam` — nest secrets under a folder
//! - `scaleway://` — region from `SCW_DEFAULT_REGION`, else `fr-par`
//!
//! With no region in the URI, `SCW_DEFAULT_REGION` supplies it, falling back to
//! `fr-par`. The project id is not part of the server identity, so it is taken
//! from the URI or `SCW_DEFAULT_PROJECT_ID` and never treated as a secret.
//!
//! # Secret naming
//!
//! Scaleway secret names may not contain `/` (that is the folder separator), so
//! the SecretSpec convention lives in the folder hierarchy rather than the
//! name: convention secrets are stored at path
//! `[{base}/]secretspec/{project}/{profile}` with name `{key}`. A native `ref`
//! names an absolute Scaleway path in `item` (e.g.
//! `ref = { item = "/prod/db-url" }`), optionally selecting a JSON key with
//! `field` and a revision with `version`. Native references are read-only.
//!
//! ```bash
//! secretspec set DATABASE_URL --provider scaleway://fr-par?project_id=…
//! secretspec check --provider scaleway://fr-par?project_id=…
//! ```

use super::{
    Address, Provider, ProviderCredentials, ProviderUrl, credential_or_envs, preferred_env,
};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use data_encoding::BASE64;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Semantic credential name for the Scaleway API secret key.
const SECRET_KEY: &str = "secret_key";
/// Environment fallback for the API secret key.
const SECRET_KEY_ENV: &str = "SCW_SECRET_KEY";
/// Environment fallback for the target project id.
const PROJECT_ID_ENV: &str = "SCW_DEFAULT_PROJECT_ID";
/// Environment fallback for the region.
const REGION_ENV: &str = "SCW_DEFAULT_REGION";
/// Region used when neither the URI nor the environment specifies one.
const DEFAULT_REGION: &str = "fr-par";
/// Revision read when a native reference does not pin `version`.
const DEFAULT_REVISION: &str = "latest_enabled";

/// Configuration for the Scaleway Secret Manager provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalewayConfig {
    /// Effective region (URI host, else `SCW_DEFAULT_REGION`, else `fr-par`).
    pub region: String,
    /// Target project id from the URI. `None` falls back to
    /// `SCW_DEFAULT_PROJECT_ID` at call time; it is not part of `uri()`.
    pub project_id: Option<String>,
    /// Base folder prepended to the convention hierarchy. Normalized to a
    /// leading slash with no trailing slash; `/` (root) is the default.
    pub path: String,
}

impl TryFrom<&ProviderUrl> for ScalewayConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "scaleway" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for scaleway provider. Expected 'scaleway'.",
                url.scheme()
            )));
        }

        let region = url
            .host()
            .filter(|s| !s.is_empty())
            .or_else(|| preferred_env(&[REGION_ENV]))
            .unwrap_or_else(|| DEFAULT_REGION.to_string());

        let project_id = url.query_value("project_id").filter(|s| !s.is_empty());

        let path = normalize_path(url.query_value("path").as_deref().unwrap_or("/"));

        Ok(Self {
            region,
            project_id,
            path,
        })
    }
}

/// Normalizes a folder path to a single leading slash and no trailing slash.
/// Root collapses to `/`.
fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Scaleway Secret Manager provider.
pub struct ScalewayProvider {
    config: ScalewayConfig,
    credentials: ProviderCredentials,
}

crate::register_provider! {
    struct: ScalewayProvider,
    config: ScalewayConfig,
    name: "scaleway",
    description: "Scaleway Secret Manager",
    schemes: ["scaleway"],
    examples: ["scaleway://fr-par", "scaleway://nl-ams?project_id=PROJECT_UUID", "scaleway://fr-par?project_id=PROJECT_UUID&path=/myteam"],
    credential_names: [SECRET_KEY],
}

/// One secret in a `ListSecrets` response (only the fields we consume).
#[derive(Deserialize)]
struct ListedSecret {
    id: String,
    name: String,
    path: String,
}

#[derive(Deserialize)]
struct ListSecretsResponse {
    #[serde(default)]
    secrets: Vec<ListedSecret>,
}

#[derive(Deserialize)]
struct CreatedSecret {
    id: String,
}

#[derive(Deserialize)]
struct AccessResponse {
    /// Base64-encoded payload.
    data: String,
}

impl ScalewayProvider {
    pub fn new(config: ScalewayConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
        }
    }

    /// Builds the convention item as an absolute Scaleway path
    /// `[{base}/]secretspec/{project}/{profile}/{key}`. The folder is
    /// everything up to the last segment; the name is `{key}`.
    fn format_item(base: &str, project: &str, profile: &str, key: &str) -> Result<String> {
        for (label, value) in [("project", project), ("profile", profile), ("key", key)] {
            if value.is_empty() {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{label} cannot be empty"
                )));
            }
        }
        // `base` is already normalized ("/" or "/prefix"); trim its slash so we
        // never emit a double slash when composing the hierarchy.
        let base = base.trim_end_matches('/');
        Ok(format!("{base}/secretspec/{project}/{profile}/{key}"))
    }

    /// Splits an absolute item path into `(secret_path, secret_name)`. The path
    /// is the folder (at least `/`); the name is the final segment.
    fn split_item(item: &str) -> Result<(String, String)> {
        let item = item.trim_end_matches('/');
        match item.rsplit_once('/') {
            Some((folder, name)) if !name.is_empty() => {
                let folder = if folder.is_empty() { "/" } else { folder };
                Ok((folder.to_string(), name.to_string()))
            }
            // No slash, or a trailing-only slash: not an addressable secret.
            _ => Err(SecretSpecError::ProviderOperationFailed(format!(
                "scaleway secret path '{item}' has no name segment; \
                 use an absolute path like /folder/NAME"
            ))),
        }
    }

    fn secret_key(&self) -> Result<SecretString> {
        credential_or_envs(&self.credentials, SECRET_KEY, &[SECRET_KEY_ENV])
            .map(|k| SecretString::new(k.into()))
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "No Scaleway secret key found. Configure the {SECRET_KEY} provider \
                     credential or set {SECRET_KEY_ENV}."
                ))
            })
    }

    fn project_id(&self) -> Result<String> {
        self.config
            .project_id
            .clone()
            .or_else(|| preferred_env(&[PROJECT_ID_ENV]))
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "No Scaleway project id found. Add ?project_id=… to the provider URI \
                     or set {PROJECT_ID_ENV}."
                ))
            })
    }

    fn region_base(&self) -> String {
        format!(
            "https://api.scaleway.com/secret-manager/v1beta1/regions/{}",
            self.config.region
        )
    }

    fn client(secret_key: &SecretString) -> Result<reqwest::Client> {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut headers = HeaderMap::new();
        let mut token = HeaderValue::from_str(secret_key.expose_secret()).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!("Invalid Scaleway secret key: {e}"))
        })?;
        token.set_sensitive(true);
        headers.insert("X-Auth-Token", token);
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to build Scaleway HTTP client: {e}"
                ))
            })
    }

    /// Extracts one key from a JSON secret value (for `key_value` secrets),
    /// mirroring the AWS provider's `field` semantics.
    fn extract_json_key(name: &str, value: &str, json_key: &str) -> Result<Option<SecretString>> {
        let json: serde_json::Value = serde_json::from_str(value).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "secret '{name}' is not JSON, cannot extract key '{json_key}': {e}"
            ))
        })?;
        match json.get(json_key) {
            Some(serde_json::Value::String(s)) => Ok(Some(SecretString::new(s.clone().into()))),
            Some(other) => Ok(Some(SecretString::new(other.to_string().into()))),
            None => Ok(None),
        }
    }

    async fn get_async(
        &self,
        item: &str,
        field: Option<&str>,
        version: Option<&str>,
    ) -> Result<Option<SecretString>> {
        let (secret_path, secret_name) = Self::split_item(item)?;
        let project_id = self.project_id()?;
        let secret_key = self.secret_key()?;
        let revision = version.unwrap_or(DEFAULT_REVISION);

        let url = format!(
            "{}/secrets-by-path/versions/{}/access",
            self.region_base(),
            revision
        );
        let response = Self::client(&secret_key)?
            .get(&url)
            .query(&[
                ("project_id", project_id.as_str()),
                ("secret_name", secret_name.as_str()),
                ("secret_path", secret_path.as_str()),
            ])
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to reach Scaleway Secret Manager: {e}"
                ))
            })?;

        match response.status().as_u16() {
            200 => {
                let body: AccessResponse = response.json().await.map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Scaleway access response: {e}"
                    ))
                })?;
                let decoded = decode_payload(item, &body.data)?;
                match field {
                    None => Ok(Some(SecretString::new(decoded.into()))),
                    Some(json_key) => Self::extract_json_key(item, &decoded, json_key),
                }
            }
            404 => Ok(None),
            401 | 403 => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Scaleway authentication failed (HTTP {}). Check {SECRET_KEY_ENV} and its \
                 permissions.",
                response.status().as_u16()
            ))),
            status => Err(http_error("reading secret", status, response).await),
        }
    }

    async fn set_async(&self, item: &str, value: &SecretString) -> Result<()> {
        let (secret_path, secret_name) = Self::split_item(item)?;
        let project_id = self.project_id()?;
        let secret_key = self.secret_key()?;
        let client = Self::client(&secret_key)?;

        let secret_id = self
            .ensure_secret(&client, &project_id, &secret_path, &secret_name)
            .await?;

        // Payloads are transmitted base64-encoded.
        let data = BASE64.encode(value.expose_secret().as_bytes());
        let url = format!("{}/secrets/{}/versions", self.region_base(), secret_id);
        let response = client
            .post(&url)
            .json(&serde_json::json!({ "data": data }))
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to reach Scaleway Secret Manager: {e}"
                ))
            })?;

        match response.status().as_u16() {
            200 | 201 => Ok(()),
            status => Err(http_error("writing secret version", status, response).await),
        }
    }

    /// Resolves the secret id for `path`/`name`, creating the secret if it does
    /// not yet exist. Create-first mirrors the AWS provider; a `409 Conflict`
    /// means it already exists, so we look the id up.
    async fn ensure_secret(
        &self,
        client: &reqwest::Client,
        project_id: &str,
        secret_path: &str,
        secret_name: &str,
    ) -> Result<String> {
        let create_url = format!("{}/secrets", self.region_base());
        let response = client
            .post(&create_url)
            .json(&serde_json::json!({
                "project_id": project_id,
                "name": secret_name,
                "path": secret_path,
            }))
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to reach Scaleway Secret Manager: {e}"
                ))
            })?;

        match response.status().as_u16() {
            200 | 201 => {
                let created: CreatedSecret = response.json().await.map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Scaleway create-secret response: {e}"
                    ))
                })?;
                Ok(created.id)
            }
            409 => {
                self.lookup_secret_id(client, project_id, secret_path, secret_name)
                    .await
            }
            status => Err(http_error("creating secret", status, response).await),
        }
    }

    async fn lookup_secret_id(
        &self,
        client: &reqwest::Client,
        project_id: &str,
        secret_path: &str,
        secret_name: &str,
    ) -> Result<String> {
        let url = format!("{}/secrets", self.region_base());
        let response = client
            .get(&url)
            .query(&[
                ("project_id", project_id),
                ("name", secret_name),
                ("path", secret_path),
                // Required by the API; deletion-scheduled secrets are excluded.
                ("scheduled_for_deletion", "false"),
            ])
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to reach Scaleway Secret Manager: {e}"
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(http_error("listing secrets", status, response).await);
        }

        let body: ListSecretsResponse = response.json().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse Scaleway list-secrets response: {e}"
            ))
        })?;

        // The `name`/`path` filters are not guaranteed exact, so match both.
        body.secrets
            .into_iter()
            .find(|s| s.name == secret_name && s.path == secret_path)
            .map(|s| s.id)
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Scaleway reported secret '{secret_name}' at '{secret_path}' exists but it \
                     was not found when listing"
                ))
            })
    }
}

/// Decodes a base64 payload into a UTF-8 string.
fn decode_payload(item: &str, data: &str) -> Result<String> {
    let bytes = BASE64.decode(data.as_bytes()).map_err(|e| {
        SecretSpecError::ProviderOperationFailed(format!(
            "Scaleway secret '{item}' payload is not valid base64: {e}"
        ))
    })?;
    String::from_utf8(bytes).map_err(|e| {
        SecretSpecError::ProviderOperationFailed(format!(
            "Scaleway secret '{item}' payload is not valid UTF-8: {e}"
        ))
    })
}

/// Builds an error for a non-success HTTP response, including the body.
async fn http_error(action: &str, status: u16, response: reqwest::Response) -> SecretSpecError {
    let body = response.text().await.unwrap_or_default();
    SecretSpecError::ProviderOperationFailed(format!(
        "Scaleway returned HTTP {status} while {action}: {body}"
    ))
}

impl Provider for ScalewayProvider {
    /// Convention secrets live at `[{base}/]secretspec/{project}/{profile}/{key}`.
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: Self::format_item(&self.config.path, project, profile, key)?,
            ..Default::default()
        })
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut params: Vec<String> = Vec::new();
        if let Some(project_id) = &self.config.project_id {
            params.push(format!(
                "project_id={}",
                ProviderUrl::encode_query(project_id)
            ));
        }
        if self.config.path != "/" {
            params.push(format!(
                "path={}",
                ProviderUrl::encode_query(&self.config.path)
            ));
        }
        if params.is_empty() {
            format!("scaleway://{}", self.config.region)
        } else {
            format!("scaleway://{}?{}", self.config.region, params.join("&"))
        }
    }

    /// `field` extracts a key from a JSON (`key_value`) secret; `version` pins a
    /// revision (default `latest_enabled`).
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field", "version"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        super::block_on(self.get_async(
            &coords.item,
            coords.field.as_deref(),
            coords.version.as_deref(),
        ))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_coords(addr)?;
        super::block_on(self.set_async(&coords.item, value))
    }

    /// Native references name secrets managed outside SecretSpec and are
    /// read-only: a `field` write would append a version that discards the
    /// other JSON keys, and the revision is server-assigned.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention { .. } => Ok(()),
            Address::Native(_) => Err(SecretSpecError::ProviderOperationFailed(
                "scaleway secret references are read-only and cannot be written".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn config(spec: &str) -> ScalewayConfig {
        ScalewayConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap())).unwrap()
    }

    #[test]
    fn region_from_uri_or_default() {
        // An explicit host is used verbatim regardless of the environment.
        assert_eq!(config("scaleway://nl-ams").region, "nl-ams");

        // With no host and no SCW_DEFAULT_REGION, the region falls back to fr-par.
        let _guard = crate::tests::EnvVarGuard::remove(REGION_ENV);
        assert_eq!(config("scaleway://").region, "fr-par");
    }

    #[test]
    fn path_is_normalized() {
        assert_eq!(config("scaleway://fr-par").path, "/");
        assert_eq!(config("scaleway://fr-par?path=/myteam/").path, "/myteam");
        assert_eq!(config("scaleway://fr-par?path=myteam").path, "/myteam");
        assert_eq!(config("scaleway://fr-par?path=/a/b").path, "/a/b");
    }

    #[test]
    fn wrong_scheme_is_rejected() {
        let err = ScalewayConfig::try_from(&ProviderUrl::new(Url::parse("awssm://x").unwrap()))
            .unwrap_err();
        assert!(err.to_string().contains("Invalid scheme"), "{err}");
    }

    #[test]
    fn format_item_root_and_prefix() {
        assert_eq!(
            ScalewayProvider::format_item("/", "app", "prod", "DB_URL").unwrap(),
            "/secretspec/app/prod/DB_URL"
        );
        assert_eq!(
            ScalewayProvider::format_item("/myteam", "app", "prod", "DB_URL").unwrap(),
            "/myteam/secretspec/app/prod/DB_URL"
        );
    }

    #[test]
    fn format_item_rejects_empty_components() {
        assert!(ScalewayProvider::format_item("/", "", "prod", "K").is_err());
        assert!(ScalewayProvider::format_item("/", "app", "", "K").is_err());
        assert!(ScalewayProvider::format_item("/", "app", "prod", "").is_err());
    }

    #[test]
    fn split_item_separates_folder_and_name() {
        assert_eq!(
            ScalewayProvider::split_item("/secretspec/app/prod/DB_URL").unwrap(),
            ("/secretspec/app/prod".to_string(), "DB_URL".to_string())
        );
        assert_eq!(
            ScalewayProvider::split_item("/DB_URL").unwrap(),
            ("/".to_string(), "DB_URL".to_string())
        );
    }

    #[test]
    fn split_item_rejects_nameless_paths() {
        assert!(ScalewayProvider::split_item("/").is_err());
        assert!(ScalewayProvider::split_item("no-leading-slash").is_err());
    }

    #[test]
    fn convention_address_uses_the_folder_hierarchy() {
        let p = ScalewayProvider::new(config("scaleway://fr-par?path=/myteam"));
        let addr = p.convention_address("app", "default", "A").unwrap();
        assert_eq!(addr.item, "/myteam/secretspec/app/default/A");
        assert_eq!(addr.field, None);
        assert_eq!(addr.version, None);
    }

    #[test]
    fn uri_round_trips() {
        let p = ScalewayProvider::new(config(
            "scaleway://nl-ams?project_id=11111111-2222-3333-4444-555555555555&path=/myteam",
        ));
        assert_eq!(
            p.uri(),
            "scaleway://nl-ams?project_id=11111111-2222-3333-4444-555555555555&path=/myteam"
        );
        // Bare region, default path: no query string.
        assert_eq!(
            ScalewayProvider::new(config("scaleway://fr-par")).uri(),
            "scaleway://fr-par"
        );
    }

    #[test]
    fn uri_omits_no_secret_material() {
        // The secret key comes from a credential/env, never the URI, so uri()
        // cannot leak it regardless of config.
        let p = ScalewayProvider::new(config("scaleway://fr-par?project_id=abc"));
        assert!(!p.uri().contains("SCW_SECRET_KEY"));
    }

    #[test]
    fn extract_json_key_reads_string_and_renders_scalars() {
        let v = r#"{"user":"admin","port":5432,"tls":true}"#;
        assert_eq!(
            ScalewayProvider::extract_json_key("s", v, "user")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "admin"
        );
        assert_eq!(
            ScalewayProvider::extract_json_key("s", v, "port")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "5432"
        );
        assert!(
            ScalewayProvider::extract_json_key("s", v, "missing")
                .unwrap()
                .is_none()
        );
        assert!(ScalewayProvider::extract_json_key("s", "not-json", "user").is_err());
    }

    #[test]
    fn decode_payload_round_trips() {
        let encoded = BASE64.encode(b"s3cret");
        assert_eq!(decode_payload("s", &encoded).unwrap(), "s3cret");
        assert!(decode_payload("s", "!!!not-base64!!!").is_err());
    }

    #[test]
    fn native_reference_is_read_only() {
        let p = ScalewayProvider::new(config("scaleway://fr-par?project_id=abc"));
        let addr = NativeAddress {
            item: "/prod/db-url".into(),
            ..Default::default()
        };
        let refusal = p.check_writable(Address::Native(&addr)).unwrap_err();
        assert!(refusal.to_string().contains("read-only"), "{refusal}");
        let err = p
            .set(Address::Native(&addr), &SecretString::new("v".into()))
            .unwrap_err();
        assert_eq!(err.to_string(), refusal.to_string());
    }

    /// The registry factory path the CLI uses: a `scaleway://` spec resolves to
    /// this provider, proving it is registered and wired end-to-end.
    #[test]
    fn scheme_resolves_through_the_registry() {
        let provider = <Box<dyn Provider>>::try_from(
            "scaleway://nl-ams?project_id=11111111-2222-3333-4444-555555555555",
        )
        .expect("scaleway scheme should resolve");
        assert_eq!(provider.name(), "scaleway");
        assert_eq!(
            provider.uri(),
            "scaleway://nl-ams?project_id=11111111-2222-3333-4444-555555555555"
        );
    }

    /// The provider appears in the enumerated registry that `config init` lists.
    #[test]
    fn registered_in_provider_list() {
        assert!(
            super::super::PROVIDER_REGISTRY
                .iter()
                .any(|r| r.info.name == "scaleway"),
            "scaleway missing from PROVIDER_REGISTRY"
        );
    }

    #[test]
    fn native_reference_rejects_unsupported_coordinate() {
        let p = ScalewayProvider::new(config("scaleway://fr-par?project_id=abc"));
        let addr = NativeAddress {
            item: "/prod/db-url".into(),
            section: Some("x".into()),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`section`"), "{err}");
    }
}
