//! Tailscale Setec provider.
//!
//! Setec is an HTTP secrets service whose authentication and authorization
//! come from the caller's Tailscale identity. SecretSpec talks to the API
//! directly; no additional provider credential is required.
//!
//! # URI format
//!
//! `setec://HOST[:PORT][?prefix=PATH][&tls=false]`
//!
//! HTTPS is used by default. `tls=false` is intended for local development.
//! Convention secrets use `[prefix/]secretspec/{project}/{profile}/{key}`.

use super::{Address, DiscoveryContext, Provider, ProviderUrl};
use crate::config::NativeAddress;
use crate::{Result, Secret, SecretBytes, SecretSpecError};
use data_encoding::BASE64;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

const NO_BROWSERS_HEADER: &str = "Sec-X-Tailscale-No-Browsers";

/// Connection and convention configuration for a Setec server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetecConfig {
    /// Setec server hostname.
    pub host: String,
    /// Optional server port.
    pub port: Option<u16>,
    /// Optional convention-name prefix, without surrounding slashes.
    pub prefix: Option<String>,
    /// Whether to connect with HTTPS. Defaults to `true`.
    pub tls: bool,
}

impl TryFrom<&ProviderUrl> for SetecConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "setec" {
            return Err(operation_error(format!(
                "invalid scheme '{}' for setec provider; expected 'setec'",
                url.scheme()
            )));
        }
        if url.host().as_deref().is_none_or(str::is_empty) {
            return Err(operation_error(
                "setec provider URI requires a server host, for example setec://secrets.example.ts.net",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(operation_error(
                "setec provider URI must not contain userinfo; Setec authenticates the caller through Tailscale",
            ));
        }
        if !url.path().trim_matches('/').is_empty() {
            return Err(operation_error(format!(
                "setec provider URI must not contain a path ('{}'); use '?prefix=PATH' to namespace convention secrets",
                url.path()
            )));
        }
        if url.has_fragment() {
            return Err(operation_error(
                "setec provider URI must not contain a fragment",
            ));
        }

        let mut seen = HashSet::new();
        let mut prefix = None;
        let mut tls = true;
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(operation_error(format!(
                    "setec provider URI contains duplicate '{key}' query parameters"
                )));
            }
            match key.as_ref() {
                "prefix" => {
                    let normalized = value.trim_matches('/');
                    if normalized.is_empty() {
                        return Err(operation_error("setec prefix must not be empty"));
                    }
                    if normalized
                        .split('/')
                        .any(|part| part.is_empty() || part == "." || part == "..")
                    {
                        return Err(operation_error(
                            "setec prefix must contain non-empty path segments other than '.' or '..'",
                        ));
                    }
                    prefix = Some(normalized.to_string());
                }
                "tls" => match value.as_ref() {
                    "true" => tls = true,
                    "false" => tls = false,
                    _ => return Err(operation_error("setec 'tls' must be 'true' or 'false'")),
                },
                _ => {
                    return Err(operation_error(format!(
                        "unknown setec provider URI query parameter '{key}'; expected 'prefix' or 'tls'"
                    )));
                }
            }
        }

        Ok(Self {
            host: url.host().expect("host validated above"),
            port: url.port(),
            prefix,
            tls,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct NameRequest<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct GetRequest<'a> {
    name: &'a str,
    version: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct PutRequest<'a> {
    name: &'a str,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ActivateRequest<'a> {
    name: &'a str,
    version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetResponse {
    value: String,
    #[allow(dead_code)]
    version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SecretInfo {
    name: String,
    #[allow(dead_code)]
    versions: Vec<u32>,
    #[allow(dead_code)]
    active_version: u32,
}

/// Provider for a Tailscale Setec secrets service.
pub struct SetecProvider {
    config: SetecConfig,
    client: OnceLock<reqwest::Client>,
}

crate::register_provider! {
    struct: SetecProvider,
    config: SetecConfig,
    metadata: &super::catalog::SETEC,
}

impl SetecProvider {
    pub fn new(config: SetecConfig) -> Self {
        Self {
            config,
            client: OnceLock::new(),
        }
    }

    fn client(&self) -> Result<&reqwest::Client> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| reach_error("building the HTTP client", error))?;
        let _ = self.client.set(client);
        Ok(self.client.get().expect("Setec HTTP client initialized"))
    }

    fn authority(&self) -> String {
        let host = if self.config.host.contains(':') {
            format!("[{}]", self.config.host)
        } else {
            self.config.host.clone()
        };
        match self.config.port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }

    fn server_url(&self) -> String {
        format!(
            "{}://{}",
            if self.config.tls { "https" } else { "http" },
            self.authority()
        )
    }

    fn convention_parent(&self, project: &str, profile: &str) -> Result<String> {
        for (label, value) in [("project", project), ("profile", profile)] {
            validate_convention_component(label, value)?;
        }
        let parent = format!("secretspec/{project}/{profile}");
        Ok(match &self.config.prefix {
            Some(prefix) => format!("{prefix}/{parent}"),
            None => parent,
        })
    }

    fn resolved<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        let coordinates = self.resolve_coords(addr)?;
        validate_name(&coordinates.item)?;
        if let Some(version) = &coordinates.version {
            parse_version(version)?;
        }
        Ok(coordinates)
    }

    async fn post<Req, Resp>(&self, path: &str, request: &Req, action: &str) -> Result<Option<Resp>>
    where
        Req: Serialize + ?Sized,
        Resp: DeserializeOwned,
    {
        let response = self
            .client()?
            .post(format!("{}{path}", self.server_url()))
            .header(NO_BROWSERS_HEADER, "setec")
            .json(request)
            .send()
            .await
            .map_err(|error| reach_error(action, error))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| reach_error(action, error))?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status != reqwest::StatusCode::OK {
            let detail = String::from_utf8_lossy(&body);
            let detail = detail.trim().chars().take(512).collect::<String>();
            let suffix = if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            };
            return Err(operation_error(format!(
                "Setec returned HTTP {} while {action}{suffix}",
                status.as_u16()
            )));
        }
        serde_json::from_slice(&body).map(Some).map_err(|error| {
            operation_error(format!(
                "Setec returned invalid JSON while {action}: {error}"
            ))
        })
    }

    async fn get_async(&self, name: &str, version: u32) -> Result<Option<SecretBytes>> {
        let Some(response): Option<GetResponse> = self
            .post(
                "/api/get",
                &GetRequest { name, version },
                &format!("reading secret '{name}'"),
            )
            .await?
        else {
            return Ok(None);
        };
        let bytes = BASE64.decode(response.value.as_bytes()).map_err(|error| {
            operation_error(format!(
                "Setec returned invalid base64 for secret '{name}': {error}"
            ))
        })?;
        Ok(Some(SecretBytes::from_vec(bytes)))
    }

    async fn set_async(&self, name: &str, value: &SecretBytes) -> Result<()> {
        let encoded = BASE64.encode(value.expose_secret());
        let version: u32 = self
            .post(
                "/api/put",
                &PutRequest {
                    name,
                    value: encoded,
                },
                &format!("writing secret '{name}'"),
            )
            .await?
            .ok_or_else(|| operation_error(format!("Setec did not store secret '{name}'")))?;
        let activated: Option<serde_json::Value> = self
            .post(
                "/api/activate",
                &ActivateRequest { name, version },
                &format!("activating version {version} of secret '{name}'"),
            )
            .await
            .map_err(|error| {
                operation_error(format!(
                    "Setec stored version {version} of secret '{name}', but did not activate it: {error}"
                ))
            })?;
        if activated.is_none() {
            return Err(operation_error(format!(
                "Setec stored version {version} of secret '{name}', but the activation target was not found"
            )));
        }
        Ok(())
    }

    async fn delete_async(&self, name: &str) -> Result<bool> {
        let info: Option<SecretInfo> = self
            .post(
                "/api/info",
                &NameRequest { name },
                &format!("checking secret '{name}' before deletion"),
            )
            .await?;
        if info.is_none() {
            return Ok(false);
        }
        let deleted: Option<serde_json::Value> = self
            .post(
                "/api/delete",
                &NameRequest { name },
                &format!("deleting secret '{name}'"),
            )
            .await?;
        if deleted.is_none() {
            return Ok(false);
        }
        Ok(true)
    }

    async fn reflect_async(
        &self,
        context: DiscoveryContext<'_>,
    ) -> Result<HashMap<String, Secret>> {
        let parent = self.convention_parent(context.project, context.profile)?;
        let prefix = format!("{parent}/");
        let listed: Option<Vec<SecretInfo>> = self
            .post("/api/list", &serde_json::json!({}), "listing secrets")
            .await?
            .ok_or_else(|| operation_error("Setec list endpoint was not found"))?;
        Ok(listed
            .unwrap_or_default()
            .into_iter()
            .filter_map(|info| {
                let key = info.name.strip_prefix(&prefix)?;
                if key.is_empty() || key.contains('/') {
                    return None;
                }
                Some((
                    key.to_string(),
                    Secret::required(format!("{key} Setec secret")),
                ))
            })
            .collect())
    }
}

impl Provider for SetecProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        validate_convention_component("key", key)?;
        Ok(NativeAddress {
            item: format!("{}/{key}", self.convention_parent(project, profile)?),
            ..Default::default()
        })
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        &["version"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let coordinates = self.resolved(addr)?;
        let version = coordinates
            .version
            .as_deref()
            .map(parse_version)
            .transpose()?
            .unwrap_or(0);
        super::block_on(self.get_async(&coordinates.item, version))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let coordinates = self.resolve_coords(addr)?;
        validate_name(&coordinates.item)?;
        if coordinates.version.is_some() {
            return Err(operation_error(
                "setec refs pinning a `version` are read-only; drop `version` to create and activate a new version",
            ));
        }
        Ok(())
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        self.check_writable(addr)?;
        let coordinates = self.resolve_coords(addr)?;
        super::block_on(self.set_async(&coordinates.item, value))
    }

    fn supports_delete(&self) -> bool {
        true
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        let coordinates = self.resolve_coords(addr)?;
        validate_name(&coordinates.item)?;
        if coordinates.version.is_some() {
            return Err(operation_error(
                "setec refs pinning a `version` cannot be deleted through SecretSpec; drop `version` to delete the whole secret",
            ));
        }
        Ok(())
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        self.check_deletable(addr)?;
        let coordinates = self.resolve_coords(addr)?;
        super::block_on(self.delete_async(&coordinates.item))
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        self.check_writable(addr)?;
        let coordinates = self.resolve_coords(addr)?;
        Ok(format!(
            "Setec server '{}' secret '{}' (new active version)",
            self.server_url(),
            coordinates.item
        ))
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut parameters = Vec::new();
        if let Some(prefix) = &self.config.prefix {
            parameters.push(format!("prefix={}", ProviderUrl::encode_query(prefix)));
        }
        if !self.config.tls {
            parameters.push("tls=false".to_string());
        }
        let base = format!("setec://{}", self.authority());
        if parameters.is_empty() {
            base
        } else {
            format!("{base}?{}", parameters.join("&"))
        }
    }

    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        super::block_on(self.reflect_async(context))
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(operation_error("Setec secret name must not be empty"));
    }
    Ok(())
}

fn validate_convention_component(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.contains('/') {
        return Err(operation_error(format!(
            "Setec convention {label} must be non-empty and must not contain '/'"
        )));
    }
    Ok(())
}

fn parse_version(version: &str) -> Result<u32> {
    version
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            operation_error(format!(
                "invalid Setec version '{version}'; versions are positive 32-bit integers"
            ))
        })
}

fn reach_error(action: &str, error: reqwest::Error) -> SecretSpecError {
    operation_error(format!(
        "failed to reach Setec while {action}: {}",
        crate::error::display_error_chain(&error)
    ))
}

fn operation_error(message: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};

    #[derive(Debug)]
    struct RecordedRequest {
        line: String,
        headers: HashMap<String, String>,
        body: serde_json::Value,
    }

    fn config(spec: &str) -> SetecConfig {
        SetecConfig::try_from(&ProviderUrl::new(url::Url::parse(spec).unwrap())).unwrap()
    }

    fn provider(endpoint: SocketAddr) -> SetecProvider {
        SetecProvider::new(config(&format!("setec://{endpoint}?tls=false")))
    }

    fn response_server(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<RecordedRequest>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut recorded = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut headers = HashMap::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.trim_end().split_once(':') {
                        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                    }
                }
                let content_length = headers
                    .get("content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut request_body = vec![0; content_length];
                reader.read_exact(&mut request_body).unwrap();
                recorded.push(RecordedRequest {
                    line: line.trim_end().to_string(),
                    headers,
                    body: serde_json::from_slice(&request_body).unwrap(),
                });
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            recorded
        });
        (endpoint, server)
    }

    #[test]
    fn parses_and_canonicalizes_uri() {
        let provider = SetecProvider::new(config(
            "setec://secrets.example.ts.net:8443?prefix=%2Fteam%2Fplatform%2F&tls=false",
        ));
        assert_eq!(provider.config.prefix.as_deref(), Some("team/platform"));
        assert_eq!(
            provider.uri(),
            "setec://secrets.example.ts.net:8443?prefix=team/platform&tls=false"
        );
        assert_eq!(config(&provider.uri()), provider.config);
    }

    #[test]
    fn rejects_invalid_uri_configuration() {
        for spec in [
            "setec:missing-host",
            "setec://user@host",
            "setec://host/api",
            "setec://host#fragment",
            "setec://host?unknown=x",
            "setec://host?tls=maybe",
            "setec://host?prefix=/",
            "setec://host?prefix=a//b",
            "setec://host?tls=false&tls=true",
        ] {
            let parsed = url::Url::parse(spec).unwrap();
            assert!(
                SetecConfig::try_from(&ProviderUrl::new(parsed)).is_err(),
                "{spec}"
            );
        }
    }

    #[test]
    fn convention_and_native_coordinates_are_distinct() {
        let provider = SetecProvider::new(config("setec://host?prefix=team"));
        assert_eq!(
            provider
                .convention_address("app", "production", "DATABASE_URL")
                .unwrap()
                .item,
            "team/secretspec/app/production/DATABASE_URL"
        );
        assert!(
            provider
                .convention_address("bad/project", "prod", "KEY")
                .is_err()
        );
    }

    #[test]
    fn reads_active_and_pinned_versions() {
        let value = BASE64.encode(b"secret value");
        let active = Box::leak(format!(r#"{{"Value":"{value}","Version":3}}"#).into_boxed_str());
        let pinned = Box::leak(format!(r#"{{"Value":"{value}","Version":2}}"#).into_boxed_str());
        let (endpoint, server) = response_server(vec![("200 OK", active), ("200 OK", pinned)]);
        let provider = provider(endpoint);
        let active = provider
            .get(Address::convention("app", "prod", "KEY"))
            .unwrap()
            .unwrap();
        assert_eq!(active.expose_secret(), b"secret value");
        let native = NativeAddress {
            item: "existing/name".into(),
            version: Some("2".into()),
            ..Default::default()
        };
        provider.get(Address::Native(&native)).unwrap().unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests[0].body["Version"], 0);
        assert_eq!(requests[1].body["Version"], 2);
        assert_eq!(requests[0].headers["sec-x-tailscale-no-browsers"], "setec");
        assert!(requests[0].headers["content-type"].starts_with("application/json"));
    }

    #[test]
    fn missing_read_is_none_and_bad_values_fail() {
        let (endpoint, server) = response_server(vec![("404 Not Found", "not found")]);
        assert!(
            provider(endpoint)
                .get(Address::convention("app", "prod", "MISSING"))
                .unwrap()
                .is_none()
        );
        server.join().unwrap();

        let (endpoint, server) =
            response_server(vec![("200 OK", r#"{"Value":"not base64!","Version":1}"#)]);
        let error = provider(endpoint)
            .get(Address::convention("app", "prod", "BAD_BASE64"))
            .unwrap_err();
        assert!(error.to_string().contains("invalid base64"), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn invalid_responses_fail_without_following_redirects() {
        let (endpoint, server) = response_server(vec![("200 OK", "not-json")]);
        let error = provider(endpoint)
            .get(Address::convention("app", "prod", "BAD_JSON"))
            .unwrap_err();
        assert!(error.to_string().contains("invalid JSON"), "{error}");
        server.join().unwrap();

        let (endpoint, server) = response_server(vec![("307 Temporary Redirect", "redirected")]);
        let error = provider(endpoint)
            .get(Address::convention("app", "prod", "REDIRECT"))
            .unwrap_err();
        assert!(error.to_string().contains("HTTP 307"), "{error}");
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn set_puts_then_activates_returned_version() {
        let (endpoint, server) = response_server(vec![("200 OK", "7"), ("200 OK", "{}")]);
        provider(endpoint)
            .set(
                Address::convention("app", "prod", "KEY"),
                &SecretBytes::from_utf8("replacement"),
            )
            .unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests[0].line, "POST /api/put HTTP/1.1");
        assert_eq!(requests[0].body["Value"], BASE64.encode(b"replacement"));
        assert_eq!(requests[1].line, "POST /api/activate HTTP/1.1");
        assert_eq!(requests[1].body["Version"], 7);
    }

    #[test]
    fn binary_values_round_trip() {
        let (endpoint, server) = response_server(vec![
            ("200 OK", "1"),
            ("200 OK", "{}"),
            ("200 OK", r#"{"Value":"/wBhCg==","Version":1}"#),
        ]);
        let provider = provider(endpoint);
        let address = Address::convention("app", "prod", "BINARY");
        let expected = b"\xff\x00a\n";
        provider
            .set(address, &SecretBytes::from_vec(expected.to_vec()))
            .unwrap();
        let value = provider.get(address).unwrap().unwrap();
        assert_eq!(value.expose_secret(), expected);
        let requests = server.join().unwrap();
        assert_eq!(requests[0].body["Value"], "/wBhCg==");
        assert_eq!(requests[1].line, "POST /api/activate HTTP/1.1");
        assert_eq!(requests[2].line, "POST /api/get HTTP/1.1");
    }

    #[test]
    fn activation_failure_reports_partial_write() {
        let (endpoint, server) =
            response_server(vec![("200 OK", "8"), ("403 Forbidden", "access denied")]);
        let error = provider(endpoint)
            .set(
                Address::convention("app", "prod", "KEY"),
                &SecretBytes::from_utf8("replacement"),
            )
            .unwrap_err();
        assert!(error.to_string().contains("stored version 8"), "{error}");
        assert!(error.to_string().contains("did not activate"), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn pinned_refs_are_read_only_and_not_deletable() {
        let native = NativeAddress {
            item: "name".into(),
            version: Some("4".into()),
            ..Default::default()
        };
        let provider = SetecProvider::new(config("setec://host"));
        assert!(provider.check_writable(Address::Native(&native)).is_err());
        assert!(provider.check_deletable(Address::Native(&native)).is_err());
    }

    #[test]
    fn delete_checks_existence_and_is_idempotent() {
        let info = r#"{"Name":"secretspec/app/prod/KEY","Versions":[1],"ActiveVersion":1}"#;
        let (endpoint, server) = response_server(vec![("200 OK", info), ("200 OK", "{}")]);
        assert!(
            provider(endpoint)
                .delete(Address::convention("app", "prod", "KEY"))
                .unwrap()
        );
        let requests = server.join().unwrap();
        assert_eq!(requests[0].line, "POST /api/info HTTP/1.1");
        assert_eq!(requests[1].line, "POST /api/delete HTTP/1.1");

        let (endpoint, server) = response_server(vec![("404 Not Found", "not found")]);
        assert!(
            !provider(endpoint)
                .delete(Address::convention("app", "prod", "MISSING"))
                .unwrap()
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn reflection_is_bounded_to_the_context_namespace() {
        let body = r#"[
            {"Name":"team/secretspec/app/prod/FIRST","Versions":[1],"ActiveVersion":1},
            {"Name":"team/secretspec/app/prod/nested/NO","Versions":[1],"ActiveVersion":1},
            {"Name":"team/secretspec/other/prod/NO","Versions":[1],"ActiveVersion":1}
        ]"#;
        let (endpoint, server) = response_server(vec![("200 OK", body)]);
        let mut provider = provider(endpoint);
        provider.config.prefix = Some("team".into());
        let reflected = provider
            .reflect(DiscoveryContext::new("app", "prod"))
            .unwrap();
        assert_eq!(reflected.len(), 1);
        assert!(reflected.contains_key("FIRST"));
        server.join().unwrap();
    }

    #[test]
    fn reflection_accepts_empty_and_null_lists() {
        for body in ["[]", "null"] {
            let (endpoint, server) = response_server(vec![("200 OK", body)]);
            let reflected = provider(endpoint)
                .reflect(DiscoveryContext::new("app", "prod"))
                .unwrap();
            assert!(reflected.is_empty(), "{body}");
            let requests = server.join().unwrap();
            assert_eq!(requests[0].line, "POST /api/list HTTP/1.1");
        }
    }

    #[test]
    fn reflection_rejects_missing_endpoint_and_invalid_json() {
        for (status, body, expected) in [
            ("404 Not Found", "not found", "list endpoint was not found"),
            ("200 OK", "not-json", "invalid JSON"),
            ("200 OK", "{}", "invalid JSON"),
        ] {
            let (endpoint, server) = response_server(vec![(status, body)]);
            let error = provider(endpoint)
                .reflect(DiscoveryContext::new("app", "prod"))
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            server.join().unwrap();
        }
    }

    #[test]
    fn registration_declares_delete_without_credentials() {
        let registration = crate::provider::PROVIDER_REGISTRY
            .iter()
            .find(|registration| registration.metadata.info.name == "setec")
            .unwrap();
        assert!(registration.metadata.credential_names.is_empty());
        assert!(registration.metadata.deletes);
        assert!(registration.metadata.reads);
    }
}
