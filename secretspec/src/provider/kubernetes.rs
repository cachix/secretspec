//! Kubernetes provider
use crate::{Result, SecretSpecError};

use super::{Address, Provider, ProviderUrl};
use base64::{Engine, engine::general_purpose::STANDARD};
use json_patch::jsonptr::Token;
use k8s_openapi::{
    ByteString,
    api::{
        authorization::v1::{
            ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
        },
        core::v1::{ConfigMap, Secret},
    },
};
use kube::{
    Api, Client,
    api::{Patch, PatchParams, PostParams},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, format, sync::OnceLock, write};

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime for kube")
    })
}

fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| runtime().block_on(future))
        }
        Ok(_) => std::thread::scope(|scope| {
            let worker = scope.spawn(move || runtime().block_on(future));
            match worker.join() {
                Ok(output) => output,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }),
        Err(_) => runtime().block_on(future),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KubernetesKind {
    ConfigMap,
    Secret,
}

impl KubernetesKind {
    fn plural(&self) -> &'static str {
        match self {
            KubernetesKind::ConfigMap => "configmaps",
            KubernetesKind::Secret => "secrets",
        }
    }
}

enum StringRepresentation {
    Plain(String),
    Base64(ByteString),
}

impl Display for KubernetesKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KubernetesKind::ConfigMap => write!(f, "configmap"),
            KubernetesKind::Secret => write!(f, "secret"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    pub kind: KubernetesKind,
    pub name: String,
    pub namespace: Option<String>,
}

impl TryFrom<&ProviderUrl> for KubernetesConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let kind: KubernetesKind;
        match url.scheme() {
            "k8s+configmap" => kind = KubernetesKind::ConfigMap,
            "k8s+secret" => kind = KubernetesKind::Secret,
            scheme => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid scheme '{}' for kubernetes provider. Expected 'k8s+configmap' or 'k8s+secret'.",
                    scheme
                )));
            }
        }

        let name: String;
        let namespace: Option<String>;
        match url.host() {
            Some(host) => {
                (name, namespace) = match url.username().as_str() {
                    "" => (host, None),
                    username => (username.into(), Some(host)),
                }
            }
            None => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "A Kubernetes objet identifier must be provided"
                )));
            }
        }

        Ok(Self {
            kind,
            name,
            namespace,
        })
    }
}

pub struct KubernetesProvider {
    config: KubernetesConfig,
    client: OnceLock<Client>,
}

crate::register_provider! {
    struct: KubernetesProvider,
    config: KubernetesConfig,
    name: "kubernetes",
    description: "Kubernetes (0.20+)",
    schemes: ["k8s+configmap", "k8s+secret"],
    examples: ["k8s+secret://db-config", "k8s+configmap://db-config@default"],
    deletes: true,
}

impl KubernetesProvider {
    pub fn new(config: KubernetesConfig) -> Self {
        Self {
            config,
            client: OnceLock::new(),
        }
    }

    pub fn build_uri(kind: &KubernetesKind, name: &String, namespace: &Option<String>) -> String {
        let mut uri = format!("k8s+{}://{}", kind, name);
        if let Some(namespace) = namespace {
            uri.push('@');
            uri.push_str(namespace);
        }
        uri
    }

    async fn client(&self) -> Result<&Client> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let created = Client::try_default().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create Kubernetes client: {}",
                crate::error::display_error_chain(&e)
            ))
        });
        match created {
            Ok(client) => Ok(self.client.get_or_init(|| client)),
            Err(e) => Err(e),
        }
    }

    /// Validates a secret name component for Kubernetes.
    ///
    /// Components contain only alphanumeric characters, underscores, periods,
    /// and internal hyphens: A component may not contain `--` or begin or
    /// end with `-`: either shape could consume or overlap a `--` boundary.
    fn validate_name_component(name: &str, component: &str) -> Result<()> {
        if component.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} cannot be empty",
                name
            )));
        }

        for c in component.chars() {
            if !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.' {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} contains invalid character '{}'. \
                    Only alphanumeric characters, underscores, periods, and hyphens are allowed",
                    name, c
                )));
            }
        }

        if component.starts_with('-') || component.ends_with('-') || component.contains("--") {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{name} '{component}' cannot start or end with a hyphen or contain `--`: the \
                 Kubernetes convention separates project, profile, and key with `--`, so only
                 single internal hyphens stay unambiguous. Rename it and run `secretspec set` to |
                 store the value under the new name, or address the secret with a `ref` entry."
            )));
        }

        Ok(())
    }

    fn format_secret_name(project: &str, profile: &str, key: &str) -> Result<String> {
        Self::validate_name_component("project", project)?;
        Self::validate_name_component("profile", profile)?;
        Self::validate_name_component("key", key)?;
        let secret_name = format!("secretspec--{}--{}--{}", project, profile, key);
        if secret_name.len() > 253 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Key cannot be longer than 253 characters"
            )));
        }
        Ok(secret_name)
    }

    async fn get_coords_async(&self, key: &str) -> Result<Option<SecretString>> {
        let client = self.client().await?;
        let namespace = match &self.config.namespace {
            Some(ns) => ns.as_str(),
            None => client.default_namespace(),
        };
        let name = self.config.name.as_str();
        let value = match self.config.kind {
            KubernetesKind::ConfigMap => {
                let api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
                api.get(name).await.map(|cm| {
                    cm.data.map_or(None, |d| {
                        d.get(key).map(|v| StringRepresentation::Plain(v.clone()))
                    })
                })
            }
            KubernetesKind::Secret => {
                let api: Api<Secret> = Api::namespaced(client.clone(), &namespace);
                api.get(name).await.map(|cm| {
                    cm.data.map_or(None, |d| {
                        d.get(key).map(|v| StringRepresentation::Base64(v.clone()))
                    })
                })
            }
        };
        match value {
            Ok(Some(StringRepresentation::Plain(s))) => Ok(Some(SecretString::new(s.into()))),
            Ok(Some(StringRepresentation::Base64(s))) => match String::from_utf8(s.0) {
                Ok(decoded) => Ok(Some(SecretString::new(decoded.into()))),
                Err(e) => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Cannot decode value for {}: {}",
                    key,
                    crate::error::display_error_chain(&e)
                ))),
            },
            Ok(None) => Ok(None),
            Err(e) => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Cannot get {}/{} in namespace {}: {}",
                self.config.kind,
                name,
                namespace,
                crate::error::display_error_chain(&e)
            ))),
        }
    }

    async fn set_secret_async(&self, key: &str, value: &SecretString) -> Result<()> {
        let client = self.client().await?;
        let namespace = match &self.config.namespace {
            Some(ns) => ns.as_str(),
            None => client.default_namespace(),
        };
        let name = self.config.name.as_str();
        let secret = value.expose_secret();
        let base64_secret = STANDARD.encode(secret);
        let secret = match self.config.kind {
            KubernetesKind::ConfigMap => secret,
            KubernetesKind::Secret => base64_secret.as_str(),
        };
        let patch = serde_json::json!({
            "data": {
                key: secret,
            },
        });
        let params = PatchParams::default();
        let patch = Patch::Merge(&patch);
        let patched = match self.config.kind {
            KubernetesKind::ConfigMap => {
                let api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
                api.patch(name, &params, &patch).await.map(|_| ())
            }
            KubernetesKind::Secret => {
                let api: Api<Secret> = Api::namespaced(client.clone(), &namespace);
                api.patch(name, &params, &patch).await.map(|_| ())
            }
        };
        patched.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to patch {}: {}",
                self.config.kind,
                crate::error::display_error_chain(&e)
            ))
        })
    }

    async fn delete_secret_async(&self, key: &str) -> Result<bool> {
        let client = self.client().await?;
        let namespace = match &self.config.namespace {
            Some(ns) => ns.as_str(),
            None => client.default_namespace(),
        };
        let name = self.config.name.as_str();
        let params = PatchParams::default();
        let patch = Patch::Json::<()>(json_patch::Patch(vec![json_patch::PatchOperation::Remove(
            json_patch::RemoveOperation {
                path: json_patch::jsonptr::PointerBuf::from_tokens(&[
                    Token::new("data"),
                    Token::new(key),
                ]),
            },
        )]));
        let patched = match self.config.kind {
            KubernetesKind::ConfigMap => {
                let api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
                api.patch(name, &params, &patch).await.map(|_| ())
            }
            KubernetesKind::Secret => {
                let api: Api<Secret> = Api::namespaced(client.clone(), &namespace);
                api.patch(name, &params, &patch).await.map(|_| ())
            }
        };
        match patched {
            Ok(_) => Ok(true),
            // This happens when we try to remove a path that doesn't exist
            Err(kube::Error::Api(status)) if status.code == 422 && status.reason == "Invalid" => {
                Ok(false)
            }
            Err(e) => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Failed to patch {}: {}",
                self.config.kind,
                crate::error::display_error_chain(&e)
            ))),
        }
    }

    async fn can_i_patch(&self) -> Result<bool> {
        let client = self.client().await?;
        let namespace = match &self.config.namespace {
            Some(ns) => ns.as_str(),
            None => client.default_namespace(),
        };
        let spec = SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                namespace: Some(namespace.into()),
                verb: Some("patch".to_string()),
                resource: Some(self.config.kind.plural().to_string()),
                group: Some(String::new()),
                version: Some("v1".to_string()),
                name: Some(self.config.name.clone()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let self_subject_access_review = SelfSubjectAccessReview {
            spec,
            ..Default::default()
        };
        let api: Api<SelfSubjectAccessReview> = Api::all(client.to_owned());
        let response = api
            .create(&PostParams::default(), &self_subject_access_review)
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Cannot verify if {} resource can be patched: {}",
                    self.config.kind,
                    crate::error::display_error_chain(&e)
                ))
            });
        response.map(|r| r.status.map(|s| s.allowed).unwrap_or(false))
    }
}

impl Provider for KubernetesProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        Self::build_uri(&self.config.kind, &self.config.name, &self.config.namespace)
    }

    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: Self::format_secret_name(project, profile, key)?,
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        block_on(self.get_coords_async(&coords.item))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_coords(addr)?;
        block_on(self.set_secret_async(&coords.item, value))
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        self.check_deletable(addr)?;
        let coords = self.resolve_coords(addr)?;
        block_on(self.delete_secret_async(&coords.item))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.resolve_coords(addr)?;
        let can_i_patch = block_on(self.can_i_patch())?;
        if !can_i_patch {
            let err_msg = if let Some(namespace) = &self.config.namespace {
                format!(
                    "Cannot patch {}/{} in {}",
                    self.config.kind, self.config.name, namespace
                )
            } else {
                format!("Cannot patch {}/{}", self.config.kind, self.config.name)
            };
            return Err(SecretSpecError::ProviderOperationFailed(err_msg));
        }
        Ok(())
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.check_writable(addr)
    }

    fn supports_delete(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread::JoinHandle,
        time::{Duration, Instant},
    };
    use url::Url;

    fn config(s: &str) -> KubernetesConfig {
        KubernetesConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    fn read_json_request(stream: &mut TcpStream) -> serde_json::Value {
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        let (headers_end, content_length) = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(
                read, 0,
                "connection closed before completing request headers"
            );
            request.extend_from_slice(&buffer[..read]);

            if let Some(headers_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
            {
                let headers = std::str::from_utf8(&request[..headers_end]).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or_default();
                break (headers_end, content_length);
            }
        };

        while request.len() < headers_end + content_length {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(read, 0, "connection closed before completing request body");
            request.extend_from_slice(&buffer[..read]);
        }

        serde_json::from_slice(&request[headers_end..headers_end + content_length]).unwrap()
    }

    fn provider_with_access_reviews(
        allowed: bool,
        expected_requests: usize,
    ) -> (KubernetesProvider, JoinHandle<Vec<serde_json::Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut requests = Vec::new();

            while requests.len() < expected_requests && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let request = read_json_request(&mut stream);
                        let body = serde_json::json!({
                            "apiVersion": "authorization.k8s.io/v1",
                            "kind": "SelfSubjectAccessReview",
                            "status": { "allowed": allowed },
                        })
                        .to_string();
                        let response = format!(
                            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                        stream.flush().unwrap();
                        requests.push(request);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("failed to accept Kubernetes API request: {error}"),
                }
            }

            requests
        });

        let config = kube::Config::new(format!("http://{address}").parse().unwrap());
        let client = block_on(async { Client::try_from(config).unwrap() });
        let provider = KubernetesProvider::new(KubernetesConfig {
            kind: KubernetesKind::Secret,
            name: "app-secrets".to_string(),
            namespace: Some("app".to_string()),
        });
        assert!(provider.client.set(client).is_ok());

        (provider, server)
    }

    fn assert_secret_patch_review(request: &serde_json::Value) {
        let attributes = &request["spec"]["resourceAttributes"];
        assert_eq!(attributes["verb"], "patch");
        assert_eq!(attributes["resource"], "secrets");
        assert_eq!(attributes["namespace"], "app");
        assert_eq!(attributes["name"], "app-secrets");
    }

    #[test]
    fn test_uri_configmap_fully_qualified() {
        let c = config("k8s+configmap://name@namespace");
        assert_eq!(c.kind, KubernetesKind::ConfigMap);
        assert_eq!(c.name, String::from("name"));
        assert_eq!(c.namespace, Some(String::from("namespace")));
    }

    #[test]
    fn test_uri_secret_fully_qualified() {
        let c = config("k8s+secret://name@namespace");
        assert_eq!(c.kind, KubernetesKind::Secret);
        assert_eq!(c.name, String::from("name"));
        assert_eq!(c.namespace, Some(String::from("namespace")));
    }

    #[test]
    fn test_uri_without_namespace() {
        let c = config("k8s+configmap://name");
        assert_eq!(c.kind, KubernetesKind::ConfigMap);
        assert_eq!(c.name, String::from("name"));
        assert_eq!(c.namespace, None);
    }

    #[test]
    fn test_uri_with_incorrect_kubernetes_kind() {
        let uri = "k8s+pod://name@namespace";
        let url = ProviderUrl::new(Url::parse(uri).unwrap());
        let config = KubernetesConfig::try_from(&url);
        assert!(config.is_err());
    }

    #[test]
    fn secret_patch_authorization_uses_plural_resource_name() {
        let (provider, server) = provider_with_access_reviews(true, 1);

        provider
            .check_writable(Address::convention("project", "default", "API_KEY"))
            .unwrap();

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert_secret_patch_review(&requests[0]);
    }

    #[test]
    fn deletion_preflight_and_delete_require_patch_permission() {
        let (provider, server) = provider_with_access_reviews(false, 2);
        let addr = Address::convention("project", "default", "API_KEY");

        let preflight = provider.check_deletable(addr).unwrap_err().to_string();
        let deletion = provider.delete(addr).unwrap_err().to_string();

        assert_eq!(preflight, deletion);
        assert!(preflight.contains("Cannot patch secret/app-secrets in app"));

        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "delete must repeat the destructive preflight"
        );
        for request in &requests {
            assert_secret_patch_review(request);
        }
    }

    #[test]
    fn test_format_secret_name() {
        let name = KubernetesProvider::format_secret_name("myapp", "prod", "DB_URL").unwrap();
        assert_eq!(name, "secretspec--myapp--prod--DB_URL");
    }

    #[test]
    fn test_format_secret_name_rejects_invalid_chars() {
        assert!(KubernetesProvider::format_secret_name("my/app", "prod", "DB_URL").is_err());
        assert!(KubernetesProvider::format_secret_name("myapp", "prod", "DB URL").is_err());
    }

    #[test]
    fn test_format_secret_name_too_long() {
        let long_key = "A".repeat(254);
        let result = KubernetesProvider::format_secret_name("myapp", "prod", &long_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_secret_name_rejects_component_with_surrounding_hyphens() {
        let result = KubernetesProvider::format_secret_name("myapp", "prod-", "DB_URL");
        assert!(result.is_err());

        let result = KubernetesProvider::format_secret_name("myapp", "prod", "-DB_URL");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_secret_name_rejects_component_with_double_hyphens() {
        let result = KubernetesProvider::format_secret_name("my--app", "prod", "DB_URL");
        assert!(result.is_err());
    }
}
