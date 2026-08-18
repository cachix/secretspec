//! Kubernetes provider
use crate::{Result, SecretSpecError};

use super::{Address, Provider, ProviderUrl};
use base64::{Engine, engine::general_purpose::STANDARD};
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
    description: "Kubernetes",
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

    fn validate_key(key: &String) -> Result<()> {
        if key.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "key cannot be empty"
            )));
        }

        if key.len() > 253 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Key cannot be longer than 253 characters"
            )));
        }

        for c in key.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Name contains invalid character '{}'. \
                    Only alphanumeric characters, hypens, underscores, and periods are allowed.",
                    c
                )));
            }
        }

        Ok(())
    }

    fn format_secret_name(project: &str, profile: &str, key: &str) -> Result<String> {
        let secret_name = format!("secretspec-{}-{}-{}", project, profile, key);
        Self::validate_key(&secret_name)?;
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
                resource: Some(self.config.kind.to_string()),
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
        let mut uri = format!("k8s+{}://{}", self.config.kind, self.config.name);
        if let Some(namespace) = &self.config.namespace {
            uri.push('@');
            uri.push_str(&namespace);
        }
        uri
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

    fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderCredentials;
    use url::Url;

    fn config(s: &str) -> KubernetesConfig {
        KubernetesConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
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
    fn test_format_secret_name() {
        let name = KubernetesProvider::format_secret_name("myapp", "prod", "DB_URL").unwrap();
        assert_eq!(name, "secretspec-myapp-prod-DB_URL");
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
}
