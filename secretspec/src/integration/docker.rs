use crate::config::GlobalConfig;
use crate::{CallerContext, NamedResolution, RequireReason, Secret, Secrets, Spec};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use url::{Host, Url};

pub(crate) const HELPER_NAME: &str = "secretspec";
pub(crate) const STATE_VERSION: u8 = 1;
const MAX_INPUT_BYTES: u64 = 1_048_576;
const NOT_FOUND: &str = "credentials not found in native keychain";
const EMBEDDED_PASSWORD: &str = "PASSWORD";

pub(crate) struct EmbeddedDockerCredentials {
    pub(crate) secrets: Secrets,
    pub(crate) password_secret: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedCredential {
    pub(crate) registry: String,
    pub(crate) docker_config: PathBuf,
    pub(crate) provider: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) source: CredentialSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub(crate) enum CredentialSource {
    Embedded {
        username: String,
    },
    Manifest {
        manifest: PathBuf,
        profile: Option<String>,
        username: UsernameSource,
        password_secret: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "source",
    content = "value"
)]
pub(crate) enum UsernameSource {
    Literal(String),
    Secret(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedState {
    pub(crate) version: u8,
    pub(crate) credentials: Vec<ManagedCredential>,
}

impl Default for ManagedState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            credentials: Vec::new(),
        }
    }
}

pub(crate) fn state_entry_path() -> Result<PathBuf, String> {
    let config = GlobalConfig::path().map_err(|error| error.to_string())?;
    let directory = config
        .parent()
        .ok_or_else(|| "SecretSpec config path has no parent directory".to_string())?;
    std::path::absolute(directory.join("docker-credentials.json"))
        .map_err(|error| format!("Failed to resolve Docker credential state path: {error}"))
}

pub(crate) fn state_path() -> Result<PathBuf, String> {
    let path = state_entry_path()?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => dunce::canonicalize(&path)
            .map_err(|error| format!("Failed to resolve {}: {error}", path.display())),
        Ok(_) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(format!("Failed to inspect {}: {error}", path.display())),
    }
}

pub(crate) fn docker_config_path() -> Result<PathBuf, String> {
    let directory = match std::env::var_os("DOCKER_CONFIG") {
        Some(directory) if !directory.is_empty() => PathBuf::from(directory),
        _ => etcetera::home_dir()
            .map_err(|error| format!("Failed to locate the user home directory: {error}"))?
            .join(".docker"),
    };
    let path = std::path::absolute(directory.join("config.json"))
        .map_err(|error| format!("Failed to resolve Docker configuration path: {error}"))?;
    match fs::symlink_metadata(&path) {
        Ok(_) => dunce::canonicalize(&path)
            .map_err(|error| format!("Failed to resolve {}: {error}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => canonicalize_missing_path(&path)
            .map_err(|error| format!("Failed to resolve {}: {error}", path.display())),
        Err(error) => Err(format!("Failed to inspect {}: {error}", path.display())),
    }
}

fn canonicalize_missing_path(path: &Path) -> io::Result<PathBuf> {
    let mut prefix = path;
    let mut suffix = Vec::new();
    loop {
        match dunce::canonicalize(prefix) {
            Ok(mut resolved) => {
                for component in suffix.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(component) = prefix.file_name() else {
                    return Err(error);
                };
                suffix.push(component.to_os_string());
                let Some(parent) = prefix.parent() else {
                    return Err(error);
                };
                prefix = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn load_state() -> Result<ManagedState, String> {
    let path = state_path()?;
    let contents = match fs::read(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ManagedState::default()),
        Err(error) => return Err(format!("Failed to read {}: {error}", path.display())),
    };
    let state: ManagedState = serde_json::from_slice(&contents)
        .map_err(|error| format!("Failed to parse {}: {error}", path.display()))?;
    if state.version != STATE_VERSION {
        return Err(format!(
            "Unsupported Docker credential configuration version {} in {}",
            state.version,
            path.display()
        ));
    }
    let mut configurations = std::collections::HashSet::new();
    for credential in &state.credentials {
        if canonical_registry(&credential.registry).as_deref() != Ok(&credential.registry)
            || !credential.docker_config.is_absolute()
            || !valid_source(&credential.source)
        {
            return Err(format!(
                "Invalid entry in Docker credential configuration {}",
                path.display()
            ));
        }
        if !configurations.insert((&credential.docker_config, &credential.registry)) {
            return Err(format!(
                "Duplicate registry and Docker configuration in managed credential state {}",
                path.display()
            ));
        }
    }
    Ok(state)
}

fn valid_source(source: &CredentialSource) -> bool {
    match source {
        CredentialSource::Embedded { username } => valid_username(username),
        CredentialSource::Manifest {
            manifest,
            profile,
            username,
            password_secret,
        } => {
            manifest.is_absolute()
                && profile.as_deref().is_none_or(|profile| !profile.is_empty())
                && !password_secret.is_empty()
                && match username {
                    UsernameSource::Literal(username) => valid_username(username),
                    UsernameSource::Secret(secret) => !secret.is_empty(),
                }
        }
    }
}

pub(crate) fn canonical_registry(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Docker registry cannot be empty".to_string());
    }
    if input.chars().any(|character| character.is_ascii_control()) {
        return Err("Docker registry cannot contain control characters".to_string());
    }
    if matches!(
        input.trim_end_matches('/').to_ascii_lowercase().as_str(),
        "docker.io"
            | "http://docker.io"
            | "https://docker.io"
            | "index.docker.io"
            | "http://index.docker.io"
            | "https://index.docker.io"
            | "registry-1.docker.io"
            | "http://registry-1.docker.io"
            | "https://registry-1.docker.io"
            | "https://index.docker.io/v1"
            | "http://index.docker.io/v1"
    ) {
        return Ok("https://index.docker.io/v1/".to_string());
    }

    let parsed = if input.contains("://") {
        Url::parse(input).map_err(|error| format!("Invalid Docker registry: {error}"))?
    } else {
        Url::parse(&format!("https://{input}"))
            .map_err(|error| format!("Invalid Docker registry: {error}"))?
    };
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "Docker registry must be a hostname with an optional port and no path".to_string(),
        );
    }
    let host = match parsed.host().expect("validated host") {
        Host::Ipv6(address) => format!("[{address}]"),
        host => host.to_string(),
    };
    let authority = input
        .split_once("://")
        .map_or(input, |(_, authority)| authority)
        .trim_end_matches('/');
    let explicit_port = if authority.starts_with('[') {
        authority
            .rsplit_once(']')
            .and_then(|(_, remainder)| remainder.strip_prefix(':'))
    } else {
        authority
            .rsplit_once(':')
            .and_then(|(host, port)| (!host.contains(':')).then_some(port))
    };
    let explicit_port = explicit_port
        .map(|port| {
            port.parse::<u16>()
                .map_err(|_| "Docker registry port is invalid".to_string())
        })
        .transpose()?;
    Ok(match parsed.port().or(explicit_port) {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn embedded_identity(registry: &str, docker_config: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(docker_config.as_os_str().as_encoded_bytes());
    hasher.update([0]);
    hasher.update(registry.as_bytes());
    data_encoding::HEXLOWER.encode(&hasher.finalize())
}

pub(crate) fn load_embedded_docker_credentials(
    registry: &str,
    docker_config: &Path,
) -> Result<EmbeddedDockerCredentials, String> {
    let registry = canonical_registry(registry)?;
    let identity = embedded_identity(&registry, docker_config);
    let password_secret = format!("{EMBEDDED_PASSWORD}_{identity}");
    let spec = Spec::builder(format!("docker-credential-{identity}"))
        .require_reason(RequireReason::Never)
        .secret(
            password_secret.clone(),
            Secret::required("Docker registry password or token"),
        )
        .build()
        .map_err(|error| error.to_string())?;
    let config_path = GlobalConfig::path().map_err(|error| error.to_string())?;
    let config_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "SecretSpec config path has no parent directory".to_string())?;
    let mut secrets = Secrets::from_spec_at(spec, config_dir).map_err(|error| error.to_string())?;
    secrets.set_profile("default");
    secrets.set_ignore_ambient_scope(true);
    Ok(EmbeddedDockerCredentials {
        secrets,
        password_secret,
    })
}

fn read_input(mut input: impl Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("Docker credential request is too large".to_string());
    }
    String::from_utf8(bytes).map_err(|_| "Docker credential request must be UTF-8".to_string())
}

fn resolve_secret(secrets: &Secrets, name: &str) -> Result<Option<SecretString>, String> {
    let config = secrets
        .resolve_secret_config(name, None)
        .ok_or_else(|| format!("Secret '{name}' is not declared in the selected profile"))?;
    if config.as_path == Some(true) {
        return Err(format!(
            "Secret '{name}' uses as_path and cannot be returned as a Docker credential"
        ));
    }
    match secrets
        .resolve_named(name)
        .map_err(|error| error.to_string())?
    {
        NamedResolution::Resolved(secret) => secret
            .value
            .map(|value| Some(SecretString::new(value.into())))
            .ok_or_else(|| {
                format!(
                    "Secret '{name}' uses as_path and cannot be returned as a Docker credential"
                )
            }),
        NamedResolution::Missing { .. } => Ok(None),
        NamedResolution::Undeclared => Err(format!(
            "Secret '{name}' is not declared in the selected profile"
        )),
    }
}

fn resolve(credential: &ManagedCredential) -> Result<Option<(String, SecretString)>, String> {
    let (mut secrets, username, password_secret) = match &credential.source {
        CredentialSource::Embedded { username } => {
            let embedded =
                load_embedded_docker_credentials(&credential.registry, &credential.docker_config)?;
            (
                embedded.secrets,
                UsernameSource::Literal(username.clone()),
                embedded.password_secret,
            )
        }
        CredentialSource::Manifest {
            manifest,
            profile,
            username,
            password_secret,
        } => {
            let mut secrets = Secrets::load_from(manifest).map_err(|error| error.to_string())?;
            if let Some(profile) = profile {
                secrets.set_profile(profile);
            }
            (secrets, username.clone(), password_secret.clone())
        }
    };
    if let Some(provider) = &credential.provider {
        secrets.set_provider(provider);
    }
    if let Some(reason) = &credential.reason {
        secrets = secrets.with_reason(reason);
    }
    secrets = secrets.with_caller(
        CallerContext::new("docker")
            .with_operation("credential_get")
            .with_resource(&credential.registry),
    );
    secrets.set_ignore_ambient_scope(true);

    let Some(password) = resolve_secret(&secrets, &password_secret)? else {
        return Ok(None);
    };
    let username = match username {
        UsernameSource::Literal(username) => username,
        UsernameSource::Secret(name) => {
            let Some(username) = resolve_secret(&secrets, &name)? else {
                return Ok(None);
            };
            username.expose_secret().to_string()
        }
    };
    if !valid_username(&username) {
        return Err("Docker username cannot be empty or contain control characters".to_string());
    }
    Ok(Some((username, password)))
}

pub(crate) fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && !username
            .chars()
            .any(|character| character.is_ascii_control())
}

fn get(input: impl Read, mut output: impl Write) -> Result<(), String> {
    let registry = canonical_registry(&read_input(input)?)?;
    let docker_config = docker_config_path()?;
    let state = load_state()?;
    let credential = state
        .credentials
        .iter()
        .find(|credential| {
            credential.registry == registry && credential.docker_config == docker_config
        })
        .ok_or_else(|| NOT_FOUND.to_string())?;
    let Some((username, password)) = resolve(credential)? else {
        return Err(NOT_FOUND.to_string());
    };
    serde_json::to_writer(
        &mut output,
        &serde_json::json!({
            "Username": username,
            "Secret": password.expose_secret(),
        }),
    )
    .map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}

fn run(operation: &str, input: impl Read, output: impl Write) -> Result<(), String> {
    match operation {
        "get" => get(input, output),
        "store" | "erase" => Err(
            "docker-credential-secretspec is read-only; manage credentials with SecretSpec"
                .to_string(),
        ),
        "list" => Err(
            "docker-credential-secretspec does not act as a global credential store".to_string(),
        ),
        _ => Err(format!("unknown Docker credential operation '{operation}'")),
    }
}

pub fn main() -> ExitCode {
    let mut arguments = std::env::args();
    let program = arguments
        .next()
        .unwrap_or_else(|| "docker-credential-secretspec".to_string());
    let Some(operation) = arguments.next() else {
        println!("Usage: {program} <store|get|erase|list>");
        return ExitCode::FAILURE;
    };
    if arguments.next().is_some() {
        println!("Usage: {program} <store|get|erase|list>");
        return ExitCode::FAILURE;
    }
    if matches!(operation.as_str(), "--help" | "-h") {
        println!("Usage: {program} <store|get|erase|list>");
        return ExitCode::SUCCESS;
    }
    if matches!(operation.as_str(), "--version" | "-v") {
        println!("docker-credential-secretspec {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match run(&operation, io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            println!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    #[test]
    fn canonicalizes_docker_hub_and_registry_hosts() {
        for registry in [
            "docker.io",
            "https://docker.io/",
            "index.docker.io",
            "http://index.docker.io/",
            "registry-1.docker.io",
            "https://registry-1.docker.io/",
            "https://index.docker.io/v1/",
        ] {
            assert_eq!(
                canonical_registry(registry).unwrap(),
                "https://index.docker.io/v1/"
            );
        }
        assert_eq!(canonical_registry("GHCR.IO").unwrap(), "ghcr.io");
        assert_eq!(
            canonical_registry("registry.example.com:5000").unwrap(),
            "registry.example.com:5000"
        );
        assert_eq!(
            canonical_registry("registry.example.com:443").unwrap(),
            "registry.example.com:443"
        );
        assert_eq!(
            canonical_registry("http://registry.example.com:80").unwrap(),
            "registry.example.com:80"
        );
    }

    #[test]
    fn rejects_registry_paths_and_credentials() {
        for registry in [
            "ghcr.io/org",
            "https://user@ghcr.io",
            "https://ghcr.io?query=yes",
            "ssh://ghcr.io",
            "ghcr.io\nexample.com",
        ] {
            assert!(canonical_registry(registry).is_err());
        }
    }

    #[test]
    fn read_only_operations_fail_without_reading_configuration() {
        for operation in ["store", "erase"] {
            let error = run(operation, Cursor::new("invalid"), Vec::new()).unwrap_err();
            assert!(error.contains("read-only"));
        }
    }

    #[test]
    fn resolves_configured_credentials() {
        let directory = TempDir::new().unwrap();
        let manifest = directory.path().join("secretspec.toml");
        fs::write(
            &manifest,
            r#"
[project]
name = "docker-helper"
revision = "1.0"
require_reason = false

[profiles.default]
DOCKER_USERNAME = { description = "Docker username", default = "registry-user", providers = ["null"] }
DOCKER_TOKEN = { description = "Docker token", default = "token=value", providers = ["null"] }
"#,
        )
        .unwrap();
        let credential = ManagedCredential {
            registry: "ghcr.io".to_string(),
            docker_config: directory.path().join("docker/config.json"),
            provider: None,
            reason: None,
            source: CredentialSource::Manifest {
                manifest,
                profile: Some("default".to_string()),
                username: UsernameSource::Secret("DOCKER_USERNAME".to_string()),
                password_secret: "DOCKER_TOKEN".to_string(),
            },
        };
        let resolved = resolve(&credential).unwrap().unwrap();
        assert_eq!(resolved.0, "registry-user");
        assert_eq!(resolved.1.expose_secret(), "token=value");
    }
}
