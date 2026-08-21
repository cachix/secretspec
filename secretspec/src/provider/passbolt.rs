//! Passbolt provider backed by `go-passbolt-cli`.
//!
//! Convention secrets use one Passbolt resource named
//! `secretspec/{project}/{profile}/{key}` and store the value in its password
//! field. Native addresses may select an existing resource by UUID or exact
//! name and may select its password, username, URI, or description field.

use crate::config::NativeAddress;
use crate::provider::{
    Address, DiscoveryContext, Provider, ProviderCredentials, ProviderUrl, credential_or_env,
};
use crate::{Result, Secret, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io;
use std::process::{Command, Stdio};

const DEFAULT_FIELD: &str = "password";
const DEFAULT_TEMPLATE: &str = "secretspec/{project}/{profile}/{key}";
const KNOWN_FIELDS: &[&str] = &["password", "username", "uri", "description"];

const PRIVATE_KEY: &str = "private_key";
const PASSPHRASE: &str = "passphrase";
const ENV_SERVER: &str = "SECRETSPEC_PASSBOLT_SERVER";
const ENV_PRIVATE_KEY_FILE: &str = "SECRETSPEC_PASSBOLT_PRIVATE_KEY_FILE";
const ENV_PRIVATE_KEY: &str = "SECRETSPEC_PASSBOLT_PRIVATE_KEY";
const ENV_PASSPHRASE: &str = "SECRETSPEC_PASSBOLT_PASSPHRASE";

#[derive(Debug, Deserialize)]
struct PassboltResource {
    id: Option<String>,
    name: Option<String>,
    username: Option<String>,
    uri: Option<String>,
    password: Option<String>,
    description: Option<String>,
}

impl PassboltResource {
    fn field(&self, field: &str) -> Option<String> {
        let value = match field {
            "password" => &self.password,
            "username" => &self.username,
            "uri" => &self.uri,
            "description" => &self.description,
            _ => &None,
        };
        value.clone().filter(|value| !value.is_empty())
    }
}

/// Authentication applied to every child process. Secret values use the
/// environment names read by `go-passbolt-cli`; only the server and key-file
/// path are placed on argv.
#[derive(Hash)]
struct CliAuth {
    server: Option<String>,
    key_file: Option<String>,
    key_inline: Option<String>,
    passphrase: Option<String>,
}

impl CliAuth {
    fn apply(&self, command: &mut Command) {
        if let Some(server) = &self.server {
            command.arg("--serverAddress").arg(server);
        }
        if let Some(key_file) = &self.key_file {
            command.arg("--userPrivateKeyFile").arg(key_file);
        } else if let Some(key) = &self.key_inline {
            command.env("USERPRIVATEKEY", key);
        }
        if let Some(passphrase) = &self.passphrase {
            command.env("USERPASSWORD", passphrase);
        }
    }
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// Canonicalizes server spellings that address the same Passbolt deployment.
fn normalize_server(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');

    match url::Url::parse(trimmed) {
        // `Url::parse` normalizes the scheme, host, and default port.
        Ok(url) => {
            let mut normalized =
                format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
            if let Some(port) = url.port() {
                normalized.push_str(&format!(":{port}"));
            }
            normalized.push_str(url.path().trim_end_matches('/'));
            normalized
        }
        Err(_) => trimmed.to_ascii_lowercase(),
    }
}

/// Replaces placeholders found in the template itself exactly once. Values
/// containing text such as `{profile}` are kept literally instead of being
/// interpreted by a later replacement pass.
fn render_template(template: &str, project: &str, profile: &str, key: &str) -> String {
    let mut rendered = String::with_capacity(template.len() + project.len() + profile.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rendered.push_str(&rest[..open]);
        rest = &rest[open..];
        if let Some(tail) = rest.strip_prefix("{project}") {
            rendered.push_str(project);
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("{profile}") {
            rendered.push_str(profile);
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("{key}") {
            rendered.push_str(key);
            rest = tail;
        } else {
            rendered.push('{');
            rest = &rest[1..];
        }
    }
    rendered.push_str(rest);
    rendered
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PassboltConfig {
    /// Complete convention resource-name template from `?template=`.
    pub template: Option<String>,
    /// Folder used to scope listings and hold newly created resources.
    pub folder_id: Option<String>,
    /// Server address passed to `go-passbolt-cli`.
    pub server_address: Option<String>,
}

impl TryFrom<&ProviderUrl> for PassboltConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "passbolt" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for passbolt provider",
                url.scheme()
            )));
        }
        if url.host().is_some() || !url.path().trim_matches('/').is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Passbolt resource templates belong in the `template` query parameter. \
                 Use `passbolt://?template=secretspec/{project}/{profile}/{key}`."
                    .to_string(),
            ));
        }

        let mut config = Self::default();
        let mut seen = HashSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Passbolt query parameter `{key}` may only be specified once"
                )));
            }

            match key.as_ref() {
                "template" => {
                    if value.is_empty() {
                        return Err(SecretSpecError::ProviderOperationFailed(
                            "Passbolt `template` cannot be empty".to_string(),
                        ));
                    }
                    config.template = Some(value.into_owned());
                }
                "folder" => config.folder_id = (!value.is_empty()).then(|| value.into_owned()),
                "server" => config.server_address = (!value.is_empty()).then(|| value.into_owned()),
                _ => {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "unknown Passbolt query parameter `{key}`; expected `template`, `folder`, \
                         or `server`"
                    )));
                }
            }
        }

        Ok(config)
    }
}

/// Provider for the self-hosted Passbolt password manager through the
/// community-maintained `go-passbolt-cli`.
///
/// Provider credentials named `private_key` and `passphrase` take precedence
/// over `SECRETSPEC_PASSBOLT_PRIVATE_KEY` and
/// `SECRETSPEC_PASSBOLT_PASSPHRASE`. A key file can instead be selected with
/// `SECRETSPEC_PASSBOLT_PRIVATE_KEY_FILE`. The server comes from `?server=`,
/// then `SECRETSPEC_PASSBOLT_SERVER`, then the CLI configuration.
///
/// `go-passbolt-cli` currently accepts values for create and update only as
/// flags. Consequently, a value written with this provider is visible in the
/// child process's argv while that command runs. Authentication secrets are
/// still kept off argv.
pub struct PassboltProvider {
    config: PassboltConfig,
    cli_binary_path: String,
    credentials: ProviderCredentials,
}

crate::register_provider! {
    struct: PassboltProvider,
    config: PassboltConfig,
    name: "passbolt",
    description: "Passbolt self-hosted password manager (0.19+) via go-passbolt-cli",
    schemes: ["passbolt"],
    examples: [
        "passbolt://",
        "passbolt://?server=https://pass.example.com",
        "passbolt://?template=teams/{project}/{profile}/{key}",
    ],
    credential_names: [PRIVATE_KEY, PASSPHRASE],
    preflight: check_auth,
}

impl PassboltProvider {
    pub fn new(config: PassboltConfig) -> Self {
        Self {
            config,
            cli_binary_path: std::env::var("SECRETSPEC_PASSBOLT_CLI_PATH")
                .unwrap_or_else(|_| "passbolt".to_string()),
            credentials: ProviderCredentials::new(),
        }
    }

    fn template(&self) -> &str {
        self.config.template.as_deref().unwrap_or(DEFAULT_TEMPLATE)
    }

    fn format_resource_name(&self, project: &str, profile: &str, key: &str) -> String {
        render_template(self.template(), project, profile, key)
    }

    fn server_address(&self) -> Option<String> {
        self.config.server_address.clone().or_else(|| {
            std::env::var(ENV_SERVER)
                .ok()
                .filter(|value| !value.is_empty())
        })
    }

    fn explicit_credential(&self, name: &str) -> Option<String> {
        self.credentials
            .get(name)
            .map(|value| value.expose_secret().to_string())
            .filter(|value| !value.is_empty())
    }

    fn cli_auth(&self) -> CliAuth {
        // An explicit provider credential wins over both environment-based key
        // forms. Otherwise the CLI's documented file-over-inline precedence is
        // preserved.
        let explicit_key = self.explicit_credential(PRIVATE_KEY);
        let (key_file, key_inline) = if let Some(key) = explicit_key {
            (None, Some(key))
        } else if let Some(path) = std::env::var(ENV_PRIVATE_KEY_FILE)
            .ok()
            .filter(|value| !value.is_empty())
        {
            (Some(path), None)
        } else {
            (
                None,
                credential_or_env(&self.credentials, PRIVATE_KEY, ENV_PRIVATE_KEY),
            )
        };

        CliAuth {
            server: self.server_address(),
            key_file,
            key_inline,
            passphrase: credential_or_env(&self.credentials, PASSPHRASE, ENV_PASSPHRASE),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.cli_binary_path);
        self.cli_auth().apply(&mut command);
        command
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let output = match self
            .command()
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Passbolt CLI is not installed. Install go-passbolt-cli and ensure the \
                     `passbolt` binary is on PATH, or set SECRETSPEC_PASSBOLT_CLI_PATH."
                        .to_string(),
                ));
            }
            Err(error) => return Err(error.into()),
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            let lower = detail.to_ascii_lowercase();
            if lower.contains("reading password") && lower.contains("eof") {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Passbolt needs a non-interactive private-key passphrase. Supply the \
                     `passphrase` provider credential, set {ENV_PASSPHRASE}, or save it with \
                     `passbolt configure --userPassword ...` (details: {detail})"
                )));
            }
            if lower.contains("reading totp") && lower.contains("eof") {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Passbolt cannot prompt for TOTP during a SecretSpec operation. Configure \
                     go-passbolt-cli with `--mfaMode noninteractive-totp` and its TOTP token \
                     before retrying (details: {detail})"
                )));
            }
            if detail.contains("is not defined") || detail.contains("serverAddress") {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Passbolt CLI is not configured. Set `server`, `private_key`, and \
                     `passphrase` through the provider configuration/credentials, or run \
                     `passbolt configure` (details: {detail})"
                )));
            }
            return Err(SecretSpecError::ProviderOperationFailed(detail.to_string()));
        }

        String::from_utf8(output.stdout).map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Passbolt CLI returned non-UTF-8 output: {}",
                crate::error::display_error_chain(&error)
            ))
        })
    }

    fn list_resources(&self) -> Result<Vec<PassboltResource>> {
        let mut args = vec![
            "list", "resource", "--json", "--column", "id", "--column", "name",
        ];
        if let Some(folder) = &self.config.folder_id {
            args.push("--folder");
            args.push(folder);
        }
        Ok(serde_json::from_str(&self.run(&args)?)?)
    }

    fn find_id_in(resources: &[PassboltResource], item: &str) -> Result<Option<String>> {
        let mut matches = resources.iter().filter(|resource| {
            if is_uuid(item) {
                resource
                    .id
                    .as_deref()
                    .is_some_and(|id| id.eq_ignore_ascii_case(item))
            } else {
                resource.name.as_deref() == Some(item)
            }
        });
        let Some(resource) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "multiple Passbolt resources are named '{item}'; use a resource UUID or \
                 narrow the provider with `?folder=`"
            )));
        }
        resource.id.clone().map(Some).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Passbolt resource '{item}' did not include an id in CLI output"
            ))
        })
    }

    fn find_id_by_name(&self, name: &str) -> Result<Option<String>> {
        Self::find_id_in(&self.list_resources()?, name)
    }

    fn resolve_read_id(&self, item: &str) -> Result<Option<String>> {
        if is_uuid(item) {
            Ok(Some(item.to_string()))
        } else {
            self.find_id_by_name(item)
        }
    }

    fn resolve_existing_id(&self, item: &str) -> Result<Option<String>> {
        if is_uuid(item) {
            Ok(self.get_resource(item)?.map(|_| item.to_string()))
        } else {
            self.find_id_by_name(item)
        }
    }

    fn get_resource(&self, id: &str) -> Result<Option<PassboltResource>> {
        match self.run(&["get", "resource", "--id", id, "--json"]) {
            Ok(output) => Ok(Some(serde_json::from_str(&output)?)),
            Err(SecretSpecError::ProviderOperationFailed(message))
                if is_resource_not_found(&message) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn operation_coordinates(&self, addr: Address<'_>) -> Result<NativeAddress> {
        let mut coords = self.resolve_coords(addr)?.into_owned();
        let field = validate_field(coords.field.as_deref().unwrap_or(DEFAULT_FIELD))?;
        coords.field = Some(field.to_string());
        Ok(coords)
    }

    fn missing_reference(item: &str) -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(format!(
            "Passbolt resource '{item}' does not exist or is not accessible; a `ref` must \
             name an existing resource"
        ))
    }

    fn discovery_parts(&self, context: DiscoveryContext<'_>) -> Result<(String, String)> {
        if self.config.folder_id.is_none() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Passbolt discovery requires `?folder=`; refusing to enumerate the whole account"
                    .to_string(),
            ));
        }
        let template = self.template();
        if template.match_indices("{key}").count() != 1 {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Passbolt discovery requires `template` to contain `{key}` exactly once"
                    .to_string(),
            ));
        }
        let (before, after) = template.split_once("{key}").expect("count checked above");
        let prefix = render_template(before, context.project, context.profile, "");
        let suffix = render_template(after, context.project, context.profile, "");
        Ok((prefix, suffix))
    }

    fn discovered_key<'a>(name: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
        let middle = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
        (!middle.is_empty() && !middle.contains('/')).then_some(middle)
    }

    pub(crate) fn check_auth(&self) -> Result<()> {
        self.list_resources().map(|_| ())
    }
}

fn validate_field(field: &str) -> Result<&str> {
    if KNOWN_FIELDS.contains(&field) {
        Ok(field)
    } else {
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "the passbolt provider has no writable `{field}` field; ref `field` must be one of: {}",
            KNOWN_FIELDS.join(", ")
        )))
    }
}

/// Only the precise `get resource` 404 shape is a read miss. A 404 from a bad
/// server path, or an unrelated "not found" error, remains an operation error.
fn is_resource_not_found(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("getting resource:")
        && (lower.contains("api error (code 404)") || lower.contains("404 not found"))
}

impl Provider for PassboltProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        let item = self.format_resource_name(project, profile, key);
        if item.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Passbolt convention template rendered an empty resource name".to_string(),
            ));
        }
        Ok(NativeAddress {
            item,
            ..Default::default()
        })
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, NativeAddress>> {
        Ok(std::borrow::Cow::Owned(self.operation_coordinates(addr)?))
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &str {
        Self::PROVIDER_NAME
    }

    fn auth_scope_key(&self) -> Option<String> {
        let auth = self.cli_auth();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        auth.hash(&mut hasher);
        Some(format!("{}:{:016x}", self.cli_binary_path, hasher.finish()))
    }

    fn uri(&self) -> String {
        let mut query = Vec::new();
        if let Some(template) = &self.config.template {
            query.push(format!("template={}", ProviderUrl::encode_query(template)));
        }
        if let Some(folder) = &self.config.folder_id {
            query.push(format!("folder={}", ProviderUrl::encode_query(folder)));
        }
        if let Some(server) = &self.config.server_address {
            query.push(format!("server={}", ProviderUrl::encode_query(server)));
        }
        if query.is_empty() {
            "passbolt".to_string()
        } else {
            format!("passbolt://?{}", query.join("&"))
        }
    }

    fn entry_container_identity(&self) -> String {
        let mut query = Vec::new();
        if let Some(folder) = &self.config.folder_id {
            query.push(format!("folder={}", ProviderUrl::encode_query(folder)));
        }
        if let Some(server) = self.server_address() {
            query.push(format!(
                "server={}",
                ProviderUrl::encode_query(&normalize_server(&server))
            ));
        }
        if query.is_empty() {
            "passbolt".to_string()
        } else {
            format!("passbolt://?{}", query.join("&"))
        }
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.operation_coordinates(addr)?;
        let field = coords.field.as_deref().expect("operation fills field");
        let Some(id) = self.resolve_read_id(&coords.item)? else {
            return Ok(None);
        };
        let Some(resource) = self.get_resource(&id)? else {
            return Ok(None);
        };
        Ok(resource
            .field(field)
            .map(|value| SecretString::new(value.into())))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        if value.expose_secret().is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Passbolt cannot store an empty value: go-passbolt-cli treats empty update \
                 fields as a no-op"
                    .to_string(),
            ));
        }
        let coords = self.operation_coordinates(addr)?;
        let field = coords.field.as_deref().expect("operation fills field");
        let flag = format!("--{field}");
        let secret = value.expose_secret();

        let existing_id = match addr {
            Address::Native(_) => self
                .resolve_existing_id(&coords.item)?
                .ok_or_else(|| Self::missing_reference(&coords.item))?,
            Address::Convention { .. } => match self.find_id_by_name(&coords.item)? {
                Some(id) => id,
                None => {
                    let mut args =
                        vec!["create", "resource", "--name", &coords.item, &flag, secret];
                    if let Some(folder) = &self.config.folder_id {
                        args.push("--folderParentID");
                        args.push(folder);
                    }
                    self.run(&args)?;
                    return Ok(());
                }
            },
        };

        self.run(&["update", "resource", "--id", &existing_id, &flag, secret])?;
        Ok(())
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let coords = self.operation_coordinates(addr)?;
        if matches!(addr, Address::Native(_)) && self.resolve_existing_id(&coords.item)?.is_none() {
            return Err(Self::missing_reference(&coords.item));
        }
        Ok(())
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }

        let mut resolved = Vec::with_capacity(requests.len());
        let mut needs_listing = false;
        for (name, addr) in requests {
            let coords = self.operation_coordinates(*addr)?;
            needs_listing |= !is_uuid(&coords.item);
            resolved.push(((*name).to_string(), coords));
        }
        let listed = if needs_listing {
            self.list_resources()?
        } else {
            Vec::new()
        };

        let mut by_id: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for (name, coords) in resolved {
            let id = if is_uuid(&coords.item) {
                Some(coords.item.clone())
            } else {
                Self::find_id_in(&listed, &coords.item)?
            };
            let Some(id) = id else {
                continue;
            };
            by_id
                .entry(id)
                .or_default()
                .push((name, coords.field.expect("operation fills field")));
        }

        struct Target {
            id: String,
            requests: Vec<(String, String)>,
        }
        struct Fetched {
            requests: Vec<(String, String)>,
            resource: Option<PassboltResource>,
        }
        let targets: Vec<Target> = by_id
            .into_iter()
            .map(|(id, requests)| Target { id, requests })
            .collect();
        let fetched: Vec<Result<Fetched>> =
            super::map_concurrently(&targets, super::get_each_concurrency(), |target| {
                self.get_resource(&target.id).map(|resource| Fetched {
                    requests: target.requests.clone(),
                    resource,
                })
            });

        let mut output = HashMap::new();
        for result in fetched {
            let Fetched { requests, resource } = result?;
            let Some(resource) = resource else {
                continue;
            };
            for (name, field) in requests {
                if let Some(value) = resource.field(&field) {
                    output.insert(name, SecretString::new(value.into()));
                }
            }
        }
        Ok(output)
    }

    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        let (prefix, suffix) = self.discovery_parts(context)?;
        let mut declarations = HashMap::new();
        for resource in self.list_resources()? {
            let Some(name) = resource.name.as_deref() else {
                continue;
            };
            let Some(key) = Self::discovered_key(name, &prefix, &suffix) else {
                continue;
            };
            if declarations
                .insert(key.to_string(), Secret::required(format!("{key} secret")))
                .is_some()
            {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "multiple Passbolt resources map to discovered key '{key}'"
                )));
            }
        }
        Ok(declarations)
    }
}

impl Default for PassboltProvider {
    fn default() -> Self {
        Self::new(PassboltConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvRestore {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.previous {
                Some(previous) => unsafe { std::env::set_var(self.key, previous) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn provider_url(spec: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(spec).unwrap())
    }

    fn config(spec: &str) -> PassboltConfig {
        PassboltConfig::try_from(&provider_url(spec)).unwrap()
    }

    fn resource(id: &str, name: &str) -> PassboltResource {
        PassboltResource {
            id: Some(id.to_string()),
            name: Some(name.to_string()),
            username: None,
            uri: None,
            password: None,
            description: None,
        }
    }

    fn with_env<T>(key: &'static str, value: &str, body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _restore = EnvRestore {
            key,
            previous: std::env::var_os(key),
        };
        unsafe { std::env::set_var(key, value) };
        body()
    }

    #[cfg(unix)]
    struct FakePassbolt {
        dir: tempfile::TempDir,
        _env_guard: std::sync::MutexGuard<'static, ()>,
    }

    #[cfg(unix)]
    impl FakePassbolt {
        fn new(list: serde_json::Value, get: serde_json::Value) -> Self {
            use std::io::Write;
            use std::os::unix::fs::PermissionsExt;

            let env_guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let dir = tempfile::tempdir().unwrap();
            let script = r#"#!/bin/sh
fixture_dir=$(dirname "$0")
printf '%s\n' "$*" >> "$fixture_dir/invocations.log"
case "$*" in
  *"list resource"*) cat "$fixture_dir/list.json" ;;
  *"get resource"*) cat "$fixture_dir/get.json" ;;
  *"update resource"*) ;;
  *) printf 'unexpected fake passbolt invocation: %s\n' "$*" >&2; exit 2 ;;
esac
"#;
            let binary = dir.path().join("passbolt");
            let mut executable = std::fs::File::create(&binary).unwrap();
            executable.write_all(script.as_bytes()).unwrap();
            executable.sync_all().unwrap();
            let mut permissions = executable.metadata().unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&binary, permissions).unwrap();
            drop(executable);
            std::fs::write(dir.path().join("list.json"), list.to_string()).unwrap();
            std::fs::write(dir.path().join("get.json"), get.to_string()).unwrap();
            Self {
                dir,
                _env_guard: env_guard,
            }
        }

        fn provider(&self, spec: &str) -> PassboltProvider {
            let mut provider = PassboltProvider::new(config(spec));
            provider.cli_binary_path = self
                .dir
                .path()
                .join("passbolt")
                .to_string_lossy()
                .into_owned();
            provider
        }

        fn invocations(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("invocations.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    #[test]
    fn uuid_recognition_is_canonical_and_case_insensitive() {
        assert!(is_uuid("a9230ec4-5507-4870-b8b5-b3f500587e4c"));
        assert!(is_uuid("A9230EC4-5507-4870-B8B5-B3F500587E4C"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("a9230ec4-5507-4870-b8b5-b3f500587e4"));
    }

    #[test]
    fn template_renders_once() {
        assert_eq!(
            render_template(
                "{project}/{profile}/{key}",
                "literal-{profile}",
                "prod",
                "KEY"
            ),
            "literal-{profile}/prod/KEY"
        );
        let provider = PassboltProvider::new(config(
            "passbolt://?template=teams/{project}/{profile}/{key}",
        ));
        assert_eq!(
            provider.format_resource_name("shop", "prod", "API_KEY"),
            "teams/shop/prod/API_KEY"
        );
    }

    #[test]
    fn config_uses_template_query_and_rejects_old_path_form() {
        let parsed = config(
            "passbolt://?template=teams/{key}&folder=fid-123&server=https://pass.example.com",
        );
        assert_eq!(parsed.template.as_deref(), Some("teams/{key}"));
        assert_eq!(parsed.folder_id.as_deref(), Some("fid-123"));
        assert_eq!(
            parsed.server_address.as_deref(),
            Some("https://pass.example.com")
        );

        let error = PassboltConfig::try_from(&provider_url("passbolt://teams/{key}")).unwrap_err();
        assert!(error.to_string().contains("`template` query parameter"));
    }

    #[test]
    fn config_rejects_unknown_and_duplicate_query_parameters() {
        for spec in [
            "passbolt://?sever=https://pass.example.com",
            "passbolt://?template=one&template=two",
            "passbolt://?folder=one&folder=two",
            "passbolt://?server=https://one.example.com&server=https://two.example.com",
        ] {
            assert!(
                PassboltConfig::try_from(&provider_url(spec)).is_err(),
                "{spec}"
            );
        }
    }

    #[test]
    fn config_rejects_an_explicitly_empty_template() {
        let error = PassboltConfig::try_from(&provider_url("passbolt://?template=")).unwrap_err();
        assert!(error.to_string().contains("`template` cannot be empty"));
    }

    #[test]
    fn uri_round_trips_non_secret_configuration() {
        for spec in [
            "passbolt://?template=secretspec/{project}/{profile}/{key}",
            "passbolt://?folder=fid-123",
            "passbolt://?server=https://pass.example.com",
            "passbolt://?template=vault/{key}&folder=fid-9&server=https://p.example.com",
        ] {
            let original = config(spec);
            let uri = PassboltProvider::new(original.clone()).uri();
            let reparsed = config(&uri);
            assert_eq!(reparsed.template, original.template, "template in {uri}");
            assert_eq!(reparsed.folder_id, original.folder_id, "folder in {uri}");
            assert_eq!(
                reparsed.server_address, original.server_address,
                "server in {uri}"
            );
        }
    }

    #[test]
    fn registry_builds_provider_and_declares_credentials() {
        let provider = Box::<dyn Provider>::try_from("passbolt").unwrap();
        assert_eq!(provider.name(), "passbolt");
        assert_eq!(provider.uri(), "passbolt");
        let registration = crate::provider::PROVIDER_REGISTRY
            .iter()
            .find(|registration| registration.info.name == "passbolt")
            .unwrap();
        assert_eq!(registration.credential_names, &[PRIVATE_KEY, PASSPHRASE]);
    }

    #[test]
    fn container_identity_uses_the_effective_normalized_server() {
        let (explicit_identity, fallback_identity) =
            with_env(ENV_SERVER, "https://pass.example.com", || {
                let explicit = PassboltProvider::new(config(
                    "passbolt://?server=HTTPS://PASS.EXAMPLE.COM:443/",
                ));
                let fallback = PassboltProvider::default();
                (
                    explicit.entry_container_identity(),
                    fallback.entry_container_identity(),
                )
            });
        assert_eq!(explicit_identity, fallback_identity);
    }

    #[test]
    fn name_is_not_an_addressable_secret_field() {
        for field in KNOWN_FIELDS {
            assert_eq!(validate_field(field).unwrap(), *field);
        }
        assert!(
            validate_field("name")
                .unwrap_err()
                .to_string()
                .contains("name")
        );
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let resources = vec![resource("one", "duplicate"), resource("two", "duplicate")];
        let error = PassboltProvider::find_id_in(&resources, "duplicate").unwrap_err();
        assert!(error.to_string().contains("multiple Passbolt resources"));
    }

    #[test]
    fn operation_coordinates_default_to_password() {
        let provider = PassboltProvider::default();
        let coords = provider
            .operation_coordinates(Address::convention("proj", "default", "KEY"))
            .unwrap();
        assert_eq!(coords.item, "secretspec/proj/default/KEY");
        assert_eq!(coords.field.as_deref(), Some("password"));
    }

    #[test]
    fn native_addresses_reject_unsupported_coordinates() {
        let provider = PassboltProvider::default();
        let native = NativeAddress {
            item: "resource".into(),
            vault: Some("Personal".into()),
            ..Default::default()
        };
        let error = provider
            .resolve_coords(Address::Native(&native))
            .unwrap_err();
        assert!(error.to_string().contains("`vault`"));
    }

    fn command_args_envs(auth: &CliAuth) -> (Vec<String>, Vec<(String, String)>) {
        let mut command = Command::new("passbolt");
        auth.apply(&mut command);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let envs = command
            .get_envs()
            .filter_map(|(key, value)| {
                Some((
                    key.to_string_lossy().into_owned(),
                    value?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        (args, envs)
    }

    #[test]
    fn authentication_secrets_stay_off_argv() {
        let auth = CliAuth {
            server: Some("https://pass.example.com".into()),
            key_file: None,
            key_inline: Some("private-key".into()),
            passphrase: Some("passphrase".into()),
        };
        let (args, envs) = command_args_envs(&auth);
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--serverAddress", "https://pass.example.com"])
        );
        assert!(!args.iter().any(|arg| arg.contains("private-key")));
        assert!(!args.iter().any(|arg| arg.contains("passphrase")));
        assert!(envs.contains(&("USERPRIVATEKEY".into(), "private-key".into())));
        assert!(envs.contains(&("USERPASSWORD".into(), "passphrase".into())));
    }

    #[test]
    fn explicit_provider_credentials_feed_cli_auth() {
        let mut provider = PassboltProvider::default();
        let mut credentials = ProviderCredentials::new();
        credentials.insert(PRIVATE_KEY.into(), SecretString::new("key".into()));
        credentials.insert(PASSPHRASE.into(), SecretString::new("phrase".into()));
        provider.with_credentials(credentials);
        let auth = provider.cli_auth();
        assert_eq!(auth.key_inline.as_deref(), Some("key"));
        assert_eq!(auth.passphrase.as_deref(), Some("phrase"));
        let scope = provider.auth_scope_key().unwrap();
        assert!(!scope.contains("key"));
        assert!(!scope.contains("phrase"));
    }

    #[test]
    fn not_found_matching_is_narrow() {
        assert!(is_resource_not_found(
            "getting resource: API error (code 404): The resource does not exist"
        ));
        assert!(is_resource_not_found("getting resource: 404 Not Found"));
        assert!(!is_resource_not_found(
            "API error (code 404): bad server path"
        ));
        assert!(!is_resource_not_found("resource type not found"));
    }

    #[test]
    fn discovery_is_bounded_and_reversible() {
        let provider = PassboltProvider::new(config("passbolt://?folder=folder-id"));
        let (prefix, suffix) = provider
            .discovery_parts(DiscoveryContext::new("shop", "prod"))
            .unwrap();
        assert_eq!(prefix, "secretspec/shop/prod/");
        assert_eq!(suffix, "");
        assert_eq!(
            PassboltProvider::discovered_key("secretspec/shop/prod/API_KEY", &prefix, &suffix),
            Some("API_KEY")
        );
        assert_eq!(
            PassboltProvider::discovered_key("secretspec/shop/prod/nested/KEY", &prefix, &suffix),
            None
        );

        let unbounded = PassboltProvider::new(config("passbolt://?template={key}"));
        assert!(
            unbounded
                .discovery_parts(DiscoveryContext::new("shop", "prod"))
                .unwrap_err()
                .to_string()
                .contains("refusing to enumerate the whole account")
        );
    }

    #[test]
    fn empty_values_fail_before_spawning_cli() {
        let native = NativeAddress {
            item: "existing-resource".into(),
            ..Default::default()
        };
        let error = PassboltProvider::default()
            .set(
                Address::Native(&native),
                &SecretString::new(String::new().into()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("cannot store an empty value"));
    }

    #[cfg(unix)]
    #[test]
    fn uuid_writes_bypass_the_folder_listing() {
        let id = "a9230ec4-5507-4870-b8b5-b3f500587e4c";
        let fake = FakePassbolt::new(
            serde_json::json!([]),
            serde_json::json!({"id": id, "name": "outside-folder"}),
        );
        let provider = fake.provider("passbolt://?folder=folder-id");
        let native = NativeAddress {
            item: id.into(),
            ..Default::default()
        };

        provider.check_writable(Address::Native(&native)).unwrap();
        provider
            .set(
                Address::Native(&native),
                &SecretString::new("updated".into()),
            )
            .unwrap();

        let invocations = fake.invocations();
        assert!(invocations.iter().any(|args| args.contains("get resource")));
        assert!(
            invocations
                .iter()
                .any(|args| args.contains("update resource"))
        );
        assert!(
            !invocations
                .iter()
                .any(|args| args.contains("list resource"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_name_write_reuses_its_resource_listing() {
        let id = "a9230ec4-5507-4870-b8b5-b3f500587e4c";
        let fake = FakePassbolt::new(
            serde_json::json!([{"id": id, "name": "existing-resource"}]),
            serde_json::json!({"id": id, "name": "existing-resource"}),
        );
        let provider = fake.provider("passbolt://?folder=folder-id");
        let native = NativeAddress {
            item: "existing-resource".into(),
            ..Default::default()
        };

        provider
            .set(
                Address::Native(&native),
                &SecretString::new("updated".into()),
            )
            .unwrap();

        let list_count = fake
            .invocations()
            .iter()
            .filter(|args| args.contains("list resource"))
            .count();
        assert_eq!(list_count, 1);
    }
}
