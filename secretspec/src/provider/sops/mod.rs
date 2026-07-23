use super::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::config::NativeAddress;
use crate::provider::sops::config::SopsConfig;
use crate::provider::sops::fields::{
    AGE_KEY, AWS_SECRET_ACCESS_KEY, AZURE_CLIENT_SECRET, CREDENTIAL_FIELDS,
    GOOGLE_OAUTH_ACCESS_TOKEN, HC_VAULT_TOKEN, HUAWEI_SDK_AK, HUAWEI_SDK_SK, PATHBUF_FIELDS,
    STRING_FIELDS,
};
use crate::provider::sops::format::SopsFormat;
use crate::provider::sops::pattern::SopsPathPattern;
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

mod config;
mod fields;
mod format;
mod pattern;

#[cfg(all(test, feature = "sops"))]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SopsMode {
    SingleFile(PathBuf),
    Directory {
        path: PathBuf,
        pattern: SopsPathPattern,
        format: SopsFormat,
    },
    Uninitialized,
}

pub struct SopsProvider {
    config: SopsConfig,
    credentials: ProviderCredentials,
}

crate::register_provider! {
    struct: SopsProvider,
    config: SopsConfig,
    name: "sops",
    description: "SOPS encrypted files (0.17+)",
    schemes: ["sops"],
    examples: [
        "sops://secrets.enc.yaml",
        "sops://secrets-dir/{project}/{profile}.enc.json",
        "sops://secrets-dir/{project}/.env.{profile}.enc?format=dotenv",
    ],
    credential_names: [
        AGE_KEY,
        AWS_SECRET_ACCESS_KEY,
        AZURE_CLIENT_SECRET,
        HC_VAULT_TOKEN,
        HUAWEI_SDK_AK,
        HUAWEI_SDK_SK,
        GOOGLE_OAUTH_ACCESS_TOKEN,
    ],
}

struct AddressParts<'a> {
    project: &'a str,
    profile: &'a str,
    key: &'a str,
}

impl SopsProvider {
    pub fn new(config: SopsConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
        }
    }

    fn provider_error(message: impl Into<String>) -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(message.into())
    }

    fn address_parts<'a>(&self, addr: Address<'a>) -> Result<AddressParts<'a>> {
        match addr {
            Address::Convention {
                project,
                profile,
                key,
            } => Ok(AddressParts {
                project,
                profile,
                key,
            }),
            Address::Native(native) => {
                // Apply the shared unsupported-coordinate validation before
                // interpreting `item` as a root key in a single SOPS file.
                self.resolve_coords(addr)?;
                if matches!(self.config.mode, SopsMode::Directory { .. }) {
                    return Err(Self::provider_error(
                        "SOPS refs require a single-file provider URI; a templated directory \
                         URI needs project and profile values to select the file",
                    ));
                }
                Ok(AddressParts {
                    project: "",
                    profile: "",
                    key: &native.item,
                })
            }
        }
    }

    fn resolve_file_path(&self, project: &str, profile: &str) -> Result<Option<PathBuf>> {
        let path = match &self.config.mode {
            SopsMode::SingleFile(path) => self.config.rebase_path(path.clone()),
            SopsMode::Directory { path, pattern, .. } => self
                .config
                .rebase_path(path.join(pattern.render(project, profile))),
            SopsMode::Uninitialized => {
                return Err(Self::provider_error(
                    "SOPS provider mode must be initialized to a file or directory pattern",
                ));
            }
        };

        Ok((path.is_file()).then_some(path))
    }

    fn new_file_path(&self, project: &str, profile: &str) -> Result<PathBuf> {
        match &self.config.mode {
            SopsMode::SingleFile(path) => Ok(self.config.rebase_path(path.clone())),
            SopsMode::Directory { path, pattern, .. } => Ok(self
                .config
                .rebase_path(path.join(pattern.render(project, profile)))),
            SopsMode::Uninitialized => Err(Self::provider_error(
                "SOPS provider mode must be initialized to a file or directory pattern",
            )),
        }
    }

    fn execute_sops_command<I, S>(&self, args: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new("sops");
        command.args(args);
        self.config.apply_env(&mut command);

        // Provider credentials override inherited environment variables for
        // this SOPS child process without exposing the values in the provider
        // URI, audit log, or launched application environment.
        for spec in CREDENTIAL_FIELDS {
            if let Some(value) = self.credentials.get(spec.name) {
                command.env(spec.env_key, value.expose_secret());
            }
        }

        let output = match command.output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Self::provider_error(
                    "The 'sops' CLI is not installed. Install it from \
                     https://github.com/getsops/sops or via your package manager.",
                ));
            }
            Err(error) => return Err(error.into()),
        };

        if !output.status.success() {
            return Err(Self::provider_error(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        Ok(output.stdout)
    }

    fn input_type(&self) -> Option<&'static str> {
        self.config.format.sops_input_type()
    }

    fn command_with_input_type(&self, command: &str) -> Vec<String> {
        let mut args = vec![command.to_string()];
        if let Some(input_type) = self.input_type() {
            args.push("--input-type".to_string());
            args.push(input_type.to_string());
        }
        args
    }

    fn command_preserving_file_type(&self, command: &str) -> Vec<String> {
        let mut args = self.command_with_input_type(command);
        if let Some(output_type) = self.input_type() {
            args.push("--output-type".to_string());
            args.push(output_type.to_string());
        }
        args
    }

    fn decrypt(&self, path: &Path) -> Result<Vec<u8>> {
        let mut args = self.command_with_input_type("decrypt");
        args.extend([
            "--output-type".to_string(),
            "json".to_string(),
            path.to_string_lossy().into_owned(),
        ]);
        self.execute_sops_command(args)
    }

    fn lookup_paths(&self, parts: &AddressParts<'_>) -> Result<Vec<Vec<String>>> {
        match &self.config.mode {
            SopsMode::SingleFile(_) => {
                let mut paths = Vec::new();
                if !parts.project.is_empty() {
                    if !parts.profile.is_empty() && parts.profile != "default" {
                        paths.push(vec![
                            parts.project.to_string(),
                            parts.profile.to_string(),
                            parts.key.to_string(),
                        ]);
                    }
                    paths.push(vec![parts.profile.to_string(), parts.key.to_string()]);
                }
                paths.push(vec![parts.key.to_string()]);
                Ok(paths)
            }
            SopsMode::Directory { .. } => Ok(vec![vec![parts.key.to_string()]]),
            SopsMode::Uninitialized => Err(Self::provider_error(
                "SOPS provider mode must be initialized to a file or directory pattern",
            )),
        }
    }

    fn parse_decrypted_json(
        &self,
        content: &[u8],
        parts: &AddressParts<'_>,
    ) -> Result<Option<String>> {
        let data: serde_json::Value = serde_json::from_slice(content).map_err(|error| {
            Self::provider_error(format!(
                "Failed to parse JSON emitted by the SOPS CLI: {error}"
            ))
        })?;

        for path in self.lookup_paths(parts)? {
            let mut current = &data;
            let mut found = true;
            for segment in path {
                match current {
                    serde_json::Value::Object(map) => match map.get(&segment) {
                        Some(value) => current = value,
                        None => {
                            found = false;
                            break;
                        }
                    },
                    _ => {
                        found = false;
                        break;
                    }
                }
            }
            if found {
                return Ok(Some(match current {
                    serde_json::Value::String(value) => value.clone(),
                    other => other.to_string(),
                }));
            }
        }

        Ok(None)
    }

    fn create_new_sops_file(&self, project: &str, profile: &str) -> Result<PathBuf> {
        let path = self.new_file_path(project, profile)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                Self::provider_error(format!(
                    "Failed to create SOPS directory {}: {error}",
                    parent.display()
                ))
            })?;
        }

        let initial = match self.config.format {
            SopsFormat::Json => "{}\n",
            SopsFormat::Yaml => "{}\n",
            SopsFormat::Env | SopsFormat::Ini => "",
        };
        std::fs::write(&path, initial).map_err(|error| {
            Self::provider_error(format!(
                "Failed to create SOPS file {}: {error}",
                path.display()
            ))
        })?;

        let mut args = self.command_preserving_file_type("encrypt");
        args.extend([
            "--in-place".to_string(),
            path.to_string_lossy().into_owned(),
        ]);
        self.execute_sops_command(args)?;
        Ok(path)
    }

    fn set_path(&self, parts: &AddressParts<'_>) -> Result<String> {
        let mut paths = self.lookup_paths(parts)?;

        match self.config.format {
            // Dotenv is always a flat map, even when one encrypted file stores
            // several SecretSpec profiles.
            SopsFormat::Env => paths = vec![vec![parts.key.to_string()]],
            SopsFormat::Ini => {
                // INI can represent one section level but not the fully nested
                // project/profile/key hierarchy.
                paths = if matches!(self.config.mode, SopsMode::Directory { .. }) {
                    vec![vec!["DEFAULT".to_string(), parts.key.to_string()]]
                } else if parts.profile.is_empty() {
                    vec![vec![parts.key.to_string()]]
                } else {
                    vec![vec![parts.profile.to_string(), parts.key.to_string()]]
                };
            }
            SopsFormat::Json | SopsFormat::Yaml => {}
        }

        let chosen = paths
            .first()
            .ok_or_else(|| Self::provider_error("No SOPS lookup path is available"))?;
        Ok(chosen
            .iter()
            .map(|segment| {
                serde_json::to_string(segment)
                    .map(|segment| format!("[{segment}]"))
                    .map_err(|error| {
                        Self::provider_error(format!("Failed to encode SOPS path: {error}"))
                    })
            })
            .collect::<Result<Vec<_>>>()?
            .join(""))
    }
}

impl Provider for SopsProvider {
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        key: &str,
    ) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: key.to_string(),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let parts = self.address_parts(addr)?;
        let Some(path) = self.resolve_file_path(parts.project, parts.profile)? else {
            return Ok(None);
        };
        let decrypted = self.decrypt(&path)?;
        Ok(self
            .parse_decrypted_json(&decrypted, &parts)?
            .map(|value| SecretString::new(value.into())))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.address_parts(addr).map(|_| ())
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let parts = self.address_parts(addr)?;
        let path = match self.resolve_file_path(parts.project, parts.profile)? {
            Some(path) => path,
            None => self.create_new_sops_file(parts.project, parts.profile)?,
        };
        let file = path.to_string_lossy().into_owned();

        // Preserve the original provider behavior of accepting an existing
        // plaintext file, but do not silently proceed until it has been
        // encrypted successfully.
        if self.decrypt(&path).is_err() {
            let mut encrypt = self.command_preserving_file_type("encrypt");
            encrypt.extend(["--in-place".to_string(), file.clone()]);
            self.execute_sops_command(encrypt)?;
        }

        let mut args = self.command_preserving_file_type("set");
        args.extend([
            file,
            self.set_path(&parts)?,
            serde_json::to_string(value.expose_secret()).map_err(|error| {
                Self::provider_error(format!("Failed to encode the secret value: {error}"))
            })?,
        ]);
        self.execute_sops_command(args)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut params = BTreeMap::<&str, String>::new();
        params.insert("format", self.config.format.to_string());

        for spec in PATHBUF_FIELDS {
            if let Some(value) = (spec.field)(&self.config) {
                params.insert(spec.url_key, value.to_string_lossy().into_owned());
            }
        }
        for spec in STRING_FIELDS {
            if let Some(value) = (spec.field)(&self.config) {
                params.insert(spec.url_key, value.clone());
            }
        }

        let path = match &self.config.mode {
            SopsMode::SingleFile(path) => path.to_string_lossy().into_owned(),
            SopsMode::Directory { path, pattern, .. } => {
                format!("{}/{}", path.to_string_lossy(), pattern.debug_template())
            }
            SopsMode::Uninitialized => String::new(),
        };
        let query = params
            .into_iter()
            .map(|(key, value)| format!("{key}={}", ProviderUrl::encode_query(&value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("sops://{path}?{query}")
    }

    fn with_base_dir(&mut self, base_dir: &Path) {
        self.config.with_base_dir(base_dir);
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }
}
