use super::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::config::NativeAddress;
use crate::provider::sops::config::SopsConfig;
#[cfg(test)]
use crate::provider::sops::fields::AGE_KEY;
use crate::provider::sops::fields::{CREDENTIAL_FIELDS, PATHBUF_FIELDS, STRING_FIELDS};
use crate::provider::sops::format::SopsFormat;
use crate::provider::sops::pattern::SopsPathPattern;
use crate::{Result, SecretSpecError};
use etcetera::{BaseStrategy, choose_base_strategy};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    metadata: &super::catalog::SOPS,
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
        self.execute_sops_command_with_stdin(args, None)
    }

    fn execute_sops_command_with_stdin<I, S>(
        &self,
        args: I,
        stdin: Option<&[u8]>,
    ) -> Result<Vec<u8>>
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

        let output = if let Some(stdin) = stdin {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Self::provider_error(
                        "The 'sops' CLI is not installed. Install it from \
                         https://github.com/getsops/sops or via your package manager.",
                    ));
                }
                Err(error) => return Err(error.into()),
            };
            let write_result = child
                .stdin
                .take()
                .ok_or_else(|| Self::provider_error("Failed to open stdin for the SOPS CLI"))
                .and_then(|mut child_stdin| {
                    child_stdin.write_all(stdin).map_err(|error| {
                        Self::provider_error(format!(
                            "Failed to send secret data to the SOPS CLI: {error}"
                        ))
                    })
                });
            let output = child.wait_with_output()?;
            if !output.status.success() {
                return Err(Self::provider_error(
                    String::from_utf8_lossy(&output.stderr).trim().to_string(),
                ));
            }
            write_result?;
            output
        } else {
            match command.output() {
                Ok(output) => output,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Self::provider_error(
                        "The 'sops' CLI is not installed. Install it from \
                         https://github.com/getsops/sops or via your package manager.",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
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
            SopsMode::SingleFile(_) => match self.config.format {
                SopsFormat::Json | SopsFormat::Yaml => {
                    let mut paths = Vec::new();
                    if !parts.project.is_empty() && !parts.profile.is_empty() {
                        paths.push(vec![
                            parts.project.to_string(),
                            parts.profile.to_string(),
                            parts.key.to_string(),
                        ]);
                    }
                    if !parts.profile.is_empty() {
                        // Compatibility with files written before SecretSpec
                        // consistently included the project namespace.
                        paths.push(vec![parts.profile.to_string(), parts.key.to_string()]);
                    }
                    paths.push(vec![parts.key.to_string()]);
                    Ok(paths)
                }
                SopsFormat::Env => Ok(vec![vec![parts.key.to_string()]]),
                SopsFormat::Ini => {
                    let mut paths = if parts.profile.is_empty() {
                        vec![vec!["DEFAULT".to_string(), parts.key.to_string()]]
                    } else {
                        vec![vec![parts.profile.to_string(), parts.key.to_string()]]
                    };
                    // Retain a root-key fallback for existing unusual files.
                    paths.push(vec![parts.key.to_string()]);
                    Ok(paths)
                }
            },
            SopsMode::Directory { .. } => {
                if self.config.format == SopsFormat::Ini {
                    Ok(vec![vec!["DEFAULT".to_string(), parts.key.to_string()]])
                } else {
                    Ok(vec![vec![parts.key.to_string()]])
                }
            }
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

    fn set_path(&self, parts: &AddressParts<'_>) -> Result<String> {
        let paths = self.lookup_paths(parts)?;
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

    /// Resolves the filesystem entry a write will replace without creating it
    /// or any of its parents. Existing symlinks are resolved so the preview and
    /// the atomic replacement name the same physical target.
    fn resolved_write_target_path(&self, project: &str, profile: &str) -> Result<PathBuf> {
        let configured = self.new_file_path(project, profile)?;
        if configured.is_file() {
            return configured.canonicalize().map_err(Into::into);
        }
        if configured.try_exists()? {
            return Err(Self::provider_error(format!(
                "SOPS target {} is not a regular file",
                configured.display()
            )));
        }

        let filename = configured.file_name().ok_or_else(|| {
            Self::provider_error(format!(
                "SOPS target {} does not name a file",
                configured.display()
            ))
        })?;
        let parent = configured
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        // The full parent may not exist yet. Canonicalize the deepest existing
        // ancestor, then append and lexically normalize the missing suffix.
        // This still resolves a symlinked project directory without mutating
        // the backing store merely to produce a preview.
        for ancestor in parent
            .ancestors()
            .filter(|ancestor| !ancestor.as_os_str().is_empty())
        {
            if !ancestor.try_exists()? {
                continue;
            }
            if !ancestor.is_dir() {
                return Err(Self::provider_error(format!(
                    "SOPS target parent {} is not a directory",
                    ancestor.display()
                )));
            }
            let canonical = ancestor.canonicalize()?;
            let suffix = parent.strip_prefix(ancestor).map_err(|error| {
                Self::provider_error(format!(
                    "Failed to resolve SOPS target parent {}: {error}",
                    parent.display()
                ))
            })?;
            return Ok(Self::normalize_path(canonical.join(suffix)).join(filename));
        }

        // Relative paths with no existing component are resolved from the
        // current directory; absolute paths always find their root above.
        let current = std::env::current_dir()?.canonicalize()?;
        Ok(Self::normalize_path(current.join(parent)).join(filename))
    }

    fn normalize_path(path: PathBuf) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                _ => normalized.push(component.as_os_str()),
            }
        }
        normalized
    }

    fn writable_target_path(&self, project: &str, profile: &str) -> Result<PathBuf> {
        let target = self.resolved_write_target_path(project, profile)?;
        let parent = target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|error| {
            Self::provider_error(format!(
                "Failed to create SOPS directory {}: {error}",
                parent.display()
            ))
        })?;
        Ok(target)
    }

    fn acquire_write_lock(path: &Path) -> Result<File> {
        let lock_directory = choose_base_strategy()
            .map_err(|error| {
                Self::provider_error(format!(
                    "Failed to find the user cache directory for SOPS write locks: {error}"
                ))
            })?
            .cache_dir()
            .join("secretspec/locks/sops");
        std::fs::create_dir_all(&lock_directory).map_err(|error| {
            Self::provider_error(format!(
                "Failed to create SOPS write-lock directory {}: {error}",
                lock_directory.display()
            ))
        })?;

        // FNV-1a gives every SecretSpec process the same stable lock name.
        // Collisions only serialize unrelated files; they cannot weaken safety.
        let mut hash = 0xcbf29ce484222325_u64;
        let identity = path.to_string_lossy();
        #[cfg(windows)]
        let identity = identity.to_lowercase();
        for byte in identity.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        let lock_path = lock_directory.join(format!("{hash:016x}.lock"));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)
            .map_err(|error| {
                Self::provider_error(format!(
                    "Failed to open SOPS write lock {}: {error}",
                    lock_path.display()
                ))
            })?;
        lock.lock().map_err(|error| {
            Self::provider_error(format!(
                "Failed to lock SOPS target {}: {error}",
                path.display()
            ))
        })?;
        Ok(lock)
    }

    fn temporary_file_for(path: &Path) -> Result<tempfile::NamedTempFile> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let suffix = path
            .extension()
            .and_then(OsStr::to_str)
            .map(|extension| format!(".{extension}"))
            .unwrap_or_default();
        tempfile::Builder::new()
            .prefix(".secretspec-sops-")
            .suffix(&suffix)
            .tempfile_in(parent)
            .map_err(|error| {
                Self::provider_error(format!(
                    "Failed to create a temporary SOPS file next to {}: {error}",
                    path.display()
                ))
            })
    }

    fn encrypt_plaintext_file(&self, temporary: &Path, logical_path: &Path) -> Result<()> {
        let mut args = self.command_preserving_file_type("encrypt");
        args.extend([
            "--filename-override".to_string(),
            logical_path.to_string_lossy().into_owned(),
            "--in-place".to_string(),
            temporary.to_string_lossy().into_owned(),
        ]);
        self.execute_sops_command(args)?;
        Ok(())
    }

    fn is_missing_metadata_error(error: &SecretSpecError) -> bool {
        error.to_string().contains("sops metadata not found")
    }

    fn set_command_args(&self, path: &Path, parts: &AddressParts<'_>) -> Result<Vec<String>> {
        let mut args = self.command_preserving_file_type("set");
        args.extend([
            "--value-stdin".to_string(),
            path.to_string_lossy().into_owned(),
            self.set_path(parts)?,
        ]);
        Ok(args)
    }

    fn set_atomically(
        &self,
        path: &Path,
        parts: &AddressParts<'_>,
        value: &SecretString,
    ) -> Result<()> {
        let mut temporary = Self::temporary_file_for(path)?;

        if path.is_file() {
            std::fs::copy(path, temporary.path()).map_err(|error| {
                Self::provider_error(format!(
                    "Failed to copy SOPS file {} for an atomic update: {error}",
                    path.display()
                ))
            })?;
            if let Err(error) = self.decrypt(temporary.path()) {
                if Self::is_missing_metadata_error(&error) {
                    self.encrypt_plaintext_file(temporary.path(), path)?;
                } else {
                    return Err(error);
                }
            }
        } else {
            let initial = match self.config.format {
                SopsFormat::Json | SopsFormat::Yaml => "{}\n",
                SopsFormat::Env | SopsFormat::Ini => "",
            };
            temporary.write_all(initial.as_bytes())?;
            temporary.flush()?;
            self.encrypt_plaintext_file(temporary.path(), path)?;
        }

        let encoded_value = serde_json::to_string(value.expose_secret()).map_err(|error| {
            Self::provider_error(format!("Failed to encode the secret value: {error}"))
        })?;
        let args = self.set_command_args(temporary.path(), parts)?;
        self.execute_sops_command_with_stdin(args, Some(encoded_value.as_bytes()))?;
        temporary.as_file().sync_all().map_err(|error| {
            Self::provider_error(format!(
                "Failed to flush updated SOPS file {}: {error}",
                path.display()
            ))
        })?;
        temporary.persist(path).map_err(|error| {
            Self::provider_error(format!(
                "Failed to atomically replace SOPS file {}: {}",
                path.display(),
                error.error
            ))
        })?;
        Ok(())
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

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        let parts = self.address_parts(addr)?;
        let path = self.resolved_write_target_path(parts.project, parts.profile)?;
        Ok(format!("{} {}", path.display(), self.set_path(&parts)?))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let parts = self.address_parts(addr)?;
        let path = self.writable_target_path(parts.project, parts.profile)?;
        let _lock = Self::acquire_write_lock(&path)?;
        self.set_atomically(&path, &parts, value)
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        let mut decrypted_files = HashMap::<PathBuf, Vec<u8>>::new();
        let mut values = HashMap::new();

        for (name, addr) in requests {
            let parts = self.address_parts(*addr)?;
            let Some(path) = self.resolve_file_path(parts.project, parts.profile)? else {
                continue;
            };
            let decrypted = match decrypted_files.entry(path) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let decrypted = self.decrypt(entry.key())?;
                    entry.insert(decrypted)
                }
            };
            if let Some(value) = self.parse_decrypted_json(decrypted, &parts)? {
                values.insert(name.to_string(), SecretString::new(value.into()));
            }
        }

        Ok(values)
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
                if path.as_os_str().is_empty() {
                    pattern.debug_template()
                } else {
                    format!("{}/{}", path.to_string_lossy(), pattern.debug_template())
                }
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
