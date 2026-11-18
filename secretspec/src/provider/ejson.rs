//! Provider that reads secrets from an EJSON file.
//!
//! The encrypted file path comes from the provider URI. The matching private
//! key is an injected `private_key` provider credential, so its source can be
//! any existing SecretSpec provider and native reference. Reads invoke the
//! official `ejson` CLI with the key on stdin, parse its JSON output, and select
//! one value with an RFC 6901 JSON Pointer.
//!
//! # URI format
//!
//! - `ejson:config/secrets.production.ejson`
//! - `ejson:///absolute/path/secrets.ejson`
//!
//! # Private key
//!
//! Configure the `private_key` provider credential on an alias. Its provider
//! reference names the stored private key and may pin an exact version. The key
//! never belongs in the URI or environment.

use super::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use secrecy::zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(all(test, unix))]
use std::process::Stdio;
use std::time::Duration;
#[cfg(all(test, unix))]
use std::time::Instant;

#[cfg(unix)]
use std::os::{fd::AsRawFd, fd::FromRawFd, unix::process::CommandExt};

const PRIVATE_KEY: &str = "private_key";
const MAX_EJSON_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_CLI_TIMEOUT: Duration = Duration::from_secs(30);

/// URI structural delimiters and path characters that must round-trip as data.
/// Path separators stay literal, while Windows separators and drive colons are
/// encoded into the opaque `ejson:` path form.
const EJSON_PATH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'%')
    .add(b'@')
    .add(b'#')
    .add(b'?')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b']')
    .add(b'|')
    .add(b'^')
    .add(b'\\')
    .add(b':');

fn provider_err(message: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.into())
}

/// An opened ciphertext snapshot. On Unix it is anonymous and inherited by the
/// child through a descriptor path; other platforms use a private named file.
struct EncryptedSnapshot {
    #[cfg(unix)]
    file: File,
    #[cfg(not(unix))]
    file: tempfile::NamedTempFile,
}

impl EncryptedSnapshot {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let file = tempfile::tempfile()?;
            let fd = file.as_raw_fd();
            if fd >= 3 {
                return Ok(Self { file });
            }
            // Keep the inherited snapshot out of stdin/stdout/stderr slots,
            // which `Command` replaces while constructing the child.
            // SAFETY: `fd` belongs to `file`; F_DUPFD_CLOEXEC returns a new
            // independently owned descriptor at or above the requested floor.
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `duplicate` is a fresh owned descriptor returned above.
            let file = unsafe { File::from_raw_fd(duplicate) };
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        {
            tempfile::NamedTempFile::new().map(|file| Self { file })
        }
    }

    fn file_mut(&mut self) -> &mut File {
        #[cfg(unix)]
        {
            &mut self.file
        }
        #[cfg(not(unix))]
        {
            self.file.as_file_mut()
        }
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        self.file_mut().seek(SeekFrom::Start(0)).map(|_| ())
    }

    #[cfg(unix)]
    fn command_path(&self) -> PathBuf {
        let fd = self.file.as_raw_fd();
        if cfg!(target_os = "linux") {
            PathBuf::from(format!("/proc/self/fd/{fd}"))
        } else {
            PathBuf::from(format!("/dev/fd/{fd}"))
        }
    }

    #[cfg(not(unix))]
    fn command_path(&self) -> PathBuf {
        self.file.path().to_path_buf()
    }

    #[cfg(unix)]
    fn configure_command(&self, command: &mut Command) {
        let fd = self.file.as_raw_fd();
        // SAFETY: `pre_exec` runs after fork and before exec. The closure uses
        // only async-signal-safe `fcntl` calls and changes only the child's
        // descriptor table, leaving the parent's close-on-exec flag unchanged.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[cfg(not(unix))]
    fn configure_command(&self, _command: &mut Command) {}
}

/// Configuration for one encrypted EJSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EjsonConfig {
    /// Path to the encrypted EJSON document.
    pub path: PathBuf,
}

impl Default for EjsonConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("secrets.ejson"),
        }
    }
}

impl TryFrom<&ProviderUrl> for EjsonConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "ejson" {
            return Err(provider_err(format!(
                "Invalid scheme '{}' for ejson provider",
                url.scheme()
            )));
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.has_port()
            || url.has_query()
            || url.has_fragment()
        {
            return Err(provider_err(
                "ejson provider URIs take only an encrypted file path; user information, ports, query options, and fragments are not supported",
            ));
        }

        let path_str = url.path();
        #[cfg(windows)]
        let path_str = if path_str.as_bytes().first() == Some(&b'/')
            && path_str.as_bytes().get(2) == Some(&b':')
            && path_str
                .as_bytes()
                .get(1)
                .is_some_and(u8::is_ascii_alphabetic)
        {
            path_str[1..].to_string()
        } else {
            path_str
        };
        let path = if !path_str.is_empty() && path_str != "/" {
            match url.host() {
                Some(host) => PathBuf::from(format!("{}{}", host, path_str)),
                None => PathBuf::from(path_str),
            }
        } else if let Some(host) = url.host() {
            PathBuf::from(host)
        } else {
            PathBuf::from("secrets.ejson")
        };

        Ok(Self { path })
    }
}

/// Reads string values from one EJSON document.
pub struct EjsonProvider {
    config: EjsonConfig,
    credentials: ProviderCredentials,
    cli_binary_path: PathBuf,
    cli_timeout: Duration,
    request: Option<crate::request::RequestContext>,
}

crate::register_provider! {
    struct: EjsonProvider,
    config: EjsonConfig,
    metadata: &super::catalog::EJSON,
}

impl EjsonProvider {
    pub fn new(config: EjsonConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            cli_binary_path: PathBuf::from("ejson"),
            cli_timeout: DEFAULT_CLI_TIMEOUT,
            request: None,
        }
    }

    #[cfg(test)]
    fn with_cli_binary(mut self, path: PathBuf) -> Self {
        self.cli_binary_path = path;
        self
    }

    #[cfg(test)]
    fn with_cli_timeout(mut self, timeout: Duration) -> Self {
        self.cli_timeout = timeout;
        self
    }

    fn pointer_segment(value: &str) -> String {
        value.replace('~', "~0").replace('/', "~1")
    }

    fn validate_pointer(pointer: &str) -> Result<()> {
        if !pointer.is_empty() && !pointer.starts_with('/') {
            return Err(provider_err(format!(
                "invalid ejson item '{pointer}': expected an RFC 6901 JSON Pointer beginning with '/'"
            )));
        }

        let bytes = pointer.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'~' {
                let escape = bytes.get(index + 1).copied();
                if !matches!(escape, Some(b'0' | b'1')) {
                    return Err(provider_err(format!(
                        "invalid ejson item '{pointer}': JSON Pointer '~' escapes must be '~0' or '~1'"
                    )));
                }
                index += 2;
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn pointer<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
        match self.resolve_coords(addr)? {
            Cow::Borrowed(native) => {
                Self::validate_pointer(&native.item)?;
                Ok(Cow::Borrowed(native.item.as_str()))
            }
            Cow::Owned(native) => {
                Self::validate_pointer(&native.item)?;
                Ok(Cow::Owned(native.item))
            }
        }
    }

    #[cfg(unix)]
    fn open_source(path: &Path) -> std::io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;

        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    #[cfg(not(unix))]
    fn open_source(path: &Path) -> std::io::Result<File> {
        OpenOptions::new().read(true).open(path)
    }

    #[cfg(unix)]
    fn is_symlink_open_error(error: &std::io::Error) -> bool {
        error.raw_os_error() == Some(libc::ELOOP)
    }

    #[cfg(not(unix))]
    fn is_symlink_open_error(_error: &std::io::Error) -> bool {
        false
    }

    /// Opens the configured source and copies its ciphertext into a private
    /// temporary file. The CLI receives only this immutable snapshot, so a
    /// replacement of the configured pathname cannot change the decrypted data.
    fn encrypted_snapshot(&self) -> Result<Option<EncryptedSnapshot>> {
        if let Some(request) = &self.request {
            request.checkpoint()?;
            match std::fs::symlink_metadata(&self.config.path) {
                Ok(metadata) if !metadata.is_file() => {
                    return Err(crate::request::unsupported("non-regular EJSON source"));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
                _ => {}
            }
            request.checkpoint()?;
        }
        let source = match Self::open_source(&self.config.path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) if Self::is_symlink_open_error(&error) => {
                return Err(provider_err(format!(
                    "ejson file '{}' is a symbolic link; symbolic links are not followed",
                    self.config.path.display()
                )));
            }
            Err(error) => {
                return Err(provider_err(format!(
                    "failed to open ejson file '{}': {error}",
                    self.config.path.display()
                )));
            }
        };
        let metadata = source.metadata().map_err(|error| {
            provider_err(format!(
                "failed to inspect opened ejson file '{}': {error}",
                self.config.path.display()
            ))
        })?;
        if !metadata.is_file() {
            if self.request.is_some() {
                return Err(crate::request::unsupported("non-regular EJSON source"));
            }
            return Err(provider_err(format!(
                "ejson path '{}' is not a regular file",
                self.config.path.display()
            )));
        }
        if metadata.len() > MAX_EJSON_BYTES {
            return Err(provider_err(format!(
                "ejson file '{}' is {} bytes; the maximum supported size is {} bytes",
                self.config.path.display(),
                metadata.len(),
                MAX_EJSON_BYTES
            )));
        }

        let mut snapshot = EncryptedSnapshot::new().map_err(|error| {
            provider_err(format!(
                "failed to create a temporary EJSON ciphertext snapshot: {error}"
            ))
        })?;
        let mut limited = source.take(MAX_EJSON_BYTES + 1);
        let copy_error = |error| {
            provider_err(format!(
                "failed to copy EJSON ciphertext into a temporary snapshot: {error}"
            ))
        };
        let copied = if let Some(request) = &self.request {
            let mut copied = 0;
            let mut chunk = [0u8; 16 * 1024];
            loop {
                request.checkpoint()?;
                let count = match limited.read(&mut chunk) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => result.map_err(copy_error)?,
                };
                if count == 0 {
                    break;
                }
                request.checkpoint()?;
                snapshot
                    .file_mut()
                    .write_all(&chunk[..count])
                    .map_err(copy_error)?;
                copied += count as u64;
            }
            copied
        } else {
            std::io::copy(&mut limited, snapshot.file_mut()).map_err(copy_error)?
        };
        if copied > MAX_EJSON_BYTES {
            return Err(provider_err(format!(
                "ejson file '{}' exceeds the maximum supported size of {MAX_EJSON_BYTES} bytes",
                self.config.path.display()
            )));
        }
        snapshot.file_mut().flush().map_err(|error| {
            provider_err(format!(
                "failed to flush the temporary EJSON ciphertext snapshot: {error}"
            ))
        })?;
        snapshot.rewind().map_err(|error| {
            provider_err(format!(
                "failed to rewind the temporary EJSON ciphertext snapshot: {error}"
            ))
        })?;
        Ok(Some(snapshot))
    }

    fn private_key(&self) -> Result<Zeroizing<String>> {
        let value = self.credentials.get(PRIVATE_KEY).ok_or_else(|| {
            provider_err(
                "No EJSON private key configured. Add the `private_key` provider credential to this provider alias.",
            )
        })?;
        let value = super::require_utf8("ejson", value)?.trim();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(provider_err(
                "Invalid EJSON `private_key` credential: expected exactly 64 hexadecimal characters.",
            ));
        }
        Ok(Zeroizing::new(value.to_string()))
    }

    /// Decrypt once through the shared runner so legacy and cancellable reads
    /// both join their child and pipe workers before returning.
    fn decrypt(&self) -> Result<Option<serde_json::Value>> {
        let request = self.request.as_ref();
        let checkpoint = || request.map_or(Ok(()), crate::request::RequestContext::checkpoint);
        checkpoint()?;
        let Some(snapshot) = self.encrypted_snapshot()? else {
            return Ok(None);
        };
        checkpoint()?;
        let mut input = Zeroizing::new(self.private_key()?.as_bytes().to_vec());
        input.extend_from_slice(if cfg!(windows) { b"\r\n" } else { b"\n" });
        let mut command = Command::new(&self.cli_binary_path);
        command
            .arg("decrypt")
            .arg("--key-from-stdin")
            .arg(snapshot.command_path());
        snapshot.configure_command(&mut command);
        let output = crate::command::output(
            &mut command,
            Some(input),
            MAX_EJSON_BYTES as usize,
            Some(self.cli_timeout),
            request,
            false,
        )
        .map_err(|error| match error {
            SecretSpecError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
                provider_err(
                    "The 'ejson' CLI is not installed. Install it through your package manager.",
                )
            }
            error if error.is_resolution_terminal() => error,
            error => provider_err(format!("EJSON CLI failed: {error}")),
        })?;
        if !output.status.success() {
            return Err(provider_err(
                "EJSON decryption failed. Check the encrypted file, EJSON CLI compatibility, and `private_key` credential.",
            ));
        }
        checkpoint()?;
        serde_json::from_slice(output.stdout.expose_secret())
            .map(Some)
            .map_err(|_| provider_err("failed to parse JSON emitted by EJSON"))
    }

    fn select(document: &serde_json::Value, pointer: &str) -> Result<Option<SecretBytes>> {
        match document.pointer(pointer) {
            None => Ok(None),
            Some(serde_json::Value::String(value)) => {
                Ok(Some(SecretBytes::from_utf8(value.clone())))
            }
            Some(_) => Err(provider_err(format!(
                "ejson item '{pointer}' does not select a string value"
            ))),
        }
    }
}

impl Provider for EjsonProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: format!(
                "/{}/{}/{}",
                Self::pointer_segment(project),
                Self::pointer_segment(profile),
                Self::pointer_segment(key)
            ),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let path = self.config.path.display().to_string();
        format!(
            "ejson:{}",
            percent_encode(path.as_bytes(), EJSON_PATH_ENCODE_SET)
        )
    }

    fn with_base_dir(&mut self, base_dir: &Path) {
        if self.config.path.is_relative() {
            self.config.path = base_dir.join(&self.config.path);
        }
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn physical_store_path(&self) -> Option<&Path> {
        Some(&self.config.path)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let pointer = self.pointer(addr)?;
        let Some(document) = self.decrypt()? else {
            return Ok(None);
        };
        Self::select(&document, &pointer)
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        let pointers = requests
            .iter()
            .map(|(name, addr)| Ok((name.to_string(), self.pointer(*addr)?.into_owned())))
            .collect::<Result<Vec<_>>>()?;
        if pointers.is_empty() {
            return Ok(HashMap::new());
        }
        let Some(document) = self.decrypt()? else {
            return Ok(HashMap::new());
        };

        let mut values = HashMap::new();
        for (name, pointer) in pointers {
            if let Some(value) = Self::select(&document, &pointer)? {
                values.insert(name, value);
            }
        }
        Ok(values)
    }

    fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
        Err(provider_err(
            "the ejson provider is read-only; edit and encrypt the EJSON file through its owning workflow",
        ))
    }

    fn set(&self, addr: Address<'_>, _value: &SecretBytes) -> Result<()> {
        self.check_writable(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use url::Url;

    const TEST_PRIVATE_KEY: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn config_from(uri: &str) -> EjsonConfig {
        let url = ProviderUrl::new(Url::parse(uri).unwrap());
        (&url).try_into().unwrap()
    }

    #[test]
    fn registration_advertises_private_key_credential() {
        assert_eq!(
            crate::provider::credential_names_for_spec("ejson:secrets.ejson").unwrap(),
            &[PRIVATE_KEY]
        );
    }

    #[test]
    fn parses_relative_absolute_and_default_paths() {
        assert_eq!(
            config_from("ejson:config/secrets.ejson").path,
            Path::new("config/secrets.ejson")
        );
        assert_eq!(
            config_from("ejson://config/secrets.ejson").path,
            Path::new("config/secrets.ejson")
        );
        assert_eq!(
            config_from("ejson:///var/run/secrets.ejson").path,
            Path::new("/var/run/secrets.ejson")
        );
        assert_eq!(config_from("ejson:").path, Path::new("secrets.ejson"));
    }

    #[test]
    fn rejects_non_path_uri_components() {
        for spec in [
            "ejson:config/secrets.ejson?private_key=nope",
            "ejson:secrets#prod.ejson",
            "ejson:dir:123/file.ejson",
        ] {
            let Err(error) = Box::<dyn Provider>::try_from(spec) else {
                panic!("{spec} unexpectedly built an EJSON provider");
            };
            assert!(
                error.to_string().contains("only an encrypted file path"),
                "{spec}: {error}"
            );
        }
    }

    #[test]
    fn convention_address_uses_escaped_json_pointer() {
        let provider = EjsonProvider::new(EjsonConfig::default());
        let address = provider
            .convention_address("my/app", "prod~blue", "API/TOKEN")
            .unwrap();
        assert_eq!(address.item, "/my~1app/prod~0blue/API~1TOKEN");
    }

    #[test]
    fn uri_round_trips_structural_path_characters() {
        for path in [
            "config/secrets #1?.ejson",
            "config/100% secrets.ejson",
            "config/name@host.ejson",
            r"C:\\Users\\app\\secrets.ejson",
        ] {
            let provider = EjsonProvider::new(EjsonConfig {
                path: PathBuf::from(path),
            });
            let reparsed = Box::<dyn Provider>::try_from(provider.uri().as_str()).unwrap();
            assert_eq!(reparsed.physical_store_path(), Some(Path::new(path)));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_round_trip_through_provider_factory() {
        for spec in [
            r"ejson://C:\Users\app\secrets.ejson",
            "ejson:///C:/Users/app/secrets.ejson",
        ] {
            let provider = Box::<dyn Provider>::try_from(spec).unwrap();
            assert_eq!(provider.name(), "ejson");
            assert_eq!(
                provider.physical_store_path(),
                Some(Path::new(r"C:\Users\app\secrets.ejson"))
            );
            let reparsed = Box::<dyn Provider>::try_from(provider.uri().as_str()).unwrap();
            assert_eq!(
                reparsed.physical_store_path(),
                provider.physical_store_path()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_decrypts_through_a_named_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson.cmd");
        fs::write(
            &cli,
            format!(
                "@echo off\r\nset /p private_key=\r\nif not \"%private_key%\" == \"{TEST_PRIVATE_KEY}\" exit /b 3\r\nif not exist \"%~3\" exit /b 4\r\necho {{\"TOKEN\":\"value\"}}\r\n"
            ),
        )
        .unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted })
            .with_cli_binary(cli)
            .with_cli_timeout(Duration::from_secs(5));
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let value = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap()
            .unwrap();
        assert_eq!(value.expose_secret(), b"value");
    }

    #[test]
    fn validates_json_pointer_escapes() {
        for valid in ["", "/API_KEY", "/nested/key", "/a~0b/c~1d"] {
            EjsonProvider::validate_pointer(valid).unwrap();
        }
        for invalid in ["API_KEY", "/bad~", "/bad~2escape"] {
            assert!(
                EjsonProvider::validate_pointer(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn rebases_relative_file_path() {
        let mut provider = EjsonProvider::new(EjsonConfig {
            path: PathBuf::from("config/secrets.ejson"),
        });
        provider.with_base_dir(Path::new("/project"));
        assert_eq!(
            provider.config.path,
            Path::new("/project/config/secrets.ejson")
        );
    }

    #[test]
    fn missing_file_is_an_absent_value_without_key_access() {
        let directory = tempfile::tempdir().unwrap();
        let provider = EjsonProvider::new(EjsonConfig {
            path: directory.path().join("missing.ejson"),
        });
        assert!(
            provider
                .get(Address::convention("app", "default", "MISSING"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn read_only_error_is_consistent() {
        let provider = EjsonProvider::new(EjsonConfig::default());
        let addr = Address::convention("app", "default", "TOKEN");
        let preflight = provider.check_writable(addr).unwrap_err().to_string();
        let write = provider
            .set(addr, &SecretBytes::from_utf8("value"))
            .unwrap_err()
            .to_string();
        assert_eq!(preflight, write);
        assert!(write.contains("read-only"));
    }

    #[test]
    fn native_address_rejects_unsupported_coordinates() {
        let provider = EjsonProvider::new(EjsonConfig::default());
        let address = NativeAddress {
            item: "/TOKEN".into(),
            field: Some("value".into()),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&address)).unwrap_err();
        assert!(error.to_string().contains("`field`"));
    }

    #[test]
    fn selects_only_string_values() {
        let document = serde_json::json!({
            "string": "value",
            "number": 42,
        });
        assert_eq!(
            EjsonProvider::select(&document, "/string")
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"value"
        );
        assert!(
            EjsonProvider::select(&document, "/missing")
                .unwrap()
                .is_none()
        );
        assert!(EjsonProvider::select(&document, "/number").is_err());
        assert!(EjsonProvider::select(&document, "").is_err());
    }

    #[cfg(unix)]
    fn fake_cli(directory: &Path, output: &str, count_file: &Path) -> PathBuf {
        let script = directory.join("ejson");
        let escaped_output = output.replace('\\', "\\\\").replace('\'', "'\\''");
        crate::fake_executable::install(
            &script,
            &format!(
                "#!/bin/sh\nset -eu\n[ \"$1\" = decrypt ]\n[ \"$2\" = --key-from-stdin ]\n[ -f \"$3\" ]\nkey=$(cat)\n[ \"$key\" = '{}' ]\nprintf x >> '{}'\nprintf '%s' '{}'\n",
                TEST_PRIVATE_KEY,
                count_file.display(),
                escaped_output,
            ),
        );
        script
    }

    #[cfg(unix)]
    #[test]
    fn decrypts_when_parent_stdio_is_closed() {
        const CHILD_ENV: &str = "SECRETSPEC_EJSON_CLOSED_STDIO_CHILD";
        const TEST_NAME: &str = "provider::ejson::tests::decrypts_when_parent_stdio_is_closed";

        if std::env::var_os(CHILD_ENV).is_some() {
            let directory = tempfile::tempdir().unwrap();
            let encrypted = directory.path().join("secrets.ejson");
            let count = directory.path().join("count");
            fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
            let cli = fake_cli(directory.path(), r#"{"TOKEN":"value"}"#, &count);
            let mut provider =
                EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
            provider.credentials.insert(
                PRIVATE_KEY.to_string(),
                SecretBytes::from_utf8(TEST_PRIVATE_KEY),
            );
            assert_eq!(
                provider
                    .get(Address::Native(&NativeAddress {
                        item: "/TOKEN".into(),
                        ..Default::default()
                    }))
                    .unwrap()
                    .unwrap()
                    .expose_secret(),
                b"value"
            );
            return;
        }

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(TEST_NAME)
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the closure runs in the child after fork and uses only the
        // async-signal-safe close operation. The parent descriptors are intact.
        unsafe {
            command.pre_exec(|| {
                libc::close(libc::STDIN_FILENO);
                libc::close(libc::STDOUT_FILENO);
                libc::close(libc::STDERR_FILENO);
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());
    }

    #[cfg(unix)]
    #[test]
    fn decrypts_with_a_low_descriptor_limit() {
        const CHILD_ENV: &str = "SECRETSPEC_EJSON_LOW_NOFILE_CHILD";
        const TEST_NAME: &str = "provider::ejson::tests::decrypts_with_a_low_descriptor_limit";

        if std::env::var_os(CHILD_ENV).is_some() {
            let directory = tempfile::tempdir().unwrap();
            let encrypted = directory.path().join("secrets.ejson");
            let count = directory.path().join("count");
            fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
            let cli = fake_cli(directory.path(), r#"{"TOKEN":"value"}"#, &count);
            let mut provider =
                EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
            provider.credentials.insert(
                PRIVATE_KEY.to_string(),
                SecretBytes::from_utf8(TEST_PRIVATE_KEY),
            );
            assert_eq!(
                provider
                    .get(Address::Native(&NativeAddress {
                        item: "/TOKEN".into(),
                        ..Default::default()
                    }))
                    .unwrap()
                    .unwrap()
                    .expose_secret(),
                b"value"
            );
            return;
        }

        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg("ulimit -n 64; exec \"$1\" --exact \"$2\" --nocapture")
            .arg("sh")
            .arg(std::env::current_exe().unwrap())
            .arg(TEST_NAME)
            .env(CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(unix)]
    #[test]
    fn batch_decrypts_once_and_selects_requested_pointers() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(
            directory.path(),
            r#"{"app":{"production":{"API_KEY":"one","OTHER":"two"}}}"#,
            &count,
        );
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let results = provider
            .get_many(&[
                (
                    "API_KEY",
                    Address::convention("app", "production", "API_KEY"),
                ),
                ("OTHER", Address::convention("app", "production", "OTHER")),
                (
                    "MISSING",
                    Address::convention("app", "production", "MISSING"),
                ),
            ])
            .unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results["API_KEY"].expose_secret(), b"one");
        assert_eq!(results["OTHER"].expose_secret(), b"two");
        assert_eq!(fs::read_to_string(count).unwrap(), "x");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_decryption_keeps_snapshot_stdin_and_batch_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(
            directory.path(),
            r#"{"app":{"production":{"A":"one","B":"two"}}}"#,
            &count,
        );
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );
        let values = crate::request::run(&crate::CancellationHandle::new(), move |request| {
            provider.request = Some(request);
            provider.get_many(&[
                ("A", Address::convention("app", "production", "A")),
                ("B", Address::convention("app", "production", "B")),
            ])
        })
        .await
        .unwrap();
        assert_eq!(values["A"].expose_secret(), b"one");
        assert_eq!(values["B"].expose_secret(), b"two");
        assert_eq!(fs::read_to_string(count).unwrap(), "x");
    }

    #[test]
    fn empty_batch_needs_no_file_or_private_key() {
        let provider = EjsonProvider::new(EjsonConfig {
            path: PathBuf::from("does-not-exist.ejson"),
        });
        assert!(provider.get_many(&[]).unwrap().is_empty());
    }

    #[test]
    fn private_key_requires_exact_hex_and_trims_outer_whitespace() {
        let mut provider = EjsonProvider::new(EjsonConfig::default());
        for invalid in [
            "1".repeat(63),
            "1".repeat(65),
            "g".repeat(64),
            "１".repeat(64),
        ] {
            provider
                .credentials
                .insert(PRIVATE_KEY.to_string(), SecretBytes::from_utf8(invalid));
            assert!(provider.private_key().is_err());
        }

        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(format!("  {TEST_PRIVATE_KEY}\n")),
        );
        assert_eq!(provider.private_key().unwrap().as_str(), TEST_PRIVATE_KEY);
    }

    #[cfg(unix)]
    #[test]
    fn missing_private_key_fails_before_cli_receives_input() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(directory.path(), r#"{"TOKEN":"value"}"#, &count);
        let provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err();
        assert!(error.to_string().contains("private_key"));
        assert!(!count.exists());
    }

    #[cfg(unix)]
    #[test]
    fn invalid_or_oversized_private_key_fails_before_cli_starts() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(directory.path(), r#"{"TOKEN":"value"}"#, &count);
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8("x".repeat(1024 * 1024)),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("64 hexadecimal"));
        assert!(!count.exists());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_source_is_rejected_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("secrets.ejson");
        let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(status.success());
        let provider = EjsonProvider::new(EjsonConfig { path: fifo });

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn cli_failure_is_generic_and_does_not_expose_key() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        crate::fake_executable::install(&cli, "#!/bin/sh\nkey=$(cat)\necho \"$key\" >&2\nexit 1\n");
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("EJSON CLI compatibility"));
        assert!(!error.contains(TEST_PRIVATE_KEY));
        assert!(!error.contains("unknown flag"));
    }

    #[cfg(unix)]
    #[test]
    fn hung_cli_that_never_reads_stdin_is_stopped_at_timeout() {
        use std::time::Instant;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        crate::fake_executable::install(&cli, "#!/bin/sh\nsleep 60\n");
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted })
            .with_cli_binary(cli)
            .with_cli_timeout(Duration::from_millis(500));
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let started = Instant::now();
        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn hung_cli_and_descendants_are_stopped_at_timeout() {
        use std::time::Instant;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        let descendant_pid = directory.path().join("descendant-pid");
        crate::fake_executable::install(
            &cli,
            &format!(
                "#!/bin/sh\nsleep 60 &\necho $! > '{}'\ncat >/dev/null\nwait\n",
                descendant_pid.display()
            ),
        );
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted })
            .with_cli_binary(cli)
            .with_cli_timeout(Duration::from_secs(2));
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let started = Instant::now();
        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(4));

        let pid: libc::pid_t = fs::read_to_string(&descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            // SAFETY: signal 0 only probes a PID recorded by the test child.
            if unsafe { libc::kill(pid, 0) } == -1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: same non-mutating existence probe as above.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }

    #[cfg(unix)]
    #[test]
    fn exited_cli_stops_descendant_holding_stdout_without_waiting_for_deadline() {
        use std::time::Instant;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        let descendant_pid = directory.path().join("descendant-pid");
        crate::fake_executable::install(
            &cli,
            &format!(
                "#!/bin/sh\ncat >/dev/null\nsleep 60 &\necho $! > '{}'\nexit 0\n",
                descendant_pid.display()
            ),
        );
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted })
            .with_cli_binary(cli)
            .with_cli_timeout(Duration::from_secs(5));
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let started = Instant::now();
        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to parse JSON"));
        assert!(started.elapsed() < Duration::from_secs(2));

        let pid: libc::pid_t = fs::read_to_string(&descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            // SAFETY: signal 0 only probes a PID recorded by the test child.
            if unsafe { libc::kill(pid, 0) } == -1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: same non-mutating existence probe as above.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_oversized_encrypted_files_before_key_access() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("oversized.ejson");
        File::create(&encrypted)
            .unwrap()
            .set_len(MAX_EJSON_BYTES + 1)
            .unwrap();
        let provider = EjsonProvider::new(EjsonConfig { path: encrypted });

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("maximum supported size"));
        assert!(!error.contains("private_key"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_oversized_decrypted_output() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        crate::fake_executable::install(
            &cli,
            "#!/bin/sh\ncat >/dev/null\nhead -c 16777217 /dev/zero\n",
        );
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("output limit"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_malformed_successful_cli_output() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(directory.path(), "not-json", &count);
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to parse JSON emitted by EJSON"));
    }

    #[cfg(unix)]
    #[test]
    fn malformed_output_stops_descendants_that_closed_stdout() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let descendant_pid = directory.path().join("descendant-pid");
        let cli = directory.path().join("ejson");
        crate::fake_executable::install(
            &cli,
            &format!(
                "#!/bin/sh\nsleep 60 </dev/null >/dev/null 2>&1 &\necho $! > '{}'\ncat >/dev/null\nprintf not-json\n",
                descendant_pid.display()
            ),
        );
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to parse JSON"));

        let pid: libc::pid_t = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            // SAFETY: signal 0 only probes a PID recorded by the test child.
            if unsafe { libc::kill(pid, 0) } == -1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: same non-mutating existence probe as above.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }

    #[cfg(unix)]
    #[test]
    fn configured_file_replacement_does_not_change_open_snapshot() {
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, r#"{"TOKEN":"original"}"#).unwrap();
        let ready = directory.path().join("ready");
        let proceed = directory.path().join("proceed");
        let cli = directory.path().join("ejson");
        crate::fake_executable::install(
            &cli,
            &format!(
                "#!/bin/sh\nset -eu\ncat >/dev/null\ntouch '{}'\nwhile [ ! -f '{}' ]; do sleep 0.01; done\ncat \"$3\"\n",
                ready.display(),
                proceed.display(),
            ),
        );
        let mut provider = EjsonProvider::new(EjsonConfig {
            path: encrypted.clone(),
        })
        .with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::from_utf8(TEST_PRIVATE_KEY),
        );

        let reader = std::thread::spawn(move || {
            provider.get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "fake EJSON CLI did not start");
        fs::write(&encrypted, r#"{"TOKEN":"replacement"}"#).unwrap();
        fs::write(&proceed, "go").unwrap();

        let value = reader.join().unwrap().unwrap().unwrap();
        assert_eq!(value.expose_secret(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_files() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.ejson");
        let link = directory.path().join("link.ejson");
        fs::write(&target, "{}").unwrap();
        symlink(&target, &link).unwrap();
        let provider = EjsonProvider::new(EjsonConfig { path: link });

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err();
        assert!(error.to_string().contains("symbolic link"));
    }
}

super::managed_read::register!(["ejson"], |url, credentials, request| {
    let mut provider = EjsonProvider::new(EjsonConfig::try_from(url)?);
    Provider::with_credentials(&mut provider, credentials);
    provider.request = Some(request.clone());
    Ok(Box::new(provider))
});
