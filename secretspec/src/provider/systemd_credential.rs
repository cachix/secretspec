use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";

/// Configuration for the read-only systemd service-credential provider.
///
/// The provider takes no URI options. systemd supplies the credential
/// directory through `$CREDENTIALS_DIRECTORY` when it starts the process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemdCredentialConfig {}

impl TryFrom<&ProviderUrl> for SystemdCredentialConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "systemd-credential" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for systemd-credential provider",
                url.scheme()
            )));
        }

        let host = url.host().filter(|host| !host.is_empty());
        let path = url.path();
        let path_item = path.trim_matches('/');
        if !url.username().is_empty()
            || url.password().is_some()
            || host.is_some()
            || !path_item.is_empty()
            || url.has_query()
        {
            let item = host
                .as_deref()
                .or((!path_item.is_empty()).then_some(path_item));
            let hint = item
                .map(|item| crate::config::ref_table_hint(None, item, None, None))
                .unwrap_or_else(|| "ref = { item = \"CREDENTIAL_NAME\" }".to_string());
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "systemd-credential:// takes no authority, path, or query: to read one \
                 specific credential, use {hint} on the secret instead"
            )));
        }

        Ok(Self {})
    }
}

/// Reads credentials systemd passed to the current service.
///
/// systemd exposes each credential as an immutable file beneath the absolute
/// directory named by `$CREDENTIALS_DIRECTORY`. Convention addresses map
/// directly to the secret key, while a native address reads the credential
/// named by its `item` coordinate. The provider is read-only because the
/// directory is owned and populated by the service manager.
pub struct SystemdCredentialProvider {
    credentials_directory: Option<PathBuf>,
}

crate::register_provider! {
    struct: SystemdCredentialProvider,
    config: SystemdCredentialConfig,
    name: "systemd-credential",
    description: "Read-only systemd service credentials (0.17+)",
    schemes: ["systemd-credential"],
    examples: ["systemd-credential://"],
}

impl SystemdCredentialProvider {
    pub fn new(_config: SystemdCredentialConfig) -> Self {
        Self {
            credentials_directory: std::env::var_os(CREDENTIALS_DIRECTORY_ENV).map(PathBuf::from),
        }
    }

    #[cfg(test)]
    fn with_directory(credentials_directory: Option<PathBuf>) -> Self {
        Self {
            credentials_directory,
        }
    }

    fn directory(&self) -> Result<&Path> {
        let directory = self.credentials_directory.as_deref().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "{CREDENTIALS_DIRECTORY_ENV} is not set; the systemd-credential provider \
                 only works inside a service that systemd started with credentials"
            ))
        })?;

        if !directory.is_absolute() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{CREDENTIALS_DIRECTORY_ENV} must contain an absolute path, got '{}'",
                directory.display()
            )));
        }

        Ok(directory)
    }

    fn credential_path(&self, name: &str) -> Result<PathBuf> {
        let mut components = Path::new(name).components();
        let is_one_normal_component = matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(component)), None) if component == OsStr::new(name)
        );
        if name.is_empty()
            || name.len() > 255
            || name.contains(['/', '\\', '\0'])
            || !is_one_normal_component
        {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "invalid systemd credential name '{name}': expected one filename of at most 255 bytes"
            )));
        }

        Ok(self.directory()?.join(name))
    }
}

impl Provider for SystemdCredentialProvider {
    /// systemd credentials form one flat namespace for the service, so project
    /// and profile do not participate in the filename.
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: key.to_string(),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let name = super::flat_item(self, addr)?;
        let path = self.credential_path(&name)?;

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "failed to inspect systemd credential '{}': {error}",
                    path.display()
                )));
            }
        };

        if !metadata.file_type().is_file() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "systemd credential '{}' is not a regular file",
                path.display()
            )));
        }

        let value = fs::read_to_string(&path).map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "failed to read systemd credential '{}': {error}",
                path.display()
            ))
        })?;
        Ok(Some(SecretString::new(value.into())))
    }

    fn set(&self, addr: Address<'_>, _value: &SecretString) -> Result<()> {
        self.check_writable(addr)
    }

    fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
        Err(SecretSpecError::ProviderOperationFailed(
            "systemd-credential provider is read-only; configure credentials with \
             LoadCredential=, LoadCredentialEncrypted=, SetCredential=, or \
             SetCredentialEncrypted= in the service unit"
                .to_string(),
        ))
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "systemd-credential".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use tempfile::TempDir;
    use url::Url;

    fn provider(directory: &Path) -> SystemdCredentialProvider {
        SystemdCredentialProvider::with_directory(Some(directory.to_path_buf()))
    }

    #[test]
    fn convention_address_reads_exact_value_without_trimming() {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join("API_TOKEN"), "line one\nline two\n").unwrap();

        let value = provider(directory.path())
            .get(Address::convention("project", "production", "API_TOKEN"))
            .unwrap()
            .unwrap();

        assert_eq!(value.expose_secret(), "line one\nline two\n");
    }

    #[test]
    fn native_address_reads_the_item_name() {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join("op-token"), "ops_example").unwrap();
        let address = crate::config::NativeAddress {
            item: "op-token".to_string(),
            ..Default::default()
        };

        let value = provider(directory.path())
            .get(Address::Native(&address))
            .unwrap()
            .unwrap();

        assert_eq!(value.expose_secret(), "ops_example");
    }

    #[test]
    fn missing_credential_is_absent() {
        let directory = TempDir::new().unwrap();
        assert!(
            provider(directory.path())
                .get(Address::convention("project", "default", "MISSING"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn missing_directory_environment_is_actionable() {
        let error = SystemdCredentialProvider::with_directory(None)
            .get(Address::convention("project", "default", "TOKEN"))
            .unwrap_err();
        assert!(
            error.to_string().contains(CREDENTIALS_DIRECTORY_ENV),
            "{error}"
        );
        assert!(error.to_string().contains("systemd"), "{error}");
    }

    #[test]
    fn relative_directory_is_rejected() {
        let error =
            SystemdCredentialProvider::with_directory(Some(PathBuf::from("relative/credentials")))
                .get(Address::convention("project", "default", "TOKEN"))
                .unwrap_err();
        assert!(error.to_string().contains("absolute path"), "{error}");
    }

    #[test]
    fn traversal_and_nested_paths_are_rejected() {
        let directory = TempDir::new().unwrap();
        for name in [
            "../secret",
            "nested/secret",
            r"nested\secret",
            ".",
            "..",
            "",
        ] {
            let address = crate::config::NativeAddress {
                item: name.to_string(),
                ..Default::default()
            };
            let error = provider(directory.path())
                .get(Address::Native(&address))
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("invalid systemd credential name"),
                "{name:?}: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("target");
        fs::write(&target, "must not be read").unwrap();
        symlink(&target, directory.path().join("TOKEN")).unwrap();

        let error = provider(directory.path())
            .get(Address::convention("project", "default", "TOKEN"))
            .unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[test]
    fn binary_credential_is_rejected_by_text_provider_api() {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join("TOKEN"), [0xff, 0xfe]).unwrap();

        let error = provider(directory.path())
            .get(Address::convention("project", "default", "TOKEN"))
            .unwrap_err();
        assert!(error.to_string().contains("failed to read"), "{error}");
        assert!(error.to_string().contains("UTF-8"), "{error}");
    }

    #[test]
    fn unsupported_native_coordinate_is_rejected() {
        let directory = TempDir::new().unwrap();
        let address = crate::config::NativeAddress {
            item: "TOKEN".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        };

        let error = provider(directory.path())
            .get(Address::Native(&address))
            .unwrap_err();
        assert!(error.to_string().contains("`field`"), "{error}");
    }

    #[test]
    fn provider_is_read_only() {
        let directory = TempDir::new().unwrap();
        let provider = provider(directory.path());
        let address = Address::convention("project", "default", "TOKEN");
        let check_error = provider.check_writable(address).unwrap_err().to_string();
        let set_error = provider
            .set(address, &SecretString::new("value".into()))
            .unwrap_err()
            .to_string();

        assert_eq!(check_error, set_error);
        assert!(check_error.contains("read-only"), "{check_error}");
    }

    #[test]
    fn uri_must_not_select_a_credential() {
        for uri in [
            "systemd-credential://TOKEN",
            "systemd-credential:///TOKEN",
            "systemd-credential://?name=TOKEN",
        ] {
            let error =
                SystemdCredentialConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap()))
                    .unwrap_err();
            assert!(
                error.to_string().contains("takes no authority"),
                "{uri}: {error}"
            );
        }
    }
}
