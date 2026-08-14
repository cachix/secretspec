use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use super::Address;
use super::Provider;
use super::ProviderUrl;
use crate::MonosecretError;
use crate::Result;
use crate::config::NativeAddress;
use crate::config::expand_tilde;

pub(crate) const MISSING_DIRECTORY_ERROR: &str = "file provider requires an explicit relative or absolute directory path (for example, 'file:./.secrets' or 'file:///run/secrets')";

/// Configuration for the plaintext file provider.
///
/// Each secret is stored in its own UTF-8 file beneath `directory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
	/// Root directory containing the provider's files.
	pub directory: PathBuf,
}

impl TryFrom<&ProviderUrl> for FileConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "file" {
			return Err(MonosecretError::ProviderOperationFailed(format!(
				"Invalid scheme '{}' for file provider",
				url.scheme()
			)));
		}

		if !url.username().is_empty() || url.password().is_some() || url.has_query() {
			return Err(MonosecretError::ProviderOperationFailed(
                "file provider URIs take only a directory path; user information and query options are not supported"
                    .to_string(),
            ));
		}

		let path = url.path();
		#[cfg(windows)]
		let path = if path.as_bytes().first() == Some(&b'/')
			&& path.as_bytes().get(2) == Some(&b':')
			&& path.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic)
		{
			path[1..].to_string()
		} else {
			path
		};
		let directory = if !path.is_empty() {
			if let Some(host) = url.host() {
				if host == "." {
					PathBuf::from(path.trim_start_matches('/'))
				} else {
					PathBuf::from(format!("{host}{path}"))
				}
			} else {
				PathBuf::from(path)
			}
		} else if let Some(host) = url.host() {
			PathBuf::from(host)
		} else {
			return Err(MonosecretError::ProviderOperationFailed(
				MISSING_DIRECTORY_ERROR.to_string(),
			));
		};

		Ok(Self { directory })
	}
}

/// Stores each secret as one plaintext file in a local directory tree.
///
/// Convention addresses are isolated by project and profile at
/// `{project}/{profile}/{key}`. A native address uses `item` as a relative path
/// beneath the configured directory, which supports existing file-mounted
/// secrets without allowing the address to escape the store.
pub struct FileProvider {
	config: FileConfig,
}

crate::register_provider! {
	struct: FileProvider,
	config: FileConfig,
	name: "file",
	description: "Plaintext files, one per secret (0.19+)",
	schemes: ["file"],
	examples: ["file:./.secrets", "file:///run/secrets"],
	deletes: true,
}

impl FileProvider {
	pub fn new(mut config: FileConfig) -> Self {
		config.directory = expand_tilde(config.directory);
		Self { config }
	}

	fn operation_error(message: impl Into<String>) -> MonosecretError {
		MonosecretError::ProviderOperationFailed(message.into())
	}

	fn validate_convention_component(value: &str, coordinate: &str) -> Result<()> {
		let mut components = Path::new(value).components();
		let is_one_normal_component = matches!(
			(components.next(), components.next()),
			(Some(Component::Normal(component)), None) if component == OsStr::new(value)
		);
		if value.is_empty()
			|| value.contains(['/', '\\', '\0'])
			|| value == "."
			|| value == ".."
			|| !is_one_normal_component
		{
			return Err(Self::operation_error(format!(
				"the file provider cannot map {coordinate} '{value}' to one safe path component"
			)));
		}
		Ok(())
	}

	fn relative_item(item: &str) -> Result<PathBuf> {
		let path = Path::new(item);
		let segments_are_safe = !item.is_empty()
			&& !item.contains(['\\', '\0'])
			&& item
				.split('/')
				.all(|segment| !segment.is_empty() && segment != "." && segment != "..");
		let components_are_normal = path
			.components()
			.all(|component| matches!(component, Component::Normal(_)));

		if !segments_are_safe || path.is_absolute() || !components_are_normal {
			return Err(Self::operation_error(format!(
				"invalid file provider item '{item}': expected a relative path without empty, '.', '..', or backslash components"
			)));
		}

		Ok(path.to_path_buf())
	}

	fn entry_path(&self, addr: Address<'_>) -> Result<PathBuf> {
		let item = super::flat_item(self, addr)?;
		Ok(self.config.directory.join(Self::relative_item(&item)?))
	}

	fn inspect_directory(path: &Path, label: &str) -> Result<bool> {
		match fs::symlink_metadata(path) {
			Ok(metadata) if metadata.file_type().is_symlink() => {
				Err(Self::operation_error(format!(
					"file provider {label} '{}' is a symbolic link; symbolic links inside the store are not followed",
					path.display()
				)))
			}
			Ok(metadata) if !metadata.is_dir() => {
				Err(Self::operation_error(format!(
					"file provider {label} '{}' is not a directory",
					path.display()
				)))
			}
			Ok(_) => Ok(true),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
			Err(error) => {
				Err(Self::operation_error(format!(
					"failed to inspect file provider {label} '{}': {error}",
					path.display()
				)))
			}
		}
	}

	/// Verifies every existing component beneath the configured root without
	/// following symlinks. Returns `false` as soon as a component is absent.
	fn inspect_parent_chain(&self, parent: &Path) -> Result<bool> {
		if !Self::inspect_directory(&self.config.directory, "root")? {
			return Ok(false);
		}

		let relative = parent.strip_prefix(&self.config.directory).map_err(|_| {
			Self::operation_error(format!(
				"file provider path '{}' escaped its configured root '{}'",
				parent.display(),
				self.config.directory.display()
			))
		})?;
		let mut current = self.config.directory.clone();
		for component in relative.components() {
			let Component::Normal(component) = component else {
				return Err(Self::operation_error(format!(
					"file provider path '{}' is not beneath its configured root",
					parent.display()
				)));
			};
			current.push(component);
			if !Self::inspect_directory(&current, "directory")? {
				return Ok(false);
			}
		}
		Ok(true)
	}

	/// Inspects one entry without following a final symlink.
	fn inspect_entry(&self, path: &Path) -> Result<bool> {
		let parent = path.parent().ok_or_else(|| {
			Self::operation_error(format!(
				"file provider entry '{}' has no parent directory",
				path.display()
			))
		})?;
		if !self.inspect_parent_chain(parent)? {
			return Ok(false);
		}

		match fs::symlink_metadata(path) {
			Ok(metadata) if metadata.file_type().is_symlink() => {
				Err(Self::operation_error(format!(
					"file provider entry '{}' is a symbolic link; symbolic links inside the store are not followed",
					path.display()
				)))
			}
			Ok(metadata) if !metadata.is_file() => {
				Err(Self::operation_error(format!(
					"file provider entry '{}' is not a regular file",
					path.display()
				)))
			}
			Ok(_) => Ok(true),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
			Err(error) => {
				Err(Self::operation_error(format!(
					"failed to inspect file provider entry '{}': {error}",
					path.display()
				)))
			}
		}
	}

	#[cfg(unix)]
	fn create_private_directories(path: &Path) -> std::io::Result<()> {
		use std::os::unix::fs::DirBuilderExt;

		let mut builder = fs::DirBuilder::new();
		builder.recursive(true).mode(0o700).create(path)
	}

	#[cfg(not(unix))]
	fn create_private_directories(path: &Path) -> std::io::Result<()> {
		fs::create_dir_all(path)
	}

	fn prepare_parent(&self, parent: &Path) -> Result<()> {
		Self::create_private_directories(parent).map_err(|error| {
			Self::operation_error(format!(
				"failed to create file provider directory '{}': {error}",
				parent.display()
			))
		})?;
		if !self.inspect_parent_chain(parent)? {
			return Err(Self::operation_error(format!(
				"file provider directory '{}' disappeared while preparing a write",
				parent.display()
			)));
		}
		Ok(())
	}

	#[cfg(unix)]
	fn restrict_temporary_file(path: &Path) -> std::io::Result<()> {
		use std::os::unix::fs::PermissionsExt;

		fs::set_permissions(path, fs::Permissions::from_mode(0o600))
	}

	#[cfg(not(unix))]
	fn restrict_temporary_file(_path: &Path) -> std::io::Result<()> {
		Ok(())
	}
}

impl Provider for FileProvider {
	fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
		Self::validate_convention_component(project, "project")?;
		Self::validate_convention_component(profile, "profile")?;
		Self::validate_convention_component(key, "secret key")?;
		Ok(NativeAddress {
			item: format!("{project}/{profile}/{key}"),
			..Default::default()
		})
	}

	fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
		let path = self.entry_path(addr)?;
		if !self.inspect_entry(&path)? {
			return Ok(None);
		}

		let mut file = fs::File::open(&path).map_err(|error| {
			Self::operation_error(format!(
				"failed to open file provider entry '{}': {error}",
				path.display()
			))
		})?;
		let mut value = String::new();
		file.read_to_string(&mut value).map_err(|error| {
			Self::operation_error(format!(
				"failed to read UTF-8 from file provider entry '{}': {error}",
				path.display()
			))
		})?;
		Ok(Some(SecretString::new(value.into())))
	}

	fn check_writable(&self, addr: Address<'_>) -> Result<()> {
		let path = self.entry_path(addr)?;
		self.inspect_entry(&path).map(|_| ())
	}

	fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
		Ok(self.entry_path(addr)?.display().to_string())
	}

	fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
		self.check_writable(addr)?;
		let path = self.entry_path(addr)?;
		let parent = path.parent().ok_or_else(|| {
			Self::operation_error(format!(
				"file provider entry '{}' has no parent directory",
				path.display()
			))
		})?;
		self.prepare_parent(parent)?;
		// Recheck after creating the directory tree so a pre-existing symlink
		// or non-file target is rejected immediately before replacement.
		self.inspect_entry(&path)?;

		let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
			Self::operation_error(format!(
				"failed to create a temporary file next to file provider entry '{}': {error}",
				path.display()
			))
		})?;
		Self::restrict_temporary_file(temporary.path()).map_err(|error| {
			Self::operation_error(format!(
				"failed to restrict permissions for file provider entry '{}': {error}",
				path.display()
			))
		})?;
		temporary
			.write_all(value.expose_secret().as_bytes())
			.map_err(|error| {
				Self::operation_error(format!(
					"failed to write file provider entry '{}': {error}",
					path.display()
				))
			})?;
		temporary.as_file().sync_all().map_err(|error| {
			Self::operation_error(format!(
				"failed to flush file provider entry '{}': {error}",
				path.display()
			))
		})?;
		temporary.persist(&path).map_err(|error| {
			Self::operation_error(format!(
				"failed to atomically replace file provider entry '{}': {}",
				path.display(),
				error.error
			))
		})?;
		Ok(())
	}

	fn delete(&self, addr: Address<'_>) -> Result<bool> {
		let path = self.entry_path(addr)?;
		if !self.inspect_entry(&path)? {
			return Ok(false);
		}
		fs::remove_file(&path).map_err(|error| {
			Self::operation_error(format!(
				"failed to delete file provider entry '{}': {error}",
				path.display()
			))
		})?;
		Ok(true)
	}

	fn name(&self) -> &'static str {
		Self::PROVIDER_NAME
	}

	fn uri(&self) -> String {
		if self.config.directory.is_absolute() {
			url::Url::from_file_path(&self.config.directory)
				.map(|url| url.to_string())
				.unwrap_or_else(|_| {
					let path = ProviderUrl::encode(&self.config.directory.display().to_string());
					format!("file://{path}")
				})
		} else {
			let path = ProviderUrl::encode(&self.config.directory.display().to_string());
			format!("file://./{path}")
		}
	}

	fn physical_store_path(&self) -> Option<&Path> {
		Some(&self.config.directory)
	}

	fn with_base_dir(&mut self, base_dir: &Path) {
		if self.config.directory.is_relative() {
			self.config.directory = base_dir.join(&self.config.directory);
		}
	}
}

#[cfg(test)]
mod tests {
	use tempfile::TempDir;
	use url::Url;

	use super::*;

	fn provider(directory: &Path) -> FileProvider {
		FileProvider::new(FileConfig {
			directory: directory.to_path_buf(),
		})
	}

	#[test]
	fn parses_explicit_relative_and_absolute_directories() {
		let cases = [
			("file://.secrets", ".secrets"),
			("file://./local%20secrets", "local secrets"),
			("file://config/secrets", "config/secrets"),
			("file://~/.local/share", "~/.local/share"),
			("file:///run/secrets", "/run/secrets"),
			("file:///", "/"),
		];
		for (uri, expected) in cases {
			let url = ProviderUrl::new(Url::parse(uri).unwrap());
			let config = FileConfig::try_from(&url).unwrap();
			assert_eq!(config.directory, Path::new(expected), "{uri}");
		}
	}

	#[test]
	fn rejects_missing_directory() {
		for spec in ["file", "file:", "file://"] {
			let Err(error) = Box::<dyn Provider>::try_from(spec) else {
				panic!("{spec} should require an explicit directory");
			};
			assert!(
				error
					.to_string()
					.contains("requires an explicit relative or absolute directory path"),
				"{spec}: {error}"
			);
		}
	}

	#[test]
	fn rejects_queries() {
		let url = ProviderUrl::new(Url::parse("file://secrets?mode=flat").unwrap());
		let error = FileConfig::try_from(&url).unwrap_err();
		assert!(
			error.to_string().contains("only a directory path"),
			"{error}"
		);
	}

	#[test]
	fn convention_round_trip_is_exact_and_profile_isolated() {
		let directory = TempDir::new().unwrap();
		let provider = provider(directory.path());
		let value = SecretString::new(" leading\nline two\n".to_string().into());

		provider
			.set(Address::convention("app", "development", "TOKEN"), &value)
			.unwrap();

		let found = provider
			.get(Address::convention("app", "development", "TOKEN"))
			.unwrap()
			.unwrap();
		assert_eq!(found.expose_secret(), value.expose_secret());
		assert!(
			provider
				.get(Address::convention("app", "production", "TOKEN"))
				.unwrap()
				.is_none()
		);
		assert_eq!(
			fs::read_to_string(directory.path().join("app/development/TOKEN")).unwrap(),
			value.expose_secret()
		);
	}

	#[test]
	fn native_item_can_address_a_nested_existing_file() {
		let directory = TempDir::new().unwrap();
		fs::create_dir_all(directory.path().join("mounted/database")).unwrap();
		fs::write(
			directory.path().join("mounted/database/password"),
			"external-value\n",
		)
		.unwrap();
		let provider = provider(directory.path());
		let address = NativeAddress {
			item: "mounted/database/password".to_string(),
			..Default::default()
		};

		let found = provider.get(Address::Native(&address)).unwrap().unwrap();
		assert_eq!(found.expose_secret(), "external-value\n");
	}

	#[test]
	fn missing_entry_and_directory_are_absent() {
		let directory = TempDir::new().unwrap();
		let missing_root = directory.path().join("not-created");
		assert!(
			provider(&missing_root)
				.get(Address::convention("app", "default", "MISSING"))
				.unwrap()
				.is_none()
		);
	}

	#[test]
	fn traversal_absolute_and_empty_items_are_rejected() {
		let directory = TempDir::new().unwrap();
		let provider = provider(directory.path());
		for item in [
			"../outside",
			"nested/../outside",
			"nested//secret",
			"nested\\secret",
			"/absolute",
			".",
			"",
		] {
			let address = NativeAddress {
				item: item.to_string(),
				..Default::default()
			};
			let error = provider.get(Address::Native(&address)).unwrap_err();
			assert!(
				error.to_string().contains("relative path"),
				"{item:?}: {error}"
			);
		}
	}

	#[test]
	fn unsafe_convention_components_are_rejected() {
		let provider = provider(Path::new("unused"));
		for (project, profile) in [("../app", "default"), ("app", "../default")] {
			let error = provider.convention_address(project, profile, "TOKEN");
			assert!(
				error
					.unwrap_err()
					.to_string()
					.contains("safe path component")
			);
		}
	}

	#[test]
	fn unsupported_native_coordinate_is_rejected() {
		let directory = TempDir::new().unwrap();
		let address = NativeAddress {
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
	fn delete_is_idempotent() {
		let directory = TempDir::new().unwrap();
		let provider = provider(directory.path());
		let address = Address::convention("app", "default", "TOKEN");
		provider
			.set(address, &SecretString::new("value".to_string().into()))
			.unwrap();

		assert!(provider.delete(address).unwrap());
		assert!(!provider.delete(address).unwrap());
	}

	#[cfg(unix)]
	#[test]
	fn symlinks_inside_the_store_are_rejected() {
		use std::os::unix::fs::symlink;

		let directory = TempDir::new().unwrap();
		let outside = TempDir::new().unwrap();
		fs::write(outside.path().join("secret"), "must not be read").unwrap();
		fs::create_dir_all(directory.path().join("app/default")).unwrap();
		symlink(
			outside.path().join("secret"),
			directory.path().join("app/default/TOKEN"),
		)
		.unwrap();

		let error = provider(directory.path())
			.get(Address::convention("app", "default", "TOKEN"))
			.unwrap_err();
		assert!(error.to_string().contains("symbolic link"), "{error}");
	}

	#[cfg(unix)]
	#[test]
	fn writes_owner_only_files() {
		use std::os::unix::fs::PermissionsExt;

		let directory = TempDir::new().unwrap();
		let provider = provider(directory.path());
		provider
			.set(
				Address::convention("app", "default", "TOKEN"),
				&SecretString::new("value".to_string().into()),
			)
			.unwrap();

		let mode = fs::metadata(directory.path().join("app/default/TOKEN"))
			.unwrap()
			.permissions()
			.mode() & 0o777;
		assert_eq!(mode, 0o600);
	}

	#[test]
	fn binary_entries_are_rejected_by_the_text_provider_api() {
		let directory = TempDir::new().unwrap();
		fs::create_dir_all(directory.path().join("app/default")).unwrap();
		fs::write(directory.path().join("app/default/TOKEN"), [0xff, 0xfe]).unwrap();

		let error = provider(directory.path())
			.get(Address::convention("app", "default", "TOKEN"))
			.unwrap_err();
		assert!(error.to_string().contains("UTF-8"), "{error}");
	}

	#[test]
	fn relative_directory_is_rebased_to_the_manifest() {
		let mut provider = FileProvider::new(FileConfig {
			directory: PathBuf::from("local/secrets"),
		});
		provider.with_base_dir(Path::new("/project"));
		assert_eq!(
			provider.config.directory,
			Path::new("/project/local/secrets")
		);
	}

	#[test]
	fn write_target_description_is_exact_and_does_not_create_directories() {
		let directory = TempDir::new().unwrap();
		let root = directory.path().join("not-created");
		let provider = provider(&root);

		let target = provider
			.describe_write_target(Address::convention("app", "development", "TOKEN"))
			.unwrap();

		assert_eq!(
			target,
			root.join("app/development/TOKEN").display().to_string()
		);
		assert!(!root.exists());
	}

	#[test]
	fn uri_round_trips_a_directory_with_spaces() {
		let provider = Box::<dyn Provider>::try_from("file:./local secrets").unwrap();
		assert_eq!(provider.name(), "file");
		assert_eq!(provider.uri(), "file://./local%20secrets");
		let reparsed = Box::<dyn Provider>::try_from(provider.uri().as_str()).unwrap();
		assert_eq!(reparsed.uri(), provider.uri());
	}
}
