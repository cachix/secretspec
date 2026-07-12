use std::io::Write;
use std::process::Command;
use std::process::Stdio;

use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use crate::MonosecretError;
use crate::Result;
use crate::provider::Address;
use crate::provider::Provider;
use crate::provider::ProviderUrl;

/// Configuration for the `LastPass` provider.
///
/// This struct contains the configuration options for interacting with `LastPass`
/// through the `lpass` CLI tool.
///
/// # Examples
///
/// ```ignore
/// use monosecret::provider::lastpass::LastPassConfig;
///
/// // Create a default configuration
/// let config = LastPassConfig::default();
///
/// // Create a configuration with a folder prefix
/// let config = LastPassConfig {
///     folder_prefix: Some("my-company".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastPassConfig {
	/// Optional folder prefix format string for organizing secrets in `LastPass`.
	///
	/// Supports placeholders: {project}, {profile}, and {key}.
	/// Defaults to "monosecret/{project}/{profile}/{key}" if not specified.
	pub folder_prefix: Option<String>,
}

impl Default for LastPassConfig {
	/// Creates a default `LastPassConfig` with no folder prefix.
	fn default() -> Self {
		Self {
			folder_prefix: None,
		}
	}
}

impl TryFrom<&ProviderUrl> for LastPassConfig {
	type Error = MonosecretError;

	/// Creates a `LastPassConfig` from a URL.
	///
	/// Parses a URL in the format `lastpass://[folder]` where the folder
	/// component is optional. The folder can be specified either as the
	/// authority or the path component of the URL.
	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "lastpass" {
			return Err(MonosecretError::ProviderOperationFailed(format!(
				"Invalid scheme '{}' for lastpass provider",
				url.scheme()
			)));
		}

		let mut config = Self::default();

		if let Some(host) = url.host() {
			config.folder_prefix = Some(format!("{}{}", host, url.path()));
		}

		Ok(config)
	}
}

/// `LastPass` provider implementation for Monosecret.
///
/// This provider integrates with `LastPass` password manager through the `lpass` CLI tool.
/// It stores secrets in a hierarchical structure within `LastPass` using a configurable
/// format string that defaults to: `monosecret/{project}/{profile}/{key}`.
///
/// # Requirements
///
/// The `LastPass` CLI (`lpass`) must be installed and the user must be logged in:
/// - macOS: `brew install lastpass-cli`
/// - Linux: Use your package manager (e.g., `apt install lastpass-cli`)
/// - NixOS: `nix-env -iA nixpkgs.lastpass-cli`
///
/// After installation, authenticate with: `lpass login <your-email>`
///
/// # Examples
///
/// ```ignore
/// use monosecret::provider::lastpass::{LastPassProvider, LastPassConfig};
///
/// // Create provider with default config
/// let provider = LastPassProvider::default();
///
/// // Create provider with custom config
/// let config = LastPassConfig {
///     folder_prefix: Some("work".to_string()),
/// };
/// let provider = LastPassProvider::new(config);
/// ```
pub struct LastPassProvider {
	#[allow(dead_code)]
	config: LastPassConfig,
}

crate::register_provider! {
	struct: LastPassProvider,
	config: LastPassConfig,
	name: "lastpass",
	description: "LastPass password manager",
	schemes: ["lastpass"],
	examples: ["lastpass://", "lastpass://Shared-Monosecret"],
	preflight: check_auth,
}

impl LastPassProvider {
	/// Creates a new `LastPassProvider` with the given configuration.
	///
	/// # Arguments
	///
	/// * `config` - The `LastPass` configuration to use
	pub fn new(config: LastPassConfig) -> Self {
		Self { config }
	}

	/// Executes a `LastPass` CLI command and returns its output.
	///
	/// This is the core method for interacting with the `LastPass` CLI. It handles
	/// command execution, error detection, and provides helpful error messages
	/// for common issues like missing CLI installation or authentication.
	///
	/// # Arguments
	///
	/// * `args` - Command line arguments to pass to `lpass`
	///
	/// # Returns
	///
	/// Returns the command's stdout as a String on success, or an error with
	/// detailed information about what went wrong.
	///
	/// # Errors
	///
	/// - Returns an error if the `lpass` CLI is not installed
	/// - Returns an error if the user is not logged in to `LastPass`
	/// - Returns an error if the command fails for any other reason
	fn execute_lpass_command(args: &[&str]) -> Result<String> {
		let mut cmd = Command::new("lpass");
		cmd.args(args);

		let output = match cmd.output() {
			Ok(output) => output,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
				return Err(MonosecretError::ProviderOperationFailed(
                    "LastPass CLI (lpass) is not installed.\n\nTo install it:\n  - macOS: brew install lastpass-cli\n  - Linux: Check your package manager (apt install lastpass-cli, yum install lastpass-cli, etc.)\n  - NixOS: nix-env -iA nixpkgs.lastpass-cli\n\nAfter installation, run 'lpass login <your-email>' to authenticate.".to_string(),
                ));
			}
			Err(e) => return Err(e.into()),
		};

		if !output.status.success() {
			let error_msg = String::from_utf8_lossy(&output.stderr);
			if error_msg.contains("Could not find decryption key")
				|| error_msg.contains("Not logged in")
			{
				return Err(MonosecretError::ProviderOperationFailed(
					"LastPass authentication required. Please run 'lpass login' first.".to_string(),
				));
			}
			return Err(MonosecretError::ProviderOperationFailed(
				error_msg.to_string(),
			));
		}

		String::from_utf8(output.stdout)
			.map_err(|e| MonosecretError::ProviderOperationFailed(e.to_string()))
	}

	/// Formats the item name for storage in `LastPass`.
	///
	/// Creates a hierarchical path for organizing secrets within `LastPass`.
	/// Uses `folder_prefix` as a format string with {project}, {profile}, and {key} placeholders.
	/// Defaults to "monosecret/{project}/{profile}/{key}" if not configured.
	///
	/// # Arguments
	///
	/// * `project` - The project name
	/// * `key` - The secret key name
	/// * `profile` - The profile name (e.g., "default", "production", "staging")
	///
	/// # Returns
	///
	/// A formatted string representing the full path to the secret in `LastPass`.
	fn format_item_name(&self, project: &str, key: &str, profile: &str) -> String {
		let format_string = self
			.config
			.folder_prefix
			.as_deref()
			.unwrap_or("monosecret/{project}/{profile}/{key}");

		format_string
			.replace("{project}", project)
			.replace("{profile}", profile)
			.replace("{key}", key)
	}

	/// Checks the current `LastPass` login status.
	///
	/// Executes `lpass status` to determine if the user is currently logged in.
	///
	/// # Returns
	///
	/// Returns `Ok(true)` if logged in, `Ok(false)` if not logged in, or an error
	/// if the status check itself fails.
	fn check_login_status() -> Result<bool> {
		match Self::execute_lpass_command(&["status"]) {
			Ok(output) => Ok(!output.contains("Not logged in")),
			Err(MonosecretError::ProviderOperationFailed(msg))
				if msg.contains("Not logged in")
					|| msg.contains("LastPass authentication required") =>
			{
				Ok(false)
			}
			Err(e) => Err(e),
		}
	}

	/// Checks that the user is logged in to `LastPass`.
	/// Called by the preflight guard before any provider operations.
	#[allow(clippy::unused_self)]
	pub(crate) fn check_auth(&self) -> Result<()> {
		if !Self::check_login_status()? {
			return Err(MonosecretError::ProviderOperationFailed(
				"LastPass authentication required. Please run 'lpass login <your-email>' first."
					.to_string(),
			));
		}
		Ok(())
	}
}

impl Provider for LastPassProvider {
	fn get_address(&self, address: Address<'_>) -> Result<Option<SecretString>> {
		match address {
			Address::Convention {
				project,
				profile,
				key,
			} => self.get(project, key, profile),
			Address::Native(native) => {
				crate::provider::reject_unsupported_coords(
					self.name(),
					native,
					self.supported_coords(),
				)?;
				let mut config = self.config.clone();
				config.folder_prefix = Some("{key}".to_string());
				Self::new(config).get("", &native.item, "")
			}
		}
	}

	fn set_address(&self, address: Address<'_>, value: &SecretString) -> Result<()> {
		match address {
			Address::Convention {
				project,
				profile,
				key,
			} => self.set(project, key, value, profile),
			Address::Native(native) => {
				crate::provider::reject_unsupported_coords(
					self.name(),
					native,
					self.supported_coords(),
				)?;
				let mut config = self.config.clone();
				config.folder_prefix = Some("{key}".to_string());
				Self::new(config).set("", &native.item, value, "")
			}
		}
	}

	fn name(&self) -> &'static str {
		Self::PROVIDER_NAME
	}

	fn uri(&self) -> String {
		// LastPass can be "lastpass" (default) or "lastpass://folder" or "lastpass://Folder/Subfolder"
		if let Some(ref prefix) = self.config.folder_prefix {
			// The folder_prefix might be something like "Monosecret/{project}/{profile}/{key}"
			// We want to extract just the folder part for the URI
			if let Some(folder) = prefix.split('/').next() {
				if folder.is_empty() || folder == "Shared" {
					"lastpass".to_string()
				} else {
					format!("lastpass://{}", ProviderUrl::encode(folder))
				}
			} else {
				"lastpass".to_string()
			}
		} else {
			"lastpass".to_string()
		}
	}

	/// Retrieves a secret from `LastPass`.
	///
	/// Fetches the value of a secret stored in `LastPass` at the path
	/// determined by the `folder_prefix` format string. Uses `lpass show` with
	/// the `--sync=now` flag to ensure fresh data from the server.
	///
	/// # Arguments
	///
	/// * `project` - The project name
	/// * `key` - The secret key to retrieve
	/// * `profile` - The profile name
	///
	/// # Returns
	///
	/// - `Ok(Some(value))` if the secret exists and has a value
	/// - `Ok(None)` if the secret doesn't exist or has an empty value
	/// - `Err` if there's an error accessing `LastPass`
	///
	/// # Errors
	///
	/// - Returns an error if not logged in to `LastPass`
	/// - Returns an error if the `LastPass` CLI fails
	fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
		let item_name = self.format_item_name(project, key, profile);

		match Self::execute_lpass_command(&["show", "--sync=now", "--password", &item_name]) {
			Ok(output) => {
				let password = output.trim();
				if password.is_empty() {
					Ok(None)
				} else {
					Ok(Some(SecretString::new(password.to_string().into())))
				}
			}
			Err(MonosecretError::ProviderOperationFailed(msg))
				if msg.contains("Could not find specified account") =>
			{
				Ok(None)
			}
			Err(e) => Err(e),
		}
	}

	/// Stores a secret in `LastPass`.
	///
	/// Creates or updates a secret in `LastPass` at the path
	/// determined by the `folder_prefix` format string. The method first checks if
	/// the item exists to determine whether to use `lpass edit` (for updates)
	/// or `lpass add` (for new items).
	///
	/// # Arguments
	///
	/// * `project` - The project name
	/// * `key` - The secret key to store
	/// * `value` - The secret value to store
	/// * `profile` - The profile name
	///
	/// # Returns
	///
	/// Returns `Ok(())` on success, or an error if the operation fails.
	///
	/// # Errors
	///
	/// - Returns an error if not logged in to `LastPass`
	/// - Returns an error if the `LastPass` CLI command fails
	///
	/// # Implementation Details
	///
	/// The method uses non-interactive mode and disables pinentry to avoid
	/// GUI prompts. The secret value is passed via stdin to avoid exposing
	/// it in the process list.
	fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
		let item_name = self.format_item_name(project, key, profile);

		// Check if item exists
		if self.get(project, key, profile)?.is_some() {
			// Update existing item
			let args = vec![
				"edit",
				"--sync=now",
				&item_name,
				"--password",
				"--non-interactive",
			];

			let mut cmd = Command::new("lpass");
			cmd.args(&args);
			cmd.env("LPASS_DISABLE_PINENTRY", "1");

			let mut child = cmd
				.stdin(Stdio::piped())
				.stdout(Stdio::piped())
				.stderr(Stdio::piped())
				.spawn()?;

			if let Some(stdin) = child.stdin.as_mut() {
				stdin.write_all(value.expose_secret().as_bytes())?;
			}

			let output = child.wait_with_output()?;
			if !output.status.success() {
				let error_msg = String::from_utf8_lossy(&output.stderr);
				return Err(MonosecretError::ProviderOperationFailed(
					error_msg.to_string(),
				));
			}
		} else {
			// Create new item using lpass add
			let args = vec![
				"add",
				"--sync=now",
				&item_name,
				"--password",
				"--non-interactive",
			];

			let mut cmd = Command::new("lpass");
			cmd.args(&args);
			cmd.env("LPASS_DISABLE_PINENTRY", "1");

			let mut child = cmd
				.stdin(Stdio::piped())
				.stdout(Stdio::piped())
				.stderr(Stdio::piped())
				.spawn()?;

			if let Some(stdin) = child.stdin.as_mut() {
				stdin.write_all(value.expose_secret().as_bytes())?;
			}

			let output = child.wait_with_output()?;
			if !output.status.success() {
				let error_msg = String::from_utf8_lossy(&output.stderr);
				return Err(MonosecretError::ProviderOperationFailed(
					error_msg.to_string(),
				));
			}
		}

		Ok(())
	}
}

impl Default for LastPassProvider {
	/// Creates a `LastPassProvider` with default configuration.
	///
	/// This is equivalent to calling `LastPassProvider::new(LastPassConfig::default())`.
	fn default() -> Self {
		Self::new(LastPassConfig::default())
	}
}

#[cfg(all(test, unix))]
mod tests {
	use std::os::unix::fs::PermissionsExt;
	use std::sync::Mutex;

	use super::*;

	/// Serializes all lastpass tests so their `PathGuard` modifications don't
	/// interfere with each other (one test finding another's fake `lpass`).
	static LASTPASS_TEST_LOCK: Mutex<()> = Mutex::new(());

	/// RAII guard that restores `PATH` when dropped, even on panic.
	struct PathGuard {
		original: Option<std::ffi::OsString>,
		_lock: std::sync::MutexGuard<'static, ()>,
	}

	impl PathGuard {
		/// Prepend `dir` to `PATH` so the fake `lpass` is found first, while
		/// keeping the rest of `PATH` intact so parallel tests that spawn `sh`
		/// (e.g. the `OnePassword` fake-op) are not broken. Acquires the test lock
		/// so only one lastpass test modifies `PATH` at a time.
		#[allow(clippy::used_underscore_binding)]
		fn prepend(dir: &std::path::Path) -> Self {
			let _lock = LASTPASS_TEST_LOCK.lock().unwrap();
			let original = std::env::var_os("PATH");
			let new_path = match &original {
				Some(p) => {
					let mut paths: Vec<std::path::PathBuf> = std::env::split_paths(p).collect();
					paths.insert(0, dir.to_path_buf());
					std::env::join_paths(paths)
						.unwrap_or_else(|_| dir.to_string_lossy().into_owned().into())
				}
				None => std::ffi::OsString::from(dir),
			};
			unsafe {
				std::env::set_var("PATH", new_path);
			}
			Self { original, _lock }
		}
	}

	impl Drop for PathGuard {
		fn drop(&mut self) {
			match self.original.take() {
				Some(p) => unsafe {
					std::env::set_var("PATH", p);
				},
				None => unsafe {
					std::env::remove_var("PATH");
				},
			}
		}
	}

	fn write_fake_lpass(dir: &std::path::Path, script_body: &str) {
		let script = dir.join("lpass");
		std::fs::write(&script, script_body).unwrap();
		let mut perms = std::fs::metadata(&script).unwrap().permissions();
		perms.set_mode(0o755);
		std::fs::set_permissions(&script, perms).unwrap();
	}

	#[test]
	fn execute_lpass_command_errors_when_cli_not_installed() {
		let _lock = LASTPASS_TEST_LOCK.lock().unwrap();
		// If real `lpass` is installed this test is meaningless — skip it.
		if Command::new("lpass").arg("--version").output().is_ok() {
			eprintln!("skipping: lpass is installed");
			return;
		}
		let err = LastPassProvider::execute_lpass_command(&["status"]).unwrap_err();
		insta::assert_snapshot!(err.to_string());
	}

	#[test]
	fn check_login_status_returns_false_when_not_logged_in() {
		let dir = tempfile::tempdir().unwrap();
		write_fake_lpass(dir.path(), "#!/bin/sh\nprintf 'Not logged in\\n'\nexit 0\n");
		let _guard = PathGuard::prepend(dir.path());
		let logged_in = LastPassProvider::check_login_status().unwrap();
		assert!(!logged_in);
	}

	#[test]
	fn check_auth_errors_when_not_logged_in() {
		let dir = tempfile::tempdir().unwrap();
		write_fake_lpass(dir.path(), "#!/bin/sh\nprintf 'Not logged in\\n'\nexit 0\n");
		let _guard = PathGuard::prepend(dir.path());
		let provider = LastPassProvider::default();
		let err = provider.check_auth().unwrap_err();
		insta::assert_snapshot!(err.to_string());
	}

	#[test]
	fn get_returns_value_when_secret_exists() {
		let dir = tempfile::tempdir().unwrap();
		write_fake_lpass(
			dir.path(),
			"#!/bin/sh\ncase \"$1\" in\n  status) printf 'Logged in\\n' ;;\n  show) printf 'secret-value\\n' ;;\nesac\n",
		);
		let _guard = PathGuard::prepend(dir.path());
		let provider = LastPassProvider::default();
		let value = provider
			.get("project", "KEY", "default")
			.unwrap()
			.expect("should find secret");
		insta::assert_snapshot!(value.expose_secret());
	}

	#[test]
	fn get_returns_none_when_secret_not_found() {
		let dir = tempfile::tempdir().unwrap();
		write_fake_lpass(
			dir.path(),
			"#!/bin/sh\ncase \"$1\" in\n  status) printf 'Logged in\\n' ;;\n  show) printf 'Could not find specified account\\n' >&2; exit 1 ;;\nesac\n",
		);
		let _guard = PathGuard::prepend(dir.path());
		let provider = LastPassProvider::default();
		let result = provider.get("project", "MISSING", "default").unwrap();
		assert!(result.is_none());
	}
}
