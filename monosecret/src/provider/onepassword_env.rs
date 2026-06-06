use std::collections::HashMap;
use std::collections::HashSet;
use std::process::Command;
use std::sync::Mutex;

use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use crate::MonosecretError;
use crate::Result;
use crate::provider::Provider;
use crate::provider::ProviderUrl;
use crate::provider::onepassword::strip_op_session_env;

/// Configuration for the `OnePassword` Environments provider.
///
/// This provider uses `op environment read` to fetch secrets from a
/// [1Password Environment](https://www.1password.dev/environments).
/// Secrets are returned as `KEY=value` lines and parsed directly —
/// no JSON parsing or section/field navigation is needed.
///
/// # URI Schemes
///
/// | Scheme | Auth | Example |
/// |--------|------|---------|
/// | `onepassword+env` | Desktop app | `onepassword+env://blgexucrwfr2dtsxe2q4uu7dp4` |
/// | `onepassword+env` | Desktop app + account | `onepassword+env://work@blgexucrwfr2dtsxe2q4uu7dp4` |
/// | `onepassword+env+token` | Service account token (in URL) | `onepassword+env+token://ops_token@env-id` |
/// | `onepassword+env+token` | Service account token (from env var) | `onepassword+env+token://env-id` |
///
/// # Example
///
/// ```toml
/// [providers]
/// prod-env = "onepassword+env://blgexucrwfr2dtsxe2q4uu7dp4"
/// ci-env   = "onepassword+env+token://ops_abc123@xyz789"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OnePasswordEnvConfig {
	/// Optional account shorthand (for multiple accounts).
	pub account: Option<String>,
	/// The 1Password Environment ID (UUID).
	pub environment_id: String,
	/// Optional service account token for automated auth.
	#[serde(skip)]
	pub service_account_token: Option<String>,
}

impl TryFrom<&ProviderUrl> for OnePasswordEnvConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		let scheme = url.scheme();

		match scheme {
			"onepassword+env" | "onepassword+env+token" => {}
			_ => {
				return Err(MonosecretError::ProviderOperationFailed(format!(
					"Invalid scheme '{scheme}' for OnePassword Environments provider. \
                     Use 'onepassword+env' or 'onepassword+env+token'"
				)));
			}
		}

		let is_token_scheme = scheme == "onepassword+env+token";
		let mut config = Self::default();

		// The host is the environment ID.
		if let Some(host) = url.host()
			&& host != "localhost"
		{
			config.environment_id = host.clone();
		}

		if config.environment_id.is_empty() {
			// If no host, the path might contain the environment ID.
			let path = url.path();
			let path = path.trim_start_matches('/');
			if !path.is_empty() {
				config.environment_id = path.to_string();
			}
		}

		if config.environment_id.is_empty() {
			return Err(MonosecretError::ProviderOperationFailed(
				"OnePassword Environments provider requires an environment ID in the URI \
                 (e.g. onepassword+env://blgexucrwfr2dtsxe2q4uu7dp4)"
					.into(),
			));
		}

		// Parse username (account or token) and optional password.
		let username = url.username();
		if !username.is_empty() {
			if is_token_scheme {
				if let Some(password) = url.password() {
					config.service_account_token = Some(password);
				} else {
					config.service_account_token = Some(username.clone());
				}
			} else {
				config.account = Some(username.clone());
			}
		}

		Ok(config)
	}
}

crate::register_provider! {
	struct: OnePasswordEnvProvider,
	config: OnePasswordEnvConfig,
	name: "onepassword-env",
	description: "1Password Environments (beta) — key-value secrets via op environment read",
	schemes: ["onepassword+env", "onepassword+env+token"],
	examples: [
		"onepassword+env://blgexucrwfr2dtsxe2q4uu7dp4",
		"onepassword+env://work@blgexucrwfr2dtsxe2q4uu7dp4",
		"onepassword+env+token://ops_abc123@xyz789",
	],
}

/// Provider for 1Password Environments.
///
/// Calls `op environment read <id>` and parses the `KEY=value` output.
///
/// **Caching:** 1Password Environments always returns all variables at once
/// (there is no per-key CLI command). To avoid calling `op` for every
/// `get()` / `get_batch()`, the provider caches the full environment on
/// first access and reuses it for the lifetime of the provider instance.
/// Supports both desktop app auth and service account tokens.
pub struct OnePasswordEnvProvider {
	config: OnePasswordEnvConfig,
	op_command: String,
	/// Provider-local dependency secrets that are passed to the `op` child process.
	dependency_env: HashMap<String, SecretString>,
	/// Lazy cache of all environment variables, populated on first access.
	cache: Mutex<Option<HashMap<String, SecretString>>>,
}

impl OnePasswordEnvProvider {
	pub fn new(config: OnePasswordEnvConfig) -> Self {
		let op_command = std::env::var("MONOSECRET_OPCLI_PATH")
			.or_else(|_| std::env::var("SECRETSPEC_OPCLI_PATH"))
			.unwrap_or_else(|_| "op".to_string());
		Self {
			config,
			op_command,
			dependency_env: HashMap::new(),
			cache: Mutex::new(None),
		}
	}

	/// Returns the cached variables, populating the cache on first call.
	fn cached_variables(
		&self,
	) -> Result<std::sync::MutexGuard<'_, Option<HashMap<String, SecretString>>>> {
		let mut guard = self
			.cache
			.lock()
			.map_err(|e| MonosecretError::ProviderOperationFailed(e.to_string()))?;

		if guard.is_none() {
			let output = self.fetch_environment()?;
			let mut vars = HashMap::new();
			for line in output.lines() {
				if let Some((k, v)) = line.split_once('=') {
					vars.insert(k.to_string(), SecretString::new(v.to_string().into()));
				}
			}
			*guard = Some(vars);
		}

		Ok(guard)
	}

	/// Runs `op environment read <id>` and returns the raw stdout.
	///
	/// Called once by [`cached_variables`]; subsequent lookups use the cache.
	fn fetch_environment(&self) -> Result<String> {
		let mut cmd = Command::new(&self.op_command);
		strip_op_session_env(&mut cmd);

		if let Some(ref token) = self.config.service_account_token {
			cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
		} else if let Some(token) = self.dependency_env.get("OP_SERVICE_ACCOUNT_TOKEN") {
			cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token.expose_secret());
		}
		if let Some(ref account) = self.config.account {
			cmd.arg("--account").arg(account);
		}

		cmd.arg("environment")
			.arg("read")
			.arg(&self.config.environment_id);

		let output = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                MonosecretError::ProviderOperationFailed(
                    "The 'op' CLI is not installed. Install it from https://1password.com/downloads/command-line".into(),
                )
            } else {
                MonosecretError::Io(e)
            }
        })?;

		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			let msg = stderr.trim().to_string();
			if msg.contains("isn't an environment")
				|| msg.contains("not found")
				|| msg.contains("doesn't exist")
			{
				return Err(MonosecretError::ProviderOperationFailed(format!(
					"1Password environment '{}' not found",
					self.config.environment_id
				)));
			}
			if msg.contains("not currently signed in") || msg.contains("no active session") {
				return Err(MonosecretError::ProviderOperationFailed(
                    "Not signed in to 1Password. Sign in via the desktop app or set a service account token.".into(),
                ));
			}
			return Err(MonosecretError::ProviderOperationFailed(msg));
		}

		String::from_utf8(output.stdout)
			.map_err(|e| MonosecretError::ProviderOperationFailed(e.to_string()))
	}
}

impl Provider for OnePasswordEnvProvider {
	fn configure_dependency_secrets(
		&mut self,
		dependencies: &[(String, SecretString)],
	) -> Result<()> {
		for (name, value) in dependencies {
			if name == "OP_SERVICE_ACCOUNT_TOKEN" {
				self.dependency_env.insert(name.clone(), value.clone());
			}
		}
		Ok(())
	}

	fn get(&self, _project: &str, key: &str, _profile: &str) -> Result<Option<SecretString>> {
		let guard = self.cached_variables()?;
		let vars = guard.as_ref().expect("cache was just populated");
		Ok(vars.get(key).cloned())
	}

	fn set(&self, _project: &str, _key: &str, _value: &SecretString, _profile: &str) -> Result<()> {
		Err(MonosecretError::ProviderOperationFailed(
            "1Password Environments provider is read-only. \
             Manage environment variables in the 1Password desktop app (Developer > View Environments)."
                .into(),
        ))
	}

	fn allows_set(&self) -> bool {
		false
	}

	fn name(&self) -> &'static str {
		Self::PROVIDER_NAME
	}

	fn uri(&self) -> String {
		let mut uri = if self.config.service_account_token.is_some() {
			"onepassword+env+token://".to_string()
		} else {
			"onepassword+env://".to_string()
		};
		if let Some(ref account) = self.config.account {
			uri.push_str(&ProviderUrl::encode(account));
			uri.push('@');
		}
		uri.push_str(&self.config.environment_id);
		uri
	}

	fn get_batch(
		&self,
		_project: &str,
		keys: &[&str],
		_profile: &str,
	) -> Result<HashMap<String, SecretString>> {
		let guard = self.cached_variables()?;
		let vars = guard.as_ref().expect("cache was just populated");
		let key_set: HashSet<&str> = keys.iter().copied().collect();
		let results = vars
			.iter()
			.filter(|(k, _)| key_set.contains(k.as_str()))
			.map(|(k, v)| (k.clone(), v.clone()))
			.collect();
		Ok(results)
	}
}

#[cfg(all(test, unix))]
mod dependency_env_tests {
	use std::fs;
	use std::os::unix::fs::PermissionsExt;

	use secrecy::ExposeSecret;

	use super::*;

	fn write_op_env_stub(script: &std::path::Path, log: &std::path::Path) {
		let script_body = format!(
			r#"#!/bin/sh
printf '%s\n' "$OP_SERVICE_ACCOUNT_TOKEN" >> '{}'
printf 'API_KEY=%s\nOTHER=value\n' "$OP_SERVICE_ACCOUNT_TOKEN"
"#,
			log.display()
		);
		fs::write(script, script_body).unwrap();
		let mut permissions = fs::metadata(script).unwrap().permissions();
		permissions.set_mode(0o755);
		fs::set_permissions(script, permissions).unwrap();
	}

	#[test]
	fn dependency_token_is_command_scoped_when_fetching_environment() {
		let temp = tempfile::TempDir::new().unwrap();
		let script = temp.path().join("op-env-stub");
		let log = temp.path().join("calls.log");
		write_op_env_stub(&script, &log);

		let mut provider = OnePasswordEnvProvider::new(OnePasswordEnvConfig {
			environment_id: "env-id".into(),
			service_account_token: None,
			..OnePasswordEnvConfig::default()
		});
		provider.op_command = script.display().to_string();
		provider
			.configure_dependency_secrets(&[
				("IGNORED".into(), SecretString::new("ignored".into())),
				(
					"OP_SERVICE_ACCOUNT_TOKEN".into(),
					SecretString::new("dependency-token".into()),
				),
			])
			.unwrap();

		let first = provider
			.get("project", "API_KEY", "default")
			.unwrap()
			.unwrap();
		let second = provider
			.get("project", "API_KEY", "default")
			.unwrap()
			.unwrap();

		assert_eq!(first.expose_secret(), "dependency-token");
		assert_eq!(second.expose_secret(), "dependency-token");
		assert_eq!(fs::read_to_string(log).unwrap(), "dependency-token\n");
	}

	#[test]
	fn explicit_env_uri_token_takes_precedence_over_dependency_token() {
		let temp = tempfile::TempDir::new().unwrap();
		let script = temp.path().join("op-env-stub");
		let log = temp.path().join("calls.log");
		write_op_env_stub(&script, &log);

		let mut provider = OnePasswordEnvProvider::new(OnePasswordEnvConfig {
			environment_id: "env-id".into(),
			service_account_token: Some("uri-token".into()),
			..OnePasswordEnvConfig::default()
		});
		provider.op_command = script.display().to_string();
		provider
			.configure_dependency_secrets(&[(
				"OP_SERVICE_ACCOUNT_TOKEN".into(),
				SecretString::new("dependency-token".into()),
			)])
			.unwrap();

		let value = provider
			.get("project", "API_KEY", "default")
			.unwrap()
			.unwrap();

		assert_eq!(value.expose_secret(), "uri-token");
		assert_eq!(fs::read_to_string(log).unwrap(), "uri-token\n");
	}
}
