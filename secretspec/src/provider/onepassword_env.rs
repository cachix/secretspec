use crate::provider::onepassword::strip_op_session_env;
use crate::provider::{Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::process::Command;

/// Configuration for the OnePassword Environments provider.
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
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();

        match scheme {
            "onepassword+env" | "onepassword+env+token" => {}
            _ => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid scheme '{scheme}' for OnePassword Environments provider. \
                     Use 'onepassword+env' or 'onepassword+env+token'"
                )));
            }
        }

        let is_token_scheme = scheme == "onepassword+env+token";
        let mut config = Self::default();

        // The host is the environment ID.
        if let Some(host) = url.host() {
            if host != "localhost" {
                config.environment_id = host.to_string();
            }
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
            return Err(SecretSpecError::ProviderOperationFailed(
                "OnePassword Environments provider requires an environment ID in the URI \
                 (e.g. onepassword+env://blgexucrwfr2dtsxe2q4uu7dp4)".into(),
            ));
        }

        // Parse username (account or token) and optional password.
        let username = url.username();
        if !username.is_empty() {
            if is_token_scheme {
                if let Some(password) = url.password() {
                    config.service_account_token = Some(password);
                } else {
                    config.service_account_token = Some(username.to_string());
                }
            } else {
                config.account = Some(username.to_string());
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
/// Supports both desktop app auth and service account tokens.
pub struct OnePasswordEnvProvider {
    config: OnePasswordEnvConfig,
    op_command: String,
}

impl OnePasswordEnvProvider {
    pub fn new(config: OnePasswordEnvConfig) -> Self {
        let op_command = std::env::var("SECRETSPEC_OPCLI_PATH").unwrap_or_else(|_| {
            "op".to_string()
        });
        Self { config, op_command }
    }

    /// Runs `op environment read <id>` and returns the raw stdout.
    fn read_environment(&self) -> Result<String> {
        let mut cmd = Command::new(&self.op_command);
        strip_op_session_env(&mut cmd);

        if let Some(ref token) = self.config.service_account_token {
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
        }
        if let Some(ref account) = self.config.account {
            cmd.arg("--account").arg(account);
        }

        cmd.arg("environment")
            .arg("read")
            .arg(&self.config.environment_id);

        let output = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretSpecError::ProviderOperationFailed(
                    "The 'op' CLI is not installed. Install it from https://1password.com/downloads/command-line".into(),
                )
            } else {
                SecretSpecError::Io(e)
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = stderr.trim().to_string();
            if msg.contains("isn't an environment")
                || msg.contains("not found")
                || msg.contains("doesn't exist")
            {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "1Password environment '{}' not found",
                    self.config.environment_id
                )));
            }
            if msg.contains("not currently signed in")
                || msg.contains("no active session")
            {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Not signed in to 1Password. Sign in via the desktop app or set a service account token.".into(),
                ));
            }
            return Err(SecretSpecError::ProviderOperationFailed(msg));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))
    }
}

impl Provider for OnePasswordEnvProvider {
    fn get(
        &self,
        _project: &str,
        key: &str,
        _profile: &str,
    ) -> Result<Option<SecretString>> {
        let output = self.read_environment()?;
        for line in output.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if k == key {
                    return Ok(Some(SecretString::new(v.to_string().into())));
                }
            }
        }
        Ok(None)
    }

    fn set(
        &self,
        _project: &str,
        _key: &str,
        _value: &SecretString,
        _profile: &str,
    ) -> Result<()> {
        Err(SecretSpecError::ProviderOperationFailed(
            "1Password Environments provider is read-only. \
             Manage environment variables in the 1Password desktop app (Developer > View Environments)."
                .into(),
        ))
    }

    fn allows_set(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "onepassword-env"
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
        let output = self.read_environment()?;
        let key_set: HashSet<&str> = keys.iter().copied().collect();
        let mut results = HashMap::new();
        for line in output.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if key_set.contains(k) {
                    results.insert(k.to_string(), SecretString::new(v.to_string().into()));
                }
            }
        }
        Ok(results)
    }
}
