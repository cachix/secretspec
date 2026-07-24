//! Bitwarden Secrets Manager (BWS) provider
//!
//! This provider integrates with Bitwarden Secrets Manager to store and retrieve secrets
//! through the official `bws` command-line interface in SecretSpec 0.17 and later.
//!
//! # Authentication
//!
//! Uses a machine account access token supplied as a provider credential or via
//! the `BWS_ACCESS_TOKEN` environment variable.
//! Generate access tokens from the Bitwarden Secrets Manager web interface.
//! The `bws` executable must be installed and available on `PATH`.
//!
//! # URI Format
//!
//! `bws://[server-base@]project-uuid`
//!
//! Server Base is a hostname pointing to the bitwarden vault instance.
//! Defaults to bitwarden.com
//!
//! The UUID identifies the Bitwarden Secrets Manager project where secrets are stored.
//! This provides namespace isolation — different projects use different BWS project IDs.
//!
//! # Secret Naming
//!
//! Secrets are stored with flat key names matching the secret key directly (e.g., `DATABASE_URL`).
//! The BWS project ID in the URI provides namespace isolation, so project/profile parameters
//! from the Provider trait are ignored for lookup purposes.
//!
//! # Example
//!
//! ```bash
//! # Set up authentication
//! export BWS_ACCESS_TOKEN="0.your-access-token..."
//!
//! # Set a secret
//! secretspec set DATABASE_URL --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c
//!
//! # Check secrets from BWS
//! secretspec check --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c
//! ```

use super::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Configuration for the Bitwarden Secrets Manager provider.
///
/// Contains the BWS project UUID where secrets are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BwsConfig {
    /// The BWS project UUID (e.g., "a9230ec4-5507-4870-b8b5-b3f500587e4c")
    pub project_id: uuid::Uuid,

    /// The Bitwarden instance base URL (e.g., "https://vault.bitwarden.eu")
    pub server_base: Option<String>,
}

impl TryFrom<&ProviderUrl> for BwsConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "bws" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for bws provider. Expected 'bws'.",
                url.scheme()
            )));
        }

        // Extract project ID from host portion: bws://project-uuid
        let project_id_str = url.host().filter(|s| !s.is_empty()).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "BWS project ID is required. Use format: bws://project-uuid".to_string(),
            )
        })?;

        let project_id = uuid::Uuid::parse_str(&project_id_str).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Invalid BWS project UUID '{}': {}. Use format: bws://a9230ec4-5507-4870-b8b5-b3f500587e4c",
                project_id_str, e
            ))
        })?;

        // Extract server base URL from the username: bws://[server-base@]project-uuid
        let server_base = if !url.username().is_empty() {
            Some(url.username())
        } else {
            None
        };

        Ok(Self {
            project_id,
            server_base,
        })
    }
}

/// Bitwarden Secrets Manager provider.
///
/// This provider stores and retrieves secrets from Bitwarden Secrets Manager using
/// a machine account access token for authentication. Secrets are namespaced by
/// the BWS project ID specified in the provider URI.
pub struct BwsProvider {
    config: BwsConfig,
    secrets_cache: OnceLock<Vec<BwsSecret>>,
    /// Credentials supplied by the provider alias.
    credentials: ProviderCredentials,
    /// Path to the official Bitwarden Secrets Manager CLI.
    cli_binary_path: String,
}

const ACCESS_TOKEN: &str = "access_token";
const BWS_ACCESS_TOKEN_ENV: &str = "BWS_ACCESS_TOKEN";
const BWS_CLI_PATH_ENV: &str = "SECRETSPEC_BWS_CLI_PATH";
const DEFAULT_SERVER_URL: &str = "https://bitwarden.com";

/// Fields consumed from `bws secret list --output json`.
#[derive(Debug, Clone, Deserialize)]
struct BwsSecret {
    id: String,
    key: String,
    value: String,
}

crate::register_provider! {
    struct: BwsProvider,
    config: BwsConfig,
    name: "bws",
    description: "Bitwarden Secrets Manager via official bws CLI",
    schemes: ["bws"],
    examples: ["bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"],
    credential_names: [ACCESS_TOKEN],
}

impl BwsProvider {
    /// Creates a new BwsProvider with the given configuration.
    pub fn new(config: BwsConfig) -> Self {
        Self {
            config,
            secrets_cache: OnceLock::new(),
            credentials: ProviderCredentials::new(),
            cli_binary_path: std::env::var(BWS_CLI_PATH_ENV).unwrap_or_else(|_| "bws".to_string()),
        }
    }

    /// Resolves the supplied access token, with the conventional environment
    /// variable retained as a provider-level fallback.
    fn access_token(&self) -> Option<String> {
        credential_or_env(&self.credentials, ACCESS_TOKEN, BWS_ACCESS_TOKEN_ENV)
    }

    /// Strips the BWS access token from error messages to avoid leaking credentials.
    fn sanitize_error(&self, message: &str) -> String {
        if let Some(token) = self.access_token()
            && !token.is_empty()
        {
            return message.replace(&token, "[REDACTED]");
        }
        message.to_string()
    }

    /// Builds an authenticated `bws` command without exposing the token in its arguments.
    fn command(&self) -> Result<Command> {
        let token = self.access_token().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "BWS access_token credential is not set. Configure \
                 credentials.access_token or set the BWS_ACCESS_TOKEN environment variable."
                    .to_string(),
            )
        })?;

        if token.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "BWS access_token credential is empty. Configure \
                 credentials.access_token or set a non-empty BWS_ACCESS_TOKEN environment variable."
                    .to_string(),
            ));
        }

        let mut command = Command::new(&self.cli_binary_path);
        command
            .env(BWS_ACCESS_TOKEN_ENV, token)
            .arg("--color")
            .arg("no")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let server_url = self.config.server_base.as_ref().map_or_else(
            || DEFAULT_SERVER_URL.to_string(),
            |base| format!("https://{base}"),
        );
        command.arg("--server-url").arg(server_url);

        Ok(command)
    }

    /// Runs the official BWS CLI and returns its UTF-8 stdout.
    fn run_bws(&self, args: &[&str], action: &str) -> Result<String> {
        let output = self
            .command()?
            .args(args)
            .output()
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => SecretSpecError::ProviderOperationFailed(format!(
                    "Bitwarden Secrets Manager CLI (bws) is not installed or was not found at \
                     '{}'. Install it from https://bitwarden.com/help/secrets-manager-cli/ \
                     and ensure it is on PATH.",
                    self.cli_binary_path
                )),
                _ => SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to start Bitwarden Secrets Manager CLI (bws): {error}"
                )),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = if stderr.trim().is_empty() {
                format!("bws exited with status {}", output.status)
            } else {
                stderr.trim().to_string()
            };
            return Err(SecretSpecError::ProviderOperationFailed(
                self.sanitize_error(&format!("Failed to {action} using BWS CLI: {detail}")),
            ));
        }

        String::from_utf8(output.stdout).map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "BWS CLI returned non-UTF-8 output while attempting to {action}: {error}"
            ))
        })
    }

    /// Returns a reference to the cached list of secrets in the project, fetching if needed.
    fn ensure_secrets(&self) -> Result<&Vec<BwsSecret>> {
        if let Some(secrets) = self.secrets_cache.get() {
            return Ok(secrets);
        }

        let secrets = self.fetch_secrets()?;
        Ok(self.secrets_cache.get_or_init(|| secrets))
    }

    /// Fetches all secrets from the BWS project (always invokes the CLI, no caching).
    fn fetch_secrets(&self) -> Result<Vec<BwsSecret>> {
        let project_id = self.config.project_id.to_string();
        let output = self.run_bws(
            &["secret", "list", &project_id, "--output", "json"],
            &format!("list secrets in BWS project '{}'", self.config.project_id),
        )?;

        serde_json::from_str(&output).map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse JSON returned by BWS CLI while listing project '{}': {error}",
                self.config.project_id
            ))
        })
    }

    /// Retrieves a secret value from BWS by its resolved key name.
    fn get_secret(&self, target: &str) -> Result<Option<SecretString>> {
        let secrets = self.ensure_secrets()?;

        // BWS uses flat key names -- match directly.
        for secret in secrets {
            if secret.key == target {
                return Ok(Some(SecretString::new(secret.value.clone().into())));
            }
        }

        Ok(None)
    }

    /// Creates or updates a secret in BWS at its resolved key name.
    fn set_secret(&self, key: &str, value: &SecretString) -> Result<()> {
        // Fetch fresh secrets list (not cached) to avoid stale data when writing
        let fresh_secrets = self.fetch_secrets()?;

        // Look for an existing secret with the same key name
        let existing = fresh_secrets.iter().find(|s| s.key == key);
        let secret_value = value.expose_secret();

        if let Some(existing_secret) = existing {
            // Keep option-like values attached to the option so clap cannot
            // interpret them as another flag.
            let value_arg = format!("--value={secret_value}");
            self.run_bws(
                &[
                    "secret",
                    "edit",
                    &existing_secret.id,
                    &value_arg,
                    "--output",
                    "none",
                ],
                &format!("update secret '{key}' in BWS"),
            )?;
        } else {
            let project_id = self.config.project_id.to_string();
            self.run_bws(
                &[
                    "secret",
                    "create",
                    "--output",
                    "none",
                    "--",
                    key,
                    secret_value,
                    &project_id,
                ],
                &format!("create secret '{key}' in BWS"),
            )?;
        }

        Ok(())
    }
}

impl Provider for BwsProvider {
    /// Convention names map straight to the BWS key named after the secret;
    /// the project UUID in the URI provides namespace isolation instead.
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

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        match self.config.server_base {
            Some(ref server_base) => format!("bws://{server_base}@{}", self.config.project_id),
            None => format!("bws://{}", self.config.project_id),
        }
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let target = super::flat_item(self, addr)?;
        self.get_secret(&target)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let target = super::flat_item(self, addr)?;
        self.set_secret(&target, value)
    }

    /// Serves every request, convention or `ref`, from one cached listing of
    /// the project's secrets.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }
        let mut targets = Vec::with_capacity(requests.len());
        for (name, addr) in requests {
            targets.push((*name, super::flat_item(self, *addr)?));
        }

        let secrets = self.ensure_secrets()?;
        let by_key: HashMap<&str, &str> = secrets
            .iter()
            .map(|s| (s.key.as_str(), s.value.as_str()))
            .collect();

        let mut results = HashMap::new();
        for (name, target) in targets {
            if let Some(value) = by_key.get(&*target) {
                results.insert(
                    name.to_string(),
                    SecretString::new((*value).to_string().into()),
                );
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use url::Url;

    fn provider_url(s: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(s).unwrap())
    }

    fn provider_with_credentials(server_base: Option<&str>) -> BwsProvider {
        let mut provider = BwsProvider::new(BwsConfig {
            project_id: uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap(),
            server_base: server_base.map(str::to_string),
        });
        let mut credentials = ProviderCredentials::new();
        credentials.insert(
            ACCESS_TOKEN.to_string(),
            SecretString::new("token-from-provider".to_string().into()),
        );
        provider.with_credentials(credentials);
        provider
    }

    #[test]
    fn test_bws_config_valid_uuid() {
        let url = provider_url("bws://a9230ec4-5507-4870-b8b5-b3f500587e4c");
        let config = BwsConfig::try_from(&url).unwrap();
        assert_eq!(
            config.project_id,
            uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap()
        );
    }

    #[test]
    fn test_bws_config_missing_project_id() {
        let url = provider_url("bws://");
        let result = BwsConfig::try_from(&url);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("project ID is required"),
            "Error should mention project ID is required, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_bws_config_read_server_base() {
        let url = provider_url("bws://bw.home.internal@a9230ec4-5507-4870-b8b5-b3f500587e4c");
        let result = BwsConfig::try_from(&url).unwrap();

        assert_eq!(result.server_base, Some("bw.home.internal".to_string()));
    }

    #[test]
    fn test_bws_config_invalid_uuid() {
        let url = provider_url("bws://not-a-valid-uuid");
        let result = BwsConfig::try_from(&url);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid BWS project UUID"),
            "Error should mention invalid UUID, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_bws_config_wrong_scheme() {
        let url = provider_url("gcsm://a9230ec4-5507-4870-b8b5-b3f500587e4c");
        let result = BwsConfig::try_from(&url);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid scheme"),
            "Error should mention invalid scheme, got: {}",
            err_msg
        );
    }

    /// A native address names the BWS key directly via `item`.
    #[test]
    fn native_address_names_the_key() {
        let config =
            BwsConfig::try_from(&provider_url("bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"))
                .unwrap();
        let p = BwsProvider::new(config);
        let addr = crate::config::NativeAddress {
            item: "prod-db-url".into(),
            ..Default::default()
        };
        assert_eq!(
            crate::provider::flat_item(&p, Address::Native(&addr)).unwrap(),
            "prod-db-url"
        );
    }

    #[test]
    fn test_bws_provider_metadata() {
        let config = BwsConfig {
            project_id: uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap(),
            server_base: Some("vault.bitwarden.com".to_string()),
        };
        let provider = BwsProvider::new(config);

        assert_eq!(provider.name(), "bws");
        assert_eq!(
            provider.uri(),
            "bws://vault.bitwarden.com@a9230ec4-5507-4870-b8b5-b3f500587e4c"
        );
        assert!(
            provider
                .check_writable(Address::convention("proj", "default", "KEY"))
                .is_ok()
        );

        let config = BwsConfig {
            project_id: uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap(),
            server_base: None,
        };
        let provider = BwsProvider::new(config);

        assert_eq!(provider.name(), "bws");
        assert_eq!(provider.uri(), "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c");
        assert!(
            provider
                .check_writable(Address::convention("proj", "default", "KEY"))
                .is_ok()
        );
    }

    #[test]
    fn test_bws_access_token_missing_produces_clear_error() {
        if std::env::var("BWS_ACCESS_TOKEN").is_ok() {
            return;
        }

        let config = BwsConfig {
            project_id: uuid::Uuid::parse_str("a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap(),
            server_base: None,
        };
        let provider = BwsProvider::new(config);

        let result = provider.get(Address::convention("test_project", "default", "TEST_KEY"));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("BWS_ACCESS_TOKEN"),
            "Error should mention BWS_ACCESS_TOKEN, got: {}",
            err_msg
        );
    }

    #[test]
    fn command_passes_token_via_environment_and_server_as_argument() {
        let provider = provider_with_credentials(Some("vault.bitwarden.eu"));
        let command = provider.command().unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let token = command
            .get_envs()
            .find(|(name, _)| *name == BWS_ACCESS_TOKEN_ENV)
            .and_then(|(_, value)| value)
            .unwrap();

        assert_eq!(token, "token-from-provider");
        assert!(!args.iter().any(|arg| arg == "token-from-provider"));
        assert_eq!(
            args,
            [
                "--color",
                "no",
                "--server-url",
                "https://vault.bitwarden.eu"
            ]
        );
    }

    #[test]
    fn command_pins_default_server_as_argument() {
        let provider = provider_with_credentials(None);
        let command = provider.command().unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            args,
            ["--color", "no", "--server-url", "https://bitwarden.com"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn get_reads_json_from_bws_cli_and_caches_the_project_listing() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join("bws");
        let count = temp.path().join("count");
        let script = format!(
            "#!/bin/sh\n\
             test \"$BWS_ACCESS_TOKEN\" = token-from-provider || exit 41\n\
             printf x >> '{}'\n\
             printf '%s' '[{{\"id\":\"11111111-1111-1111-1111-111111111111\",\
             \"key\":\"DATABASE_URL\",\"value\":\"postgres://db\"}}]'\n",
            count.display()
        );
        std::fs::write(&cli, script).unwrap();
        let mut permissions = std::fs::metadata(&cli).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&cli, permissions).unwrap();

        let mut provider = provider_with_credentials(None);
        provider.cli_binary_path = cli.to_string_lossy().into_owned();

        let first = provider
            .get(Address::convention("project", "default", "DATABASE_URL"))
            .unwrap()
            .unwrap();
        let second = provider
            .get(Address::convention("project", "default", "DATABASE_URL"))
            .unwrap()
            .unwrap();

        assert_eq!(first.expose_secret(), "postgres://db");
        assert_eq!(second.expose_secret(), "postgres://db");
        assert_eq!(std::fs::read_to_string(count).unwrap(), "x");
    }

    #[cfg(unix)]
    #[test]
    fn set_updates_an_existing_secret_through_bws_cli() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join("bws");
        let args_log = temp.path().join("args");
        let script = format!(
            "#!/bin/sh\n\
             case \" $* \" in\n\
             *' secret list '*)\n\
               printf '%s' '[{{\"id\":\"11111111-1111-1111-1111-111111111111\",\
               \"key\":\"DATABASE_URL\",\"value\":\"old\"}}]'\n\
               ;;\n\
             *)\n\
               for argument in \"$@\"; do printf '%s\\n' \"$argument\"; done > '{}'\n\
               ;;\n\
             esac\n",
            args_log.display()
        );
        std::fs::write(&cli, script).unwrap();
        let mut permissions = std::fs::metadata(&cli).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&cli, permissions).unwrap();

        let mut provider = provider_with_credentials(None);
        provider.cli_binary_path = cli.to_string_lossy().into_owned();
        provider
            .set(
                Address::convention("project", "default", "DATABASE_URL"),
                &SecretString::new("--password".to_string().into()),
            )
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(args_log).unwrap(),
            "--color\nno\n--server-url\nhttps://bitwarden.com\nsecret\nedit\n\
             11111111-1111-1111-1111-111111111111\n--value=--password\n--output\nnone\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn set_creates_a_missing_secret_through_bws_cli() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join("bws");
        let args_log = temp.path().join("args");
        let script = format!(
            "#!/bin/sh\n\
             case \" $* \" in\n\
             *' secret list '*) printf '%s' '[]' ;;\n\
             *) for argument in \"$@\"; do printf '%s\\n' \"$argument\"; done > '{}' ;;\n\
             esac\n",
            args_log.display()
        );
        std::fs::write(&cli, script).unwrap();
        let mut permissions = std::fs::metadata(&cli).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&cli, permissions).unwrap();

        let mut provider = provider_with_credentials(None);
        provider.cli_binary_path = cli.to_string_lossy().into_owned();
        provider
            .set(
                Address::convention("project", "default", "--API_KEY"),
                &SecretString::new("--password".to_string().into()),
            )
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(args_log).unwrap(),
            "--color\nno\n--server-url\nhttps://bitwarden.com\nsecret\ncreate\n--output\nnone\n--\n\
             --API_KEY\n--password\na9230ec4-5507-4870-b8b5-b3f500587e4c\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cli_errors_redact_the_access_token() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join("bws");
        std::fs::write(
            &cli,
            "#!/bin/sh\nprintf 'rejected %s\\n' \"$BWS_ACCESS_TOKEN\" >&2\nexit 1\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&cli).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&cli, permissions).unwrap();

        let mut provider = provider_with_credentials(None);
        provider.cli_binary_path = cli.to_string_lossy().into_owned();

        let error = provider
            .get(Address::convention("project", "default", "DATABASE_URL"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("[REDACTED]"), "{error}");
        assert!(!error.contains("token-from-provider"), "{error}");
    }

    /// BWS secrets are flat key/value pairs; a `field` coordinate is rejected.
    #[test]
    fn native_address_rejects_field() {
        let config =
            BwsConfig::try_from(&provider_url("bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"))
                .unwrap();
        let p = BwsProvider::new(config);
        let addr = crate::config::NativeAddress {
            item: "prod-db-url".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let err = crate::provider::flat_item(&p, Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }
}
