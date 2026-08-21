//! Fly.io application-secrets provider backed by `flyctl secrets`.
//!
//! Fly.io's secrets service can encrypt values but cannot decrypt them, so the
//! provider intentionally supports writes, deletion, and name discovery while
//! rejecting value reads. Secret values are sent to `flyctl` over stdin rather
//! than placed in process arguments.

use super::{Address, DiscoveryContext, Provider, ProviderCredentials, ProviderUrl};
use crate::config::NativeAddress;
use crate::{Result, Secret, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
use std::process::{Command, Output, Stdio};

const ACCESS_TOKEN: &str = "access_token";
const API_TOKEN_ENV: &str = "FLY_API_TOKEN";
const ACCESS_TOKEN_ENV: &str = "FLY_ACCESS_TOKEN";
const CLI_PATH_ENV: &str = "SECRETSPEC_FLYCTL_PATH";

/// Configuration for one Fly.io application's secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlyConfig {
    /// Fly.io application name.
    pub app: String,
    /// Register changes without immediately updating the app's Machines.
    pub stage: bool,
    /// Return without monitoring the Machine update.
    pub detach: bool,
}

impl TryFrom<&ProviderUrl> for FlyConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "fly" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for fly provider",
                url.scheme()
            )));
        }

        if !url.username().is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "fly:// takes the Fly.io app name as its authority, not a username".to_string(),
            ));
        }

        let app = url.host().filter(|app| !app.is_empty()).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "fly provider requires a Fly.io app name, for example fly://my-app".to_string(),
            )
        })?;

        let path = url.path();
        if !path.is_empty() && path != "/" {
            return Err(SecretSpecError::ProviderOperationFailed(
                "fly:// takes no path; put the Fly.io app name in the URI authority".to_string(),
            ));
        }

        let mut stage = None;
        let mut detach = None;
        for (key, value) in url.query_pairs() {
            let slot = match key.as_ref() {
                "stage" => &mut stage,
                "detach" => &mut detach,
                unknown => {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "unknown fly query parameter '{unknown}'; supported parameters are `stage` and `detach`"
                    )));
                }
            };
            if slot.is_some() {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "duplicate fly query parameter '{key}'"
                )));
            }
            *slot = Some(parse_bool(&key, &value)?);
        }

        Ok(Self {
            app,
            stage: stage.unwrap_or(false),
            detach: detach.unwrap_or(false),
        })
    }
}

fn parse_bool(name: &str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(SecretSpecError::ProviderOperationFailed(format!(
            "fly query parameter `{name}` must be `true` or `false`"
        ))),
    }
}

#[derive(Debug, Deserialize)]
struct ListedSecret {
    #[serde(alias = "Name")]
    name: String,
}

/// A write-only provider for Fly.io application secrets.
pub struct FlyProvider {
    config: FlyConfig,
    credentials: ProviderCredentials,
    cli_binary_path: String,
}

crate::register_provider! {
    struct: FlyProvider,
    config: FlyConfig,
    name: "fly",
    description: "Fly.io application secrets via flyctl, write-only (0.20+)",
    schemes: ["fly"],
    examples: ["fly://my-app", "fly://my-app?stage=true"],
    credential_names: [ACCESS_TOKEN],
    reads: false,
    deletes: true,
}

impl FlyProvider {
    pub fn new(config: FlyConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            cli_binary_path: std::env::var(CLI_PATH_ENV).unwrap_or_else(|_| "flyctl".to_string()),
        }
    }

    fn effective_access_token(&self) -> Option<String> {
        super::credential_or_envs(
            &self.credentials,
            ACCESS_TOKEN,
            &["FLY_API_TOKEN", "FLY_ACCESS_TOKEN"],
        )
    }

    fn command(&self) -> Command {
        self.command_with_access_token(self.effective_access_token())
    }

    fn command_with_access_token(&self, token: Option<String>) -> Command {
        let mut command = Command::new(&self.cli_binary_path);
        // Never let flyctl resolve credentials independently from the parent
        // environment. SecretSpec selects the provider credential (including
        // its documented environment fallbacks), scrubs both flyctl variables,
        // and injects only that selected value.
        command.env_remove(API_TOKEN_ENV);
        command.env_remove(ACCESS_TOKEN_ENV);
        if let Some(token) = token {
            command.env(API_TOKEN_ENV, token);
        }
        command
    }

    fn deployment_args(&self, command: &mut Command) {
        if self.config.stage {
            command.arg("--stage");
        }
        if self.config.detach {
            command.arg("--detach");
        }
    }

    fn finish(&self, output: Output) -> Result<Output> {
        if output.status.success() {
            return Ok(output);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "flyctl failed for app '{}': {}",
            self.config.app,
            if detail.is_empty() {
                "command exited unsuccessfully"
            } else {
                detail
            }
        )))
    }

    fn spawn_error(&self, error: io::Error) -> SecretSpecError {
        let message = if error.kind() == io::ErrorKind::NotFound {
            format!(
                "flyctl executable '{}' was not found; install flyctl from https://fly.io/docs/flyctl/install/ or set {CLI_PATH_ENV}",
                self.cli_binary_path
            )
        } else {
            format!("failed to execute '{}': {error}", self.cli_binary_path)
        };
        SecretSpecError::ProviderOperationFailed(message)
    }

    fn list(&self) -> Result<Vec<ListedSecret>> {
        let output = self
            .command()
            .args([
                "secrets",
                "list",
                "--app",
                self.config.app.as_str(),
                "--json",
            ])
            .output()
            .map_err(|error| self.spawn_error(error))?;
        let output = self.finish(output)?;
        serde_json::from_slice(&output.stdout).map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "flyctl returned invalid JSON while listing secrets for app '{}': {error}",
                self.config.app
            ))
        })
    }

    fn secret_name<'a>(&self, addr: Address<'a>) -> Result<std::borrow::Cow<'a, str>> {
        let name = super::flat_item(self, addr)?;
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "'{}' is not a valid Fly.io secret name: names must be non-empty and cannot contain `=` or NUL",
                name
            )));
        }
        Ok(name)
    }
}

impl Provider for FlyProvider {
    /// Fly application secrets become environment variables, so convention
    /// addresses use the declared key directly. The app URI provides project
    /// and environment isolation.
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

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut parameters = Vec::new();
        if self.config.stage {
            parameters.push("stage=true");
        }
        if self.config.detach {
            parameters.push("detach=true");
        }
        let base = format!("fly://{}", ProviderUrl::encode(&self.config.app));
        if parameters.is_empty() {
            base
        } else {
            format!("{base}?{}", parameters.join("&"))
        }
    }

    /// Deployment options change how an update is rolled out, not which Fly
    /// vault stores the secret.
    fn storage_identity(&self) -> String {
        format!("fly://{}", self.config.app)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let _ = self.secret_name(addr)?;
        Err(SecretSpecError::ProviderOperationFailed(
            "Fly.io application secrets are write-only and their plaintext values cannot be read back; use the fly provider with `secretspec set`, `secretspec delete`, or `secretspec init --from`"
                .to_string(),
        ))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.secret_name(addr).map(|_| ())
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let value = value.expose_secret();
        if value.trim() != value {
            return Err(SecretSpecError::ProviderOperationFailed(
                "flyctl trims leading and trailing whitespace from values supplied on stdin; refusing to store a changed secret value"
                    .to_string(),
            ));
        }
        let name = self.secret_name(addr)?;
        let assignment = format!("{name}=-");
        let mut command = self.command();
        command
            .args([
                "secrets",
                "set",
                assignment.as_str(),
                "--app",
                self.config.app.as_str(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.deployment_args(&mut command);

        let mut child = command.spawn().map_err(|error| self.spawn_error(error))?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "failed to open flyctl stdin for the secret value".to_string(),
            )
        })?;
        stdin.write_all(value.as_bytes())?;
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|error| self.spawn_error(error))?;
        self.finish(output).map(|_| ())
    }

    fn supports_delete(&self) -> bool {
        true
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.secret_name(addr).map(|_| ())
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        self.check_deletable(addr)?;
        let name = self.secret_name(addr)?;
        if !self.list()?.iter().any(|secret| secret.name == name) {
            return Ok(false);
        }

        let mut command = self.command();
        command.args([
            "secrets",
            "unset",
            name.as_ref(),
            "--app",
            self.config.app.as_str(),
        ]);
        self.deployment_args(&mut command);
        let output = command.output().map_err(|error| self.spawn_error(error))?;
        self.finish(output).map(|_| true)
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        let name = self.secret_name(addr)?;
        let rollout = if self.config.stage {
            ", staged without an immediate deployment"
        } else if self.config.detach {
            ", deployment detached"
        } else {
            ""
        };
        Ok(format!(
            "Fly.io app '{}' secret '{}'{}",
            self.config.app, name, rollout
        ))
    }

    fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        Ok(self
            .list()?
            .into_iter()
            .map(|listed| {
                let name = listed.name;
                let secret = Secret::required(format!("{name} Fly.io app secret"));
                (name, secret)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_url(spec: &str) -> ProviderUrl {
        ProviderUrl::new(url::Url::parse(spec).unwrap())
    }

    fn config(spec: &str) -> FlyConfig {
        FlyConfig::try_from(&provider_url(spec)).unwrap()
    }

    #[test]
    fn parses_app_and_rollout_options() {
        assert_eq!(
            config("fly://my-app?stage=true&detach=true"),
            FlyConfig {
                app: "my-app".to_string(),
                stage: true,
                detach: true,
            }
        );
    }

    #[test]
    fn rejects_missing_app_path_and_bad_queries() {
        for spec in [
            "fly://",
            "fly://my-app/path",
            "fly://my-app?unknown=true",
            "fly://my-app?stage=yes",
            "fly://my-app?stage=true&stage=false",
        ] {
            assert!(FlyConfig::try_from(&provider_url(spec)).is_err(), "{spec}");
        }
    }

    #[test]
    fn uri_round_trips_and_store_identity_ignores_rollout() {
        let provider = FlyProvider::new(config("fly://my-app?stage=true&detach=true"));
        assert_eq!(provider.uri(), "fly://my-app?stage=true&detach=true");
        assert_eq!(provider.storage_identity(), "fly://my-app");
        assert_eq!(config(&provider.uri()), provider.config);
    }

    #[test]
    fn convention_uses_the_environment_variable_name_directly() {
        let provider = FlyProvider::new(config("fly://my-app"));
        let address = provider
            .convention_address("project", "production", "DATABASE_URL")
            .unwrap();
        assert_eq!(address.item, "DATABASE_URL");
        assert!(address.field.is_none());
    }

    #[test]
    fn reads_explain_fly_write_only_semantics() {
        let provider = FlyProvider::new(config("fly://my-app"));
        let error = provider
            .get(Address::convention("project", "default", "API_KEY"))
            .unwrap_err();
        assert!(error.to_string().contains("write-only"), "{error}");
        assert!(error.to_string().contains("cannot be read back"), "{error}");
    }

    #[test]
    fn invalid_secret_names_are_rejected_before_a_write() {
        let provider = FlyProvider::new(config("fly://my-app"));
        for item in ["", "BAD=NAME", "BAD\0NAME"] {
            let native = NativeAddress {
                item: item.to_string(),
                ..Default::default()
            };
            assert!(provider.check_writable(Address::Native(&native)).is_err());
        }
    }

    #[test]
    fn registration_declares_the_provider_capabilities() {
        let registration = crate::provider::PROVIDER_REGISTRY
            .iter()
            .find(|registration| registration.info.name == "fly")
            .unwrap();
        assert_eq!(registration.credential_names, &[ACCESS_TOKEN]);
        assert!(!registration.reads);
        assert!(!crate::provider::spec_provider_reads("fly://my-app"));
        assert!(crate::provider::spec_provider_reads("dotenv://.env"));
        assert!(registration.deletes);
    }

    #[test]
    fn injected_access_token_is_applied_to_the_child_environment() {
        let mut provider = FlyProvider::new(config("fly://my-app"));
        let mut credentials = ProviderCredentials::new();
        credentials.insert(
            ACCESS_TOKEN.to_string(),
            SecretString::new("fly-token".into()),
        );
        provider.with_credentials(credentials);
        let command = provider.command();
        let envs: HashMap<_, _> = command
            .get_envs()
            .filter_map(|(key, value)| {
                Some((
                    key.to_string_lossy().into_owned(),
                    value?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(
            envs.get(API_TOKEN_ENV).map(String::as_str),
            Some("fly-token")
        );
        let inherited_access_token = command
            .get_envs()
            .find(|(key, _)| key.to_string_lossy() == ACCESS_TOKEN_ENV)
            .expect("the higher-precedence access token must be overridden");
        assert!(
            inherited_access_token.1.is_none(),
            "FLY_ACCESS_TOKEN must be removed from the child environment"
        );
        assert!(!provider.uri().contains("fly-token"));
    }

    #[test]
    fn command_without_a_selected_token_scrubs_fly_credentials() {
        let provider = FlyProvider::new(config("fly://my-app"));
        let command = provider.command_with_access_token(None);
        for credential_env in [API_TOKEN_ENV, ACCESS_TOKEN_ENV] {
            let override_value = command
                .get_envs()
                .find(|(key, _)| key.to_string_lossy() == credential_env)
                .unwrap_or_else(|| panic!("{credential_env} must be scrubbed"));
            assert!(
                override_value.1.is_none(),
                "{credential_env} must not be inherited by flyctl"
            );
        }
    }

    #[cfg(unix)]
    struct FakeFlyctl {
        dir: tempfile::TempDir,
        provider: FlyProvider,
    }

    #[cfg(unix)]
    impl FakeFlyctl {
        fn new(spec: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let binary = dir.path().join("flyctl");
            let scratch = dir.path().join("flyctl.script");
            std::fs::write(
                &scratch,
                r#"#!/bin/sh
fixture_dir=$(dirname "$0")
printf '%s\n' "$*" >> "$fixture_dir/invocations.log"
printf '%s' "${FLY_API_TOKEN:-}" >> "$fixture_dir/token.log"
case "$1 $2" in
  "secrets list") cat "$fixture_dir/list.json" ;;
  "secrets set") cat > "$fixture_dir/stdin.log" ;;
  "secrets unset") ;;
  *) printf 'unexpected flyctl invocation: %s\n' "$*" >&2; exit 2 ;;
esac
"#,
            )
            .unwrap();
            // Install only after the writer has closed. Concurrent subprocess
            // tests can otherwise inherit the write descriptor and make Linux
            // reject execution with ETXTBSY.
            std::fs::rename(&scratch, &binary).unwrap();
            let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&binary, permissions).unwrap();
            std::fs::write(
                dir.path().join("list.json"),
                r#"[{"name":"EXISTING","digest":"abc","status":"Deployed"},{"Name":"LEGACY","Digest":"def"}]"#,
            )
            .unwrap();

            let mut provider = FlyProvider::new(config(spec));
            provider.cli_binary_path = binary.to_string_lossy().into_owned();
            let mut credentials = ProviderCredentials::new();
            credentials.insert(
                ACCESS_TOKEN.to_string(),
                SecretString::new("injected-token".into()),
            );
            provider.with_credentials(credentials);
            Self { dir, provider }
        }

        fn read(&self, name: &str) -> String {
            std::fs::read_to_string(self.dir.path().join(name)).unwrap_or_default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn set_keeps_the_value_off_argv_and_sends_it_on_stdin() {
        let fake = FakeFlyctl::new("fly://my-app?stage=true&detach=true");
        let value = SecretString::new("super-secret-value\nwith-newline".into());
        fake.provider
            .set(
                Address::convention("project", "production", "API_KEY"),
                &value,
            )
            .unwrap();

        let invocation = fake.read("invocations.log");
        assert!(
            invocation.contains("secrets set API_KEY=- --app my-app --stage --detach"),
            "{invocation}"
        );
        assert!(!invocation.contains("super-secret-value"));
        assert_eq!(fake.read("stdin.log"), value.expose_secret());
        assert_eq!(fake.read("token.log"), "injected-token");
    }

    #[cfg(unix)]
    #[test]
    fn set_rejects_boundary_whitespace_before_invoking_flyctl() {
        let fake = FakeFlyctl::new("fly://my-app");
        for value in [" leading", "trailing ", "final-newline\n"] {
            let error = fake
                .provider
                .set(
                    Address::convention("project", "production", "API_KEY"),
                    &SecretString::new(value.into()),
                )
                .unwrap_err();
            assert!(error.to_string().contains("whitespace"), "{error}");
            assert!(error.to_string().contains("refusing"), "{error}");
        }
        assert!(fake.read("invocations.log").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn delete_is_idempotent_and_unsets_existing_names() {
        let fake = FakeFlyctl::new("fly://my-app?stage=true");
        assert!(
            fake.provider
                .delete(Address::convention("project", "production", "EXISTING"))
                .unwrap()
        );
        assert!(
            !fake
                .provider
                .delete(Address::convention("project", "production", "MISSING"))
                .unwrap()
        );

        let invocations = fake.read("invocations.log");
        assert!(
            invocations.contains("secrets unset EXISTING --app my-app --stage"),
            "{invocations}"
        );
        assert!(!invocations.contains("secrets unset MISSING"));
    }

    #[cfg(unix)]
    #[test]
    fn discovery_uses_names_without_trying_to_read_values() {
        let fake = FakeFlyctl::new("fly://my-app");
        let reflected = fake
            .provider
            .reflect(DiscoveryContext::new("project", "production"))
            .unwrap();
        assert_eq!(reflected.len(), 2);
        assert!(reflected.contains_key("EXISTING"));
        assert!(reflected.contains_key("LEGACY"));
        assert_eq!(
            fake.read("invocations.log"),
            "secrets list --app my-app --json\n"
        );
    }
}
