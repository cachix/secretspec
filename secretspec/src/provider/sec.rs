//! sec provider backed by the `sec` CLI.
//!
//! [sec](https://github.com/kaidstor/sec) is a local secrets manager that
//! keeps every value in one XChaCha20-Poly1305-encrypted file, with the
//! master key in the OS keychain (macOS Keychain / Secret Service / Windows
//! Credential Manager) or supplied via `SEC_KEY` for headless use. It is
//! built for agent-safe workflows: values never appear on argv or in shell
//! history.
//!
//! Convention secrets map onto sec's own address space instead of a
//! secretspec-specific folder: `{project}@{profile}/{KEY}`, with the
//! `default` profile collapsing to the project's base (profile-less) set,
//! addressed explicitly as `{project}@/{KEY}`. Existing sec stores therefore
//! work without migration or re-import.
//!
//! All outcome decisions rely on sec's documented exit codes (0 = ok,
//! 3 = no such key/project, anything else = real failure) — never on stderr
//! text, which is localized.

use crate::config::NativeAddress;
use crate::provider::{Address, DiscoveryContext, Provider, ProviderUrl};
use crate::{Result, Secret, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};

/// Exit code sec reserves for "no such key/project" (sec 1.0+, documented in
/// its machine-interface contract). Distinct from 2, which covers real
/// failures such as an unreadable store.
const EXIT_NOT_FOUND: i32 = 3;

/// One entry of `sec ls <project> --json` (values are never included).
#[derive(Debug, Deserialize)]
struct LsEntry {
    key: String,
    #[serde(default)]
    meta: Option<LsMeta>,
}

#[derive(Debug, Default, Deserialize)]
struct LsMeta {
    #[serde(default)]
    note: Option<String>,
}

/// Replaces `{project}`, `{profile}`, and `{key}` placeholders exactly once,
/// keeping any placeholder-like text inside the substituted values literal.
fn render_template(template: &str, project: &str, profile: &str, key: &str) -> String {
    let mut rendered = String::with_capacity(template.len() + project.len() + profile.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rendered.push_str(&rest[..open]);
        rest = &rest[open..];
        if let Some(tail) = rest.strip_prefix("{project}") {
            rendered.push_str(project);
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("{profile}") {
            rendered.push_str(profile);
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("{key}") {
            rendered.push_str(key);
            rest = tail;
        } else {
            rendered.push('{');
            rest = &rest[1..];
        }
    }
    rendered.push_str(rest);
    rendered
}

/// Configuration for the sec provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecConfig {
    /// Complete convention address template from `?template=`. Defaults to
    /// sec's native layout: `{project}@{profile}/{key}` with the `default`
    /// profile collapsing to the base set `{project}@/{key}`.
    pub template: Option<String>,
}

impl TryFrom<&ProviderUrl> for SecConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "sec" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for sec provider",
                url.scheme()
            )));
        }
        if url.host().is_some() || !url.path().trim_matches('/').is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "sec address templates belong in the `template` query parameter. \
                 Use `sec://?template={project}@{profile}/{key}`."
                    .to_string(),
            ));
        }

        let mut config = Self::default();
        let mut seen = HashSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "sec query parameter `{key}` may only be specified once"
                )));
            }
            match key.as_ref() {
                "template" => {
                    if value.is_empty() {
                        return Err(SecretSpecError::ProviderOperationFailed(
                            "sec `template` cannot be empty".to_string(),
                        ));
                    }
                    config.template = Some(value.into_owned());
                }
                _ => {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "unknown sec query parameter `{key}`; expected `template`"
                    )));
                }
            }
        }

        Ok(config)
    }
}

/// Provider for the [sec](https://github.com/kaidstor/sec) local encrypted
/// secrets manager, driven through its CLI. Requires sec 1.0 or newer (the
/// first version with the not-found exit code this provider relies on).
pub struct SecProvider {
    config: SecConfig,
}

crate::register_provider! {
    struct: SecProvider,
    config: SecConfig,
    name: "sec",
    description: "sec local encrypted secrets manager (0.19+) via the sec CLI",
    schemes: ["sec"],
    examples: ["sec://", "sec://?template={project}@{profile}/{key}"],
    deletes: true,
}

impl SecProvider {
    /// Creates a new SecProvider with the given configuration.
    pub fn new(config: SecConfig) -> Self {
        Self { config }
    }

    /// sec project address for a convention (project, profile) pair. The
    /// explicit `@` form is used even for the base set so the address
    /// resolves identically no matter which directory `sec` runs from: a
    /// local `.sec` manifest may declare a default profile that would
    /// otherwise rewrite a bare `project/KEY`.
    fn container(project: &str, profile: &str) -> String {
        if profile == "default" {
            format!("{project}@")
        } else {
            format!("{project}@{profile}")
        }
    }

    /// Full sec address for a convention secret.
    fn convention_item(&self, project: &str, profile: &str, key: &str) -> String {
        if let Some(template) = &self.config.template {
            return render_template(template, project, profile, key);
        }
        format!("{}/{}", Self::container(project, profile), key)
    }

    /// Creates a `sec` command. The child inherits the environment, so
    /// keychain access on desktops and `SEC_KEY`/`SEC_STORE` in CI work
    /// without provider-side configuration.
    fn command(&self) -> Command {
        Command::new("sec")
    }

    fn exec_failed(err: std::io::Error) -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(format!(
            "Failed to execute 'sec' command: {err}. Is sec installed? \
             (https://github.com/kaidstor/sec)"
        ))
    }

    fn cli_failed(what: &str, output: &std::process::Output) -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(format!(
            "sec {what} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

impl Provider for SecProvider {
    /// Convention entries live at sec's native addresses,
    /// `{project}@{profile}/{key}` by default (`{project}@/{key}` for the
    /// `default` profile).
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: self.convention_item(project, profile, key),
            ..Default::default()
        })
    }

    /// Retrieves a secret via `sec get`.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(SecretString))` - The secret value if found
    /// * `Ok(None)` - The address does not exist (exit code 3)
    /// * `Err` - `sec` could not run or the store could not be read
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let item = super::flat_item(self, addr)?;

        let output = self
            .command()
            .arg("get")
            .arg(&*item)
            .output()
            .map_err(Self::exec_failed)?;

        if output.status.success() {
            let mut content = String::from_utf8(output.stdout).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to parse sec output as UTF-8: {e}"
                ))
            })?;
            // `sec get` terminates the value with one newline; values are
            // trimmed at write time, so stripping it is lossless.
            if content.ends_with('\n') {
                content.pop();
                if content.ends_with('\r') {
                    content.pop();
                }
            }
            Ok(Some(SecretString::new(content.into())))
        } else if output.status.code() == Some(EXIT_NOT_FOUND) {
            Ok(None)
        } else {
            Err(Self::cli_failed("get", &output))
        }
    }

    /// Stores a secret via `sec set`, passing the value over stdin (sec
    /// refuses values on argv by design).
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let item = super::flat_item(self, addr)?;

        let mut child = self
            .command()
            .args(["set", &item, "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(Self::exec_failed)?;

        let mut stdin = child.stdin.take().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Failed to obtain stdin for sec command".to_string(),
            )
        })?;
        stdin
            .write_all(value.expose_secret().as_bytes())
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to write to sec stdin: {e}"
                ))
            })?;
        // Close the pipe so sec sees EOF and finishes reading the value.
        drop(stdin);

        let output = child.wait_with_output().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!("Failed to wait for sec command: {e}"))
        })?;

        if !output.status.success() {
            return Err(Self::cli_failed("set", &output));
        }
        Ok(())
    }

    /// Deletes a secret via `sec rm`. Deleting an absent entry is a no-op.
    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let item = super::flat_item(self, addr)?;
        let output = self
            .command()
            .args(["rm", &item])
            .output()
            .map_err(Self::exec_failed)?;

        if output.status.success() {
            return Ok(true);
        }
        if output.status.code() == Some(EXIT_NOT_FOUND) {
            return Ok(false);
        }
        Err(Self::cli_failed("rm", &output))
    }

    /// Discovers declarations from an existing sec project via
    /// `sec ls <project> --json` (key names and non-secret metadata only —
    /// sec never prints values in listings).
    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        if self.config.template.is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "sec: discovery with a custom `template` is not supported; \
                 use the default convention"
                    .to_string(),
            ));
        }

        let container = Self::container(context.project, context.profile);
        let output = self
            .command()
            .args(["ls", &container, "--json"])
            .output()
            .map_err(Self::exec_failed)?;

        if output.status.code() == Some(EXIT_NOT_FOUND) {
            return Ok(HashMap::new()); // no such project — nothing to declare
        }
        if !output.status.success() {
            return Err(Self::cli_failed("ls", &output));
        }

        let entries: Vec<LsEntry> = serde_json::from_slice(&output.stdout).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse `sec ls --json` output: {e}"
            ))
        })?;

        let mut declarations = HashMap::new();
        for entry in entries {
            let description = entry
                .meta
                .and_then(|m| m.note)
                .filter(|note| !note.is_empty())
                .unwrap_or_else(|| format!("{} secret", entry.key));
            declarations.insert(
                entry.key,
                Secret {
                    description: Some(description),
                    required: Some(true),
                    ..Default::default()
                },
            );
        }
        Ok(declarations)
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        match &self.config.template {
            Some(template) => {
                format!("sec://?template={}", ProviderUrl::encode_query(template))
            }
            None => "sec".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn provider_url(spec: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(spec).unwrap())
    }

    fn config(spec: &str) -> SecConfig {
        SecConfig::try_from(&provider_url(spec)).unwrap()
    }

    #[test]
    fn default_convention_uses_native_profile_addresses() {
        let provider = SecProvider::new(SecConfig::default());
        assert_eq!(
            provider.convention_item("myapp", "production", "DATABASE_URL"),
            "myapp@production/DATABASE_URL"
        );
    }

    #[test]
    fn default_profile_collapses_to_base_set() {
        let provider = SecProvider::new(SecConfig::default());
        // `myapp@/KEY` (explicit base), not `myapp/KEY`: a bare address would
        // be rewritten by a local .sec default profile depending on cwd.
        assert_eq!(
            provider.convention_item("myapp", "default", "API_KEY"),
            "myapp@/API_KEY"
        );
    }

    #[test]
    fn template_overrides_convention() {
        let provider = SecProvider::new(config("sec://?template=shared@{profile}/{key}"));
        assert_eq!(
            provider.convention_item("ignored", "prod", "TOKEN"),
            "shared@prod/TOKEN"
        );
    }

    #[test]
    fn template_substitutes_placeholders_once() {
        assert_eq!(
            render_template("{project}@{profile}/{key}", "a{key}", "p", "K"),
            "a{key}@p/K"
        );
    }

    #[test]
    fn uri_round_trips_default_and_template() {
        assert_eq!(SecProvider::new(SecConfig::default()).uri(), "sec");
        let spec = "sec://?template={project}@{profile}/{key}";
        let provider = SecProvider::new(config(spec));
        assert_eq!(
            SecConfig::try_from(&provider_url(&provider.uri()))
                .unwrap()
                .template,
            provider.config.template
        );
    }

    #[test]
    fn config_rejects_wrong_scheme_host_and_unknown_params() {
        assert!(SecConfig::try_from(&provider_url("gopass://")).is_err());
        assert!(SecConfig::try_from(&provider_url("sec://somewhere")).is_err());
        assert!(SecConfig::try_from(&provider_url("sec://?bogus=1")).is_err());
        assert!(SecConfig::try_from(&provider_url("sec://?template=")).is_err());
        assert!(SecConfig::try_from(&provider_url("sec://?template=a&template=b")).is_err());
    }
}
