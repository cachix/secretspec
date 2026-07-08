use crate::provider::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// Environment variable pass-cli (>= 2.1.0) requires agent sessions to set before
/// audited item operations (`item view`, `item create`, `item delete`, ...). For
/// non-agent sessions and older pass-cli releases it is ignored, so setting it
/// unconditionally is safe and backward compatible.
const AGENT_REASON_ENV: &str = "PROTON_PASS_AGENT_REASON";

/// Reason recorded in Proton Pass' agent audit log when neither a session reason
/// (via `Secrets::with_reason`) nor `PROTON_PASS_AGENT_REASON` is provided.
/// Carries the secretspec version so the audit log identifies the exact client.
const DEFAULT_AGENT_REASON: &str = concat!(
    "secretspec/",
    env!("CARGO_PKG_VERSION"),
    " (https://secretspec.dev)"
);

// You can get the shape of pass-cli data with commands such as:
// $ pass-cli item view --output json
//   {"item": {"id": "...", "share_id": "...", "content": {"title": "...", "note": "..."}}}
//
// or:
// $ pass-cli item list <vault> --output json
//   pass-cli <= 2.0.2: {"items": [{"id": "...", "share_id": "...", "content": {"title": "..."}}]}
//   pass-cli >= 2.0.3: {"items": [{"id": "...", "share_id": "...", "title": "...", "item_type": "note"}]}
//
// We only use a limited subset of the full data.

#[derive(Deserialize)]
struct ProtonPassItemContent {
    title: String,
    note: Option<String>,
}

#[derive(Deserialize)]
struct ProtonPassItemData {
    content: ProtonPassItemContent,
}

#[derive(Deserialize)]
struct ProtonPassViewResponse {
    item: ProtonPassItemData,
}

/// A single entry from `pass-cli item list ... --output json`.
///
/// The list payload changed shape in pass-cli 2.0.3 (protonpass/pass-cli commit
/// 1c09fd8): the title moved from a nested `content.title` to a top-level
/// `title`, and the per-item `content` object was dropped entirely from list
/// output (it no longer carries any secret material). `id`/`share_id` remain
/// top-level in both shapes, and only those plus the title are used here, so we
/// accept either layout and keep working across pass-cli versions.
#[derive(Deserialize)]
struct ProtonPassListItem {
    id: String,
    share_id: String,
    /// Top-level title (pass-cli >= 2.0.3).
    title: Option<String>,
    /// Legacy nested content carrying the title (pass-cli <= 2.0.2).
    content: Option<ProtonPassItemContent>,
}

impl ProtonPassListItem {
    /// The item title regardless of pass-cli version, preferring the top-level
    /// field and falling back to the legacy nested `content.title`.
    fn title(&self) -> Option<&str> {
        self.title
            .as_deref()
            .or_else(|| self.content.as_ref().map(|c| c.title.as_str()))
    }
}

#[derive(Deserialize)]
struct ProtonPassListResponse {
    items: Vec<ProtonPassListItem>,
}

// You can get the JSON template for this struct via:
// $ pass-cli item create note --get-template
#[derive(Serialize)]
struct ProtonPassNoteTemplate {
    title: String,
    note: String,
}

/// Configuration for the Proton Pass provider.
///
/// Vault name and title template are parsed from the provider URI:
/// `protonpass://[vault_name[/title-template]]`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtonPassConfig {
    /// Target vault in Proton Pass. Defaults to "secretspec" when absent.
    pub vault_name: Option<String>,
    /// Item title format string. Supports {project}, {profile}, {key} placeholders.
    /// Defaults to "{project}/{profile}/{key}" when absent.
    pub title_template: Option<String>,
}

impl TryFrom<&ProviderUrl> for ProtonPassConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "protonpass" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for protonpass provider",
                url.scheme()
            )));
        }

        let mut config = Self::default();

        if let Some(host) = url.host() {
            config.vault_name = Some(host);
        }

        let path = url.path();
        let path = path.trim_start_matches('/');
        if !path.is_empty() {
            config.title_template = Some(path.to_string());
        }

        Ok(config)
    }
}

/// Provider for managing secrets in Proton Pass via the official `pass-cli`.
///
/// Secrets are stored as note items inside a configurable vault. Each secret
/// maps to one item; the item title encodes project/profile/key and the note
/// body holds the secret value.
///
/// # Authentication
///
/// Interactive: `pass-cli login`
/// CI with a personal access token: `pass-cli login --pat $PROTON_PASS_PAT`
///
/// The provider checks session validity via `pass-cli test` before operations.
///
/// # Storage
///
/// Vault: configured in the URI (defaults to "secretspec", must be created prior to usage).
/// Item title: `{project}/{profile}/{key}` by default, customizable via the URI path.
pub struct ProtonPassProvider {
    config: ProtonPassConfig,
    /// Path to `pass-cli` binary.
    /// Override with the `SECRETSPEC_PROTONPASS_CLI_PATH` environment variable.
    cli_binary_path: String,
    /// Session reason for the audit log, set via `set_reason` (last write wins). Uses
    /// interior mutability because the provider is shared behind an `Arc` once
    /// registered.
    session_reason: Mutex<Option<String>>,
}

crate::register_provider! {
    struct: ProtonPassProvider,
    config: ProtonPassConfig,
    name: "protonpass",
    description: "Proton Pass via official pass-cli",
    schemes: ["protonpass"],
    examples: [
        "protonpass://",
        "protonpass://Work",
        "protonpass://Work/{project}/{profile}/{key}",
    ],
    preflight: test_authentication,
}

impl ProtonPassProvider {
    pub fn new(config: ProtonPassConfig) -> Self {
        let cli_binary_path = std::env::var("SECRETSPEC_PROTONPASS_CLI_PATH")
            .unwrap_or_else(|_| "pass-cli".to_string());
        Self {
            config,
            cli_binary_path,
            session_reason: Mutex::new(None),
        }
    }

    pub(crate) fn test_authentication(&self) -> Result<()> {
        self.run_pass_cli(&["test"], None)?;
        Ok(())
    }

    /// Resolves the reason passed to `pass-cli` for agent-session audit logging.
    ///
    /// Precedence: the session reason set via [`Secrets::with_reason`], then a
    /// user-provided `PROTON_PASS_AGENT_REASON`, then a generic default. The value
    /// is only consumed by `pass-cli` agent sessions; it is ignored otherwise.
    ///
    /// [`Secrets::with_reason`]: crate::Secrets::with_reason
    fn agent_reason(&self) -> String {
        let session = self.session_reason.lock().unwrap().clone();
        let env = std::env::var(AGENT_REASON_ENV).ok();
        Self::resolve_reason(session, env)
    }

    /// Pure precedence logic for [`Self::agent_reason`], split out so it can be
    /// tested without touching the process environment.
    ///
    /// Each source is normalized via [`crate::secrets::normalize_reason`] *before*
    /// falling through, so a blank/whitespace session reason does not shadow a
    /// usable `PROTON_PASS_AGENT_REASON` (it falls through to it), and a blank env
    /// value falls through to the default.
    fn resolve_reason(session: Option<String>, env: Option<String>) -> String {
        session
            .as_deref()
            .and_then(crate::secrets::normalize_reason)
            .or_else(|| env.as_deref().and_then(crate::secrets::normalize_reason))
            .unwrap_or_else(|| DEFAULT_AGENT_REASON.to_string())
    }

    fn get_vault_name(&self) -> &str {
        self.config.vault_name.as_deref().unwrap_or("secretspec")
    }

    fn format_item_title(&self, project: &str, profile: &str, key: &str) -> String {
        let template = self
            .config
            .title_template
            .as_deref()
            .unwrap_or("{project}/{profile}/{key}");
        template
            .replace("{project}", project)
            .replace("{profile}", profile)
            .replace("{key}", key)
    }

    /// Builds a `pass-cli` command with the agent-session reason wired in.
    ///
    /// Both the single-shot [`Self::run_pass_cli`] and the parallel batch-fetch
    /// threads go through here, so the `PROTON_PASS_AGENT_REASON` env var (required
    /// by `pass-cli` >= 2.1.0) can never drift between the two paths. Takes the
    /// resolved values by `&str` so the batch threads can call it without `&self`.
    fn pass_cli_command(binary: &str, reason: &str) -> Command {
        let mut cmd = Command::new(binary);
        cmd.env(AGENT_REASON_ENV, reason);
        cmd
    }

    fn run_pass_cli(&self, args: &[&str], stdin: Option<&str>) -> Result<String> {
        let mut cmd = Self::pass_cli_command(&self.cli_binary_path, &self.agent_reason());
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = if let Some(data) = stdin {
            cmd.stdin(Stdio::piped());
            let mut child = match cmd.spawn() {
                Ok(child) => child,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(SecretSpecError::ProviderOperationFailed(
                        "Proton Pass CLI (pass-cli) is not installed.\n\n\
                         Download it from: https://proton.me/pass/download\n\n\
                         After installation, run 'pass-cli login' to authenticate."
                            .to_string(),
                    ));
                }
                Err(e) => return Err(e.into()),
            };

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data.as_bytes())?;
            }

            child.wait_with_output()?
        } else {
            match cmd.output() {
                Ok(output) => output,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(SecretSpecError::ProviderOperationFailed(
                        "Proton Pass CLI (pass-cli) is not installed.\n\n\
                         Download it from: https://proton.me/pass/download\n\n\
                         After installation, run 'pass-cli login' to authenticate."
                            .to_string(),
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("This operation requires an authenticated client") {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Proton Pass authentication required. Please run 'pass-cli login' first."
                        .to_string(),
                ));
            }
            return Err(SecretSpecError::ProviderOperationFailed(stderr.to_string()));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))
    }
}

impl Provider for ProtonPassProvider {
    /// Convention items are titled by the title template,
    /// `{project}/{profile}/{key}` by default.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: self.format_item_title(project, profile, key),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        match (&self.config.vault_name, &self.config.title_template) {
            (None, _) => "protonpass".to_string(),
            (Some(vault), None) => format!("protonpass://{}", ProviderUrl::encode(vault)),
            (Some(vault), Some(template)) => format!(
                "protonpass://{}/{}",
                ProviderUrl::encode(vault),
                ProviderUrl::encode(template)
            ),
        }
    }

    /// `pass-cli test` probes the CLI's login session, which every instance
    /// using the same binary shares, so they share one preflight probe.
    fn auth_scope_key(&self) -> Option<String> {
        Some(self.cli_binary_path.clone())
    }

    fn set_reason(&self, reason: Option<String>) {
        *self.session_reason.lock().unwrap() = reason;
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let title = crate::provider::flat_item(self, addr)?;
        match self.run_pass_cli(
            &[
                "item",
                "view",
                "--vault-name",
                self.get_vault_name(),
                "--item-title",
                &title,
                "--output",
                "json",
            ],
            None,
        ) {
            Ok(output) => {
                let response: ProtonPassViewResponse = serde_json::from_str(&output)
                    .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))?;
                Ok(response
                    .item
                    .content
                    .note
                    .filter(|n| !n.is_empty())
                    .map(|n| SecretString::new(n.into())))
            }
            Err(SecretSpecError::ProviderOperationFailed(msg)) if msg.contains("No item found") => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let title = crate::provider::flat_item(self, addr)?;
        let maybe_existing_item = {
            let output = self.run_pass_cli(
                &["item", "list", self.get_vault_name(), "--output", "json"],
                None,
            )?;
            let response: ProtonPassListResponse =
                serde_json::from_str(&output).unwrap_or(ProtonPassListResponse { items: vec![] });
            response
                .items
                .into_iter()
                .find(|item| item.title() == Some(&*title))
        };

        if let Some(existing_item) = maybe_existing_item {
            self.run_pass_cli(
                &[
                    "item",
                    "delete",
                    "--share-id",
                    &existing_item.share_id,
                    "--item-id",
                    &existing_item.id,
                ],
                None,
            )?;
        }

        let template = serde_json::to_string(&ProtonPassNoteTemplate {
            title: title.into_owned(),
            note: value.expose_secret().to_string(),
        })
        .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))?;

        self.run_pass_cli(
            &[
                "item",
                "create",
                "note",
                "--vault-name",
                self.get_vault_name(),
                "--from-template",
                "-",
            ],
            Some(&template),
        )?;

        Ok(())
    }

    /// Serves every request, convention or `ref`, from one vault listing plus
    /// parallel `item view` calls for the titles that exist.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        use std::thread;

        if requests.is_empty() {
            return Ok(HashMap::new());
        }

        let mut titles = Vec::with_capacity(requests.len());
        for (name, addr) in requests {
            titles.push((*name, crate::provider::flat_item(self, *addr)?));
        }

        let list_response: ProtonPassListResponse = serde_json::from_str(&self.run_pass_cli(
            &["item", "list", self.get_vault_name(), "--output", "json"],
            None,
        )?)
        .unwrap_or(ProtonPassListResponse { items: vec![] });

        let item_map: HashMap<String, (String, String)> = list_response
            .items
            .into_iter()
            .filter_map(|item| {
                let title = item.title()?.to_string();
                Some((title, (item.share_id, item.id)))
            })
            .collect();

        let keys_to_fetch: Vec<(&str, String, String)> = titles
            .iter()
            .filter_map(|(name, title)| {
                item_map
                    .get(&**title)
                    .map(|(share_id, id)| (*name, share_id.clone(), id.clone()))
            })
            .collect();

        let cli_command = self.cli_binary_path.clone();
        let reason = self.agent_reason();

        let handles: Vec<_> = keys_to_fetch
            .into_iter()
            .map(|(key, share_id, id)| {
                let cmd = cli_command.clone();
                let reason = reason.clone();
                let key_owned = key.to_string();
                thread::spawn(move || {
                    let output = Self::pass_cli_command(&cmd, &reason)
                        .args([
                            "item",
                            "view",
                            "--share-id",
                            &share_id,
                            "--item-id",
                            &id,
                            "--output",
                            "json",
                        ])
                        .output();
                    match output {
                        Ok(output) if output.status.success() => {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            if let Ok(res) = serde_json::from_str::<ProtonPassViewResponse>(&stdout)
                            {
                                if let Some(note) = res.item.content.note.filter(|n| !n.is_empty())
                                {
                                    return Some((key_owned, SecretString::new(note.into())));
                                }
                            }
                            None
                        }
                        _ => None,
                    }
                })
            })
            .collect();

        let mut results = HashMap::new();
        for handle in handles {
            if let Ok(Some((key, value))) = handle.join() {
                results.insert(key, value);
            }
        }

        Ok(results)
    }
}

impl Default for ProtonPassProvider {
    fn default() -> Self {
        Self::new(ProtonPassConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn session_reason_is_used_and_trimmed() {
        let provider = ProtonPassProvider::default();
        provider.set_reason(Some("  deploy web frontend  ".to_string()));
        assert_eq!(provider.agent_reason(), "deploy web frontend");
    }

    #[test]
    fn set_reason_overwrites_previous_value() {
        // set_reason is last-write-wins: a later reason must replace an earlier one
        // (e.g. a default-reason build followed by an explicit reason).
        let provider = ProtonPassProvider::default();
        provider.set_reason(Some("first".to_string()));
        provider.set_reason(Some("second".to_string()));
        assert_eq!(provider.agent_reason(), "second");
    }

    #[test]
    fn resolve_reason_precedence() {
        let r = |s: Option<&str>, e: Option<&str>| {
            ProtonPassProvider::resolve_reason(s.map(str::to_string), e.map(str::to_string))
        };
        // Session reason wins and is trimmed.
        assert_eq!(r(Some("  session  "), Some("env")), "session");
        // Env value is used (and trimmed) when no session reason is set.
        assert_eq!(r(None, Some("  env reason  ")), "env reason");
        // A blank/whitespace session reason must NOT shadow a usable env value: it
        // falls through to `PROTON_PASS_AGENT_REASON` rather than the default.
        assert_eq!(r(Some("   "), Some("audit env reason")), "audit env reason");
        // With every source blank or absent, fall back to the versioned default.
        assert_eq!(r(Some("   "), None), DEFAULT_AGENT_REASON);
        assert_eq!(r(None, Some("   ")), DEFAULT_AGENT_REASON);
        assert_eq!(r(None, None), DEFAULT_AGENT_REASON);
    }

    #[test]
    fn default_reason_identifies_secretspec_with_version() {
        assert!(DEFAULT_AGENT_REASON.starts_with("secretspec/"));
        assert!(DEFAULT_AGENT_REASON.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn pass_cli_command_sets_agent_reason_env() {
        // Both the single-shot and batch-fetch paths build their command through
        // this helper, so verifying it wires PROTON_PASS_AGENT_REASON keeps the two
        // from drifting apart and silently re-introducing the >= 2.1.0 regression.
        let cmd = ProtonPassProvider::pass_cli_command("pass-cli", "deploy web");
        let found = cmd.get_envs().any(|(k, v)| {
            k.to_str() == Some(AGENT_REASON_ENV) && v.and_then(|v| v.to_str()) == Some("deploy web")
        });
        assert!(found, "PROTON_PASS_AGENT_REASON must be set on the command");
    }

    #[test]
    fn list_response_parses_legacy_nested_title() {
        // pass-cli <= 2.0.2: the title lives under a nested `content` object.
        let json =
            r#"{"items":[{"id":"i1","share_id":"s1","content":{"title":"proj/default/KEY"}}]}"#;
        let response: ProtonPassListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].title(), Some("proj/default/KEY"));
        assert_eq!(response.items[0].id, "i1");
        assert_eq!(response.items[0].share_id, "s1");
    }

    #[test]
    fn list_response_parses_top_level_title() {
        // pass-cli >= 2.0.3: the title is top-level and `content` is gone from
        // list output. Regression test for the issue where active secrets were
        // reported as missing because this shape failed to deserialize.
        let json = r#"{"items":[{"id":"i1","share_id":"s1","title":"proj/default/KEY","item_type":"note"}]}"#;
        let response: ProtonPassListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].title(), Some("proj/default/KEY"));
        assert_eq!(response.items[0].id, "i1");
        assert_eq!(response.items[0].share_id, "s1");
    }

    #[test]
    fn set_reason_reaches_provider_through_arc() {
        // Preflight-enabled providers are stored behind an `Arc`, so the reason
        // must propagate through the blanket `Provider for Arc<T>` impl.
        let provider: Arc<ProtonPassProvider> = Arc::new(ProtonPassProvider::default());
        Provider::set_reason(&provider, Some("via arc".to_string()));
        assert_eq!(provider.agent_reason(), "via arc");
    }

    /// A native address names the item title directly via `item`, bypassing
    /// the title template.
    #[test]
    fn native_address_names_the_title() {
        let p = ProtonPassProvider::new(ProtonPassConfig {
            title_template: Some("{project}/{key}".to_string()),
            ..Default::default()
        });
        let addr = crate::config::NativeAddress {
            item: "my api token".into(),
            ..Default::default()
        };
        assert_eq!(
            crate::provider::flat_item(&p, Address::Native(&addr)).unwrap(),
            "my api token"
        );
    }

    /// Note items carry the whole secret; a `field` coordinate is rejected.
    #[test]
    fn native_address_rejects_field() {
        let p = ProtonPassProvider::new(ProtonPassConfig::default());
        let addr = crate::config::NativeAddress {
            item: "my api token".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let err = crate::provider::flat_item(&p, Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }
}
