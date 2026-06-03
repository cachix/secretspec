use std::collections::HashMap;
use std::io::Write;
use std::io::{self};
use std::process::Command;
use std::process::Stdio;

use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use crate::MonosecretError;
use crate::Result;
use crate::provider::Provider;
use crate::provider::ProviderUrl;

// You can get the shape of pass-cli data with commands such as:
// $ pass-cli item view --output json
//   {"item": {"id": "...", "share_id": "...", "content": {"title": "...", "note": "..."}}}
//
// or:
// $ pass-cli item list <vault> --output json
//   {"items": [{"id": "...", "share_id": "...", "content": {"title": "...", "note": "..."}}]}
//
// We only use a limited subset of the full data.

#[derive(Deserialize)]
struct ProtonPassItemContent {
	title: String,
	note: Option<String>,
}

#[derive(Deserialize)]
struct ProtonPassItemData {
	id: String,
	share_id: String,
	content: ProtonPassItemContent,
}

#[derive(Deserialize)]
struct ProtonPassViewResponse {
	item: ProtonPassItemData,
}

#[derive(Deserialize)]
struct ProtonPassListResponse {
	items: Vec<ProtonPassItemData>,
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
	/// Target vault in Proton Pass. Defaults to "monosecret" when absent.
	pub vault_name: Option<String>,
	/// Item title format string. Supports {project}, {profile}, {key} placeholders.
	/// Defaults to "{project}/{profile}/{key}" when absent.
	pub title_template: Option<String>,
}

impl TryFrom<&ProviderUrl> for ProtonPassConfig {
	type Error = MonosecretError;

	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "protonpass" {
			return Err(MonosecretError::ProviderOperationFailed(format!(
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
/// Vault: configured in the URI (defaults to "monosecret", must be created prior to usage).
/// Item title: `{project}/{profile}/{key}` by default, customizable via the URI path.
pub struct ProtonPassProvider {
	config: ProtonPassConfig,
	/// Path to `pass-cli` binary.
	/// Override with the `MONOSECRET_PROTONPASS_CLI_PATH` environment variable.
	cli_binary_path: String,
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
		let cli_binary_path = std::env::var("MONOSECRET_PROTONPASS_CLI_PATH")
			.or_else(|_| std::env::var("SECRETSPEC_PROTONPASS_CLI_PATH"))
			.unwrap_or_else(|_| "pass-cli".to_string());
		Self {
			config,
			cli_binary_path,
		}
	}

	pub(crate) fn test_authentication(&self) -> Result<()> {
		self.run_pass_cli(&["test"], None)?;
		Ok(())
	}

	fn get_vault_name(&self) -> &str {
		self.config.vault_name.as_deref().unwrap_or("monosecret")
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

	fn run_pass_cli(&self, args: &[&str], stdin: Option<&str>) -> Result<String> {
		let mut cmd = Command::new(&self.cli_binary_path);
		cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

		let output = if let Some(data) = stdin {
			cmd.stdin(Stdio::piped());
			let mut child = match cmd.spawn() {
				Ok(child) => child,
				Err(e) if e.kind() == io::ErrorKind::NotFound => {
					return Err(MonosecretError::ProviderOperationFailed(
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
					return Err(MonosecretError::ProviderOperationFailed(
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
				return Err(MonosecretError::ProviderOperationFailed(
					"Proton Pass authentication required. Please run 'pass-cli login' first."
						.to_string(),
				));
			}
			return Err(MonosecretError::ProviderOperationFailed(stderr.to_string()));
		}

		String::from_utf8(output.stdout)
			.map_err(|e| MonosecretError::ProviderOperationFailed(e.to_string()))
	}
}

impl Provider for ProtonPassProvider {
	fn name(&self) -> &'static str {
		Self::PROVIDER_NAME
	}

	fn uri(&self) -> String {
		match (&self.config.vault_name, &self.config.title_template) {
			(None, _) => "protonpass".to_string(),
			(Some(vault), None) => format!("protonpass://{}", ProviderUrl::encode(vault)),
			(Some(vault), Some(template)) => {
				format!(
					"protonpass://{}/{}",
					ProviderUrl::encode(vault),
					ProviderUrl::encode(template)
				)
			}
		}
	}

	fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
		match self.run_pass_cli(
			&[
				"item",
				"view",
				"--vault-name",
				self.get_vault_name(),
				"--item-title",
				&self.format_item_title(project, profile, key),
				"--output",
				"json",
			],
			None,
		) {
			Ok(output) => {
				let response: ProtonPassViewResponse = serde_json::from_str(&output)
					.map_err(|e| MonosecretError::ProviderOperationFailed(e.to_string()))?;
				Ok(response
					.item
					.content
					.note
					.filter(|n| !n.is_empty())
					.map(|n| SecretString::new(n.into())))
			}
			Err(MonosecretError::ProviderOperationFailed(msg)) if msg.contains("No item found") => {
				Ok(None)
			}
			Err(e) => Err(e),
		}
	}

	fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
		let title = self.format_item_title(project, profile, key);
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
				.find(|item| item.content.title == title)
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
			title,
			note: value.expose_secret().to_string(),
		})
		.map_err(|e| MonosecretError::ProviderOperationFailed(e.to_string()))?;

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

	#[allow(clippy::collapsible_if)]
	fn get_batch(
		&self,
		project: &str,
		keys: &[&str],
		profile: &str,
	) -> Result<HashMap<String, SecretString>> {
		use std::thread;

		if keys.is_empty() {
			return Ok(HashMap::new());
		}

		let list_response: ProtonPassListResponse = serde_json::from_str(&self.run_pass_cli(
			&["item", "list", self.get_vault_name(), "--output", "json"],
			None,
		)?)
		.unwrap_or(ProtonPassListResponse { items: vec![] });

		let item_map: HashMap<String, (String, String)> = list_response
			.items
			.into_iter()
			.map(|item| (item.content.title, (item.share_id, item.id)))
			.collect();

		let keys_to_fetch: Vec<(&str, String, String)> = keys
			.iter()
			.filter_map(|key| {
				let title = self.format_item_title(project, profile, key);
				item_map
					.get(&title)
					.map(|(share_id, id)| (*key, share_id.clone(), id.clone()))
			})
			.collect();

		let cli_command = self.cli_binary_path.clone();

		let handles: Vec<_> = keys_to_fetch
			.into_iter()
			.map(|(key, share_id, id)| {
				let cmd = cli_command.clone();
				let key_owned = key.to_string();
				thread::spawn(move || {
					let output = Command::new(&cmd)
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
