//! Core secrets management functionality

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::env;
use std::io::IsTerminal;
use std::io::Read;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use colored::Colorize;
use secrecy::ExposeSecret;
use secrecy::SecretString;

use crate::audit::AuditAction;
use crate::audit::AuditContext;
use crate::audit::AuditLogger;
use crate::audit::AuditOutcome;
use crate::config::Config;
use crate::config::GlobalConfig;
use crate::config::Manifest;
use crate::config::Profile;
use crate::config::ProviderDependency;
use crate::config::ProviderRef;
use crate::config::RequireReason;
use crate::config::Resolved;
use crate::config::SecretRequest;
use crate::error::MonosecretError;
use crate::error::Result;
use crate::provider::Address;
use crate::provider::Provider as ProviderTrait;
use crate::provider::provider_from_spec_with_dependencies;
use crate::report::ResolutionReport;
use crate::report::ResolutionStatus;
use crate::report::SecretResolution;
use crate::resolve::RESOLVE_SCHEMA_VERSION;
use crate::resolve::ResolveResponse;
use crate::resolve::ResolvedSecret;
use crate::resolve::ResolvedSource;
use crate::validation::ValidatedSecrets;
use crate::validation::ValidationErrors;

fn redact_provider_uri(uri: &str) -> String {
	let Ok(mut parsed) = url::Url::parse(uri) else {
		return uri.to_string();
	};

	if !parsed.username().is_empty() {
		let _ = parsed.set_username("<redacted>");
	}
	if parsed.password().is_some() {
		let _ = parsed.set_password(Some("<redacted>"));
	}

	parsed.to_string()
}

/// Emits a warning when a provider in a fallback chain fails so the user
/// can see why a particular link was skipped, without aborting the chain.
fn warn_provider_failure(uri: &str, secret_name: &str, err: &MonosecretError) {
	let uri = redact_provider_uri(uri);
	tracing::warn!(
		provider = %uri,
		secret = %secret_name,
		error = %err,
		"provider failed while resolving secret"
	);
	eprintln!(
		"{} provider {} failed for {}: {}; trying next provider in chain",
		"warning:".yellow(),
		uri.bold(),
		secret_name.bold(),
		err
	);
}

/// Emits a warning when a primary provider cannot be constructed; affected
/// secrets will still be retried via their per-secret fallback chains below.
fn warn_primary_provider_failure(uri: Option<&str>, err: &MonosecretError) {
	let uri = uri.map_or_else(|| "<default>".to_string(), redact_provider_uri);
	tracing::warn!(provider = %uri, error = %err, "primary provider failed");
	eprintln!(
		"{} primary provider {} failed: {}; will try fallback chain for affected secrets",
		"warning:".yellow(),
		uri.bold(),
		err
	);
}

/// Emits a warning when an optimized batch lookup fails. The caller retries
/// each address so a request-specific failure cannot poison its healthy peers.
fn warn_primary_batch_failure(uri: Option<&str>, err: &MonosecretError) {
	let uri = uri.map_or_else(|| "<default>".to_string(), redact_provider_uri);
	tracing::warn!(provider = %uri, error = %err, "primary provider batch failed");
	eprintln!(
		"{} primary provider {} batch failed: {}; retrying addresses individually",
		"warning:".yellow(),
		uri.bold(),
		err
	);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Materialize {
	Values,
	None,
}

/// Walks up from the current directory looking for `monosecret.toml`.
fn find_config_file() -> Result<PathBuf> {
	let mut dir = env::current_dir()?;
	loop {
		let candidate = dir.join("monosecret.toml");
		if candidate.exists() {
			return Ok(candidate);
		}

		// Compatibility fallback for projects that have not renamed yet.
		let legacy_candidate = dir.join("secretspec.toml");
		if legacy_candidate.exists() {
			return Ok(legacy_candidate);
		}

		if !dir.pop() {
			return Err(MonosecretError::NoManifest);
		}
	}
}

fn env_var_with_legacy(name: &str, legacy_name: &str) -> Option<String> {
	env::var(name).ok().or_else(|| env::var(legacy_name).ok())
}

/// Monosecret's own opt-in for marking the current process as an agent. Lets any
/// harness that the `detect-coding-agent` crate does not recognize identify itself.
const AGENT_OPT_IN_ENV: &str = "MONOSECRET_AGENT";
const LEGACY_AGENT_OPT_IN_ENV: &str = "SECRETSPEC_AGENT";

/// The id of the detected coding agent (e.g. `"claude-code"`), or `None`.
pub(crate) fn detect_agent_id() -> Option<&'static str> {
	detect_coding_agent::detect().map(|agent| agent.id)
}

/// Whether monosecret is currently running as an AI coding agent.
pub(crate) fn running_as_agent() -> bool {
	env::var_os(AGENT_OPT_IN_ENV).is_some_and(|v| !v.is_empty())
		|| env::var_os(LEGACY_AGENT_OPT_IN_ENV).is_some_and(|v| !v.is_empty())
		|| detect_coding_agent::is_agent()
}

/// Pure policy decision: does `mode` require a reason given whether the caller is
/// an agent? Kept separate from [`running_as_agent`] so it is deterministically testable.
fn policy_requires_reason(mode: RequireReason, is_agent: bool) -> bool {
	match mode {
		RequireReason::Never => false,
		RequireReason::Always => true,
		RequireReason::Agents => is_agent,
	}
}

/// Environment variable holding the session reason for SDK/library callers.
const REASON_ENV: &str = "MONOSECRET_REASON";
const LEGACY_REASON_ENV: &str = "SECRETSPEC_REASON";

/// Normalizes a session reason: trims surrounding whitespace and treats a blank
/// result as "no reason given".
pub(crate) fn normalize_reason(reason: &str) -> Option<String> {
	let trimmed = reason.trim();
	(!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Resolves the session reason from the environment, normalized via
/// [`normalize_reason`]. An explicit [`Secrets::with_reason`] takes precedence.
fn env_reason() -> Option<String> {
	env_var_with_legacy(REASON_ENV, LEGACY_REASON_ENV)
		.as_deref()
		.and_then(normalize_reason)
}

/// The main entry point for the monosecret library
///
/// `Secrets` manages the loading, validation, and retrieval of secrets
/// based on the project and global configuration files.
///
/// # Example
///
/// ```no_run
/// use monosecret::Secrets;
///
/// // Load configuration and validate secrets
/// let mut spec = Secrets::load().unwrap();
/// spec.check(false).unwrap();
/// ```
pub struct Secrets {
	/// The project-specific configuration
	config: Config,
	/// Optional global user configuration
	global_config: Option<GlobalConfig>,
	/// The provider to use (if set via builder)
	provider: Option<String>,
	/// The profile to use (if set via builder)
	profile: Option<String>,
	/// Reason for this session's secret access, forwarded to providers that
	/// support audit logging (set via [`Secrets::with_reason`]).
	reason: Option<String>,
	/// Project policy (`[project].require_reason` in monosecret.toml) controlling
	/// when secret access requires an explicit reason.
	require_reason: RequireReason,
	/// Per-machine value-free audit sink.
	audit: Option<AuditLogger>,
}

impl Secrets {
	/// Creates a new `Secrets` instance with the given configurations
	///
	/// # Arguments
	///
	/// * `config` - The project configuration
	/// * `global_config` - Optional global user configuration
	/// * `provider` - Optional provider to use
	/// * `profile` - Optional profile to use
	///
	/// # Returns
	///
	/// A new `Secrets` instance
	#[cfg(test)]
	pub(crate) fn new(
		config: Config,
		global_config: Option<GlobalConfig>,
		provider: Option<String>,
		profile: Option<String>,
	) -> Self {
		Self {
			config,
			global_config,
			provider,
			profile,
			reason: None,
			require_reason: RequireReason::Never,
			audit: None,
		}
	}

	/// Loads a `Secrets` by walking up from the current directory to find `monosecret.toml`
	///
	/// This method searches the current directory and all parent directories for
	/// a `monosecret.toml` file, similar to how `cargo` and `git` find their configs.
	///
	/// # Returns
	///
	/// A loaded `Secrets` instance
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - No `monosecret.toml` file is found in the current or any parent directory
	/// - Configuration files are invalid
	/// - The project revision is unsupported
	///
	/// # Example
	///
	/// ```no_run
	/// use monosecret::Secrets;
	///
	/// let mut spec = Secrets::load().unwrap();
	/// spec.set_provider("keyring");
	/// spec.check(false).unwrap();
	/// ```
	pub fn load() -> Result<Self> {
		let config_path = find_config_file()?;
		Self::load_from(&config_path)
	}

	/// Loads a `Secrets` from an explicit config file path
	///
	/// Use this when the path to `monosecret.toml` is known, e.g. via the `--file` flag.
	///
	/// # Arguments
	///
	/// * `path` - Path to the `monosecret.toml` file
	pub fn load_from(path: &Path) -> Result<Self> {
		let project_config = Config::try_from(path)?;
		// Every entry point loads through here, so semantic validation must not be
		// left to individual commands or SDKs.
		project_config.validate()?;
		let global_config = GlobalConfig::load()?;
		let audit_config = global_config
			.as_ref()
			.and_then(|config| config.audit.clone())
			.unwrap_or_default();
		let audit = AuditLogger::from_config(&audit_config);
		Ok(Self {
			require_reason: project_config.project.require_reason.unwrap_or_default(),
			config: project_config,
			global_config,
			provider: None,
			profile: None,
			reason: env_reason(),
			audit,
		})
	}

	/// Sets the provider to use for secret operations
	///
	/// This overrides the provider from global configuration.
	///
	/// # Arguments
	///
	/// * `provider` - The provider name or URI (e.g., "keyring", "<dotenv:/path/to/.env>")
	///
	/// # Example
	///
	/// ```no_run
	/// use monosecret::Secrets;
	///
	/// let mut spec = Secrets::load().unwrap();
	/// spec.set_provider("dotenv:.env.production");
	/// spec.check(false).unwrap();
	/// ```
	pub fn set_provider(&mut self, provider: impl Into<String>) {
		self.provider = Some(provider.into());
	}

	/// Sets the profile to use for secret operations
	///
	/// This overrides the profile from global configuration.
	///
	/// # Arguments
	///
	/// * `profile` - The profile name (e.g., "development", "staging", "production")
	///
	/// # Example
	///
	/// ```no_run
	/// use monosecret::Secrets;
	///
	/// let mut spec = Secrets::load().unwrap();
	/// spec.set_profile("production");
	/// spec.check(false).unwrap();
	/// ```
	pub fn set_profile(&mut self, profile: impl Into<String>) {
		self.profile = Some(profile.into());
	}

	/// Returns a secret-value-free manifest for SDK code generation.
	pub fn manifest(&self) -> Manifest {
		self.config.to_manifest()
	}

	/// Sets a human-readable reason for this session's secret access.
	#[must_use]
	pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
		if let Some(reason) = normalize_reason(&reason.into()) {
			self.reason = Some(reason);
		}
		self
	}

	fn ensure_reason(&self) -> Result<()> {
		if self.reason.is_some() {
			return Ok(());
		}
		let is_agent = self.require_reason == RequireReason::Agents && running_as_agent();
		if policy_requires_reason(self.require_reason, is_agent) {
			return Err(MonosecretError::ReasonRequired);
		}
		Ok(())
	}

	#[allow(clippy::too_many_arguments)]
	fn record_secret_access(
		&self,
		action: AuditAction,
		key: &str,
		profile: &str,
		provider_uri: Option<String>,
		reference: Option<&crate::config::NativeAddress>,
		outcome: AuditOutcome,
		error_kind: Option<&str>,
	) {
		if let Some(audit) = &self.audit {
			audit.record(
				action,
				&AuditContext {
					project: &self.config.project.name,
					profile,
					key: Some(key),
					keys: &[],
					command: None,
					provider_uri,
					reference: reference.map(crate::config::NativeAddress::render),
					outcome,
					error_kind,
					reason: self.reason.as_deref(),
				},
			);
		}
	}

	fn build_provider(&self, spec: &str) -> Result<Box<dyn ProviderTrait>> {
		let provider = Box::<dyn ProviderTrait>::try_from(spec.to_string())?;
		provider.set_reason(self.reason.clone());
		Ok(provider)
	}

	/// Get the loaded project configuration for value-free code generation.
	#[allow(dead_code)]
	pub(crate) fn config(&self) -> &Config {
		&self.config
	}

	/// Get a reference to the global configuration (for testing)
	#[cfg(test)]
	pub(crate) fn global_config(&self) -> Option<&GlobalConfig> {
		self.global_config.as_ref()
	}

	/// Resolves the profile to use based on the provided value and configuration
	///
	/// Profile resolution order:
	/// 1. Provided profile argument
	/// 2. Profile set via `set_profile()`
	/// 3. `MONOSECRET_PROFILE` environment variable
	/// 4. Global configuration default profile
	/// 5. "default" profile
	///
	/// # Arguments
	///
	/// * `profile` - Optional profile name to use
	///
	/// # Returns
	///
	/// The resolved profile name
	pub(crate) fn resolve_profile_name(&self, profile: Option<&str>) -> String {
		profile
			.map(ToString::to_string)
			.or_else(|| self.profile.clone())
			.or_else(|| env_var_with_legacy("MONOSECRET_PROFILE", "SECRETSPEC_PROFILE"))
			.or_else(|| {
				self.global_config
					.as_ref()
					.and_then(|gc| gc.defaults.profile.clone())
			})
			.unwrap_or_else(|| "default".to_string())
	}

	/// Returns the named profile or an `InvalidProfile` error listing the profiles
	/// defined in `monosecret.toml`.
	fn require_profile(&self, profile_name: &str) -> Result<&Profile> {
		self.config.profiles.get(profile_name).ok_or_else(|| {
			let mut available: Vec<&str> =
				self.config.profiles.keys().map(String::as_str).collect();
			available.sort_unstable();
			MonosecretError::InvalidProfile(format!(
				"'{}' is not defined in monosecret.toml. Available profiles: {}",
				profile_name,
				available.join(", ")
			))
		})
	}

	/// Resolves the full profile configuration, merging with default profile if needed
	///
	/// # Arguments
	///
	/// * `profile` - Optional profile name to resolve (if None, uses resolved profile name)
	///
	/// # Returns
	///
	/// The resolved profile configuration
	pub(crate) fn resolve_profile(&self, profile: Option<&str>) -> Result<Profile> {
		let profile_name = profile.map_or_else(|| self.resolve_profile_name(None), str::to_string);
		let mut profile_config = self.require_profile(&profile_name)?.clone();

		// If not the default profile, also add secrets from default profile
		if profile_name != "default"
			&& let Some(default_profile) = self.config.profiles.get("default").cloned()
		{
			profile_config.merge_with(default_profile);
		}

		Ok(profile_config)
	}

	/// Resolves the configuration for a specific secret
	///
	/// This method looks for the secret in the specified profile, falling back
	/// to the default profile if not found. If the secret exists in both profiles,
	/// fields are merged with the current profile taking precedence.
	/// Profile defaults are also applied with lower precedence than explicit secret config.
	///
	/// Precedence order (highest to lowest):
	/// 1. Secret config in current profile
	/// 2. Secret config in default profile
	/// 3. Profile defaults from current profile
	///
	/// # Arguments
	///
	/// * `name` - The name of the secret
	/// * `profile` - Optional profile to search in (if None, uses resolved profile)
	///
	/// # Returns
	///
	/// The secret configuration if found (may be merged from multiple profiles)
	pub(crate) fn resolve_secret_config(
		&self,
		name: &str,
		profile: Option<&str>,
	) -> Option<crate::config::Secret> {
		let profile_name = self.resolve_profile_name(profile);

		let current_profile = self.config.profiles.get(&profile_name);
		let current_secret =
			current_profile.and_then(|profile_config| profile_config.secrets.get(name));
		let current_defaults =
			current_profile.and_then(|profile_config| profile_config.defaults.as_ref());

		let default_secret = if profile_name == "default" {
			None
		} else {
			self.config
				.profiles
				.get("default")
				.and_then(|default_profile| default_profile.secrets.get(name))
		};

		match (current_secret, default_secret) {
			(Some(current), Some(default)) => {
				// Merge: current profile takes precedence, then default profile, then profile defaults
				Some(crate::config::Secret {
					description: current
						.description
						.clone()
						.or_else(|| default.description.clone()),
					required: current
						.required
						.or(default.required)
						.or(current_defaults.and_then(|d| d.required)),
					default: current
						.default
						.clone()
						.or_else(|| default.default.clone())
						.or_else(|| current_defaults.and_then(|d| d.default.clone())),
					groups: current.groups.clone().or_else(|| default.groups.clone()),
					providers: current
						.providers
						.clone()
						.or_else(|| default.providers.clone())
						.or_else(|| {
							current_defaults.and_then(|d| {
								d.providers
									.clone()
									.map(|v| v.into_iter().map(ProviderRef::from).collect())
							})
						}),
					reference: current
						.reference
						.clone()
						.or_else(|| default.reference.clone()),
					as_path: current.as_path.or(default.as_path),
					secret_type: current
						.secret_type
						.clone()
						.or_else(|| default.secret_type.clone()),
					generate: current
						.generate
						.clone()
						.or_else(|| default.generate.clone()),
				})
			}
			(Some(secret), None) | (None, Some(secret)) => {
				// Apply profile defaults to the found secret
				Some(crate::config::Secret {
					description: secret.description.clone(),
					required: secret
						.required
						.or(current_defaults.and_then(|d| d.required)),
					default: secret
						.default
						.clone()
						.or_else(|| current_defaults.and_then(|d| d.default.clone())),
					groups: secret.groups.clone(),
					providers: secret.providers.clone().or_else(|| {
						current_defaults.and_then(|d| {
							d.providers
								.clone()
								.map(|v| v.into_iter().map(ProviderRef::from).collect())
						})
					}),
					reference: secret.reference.clone(),
					as_path: secret.as_path,
					secret_type: secret.secret_type.clone(),
					generate: secret.generate.clone(),
				})
			}
			(None, None) => None,
		}
	}

	/// Look up a provider alias to its URI, checking the project `[providers]`
	/// first (which now uses [`ProviderConfig`]) then the user-global config.
	fn lookup_provider_alias(&self, alias: &str) -> Option<String> {
		// Project-level config (can be ProviderConfig::Alias or Structured).
		if let Some(config) = self.config.providers.as_ref().and_then(|m| m.get(alias)) {
			return Some(config.uri().to_string());
		}
		// User-global config (still HashMap<String, String>).
		self.global_config
			.as_ref()
			.and_then(|gc| gc.defaults.providers.as_ref())
			.and_then(|m| m.get(alias))
			.cloned()
	}

	fn alias_for_provider_uri(&self, uri: &str) -> Option<String> {
		self.config.providers.as_ref().and_then(|providers| {
			providers
				.iter()
				.find(|(_, config)| config.uri() == uri)
				.map(|(alias, _)| alias.clone())
		})
	}

	fn provider_from_alias(
		&self,
		alias: &str,
		uri: &str,
		profile_name: &str,
	) -> Result<Box<dyn ProviderTrait>> {
		let dependencies = self.resolve_provider_requirements(alias, profile_name)?;
		let dependencies = dependencies
			.into_iter()
			.map(|(dep, value)| (dep.effective_as().to_string(), value))
			.collect::<Vec<_>>();

		let provider = provider_from_spec_with_dependencies(uri, &dependencies)?;
		provider.set_reason(self.reason.clone());
		Ok(provider)
	}

	fn provider_from_uri(&self, uri: &str, profile_name: &str) -> Result<Box<dyn ProviderTrait>> {
		match self.alias_for_provider_uri(uri) {
			Some(alias) => self.provider_from_alias(&alias, uri, profile_name),
			None => self.build_provider(uri),
		}
	}

	/// Resolves required secrets for a provider with `requires` declarations.
	///
	/// Returns a map from requirement key (e.g. `"service_token"`) to the
	/// resolved secret value.  Uses only bootstrap providers (those without
	/// their own `requires`) to avoid circular dependency problems.
	///
	/// Returns `Ok(HashMap)` on success, or an error if a required secret
	/// cannot be resolved.
	pub(crate) fn resolve_provider_requirements(
		&self,
		alias: &str,
		profile_name: &str,
	) -> Result<Vec<(ProviderDependency, SecretString)>> {
		let config = self.config.providers.as_ref().and_then(|m| m.get(alias));

		let dependencies = match config {
			Some(crate::config::ProviderConfig::Structured(s)) => &s.depends_on,
			_ => return Ok(Vec::new()),
		};

		if dependencies.is_empty() {
			return Ok(Vec::new());
		}

		let mut resolved = Vec::new();

		for dep in dependencies {
			let secret_name = &dep.secret;

			// Look up the required secret using only bootstrap providers.
			// We resolve the secret config but restrict to providers that have
			// no `requires` of their own (bootstrap providers).
			let secret_config = self
				.resolve_secret_config(secret_name, Some(profile_name))
				.ok_or_else(|| {
					MonosecretError::SecretNotFound(format!(
						"Provider '{alias}' requires secret '{secret_name}' but it is not defined in monosecret.toml"
					))
				})?;

			let provider_entries = self.resolve_read_provider_uris(&secret_config, None)?;
			let project_name = &self.config.project.name;

			let value = match provider_entries {
				Some(entries) if !entries.is_empty() => {
					match self.get_secret_from_providers(
						project_name,
						secret_name,
						profile_name,
						&secret_config,
						Some(&entries),
						None,
					)? {
						(Some(v), _) => v,
						(None, _) => {
							return Err(MonosecretError::ProviderOperationFailed(format!(
								"Provider '{alias}' requires secret '{secret_name}' but it was not found"
							)));
						}
					}
				}
				_ => {
					// Use default provider.
					let provider = self.get_provider(None)?;
					let address = secret_config.reference.as_ref().map_or_else(
						|| Address::convention(project_name, profile_name, secret_name),
						Address::Native,
					);
					match provider.get_address(address)? {
						Some(v) => v,
						None => {
							return Err(MonosecretError::ProviderOperationFailed(format!(
								"Provider '{alias}' requires secret '{secret_name}' but it was not found"
							)));
						}
					}
				}
			};

			resolved.push((dep.clone(), value));
		}

		Ok(resolved)
	}

	/// Returns the union of alias names known across all sources, sorted.
	fn known_provider_aliases(&self) -> Vec<String> {
		let mut names: Vec<String> = self
			.config
			.providers
			.iter()
			.flat_map(|m| m.keys())
			.chain(
				self.global_config
					.as_ref()
					.and_then(|gc| gc.defaults.providers.as_ref())
					.into_iter()
					.flat_map(|m| m.keys()),
			)
			.cloned()
			.collect::<HashSet<_>>()
			.into_iter()
			.collect();
		names.sort();
		names
	}

	/// Resolves a list of [`ProviderRef`]s to (URI, `SecretRequest`) pairs, preserving order.
	///
	/// Each [`ProviderRef`] contributes its resolved URI and any location hints
	/// (path, key) from [`ProviderRefDetail`].  Bare alias refs produce a default
	/// [`SecretRequest`].
	///
	/// # Errors
	///
	/// Returns an error if any provider alias is not defined in either the
	/// project or global config.
	pub(crate) fn resolve_provider_ref_uris(
		&self,
		provider_refs: Option<&[ProviderRef]>,
	) -> Result<Option<Vec<(String, SecretRequest)>>> {
		let Some(refs) = provider_refs else {
			return Ok(None);
		};
		let mut entries = Vec::with_capacity(refs.len());
		for r in refs {
			let alias = r.provider_alias();
			if alias.contains("://") {
				entries.push((alias.to_string(), SecretRequest::from_provider_ref(r)));
				continue;
			}
			if let Some(uri) = self.lookup_provider_alias(alias) {
				let request = SecretRequest::from_provider_ref(r);
				tracing::debug!(
					alias = %alias,
					provider = %redact_provider_uri(&uri),
					path = ?request.path,
					key = ?request.key,
					"resolved provider reference"
				);
				entries.push((uri, request));
			} else {
				let known = self.known_provider_aliases();
				let msg = if known.is_empty() {
					format!(
						"Provider alias '{alias}' is not defined. Declare it in [providers] in monosecret.toml or in the global config."
					)
				} else {
					format!(
						"Provider alias '{}' is not defined. Available aliases: {}",
						alias,
						known.join(", ")
					)
				};
				return Err(MonosecretError::ProviderNotFound(msg));
			}
		}
		Ok(Some(entries))
	}

	/// Resolves a list of provider aliases (from profile defaults) to URIs.
	/// Preserves order. Each alias is looked up via [`Self::lookup_provider_alias`].
	///
	/// # Errors
	///
	/// Returns an error if any alias is not defined.
	pub(crate) fn resolve_provider_aliases(
		&self,
		provider_aliases: Option<&[String]>,
	) -> Result<Option<Vec<String>>> {
		let Some(aliases) = provider_aliases else {
			return Ok(None);
		};
		let mut uris = Vec::with_capacity(aliases.len());
		for alias in aliases {
			if alias.contains("://") {
				uris.push(alias.clone());
				continue;
			}
			if let Some(uri) = self.lookup_provider_alias(alias) {
				uris.push(uri);
			} else {
				let known = self.known_provider_aliases();
				let msg = if known.is_empty() {
					format!(
						"Provider alias '{alias}' is not defined. Declare it in [providers] in monosecret.toml or in the global config."
					)
				} else {
					format!(
						"Provider alias '{}' is not defined. Available aliases: {}",
						alias,
						known.join(", ")
					)
				};
				return Err(MonosecretError::ProviderNotFound(msg));
			}
		}
		Ok(Some(uris))
	}

	/// Returns the explicit provider spec from caller arg, builder, or env, in
	/// that priority order.
	///
	/// Used as the shared head of provider resolution so the precedence between
	/// the `--provider` flag (forwarded via `set_provider`) and the
	/// `MONOSECRET_PROVIDER` env var stays consistent across resolvers.
	fn explicit_provider_spec(&self, override_arg: Option<&str>) -> Option<String> {
		override_arg
			.map(ToString::to_string)
			.or_else(|| self.provider.clone())
			.or_else(|| env_var_with_legacy("MONOSECRET_PROVIDER", "SECRETSPEC_PROVIDER"))
	}

	/// Returns the explicit provider override resolved to a URI, if one is set.
	///
	/// Resolves the explicit spec via [`Self::explicit_provider_spec`], then
	/// expands any matching alias via [`Self::lookup_provider_alias`].
	pub(crate) fn resolve_provider_override(&self, override_arg: Option<&str>) -> Option<String> {
		let spec = self.explicit_provider_spec(override_arg)?;
		Some(self.lookup_provider_alias(&spec).unwrap_or(spec))
	}

	/// Resolves the write target for a secret.
	///
	/// Resolution order:
	/// 1. Explicit override (`--provider` flag, `MONOSECRET_PROVIDER`, or builder)
	/// 2. First entry of the secret's `providers` chain
	/// 3. Default provider from global config
	pub(crate) fn resolve_write_provider(
		&self,
		secret_config: &crate::config::Secret,
		override_arg: Option<&str>,
	) -> Result<Box<dyn ProviderTrait>> {
		let profile_name = self.resolve_profile_name(None);

		if let Some(uri) = self.resolve_provider_override(override_arg) {
			return self.provider_from_uri(&uri, &profile_name);
		}
		if let Some(first_ref) = secret_config.providers.as_ref().and_then(|p| p.first()) {
			let alias = first_ref.provider_alias().to_string();
			let provider_uris =
				self.resolve_provider_aliases(Some(std::slice::from_ref(&alias)))?;
			let uri = provider_uris
				.and_then(|uris| uris.into_iter().next())
				.ok_or_else(|| {
					MonosecretError::ProviderNotFound(format!(
						"Provider alias '{alias}' could not be resolved"
					))
				})?;
			return self.provider_from_alias(&alias, &uri, &profile_name);
		}
		self.get_provider(None)
	}

	/// Resolves the read provider chain for a secret.
	///
	/// If an explicit override is set, returns just that single URI (no chain fallback).
	/// Otherwise, resolves the secret's `providers` chain to URIs, or returns `None`
	/// to indicate the default provider should be used.
	pub(crate) fn resolve_read_provider_uris(
		&self,
		secret_config: &crate::config::Secret,
		override_arg: Option<&str>,
	) -> Result<Option<Vec<(String, SecretRequest)>>> {
		if let Some(uri) = self.resolve_provider_override(override_arg) {
			return Ok(Some(vec![(uri, SecretRequest::default())]));
		}
		self.resolve_provider_ref_uris(secret_config.providers.as_deref())
	}

	/// Gets the provider instance to use for secret operations
	///
	/// Provider resolution order:
	/// 1. Provided provider argument
	/// 2. Provider set via builder (used by the CLI to forward `--provider`)
	/// 3. Environment variable (`MONOSECRET_PROVIDER`)
	/// 4. Global configuration default provider
	/// 5. Error if no provider is configured
	///
	/// # Arguments
	///
	/// * `provider_arg` - Optional provider specification (name or URI)
	///
	/// # Returns
	///
	/// A boxed provider instance
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - No provider is configured
	/// - The specified provider is not found
	pub(crate) fn get_provider(
		&self,
		provider_arg: Option<&str>,
	) -> Result<Box<dyn ProviderTrait>> {
		let provider_spec = self
			.explicit_provider_spec(provider_arg)
			.or_else(|| {
				self.global_config
					.as_ref()
					.and_then(|gc| gc.defaults.provider.clone())
			})
			.map(|spec| self.lookup_provider_alias(&spec).unwrap_or(spec))
			.ok_or(MonosecretError::NoProviderConfigured)?;

		let profile_name = self.resolve_profile_name(None);
		self.provider_from_uri(&provider_spec, &profile_name)
	}

	/// Returns a provider URI for validation result metadata without forcing a
	/// user-global default when every secret used an explicit or per-secret provider.
	fn validation_report_provider_uri(
		&self,
		override_uri: Option<&str>,
		secret_primary_uris: &HashMap<String, Option<String>>,
	) -> Result<String> {
		if let Some(uri) = override_uri {
			return Ok(uri.to_string());
		}

		if secret_primary_uris.values().any(Option::is_none) {
			return self.get_provider(None).map(|provider| provider.uri());
		}

		let mut provider_uris: Vec<&String> = secret_primary_uris
			.values()
			.filter_map(Option::as_ref)
			.collect();
		provider_uris.sort();

		if let Some(uri) = provider_uris.first() {
			return Ok((*uri).clone());
		}

		self.get_provider(None).map(|provider| provider.uri())
	}

	/// Gets a secret from a list of providers with fallback.
	///
	/// Tries each provider in order until one has the secret. Errors from a
	/// provider (e.g. authentication failure, network error) are treated like
	/// "not found" so the chain continues; a warning is emitted and the next
	/// provider is tried. If every provider errored without any reporting a
	/// healthy "not found", the last error is returned so the user sees why
	/// the secret could not be retrieved.
	///
	/// If no provider URIs are specified, falls back to the global provider.
	///
	/// # Arguments
	///
	/// * `project_name` - The project name
	/// * `secret_name` - The secret name
	/// * `profile_name` - The profile name
	/// * `provider_uris` - Optional list of provider URIs to try in order
	/// * `default_provider_arg` - Optional default provider if no URIs provided
	///
	/// # Returns
	///
	/// The secret value if found in any provider, or None if not found in any
	fn get_secret_from_providers(
		&self,
		project_name: &str,
		secret_name: &str,
		profile_name: &str,
		secret_config: &crate::config::Secret,
		provider_entries: Option<&[(String, SecretRequest)]>,
		default_provider_arg: Option<&str>,
	) -> Result<(Option<SecretString>, Option<String>)> {
		let address = secret_config.reference.as_ref().map_or_else(
			|| Address::convention(project_name, profile_name, secret_name),
			Address::Native,
		);

		// If provider entries are specified, try them in order
		if let Some(entries) = provider_entries {
			let mut last_error: Option<MonosecretError> = None;
			let mut any_healthy = false;
			for (uri, request) in entries {
				tracing::debug!(
					provider = %redact_provider_uri(uri),
					secret = %secret_name,
					profile = %profile_name,
					path = ?request.path,
					key = ?request.key,
					"attempting provider lookup"
				);
				let provider = match self.provider_from_uri(uri, profile_name) {
					Ok(p) => p,
					Err(e) => {
						warn_provider_failure(uri, secret_name, &e);
						last_error = Some(e);
						continue;
					}
				};
				let result = if secret_config.reference.is_some() {
					provider.get_address(address)
				} else {
					provider.get_with_request(project_name, secret_name, profile_name, request)
				};
				match result {
					Ok(Some(value)) => {
						tracing::debug!(provider = %redact_provider_uri(uri), secret = %secret_name, "provider lookup found secret");
						return Ok((Some(value), Some(redact_provider_uri(&provider.uri()))));
					}
					Ok(None) => {
						any_healthy = true;
					}
					Err(e) => {
						warn_provider_failure(uri, secret_name, &e);
						last_error = Some(e);
					}
				}
			}
			// Surface the last error only if no provider in the chain returned
			// a healthy "not found" — otherwise the secret is genuinely missing.
			match last_error {
				Some(e) if !any_healthy => Err(e),
				_ => {
					Ok((
						None,
						entries.last().map(|(uri, _)| redact_provider_uri(uri)),
					))
				}
			}
		} else {
			// No per-secret providers, use default provider
			let backend = self.get_provider(default_provider_arg)?;
			let uri = redact_provider_uri(&backend.uri());
			backend.get_address(address).map(|value| (value, Some(uri)))
		}
	}

	/// Sets a secret value in the provider
	///
	/// If no value is provided, the user will be prompted to enter it securely.
	///
	/// # Arguments
	///
	/// * `name` - The name of the secret to set
	/// * `value` - Optional value to set (prompts if None)
	/// * `provider_arg` - Optional provider to use
	/// * `profile` - Optional profile to use
	///
	/// # Returns
	///
	/// `Ok(())` if the secret was successfully set
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The secret is not defined in the specification
	/// - The provider doesn't support setting values
	/// - The storage operation fails
	///
	/// # Example
	///
	/// ```no_run
	/// use monosecret::Secrets;
	///
	/// let mut spec = Secrets::load().unwrap();
	/// spec.set("DATABASE_URL", Some("postgres://localhost".to_string())).unwrap();
	/// ```
	pub fn set(&self, name: &str, value: Option<String>) -> Result<()> {
		self.ensure_reason()?;
		// Check if the secret exists in the spec
		let profile_name = self.resolve_profile_name(None);
		self.require_profile(&profile_name)?;

		// Check if the secret exists in the profile or is inherited from default
		let Some(secret_config) = self.resolve_secret_config(name, None) else {
			let profile = self.resolve_profile(Some(&profile_name))?;
			let mut available_secrets = profile
				.into_iter()
				.map(|(name, _)| name)
				.collect::<Vec<_>>();
			available_secrets.sort();

			return Err(MonosecretError::SecretNotFound(format!(
				"Secret '{}' is not defined in profile '{}'. Available secrets: {}",
				name,
				profile_name,
				available_secrets.join(", ")
			)));
		};

		let (backend, write_request) = if self.resolve_provider_override(None).is_none() {
			if let Some(first_ref) = secret_config.providers.as_ref().and_then(|p| p.first()) {
				let alias = first_ref.provider_alias().to_string();
				let provider_uris = self
					.resolve_provider_aliases(Some(std::slice::from_ref(&alias)))?
					.expect("provider aliases are supplied");
				let uri = provider_uris
					.into_iter()
					.next()
					.expect("provider alias resolution returns one URI per alias");
				(
					self.provider_from_alias(&alias, &uri, &profile_name)?,
					SecretRequest::from_provider_ref(first_ref),
				)
			} else {
				(
					self.resolve_write_provider(&secret_config, None)?,
					SecretRequest::default(),
				)
			}
		} else {
			(
				self.resolve_write_provider(&secret_config, None)?,
				SecretRequest::default(),
			)
		};

		if !backend.allows_set() {
			return Err(MonosecretError::ProviderOperationFailed(format!(
				"Provider '{}' is read-only and does not support setting values",
				backend.name()
			)));
		}

		let value = if let Some(v) = value {
			SecretString::new(v.into())
		} else if io::stdin().is_terminal() {
			let secret = inquire::Password::new(&format!(
				"Enter value for {name} (profile: {profile_name}):"
			))
			.without_confirmation()
			.prompt()?;
			SecretString::new(secret.into())
		} else {
			// Read from stdin when input is piped
			let mut buffer = String::new();
			io::stdin().read_to_string(&mut buffer)?;
			SecretString::new(buffer.trim().to_string().into())
		};

		if value.expose_secret().is_empty() {
			return Err(MonosecretError::ProviderOperationFailed(
				"Secret value cannot be empty".to_string(),
			));
		}

		let address = secret_config.reference.as_ref().map_or_else(
			|| Address::convention(&self.config.project.name, &profile_name, name),
			Address::Native,
		);
		let result = backend.check_writable(address).and_then(|()| {
			if secret_config.reference.is_some() {
				backend.set_address(address, &value)
			} else {
				backend.set_with_request(
					&self.config.project.name,
					name,
					&value,
					&profile_name,
					&write_request,
				)
			}
		});
		self.record_secret_access(
			AuditAction::Set,
			name,
			&profile_name,
			Some(backend.uri()),
			secret_config.reference.as_ref(),
			if result.is_ok() {
				AuditOutcome::Written
			} else {
				AuditOutcome::Error
			},
			result.as_ref().err().map(MonosecretError::kind),
		);
		result?;
		eprintln!(
			"{} Secret '{}' saved to {} (profile: {})",
			"✓".green(),
			name,
			backend.name(),
			profile_name
		);

		Ok(())
	}

	/// Retrieves and prints a secret value
	///
	/// This method retrieves a secret from the storage backend and prints it
	/// to stdout. If the secret is not found but has a default value, the
	/// default is printed.
	///
	/// # Arguments
	///
	/// * `name` - The name of the secret to retrieve
	/// * `provider_arg` - Optional provider to use
	/// * `profile` - Optional profile to use
	///
	/// # Returns
	///
	/// `Ok(())` if the secret was found and printed
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The secret is not defined in the specification
	/// - The secret is not found and has no default value
	pub fn get(&self, name: &str) -> Result<()> {
		self.ensure_reason()?;
		let profile_name = self.resolve_profile_name(None);
		let secret_config = self
			.resolve_secret_config(name, None)
			.ok_or_else(|| MonosecretError::SecretNotFound(name.to_string()))?;
		let default = secret_config.default.clone();
		let as_path = secret_config.as_path.unwrap_or(false);

		let provider_uris = self.resolve_read_provider_uris(&secret_config, None)?;

		let result = self.get_secret_from_providers(
			&self.config.project.name,
			name,
			&profile_name,
			&secret_config,
			provider_uris.as_deref(),
			None,
		);
		if let Err(error) = &result {
			self.record_secret_access(
				AuditAction::Get,
				name,
				&profile_name,
				None,
				secret_config.reference.as_ref(),
				AuditOutcome::Error,
				Some(error.kind()),
			);
		}
		match result? {
			(Some(value), source) => {
				self.record_secret_access(
					AuditAction::Get,
					name,
					&profile_name,
					source,
					secret_config.reference.as_ref(),
					AuditOutcome::Found,
					None,
				);
				if as_path {
					// Write to temp file and persist it (don't auto-delete)
					let (temp_file, _path_str) = Self::write_secret_to_temp_file(&value)?;
					let temp_path = temp_file.into_temp_path();
					let persisted_path = temp_path.keep().map_err(|e| {
						MonosecretError::Io(io::Error::other(format!(
							"Failed to persist temporary file: {e}"
						)))
					})?;
					println!("{}", persisted_path.display());
				} else {
					// Use expose_secret() to access the actual value for printing
					println!("{}", value.expose_secret());
				}
				Ok(())
			}
			(None, source) => {
				self.record_secret_access(
					AuditAction::Get,
					name,
					&profile_name,
					source,
					secret_config.reference.as_ref(),
					if default.is_some() {
						AuditOutcome::Default
					} else {
						AuditOutcome::Missing
					},
					None,
				);
				if let Some(default_value) = default {
					if as_path {
						// Write default value to temp file and persist it
						let (temp_file, _) = Self::write_secret_to_temp_file(&SecretString::new(
							default_value.into(),
						))?;
						let temp_path = temp_file.into_temp_path();
						let persisted_path = temp_path.keep().map_err(|e| {
							MonosecretError::Io(io::Error::other(format!(
								"Failed to persist temporary file: {e}"
							)))
						})?;
						println!("{}", persisted_path.display());
					} else {
						println!("{default_value}");
					}
					Ok(())
				} else {
					Err(MonosecretError::SecretNotFound(name.to_string()))
				}
			}
		}
	}

	/// Ensures all required secrets are present, optionally prompting for missing ones
	///
	/// This method validates all secrets and, in interactive mode, prompts the
	/// user to provide values for any missing required secrets.
	///
	/// # Arguments
	///
	/// * `provider_arg` - Optional provider to use
	/// * `profile` - Optional profile to use
	/// * `interactive` - Whether to prompt for missing secrets
	///
	/// # Returns
	///
	/// A `ValidatedSecrets` with the final state of all secrets
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - Required secrets are missing and interactive mode is disabled
	/// - Storage operations fail
	#[allow(clippy::needless_pass_by_value)]
	pub fn ensure_secrets(
		&self,
		provider_arg: Option<String>,
		profile: Option<String>,
		interactive: bool,
	) -> Result<ValidatedSecrets> {
		self.ensure_secrets_selected(
			provider_arg.as_deref(),
			profile.as_deref(),
			interactive,
			None,
		)
	}

	fn ensure_secrets_selected(
		&self,
		provider_arg: Option<&str>,
		profile: Option<&str>,
		interactive: bool,
		selected_names: Option<&HashSet<String>>,
	) -> Result<ValidatedSecrets> {
		let profile_display = self.resolve_profile_name(profile);

		// First validate to see what's missing
		let validation_result = self.validate_selected(selected_names, Materialize::Values)?;

		match validation_result {
			Ok(valid_secrets) => Ok(valid_secrets),
			Err(validation_errors) => {
				// If we're in interactive mode and have missing required secrets, prompt for them
				if interactive && !validation_errors.missing_required.is_empty() {
					if !io::stdin().is_terminal() {
						return Err(MonosecretError::RequiredSecretMissing(
							validation_errors.missing_required.join(", "),
						));
					}

					self.prompt_and_store_missing(
						&validation_errors.missing_required,
						&profile_display,
						provider_arg,
						|msg| {
							inquire::Password::new(msg)
								.without_confirmation()
								.prompt()
								.map_err(Into::into)
						},
					)?;

					// Re-validate to get the updated results
					match self.validate()? {
						Ok(valid_secrets) => Ok(valid_secrets),
						Err(still_errors) => {
							Err(MonosecretError::RequiredSecretMissing(
								still_errors.missing_required.join(", "),
							))
						}
					}
				} else {
					// Not interactive or no missing required secrets
					Err(MonosecretError::RequiredSecretMissing(
						validation_errors.missing_required.join(", "),
					))
				}
			}
		}
	}

	/// Lists each missing required secret and prompts for a value, storing it in
	/// the resolved write provider.
	///
	/// Extracted from [`Self::ensure_secrets_selected`] so the prompt loop can be
	/// tested without a real terminal by injecting the password reader.
	pub(crate) fn prompt_and_store_missing(
		&self,
		missing: &[String],
		profile_display: &str,
		provider_arg: Option<&str>,
		read_password: impl Fn(&str) -> Result<String>,
	) -> Result<()> {
		let total = missing.len();
		let default_backend = self.get_provider(provider_arg)?;

		eprintln!(
			"\n{} required {} missing in profile {} with provider {}:\n",
			total,
			if total == 1 {
				"secret is"
			} else {
				"secrets are"
			},
			profile_display.bold(),
			default_backend.name().bold(),
		);
		for secret_name in missing {
			let description = self
				.resolve_secret_config(secret_name, Some(profile_display))
				.and_then(|c| c.description)
				.unwrap_or_default();
			if description.is_empty() {
				eprintln!("  {} {}", "-".dimmed(), secret_name.bold());
			} else {
				eprintln!(
					"  {} {} - {}",
					"-".dimmed(),
					secret_name.bold(),
					description
				);
			}
		}
		eprintln!();

		for (i, secret_name) in missing.iter().enumerate() {
			if let Some(secret_config) =
				self.resolve_secret_config(secret_name, Some(profile_display))
			{
				let prompt_msg = format!("[{}/{}] Enter value for {}:", i + 1, total, secret_name);
				let value = read_password(&prompt_msg)?;

				let backend = self.resolve_write_provider(&secret_config, provider_arg)?;
				let value = SecretString::new(value.into());
				let address = secret_config.reference.as_ref().map_or_else(
					|| Address::convention(&self.config.project.name, profile_display, secret_name),
					Address::Native,
				);
				let result = if secret_config.reference.is_some() {
					backend.set_address(address, &value)
				} else {
					let request = secret_config
						.providers
						.as_ref()
						.and_then(|providers| providers.first())
						.map(SecretRequest::from_provider_ref)
						.unwrap_or_default();
					backend.set_with_request(
						&self.config.project.name,
						secret_name,
						&value,
						profile_display,
						&request,
					)
				};
				self.record_secret_access(
					AuditAction::Set,
					secret_name,
					profile_display,
					Some(backend.uri()),
					secret_config.reference.as_ref(),
					if result.is_ok() {
						AuditOutcome::Written
					} else {
						AuditOutcome::Error
					},
					result.as_ref().err().map(MonosecretError::kind),
				);
				result?;
				eprintln!(
					"{} Secret '{}' saved to {} (profile: {})",
					"✓".green(),
					secret_name,
					backend.name(),
					profile_display
				);
			}
		}

		eprintln!("\nAll required secrets have been set.");
		Ok(())
	}

	/// Checks the status of all secrets and optionally prompts for missing required ones
	///
	/// This method displays the status of all secrets defined in the specification,
	/// showing which are present, missing, or using defaults. Unless `no_prompt` is set,
	/// it then prompts the user to provide values for any missing required secrets.
	///
	/// # Arguments
	///
	/// * `no_prompt` - If true, don't prompt for missing secrets and return an error instead
	///
	/// # Returns
	///
	/// A `ValidatedSecrets` if all required secrets are present
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The provider cannot be initialized
	/// - Storage operations fail
	/// - Required secrets are missing (when `no_prompt` is true)
	///
	/// # Example
	///
	/// ```no_run
	/// use monosecret::Secrets;
	///
	/// let mut spec = Secrets::load().unwrap();
	/// let validated = spec.check(false).unwrap();
	/// ```
	pub fn check(&self, no_prompt: bool) -> Result<ValidatedSecrets> {
		self.ensure_reason()?;
		let profile_display = self.resolve_profile_name(None);

		eprintln!(
			"Checking secrets in {} (profile: {})...\n",
			self.config.project.name.bold(),
			profile_display.cyan()
		);

		// Validate and display results
		match self.validate()? {
			Ok(valid) => {
				self.display_validation_success(&valid)?;
				// All secrets present - return early without re-validating
				Ok(valid)
			}
			Err(errors) => {
				self.display_validation_errors(&errors)?;
				// Missing secrets - prompt if interactive (and not no_prompt) and re-validate
				self.ensure_secrets(None, None, !no_prompt)
			}
		}
	}

	/// Display validation success results
	fn display_validation_success(&self, valid: &ValidatedSecrets) -> Result<()> {
		let profile = self.resolve_profile(Some(&valid.resolved.profile))?;
		let mut found_count = 0;
		let mut optional_count = 0;
		let default_names = valid
			.with_defaults
			.iter()
			.map(|(name, _)| name)
			.collect::<HashSet<_>>();
		let missing_optional: HashSet<&String> = valid.missing_optional.iter().collect();

		let mut sorted_profile: Vec<_> = profile.into_iter().collect();
		sorted_profile.sort_by(|a, b| a.0.cmp(&b.0));
		for (name, config) in &sorted_profile {
			if missing_optional.contains(&name) {
				optional_count += 1;
				eprintln!(
					"{} {} - {} {}",
					"○".blue(),
					name,
					config.description.as_deref().unwrap_or("No description"),
					"(optional)".blue()
				);
			} else if config.default.is_some() && default_names.contains(&name) {
				found_count += 1;
				eprintln!(
					"{} {} - {} {}",
					"○".yellow(),
					name,
					config.description.as_deref().unwrap_or("No description"),
					"(has default)".yellow()
				);
			} else {
				found_count += 1;
				eprintln!(
					"{} {} - {}",
					"✓".green(),
					name,
					config.description.as_deref().unwrap_or("No description")
				);
			}
		}

		eprintln!("\n{}", Self::format_summary(found_count, 0, optional_count));

		Ok(())
	}

	/// Display validation error results
	fn display_validation_errors(&self, errors: &ValidationErrors) -> Result<()> {
		let profile = self.resolve_profile(Some(&errors.profile))?;
		let mut found_count = 0;
		let mut missing_count = 0;
		let mut optional_count = 0;
		let default_names = errors
			.with_defaults
			.iter()
			.map(|(name, _)| name)
			.collect::<HashSet<_>>();

		let mut sorted_profile: Vec<_> = profile.into_iter().collect();
		sorted_profile.sort_by(|a, b| a.0.cmp(&b.0));
		for (name, config) in &sorted_profile {
			if errors.missing_required.contains(name) {
				missing_count += 1;
				eprintln!(
					"{} {} - {} {}",
					"✗".red(),
					name,
					config.description.as_deref().unwrap_or("No description"),
					"(required)".red()
				);
			} else if errors.missing_optional.contains(name) {
				optional_count += 1;
				eprintln!(
					"{} {} - {} {}",
					"○".blue(),
					name,
					config.description.as_deref().unwrap_or("No description"),
					"(optional)".blue()
				);
			} else {
				found_count += 1;
				if default_names.contains(name) {
					eprintln!(
						"{} {} - {} {}",
						"○".yellow(),
						name,
						config.description.as_deref().unwrap_or("No description"),
						"(has default)".yellow()
					);
				} else {
					eprintln!(
						"{} {} - {}",
						"✓".green(),
						name,
						config.description.as_deref().unwrap_or("No description")
					);
				}
			}
		}

		eprintln!(
			"\n{}",
			Self::format_summary(found_count, missing_count, optional_count)
		);

		Ok(())
	}

	/// Build the trailing "Summary: X found, Y missing[, Z optional]" line.
	/// The `optional` segment is appended only when at least one optional
	/// secret is unset, so the all-set output keeps its previous two-segment
	/// form.
	pub(crate) fn format_summary(found: usize, missing: usize, optional: usize) -> String {
		if optional > 0 {
			format!(
				"Summary: {} found, {} missing, {} optional",
				found.to_string().green(),
				missing.to_string().red(),
				optional.to_string().blue()
			)
		} else {
			format!(
				"Summary: {} found, {} missing",
				found.to_string().green(),
				missing.to_string().red()
			)
		}
	}

	/// Imports secrets from one provider to another
	///
	/// This method copies all secrets defined in the specification from the
	/// source provider to the default provider configured in the global settings.
	///
	/// # Arguments
	///
	/// * `from_provider` - The provider specification to import from
	///
	/// # Returns
	///
	/// `Ok(())` if the import completes (even if some secrets were not found)
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The source provider cannot be initialized
	/// - The target provider cannot be initialized
	/// - Storage operations fail
	///
	/// # Example
	///
	/// ```no_run
	/// use monosecret::Secrets;
	///
	/// let spec = Secrets::load().unwrap();
	/// spec.import("dotenv://.env.production").unwrap();
	/// ```
	pub fn import(&self, from_provider: &str) -> Result<()> {
		self.ensure_reason()?;
		// Resolve profile (checks env var, then global config, then defaults to "default")
		let profile_display = self.resolve_profile_name(None);

		// Create the "from" provider and check availability
		let from_provider_instance = self.provider_from_uri(from_provider, &profile_display)?;

		eprintln!(
			"Importing secrets from {} (profile: {})...\n",
			from_provider.blue(),
			profile_display.cyan()
		);

		let mut imported = 0;
		let mut already_exists = 0;
		let mut not_found = 0;

		// Collect all secrets to import - from current profile and default profile
		// This ensures we can import secrets defined in default profile when using other profiles
		let profile = self.resolve_profile(Some(&profile_display))?;

		// Process each secret using proper profile resolution
		for (name, config) in profile {
			let secret_config = self
				.resolve_secret_config(&name, Some(&profile_display))
				.expect("Secret should exist since we're iterating over it");

			let to_provider = self.resolve_write_provider(&secret_config, None)?;
			let address = secret_config.reference.as_ref().map_or_else(
				|| Address::convention(&self.config.project.name, &profile_display, &name),
				Address::Native,
			);

			// The same address applies to source and target; `ref` changes naming,
			// never routing.
			match from_provider_instance.get_address(address)? {
				Some(value) => {
					// Secret exists in "from" provider, check if it exists in "to" provider
					if to_provider.get_address(address)?.is_some() {
						eprintln!(
							"{} {} - {} {} (→ {})",
							"○".yellow(),
							name,
							config.description.as_deref().unwrap_or("No description"),
							"(already exists in target)".yellow(),
							to_provider.name().blue()
						);
						already_exists += 1;
					} else {
						// Secret doesn't exist in "to" provider, import it
						let result = to_provider.set_address(address, &value);
						self.record_secret_access(
							AuditAction::Set,
							&name,
							&profile_display,
							Some(to_provider.uri()),
							secret_config.reference.as_ref(),
							if result.is_ok() {
								AuditOutcome::Written
							} else {
								AuditOutcome::Error
							},
							result.as_ref().err().map(MonosecretError::kind),
						);
						result?;
						eprintln!(
							"{} {} - {} (→ {})",
							"✓".green(),
							name,
							config.description.as_deref().unwrap_or("No description"),
							to_provider.name().blue()
						);
						imported += 1;
					}
				}
				None => {
					// Secret doesn't exist in "from" provider
					// Check if it exists in the "to" provider
					if to_provider.get_address(address)?.is_some() {
						eprintln!(
							"{} {} - {} {} (→ {})",
							"○".blue(),
							name,
							config.description.as_deref().unwrap_or("No description"),
							"(already in target, not in source)".blue(),
							to_provider.name().blue()
						);
						already_exists += 1;
					} else {
						eprintln!(
							"{} {} - {} {}",
							"✗".red(),
							name,
							config.description.as_deref().unwrap_or("No description"),
							"(not found in source)".red()
						);
						not_found += 1;
					}
				}
			}
		}

		eprintln!(
			"\nSummary: {} imported, {} already exists, {} not found in source",
			imported.to_string().green(),
			already_exists.to_string().yellow(),
			not_found.to_string().red()
		);

		if imported > 0 {
			eprintln!(
				"\n{} Successfully imported {} secrets from {}",
				"✓".green(),
				imported,
				from_provider,
			);
		}

		Ok(())
	}

	/// Resolves a writable provider for a secret.
	///
	/// Uses the first provider from the secret's provider list if specified,
	/// otherwise falls back to the default provider.
	fn get_writable_provider_for_secret(
		&self,
		secret_config: &crate::config::Secret,
	) -> Result<Box<dyn ProviderTrait>> {
		let backend = self.resolve_write_provider(secret_config, None)?;

		if !backend.allows_set() {
			return Err(MonosecretError::ProviderOperationFailed(format!(
				"Provider '{}' is read-only and cannot store generated secrets",
				backend.name()
			)));
		}

		Ok(backend)
	}

	/// Attempts to generate a secret if it has generation config.
	///
	/// Returns `Ok(Some(value))` if generation succeeded,
	/// `Ok(None)` if generation is not configured,
	/// or `Err` if generation was configured but failed.
	fn try_generate_secret(
		&self,
		name: &str,
		secret_config: &crate::config::Secret,
		profile_name: &str,
	) -> Result<Option<SecretString>> {
		let gen_config = match &secret_config.generate {
			Some(config) if config.is_enabled() => config,
			_ => return Ok(None),
		};

		let secret_type = match &secret_config.secret_type {
			Some(t) => t.as_str(),
			None => {
				return Err(MonosecretError::GenerationFailed(format!(
					"Secret '{name}' has generate config but no type"
				)));
			}
		};

		let value = crate::generator::generate(secret_type, gen_config)?;

		// Store at the same native or conventional address used for reads.
		let backend = self.get_writable_provider_for_secret(secret_config)?;
		let address = secret_config.reference.as_ref().map_or_else(
			|| Address::convention(&self.config.project.name, profile_name, name),
			Address::Native,
		);
		let result = backend.set_address(address, &value);
		self.record_secret_access(
			AuditAction::Set,
			name,
			profile_name,
			Some(backend.uri()),
			secret_config.reference.as_ref(),
			if result.is_ok() {
				AuditOutcome::Written
			} else {
				AuditOutcome::Error
			},
			result.as_ref().err().map(MonosecretError::kind),
		);
		result?;

		eprintln!(
			"{} {} - generated and saved to {} (profile: {})",
			"✓".green(),
			name,
			backend.name(),
			profile_name
		);

		Ok(Some(value))
	}

	/// Writes a secret value to a temporary file and returns the file handle and path
	///
	/// # Arguments
	///
	/// * `secret` - The secret value to write
	///
	/// # Returns
	///
	/// A tuple containing the temporary file handle and the path as a string
	///
	/// # Errors
	///
	/// Returns an error if the temporary file cannot be created or written to
	fn write_secret_to_temp_file(
		secret: &SecretString,
	) -> Result<(tempfile::NamedTempFile, String)> {
		use std::io::Write;

		let mut temp_file = tempfile::NamedTempFile::new().map_err(MonosecretError::Io)?;

		temp_file
			.write_all(secret.expose_secret().as_bytes())
			.map_err(MonosecretError::Io)?;

		// Flush to ensure the data is written
		temp_file.flush().map_err(MonosecretError::Io)?;

		// Set restrictive permissions (0o400) so only the owner can read
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let mut perms = temp_file
				.as_file()
				.metadata()
				.map_err(MonosecretError::Io)?
				.permissions();
			perms.set_mode(0o400);
			temp_file
				.as_file()
				.set_permissions(perms)
				.map_err(MonosecretError::Io)?;
		}

		// Get the path as a string
		let path_str = temp_file
			.path()
			.to_str()
			.ok_or_else(|| {
				MonosecretError::Io(io::Error::new(
					io::ErrorKind::InvalidData,
					"Temporary file path is not valid UTF-8",
				))
			})?
			.to_string();

		Ok((temp_file, path_str))
	}

	/// Resolve all secrets into the value-carrying SDK payload.
	pub fn resolve(&self) -> Result<ResolveResponse> {
		self.resolve_impl(true, None)
	}

	/// Resolve selected secrets into the value-carrying SDK payload.
	pub fn resolve_filtered(
		&self,
		includes: &[String],
		groups: &[String],
	) -> Result<ResolveResponse> {
		let selected = self.selected_secret_names(includes, groups)?;
		self.resolve_impl(true, selected.as_ref())
	}

	/// Resolve structure and provenance without values or side effects.
	pub fn resolve_without_values(&self) -> Result<ResolveResponse> {
		self.resolve_impl(false, None)
	}

	/// Resolve selected structure and provenance without values or side effects.
	pub fn resolve_without_values_filtered(
		&self,
		includes: &[String],
		groups: &[String],
	) -> Result<ResolveResponse> {
		let selected = self.selected_secret_names(includes, groups)?;
		self.resolve_impl(false, selected.as_ref())
	}

	fn resolve_impl(
		&self,
		include_values: bool,
		selected_names: Option<&HashSet<String>>,
	) -> Result<ResolveResponse> {
		self.ensure_reason()?;
		let materialize = if include_values {
			Materialize::Values
		} else {
			Materialize::None
		};
		match self.validate_selected(selected_names, materialize)? {
			Ok(mut validated) => {
				if include_values {
					validated.keep_temp_files()?;
				}
				let mut secrets = BTreeMap::new();
				for entry in &validated.resolution {
					if entry.status != ResolutionStatus::Resolved {
						continue;
					}
					let source = if entry.generated {
						ResolvedSource::Generated
					} else if entry.default_applied {
						ResolvedSource::Default
					} else {
						ResolvedSource::Provider
					};
					let (value, path) = if include_values {
						let raw = validated
							.resolved
							.secrets
							.get(&entry.name)
							.expect("resolved values pass has every resolved secret")
							.expose_secret()
							.to_string();
						if entry.as_path {
							(None, Some(raw))
						} else {
							(Some(raw), None)
						}
					} else {
						(None, None)
					};
					secrets.insert(
						entry.name.clone(),
						ResolvedSecret {
							value,
							path,
							as_path: entry.as_path,
							source,
							source_provider: entry.source_provider.clone(),
						},
					);
				}
				let mut missing_optional = validated.missing_optional;
				missing_optional.sort();
				Ok(ResolveResponse {
					schema_version: RESOLVE_SCHEMA_VERSION,
					provider: validated.resolved.provider,
					profile: validated.resolved.profile,
					secrets,
					missing_required: Vec::new(),
					missing_optional,
				})
			}
			Err(errors) => {
				let mut missing_required = errors.missing_required;
				missing_required.sort();
				let mut missing_optional = errors.missing_optional;
				missing_optional.sort();
				Ok(ResolveResponse {
					schema_version: RESOLVE_SCHEMA_VERSION,
					provider: errors.provider,
					profile: errors.profile,
					secrets: BTreeMap::new(),
					missing_required,
					missing_optional,
				})
			}
		}
	}

	/// Produce a stable value-free report without generation or temp files.
	pub fn report(&self) -> Result<ResolutionReport> {
		self.report_impl(None)
	}

	/// Produce a stable value-free report for selected secrets.
	pub fn report_filtered(
		&self,
		includes: &[String],
		groups: &[String],
	) -> Result<ResolutionReport> {
		let selected = self.selected_secret_names(includes, groups)?;
		self.report_impl(selected.as_ref())
	}

	fn report_impl(&self, selected_names: Option<&HashSet<String>>) -> Result<ResolutionReport> {
		self.ensure_reason()?;
		Ok(
			match self.validate_selected(selected_names, Materialize::None)? {
				Ok(validated) => validated.report(),
				Err(errors) => errors.report(),
			},
		)
	}

	/// Validates all secrets in the specification
	///
	/// This method checks all secrets defined in the current profile (and default
	/// profile if different) and returns detailed information about their status.
	///
	/// Uses batch fetching when possible to improve performance with providers
	/// that have high latency (like 1Password).
	///
	/// # Returns
	///
	/// A `ValidatedSecrets` containing the status of all secrets
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The provider cannot be initialized
	/// - The specified profile doesn't exist
	/// - Storage operations fail
	///
	/// # Example
	///
	/// ```no_run
	/// use monosecret::Secrets;
	///
	/// let mut spec = Secrets::load().unwrap();
	/// let result = spec.validate().unwrap();
	/// if let Ok(validated) = result {
	///     println!("All required secrets are present!");
	/// }
	/// ```
	pub fn validate(&self) -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
		self.ensure_reason()?;
		self.validate_selected(None, Materialize::Values)
	}

	fn validate_selected(
		&self,
		selected_names: Option<&HashSet<String>>,
		materialize: Materialize,
	) -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
		let mut secrets: HashMap<String, SecretString> = HashMap::new();
		let mut missing_required = Vec::new();
		let mut missing_optional = Vec::new();
		let mut with_defaults = Vec::new();
		let mut temp_files = Vec::new();
		let mut resolution = Vec::new();

		let profile_name = self.resolve_profile_name(None);
		let profile = self.resolve_profile(Some(&profile_name))?;

		let all_secrets: Vec<(String, crate::config::Secret)> = profile
			.into_iter()
			.filter(|(name, _)| selected_names.is_none_or(|selected| selected.contains(name)))
			.collect();

		let override_uri = self.resolve_provider_override(None);

		let mut provider_groups: HashMap<Option<String>, Vec<String>> = HashMap::new();
		let mut secret_primary_uris: HashMap<String, Option<String>> = HashMap::new();
		let mut fetched_values: HashMap<String, SecretString> = HashMap::new();
		let mut fetched_sources: HashMap<String, String> = HashMap::new();

		for (name, _) in &all_secrets {
			let secret_config = self
				.resolve_secret_config(name, Some(&profile_name))
				.expect("Secret should exist in config since we're iterating over it");

			let primary_entry = match (&override_uri, secret_config.providers.as_deref()) {
				(Some(uri), _) => Some((uri.clone(), SecretRequest::default())),
				(None, Some([first_ref, ..])) => {
					self.resolve_provider_ref_uris(Some(std::slice::from_ref(first_ref)))?
						.and_then(|entries| entries.into_iter().next())
				}
				_ => None,
			};
			let provider_uri = primary_entry.as_ref().map(|(uri, _)| uri.clone());

			secret_primary_uris.insert(name.clone(), provider_uri.clone());

			let can_batch = primary_entry
				.as_ref()
				.is_none_or(|(_, request)| request == &SecretRequest::default());

			if can_batch {
				provider_groups
					.entry(provider_uri)
					.or_default()
					.push(name.clone());
				continue;
			}

			let provider_entries =
				self.resolve_provider_ref_uris(secret_config.providers.as_deref())?;

			if let (Some(value), source) = self.get_secret_from_providers(
				&self.config.project.name,
				name,
				&profile_name,
				&secret_config,
				provider_entries.as_deref(),
				None,
			)? {
				fetched_values.insert(name.clone(), value);
				if let Some(source) = source {
					fetched_sources.insert(name.clone(), source);
				}
			}
		}

		// Batch fetch from each provider group. Provider construction failures
		// apply to the group, while aggregate lookup failures are retried by
		// address so one invalid request cannot poison healthy peers. Only the
		// addresses that also fail individually are marked as failed.
		let mut failed_primary_providers: HashMap<Option<String>, MonosecretError> = HashMap::new();
		let mut failed_primary_secret_errors: HashMap<String, usize> = HashMap::new();
		let mut primary_address_errors: Vec<Option<MonosecretError>> = Vec::new();

		for (provider_uri, secret_names) in provider_groups {
			let provider_result = if let Some(uri) = provider_uri.clone() {
				self.provider_from_uri(&uri, &profile_name)
			} else {
				self.get_provider(None)
			};

			let provider = match provider_result {
				Ok(p) => p,
				Err(e) => {
					warn_primary_provider_failure(provider_uri.as_deref(), &e);
					failed_primary_providers.insert(provider_uri, e);
					continue;
				}
			};

			let configs = secret_names
				.iter()
				.map(|name| {
					self.resolve_secret_config(name, Some(&profile_name))
						.map(|config| (name, config))
						.expect("grouped secret exists in resolved profile")
				})
				.collect::<Vec<_>>();
			let requests = configs
				.iter()
				.map(|(name, config)| {
					let address = config.reference.as_ref().map_or_else(
						|| Address::convention(&self.config.project.name, &profile_name, name),
						Address::Native,
					);
					(name.as_str(), address)
				})
				.collect::<Vec<_>>();
			let provider_source_uri = provider.uri();
			let source_uri = redact_provider_uri(&provider_source_uri);
			match provider.get_many(&requests) {
				Ok(batch_results) => {
					for name in batch_results.keys() {
						fetched_sources.insert(name.clone(), source_uri.clone());
					}
					fetched_values.extend(batch_results);
				}
				Err(batch_error) => {
					warn_primary_batch_failure(provider_uri.as_deref(), &batch_error);
					let warning_uri = provider_uri.as_deref().unwrap_or(&provider_source_uri);

					// Preserve `get_many`'s address deduplication and panic isolation
					// while obtaining a result for every unique address.
					let mut address_groups: HashMap<Address<'_>, Vec<&str>> = HashMap::new();
					for (name, address) in requests {
						address_groups.entry(address).or_default().push(name);
					}
					let retry_provider = provider.as_ref();
					let retries = std::thread::scope(|scope| {
						address_groups
							.into_iter()
							.map(|(address, names)| {
								(
									names,
									scope.spawn(move || retry_provider.get_address(address)),
								)
							})
							.collect::<Vec<_>>()
							.into_iter()
							.map(|(names, handle)| {
								let result = handle.join().unwrap_or_else(|_| {
									Err(MonosecretError::ProviderOperationFailed(
										"provider fetch worker panicked".to_string(),
									))
								});
								(names, result)
							})
							.collect::<Vec<_>>()
					});

					for (names, result) in retries {
						match result {
							Ok(Some(value)) => {
								for name in names {
									fetched_sources.insert(name.to_string(), source_uri.clone());
									fetched_values.insert(name.to_string(), value.clone());
								}
							}
							Ok(None) => {}
							Err(error) => {
								for name in &names {
									warn_provider_failure(warning_uri, name, &error);
								}
								let error_index = primary_address_errors.len();
								primary_address_errors.push(Some(error));
								for name in names {
									failed_primary_secret_errors
										.insert(name.to_string(), error_index);
								}
							}
						}
					}
				}
			}
		}

		// Apply the resolution waterfall while recording value-free provenance.
		for (name, _) in all_secrets {
			let secret_config = self
				.resolve_secret_config(&name, Some(&profile_name))
				.expect("secret exists in resolved profile");
			let required = secret_config.required.unwrap_or(true);
			let as_path = secret_config.as_path.unwrap_or(false);
			let mut source_provider = fetched_sources.remove(&name);
			let mut generated = false;
			let mut default_applied = false;
			let mut value = fetched_values.remove(&name);

			if value.is_none() {
				let primary_uri = &secret_primary_uris[&name];
				let primary_failed = failed_primary_secret_errors.contains_key(&name)
					|| failed_primary_providers.contains_key(primary_uri);
				let fallback = match (override_uri.as_ref(), secret_config.providers.as_deref()) {
					(None, Some(providers)) if providers.len() > 1 => {
						let entries = self.resolve_provider_ref_uris(Some(&providers[1..]))?;
						self.get_secret_from_providers(
							&self.config.project.name,
							&name,
							&profile_name,
							&secret_config,
							entries.as_deref(),
							None,
						)?
					}
					_ if primary_failed => {
						if let Some(error_index) = failed_primary_secret_errors.remove(&name) {
							let error = primary_address_errors
								.get_mut(error_index)
								.and_then(Option::take)
								.expect("primary address failure was recorded");
							return Err(error);
						}
						return Err(failed_primary_providers
							.remove(primary_uri)
							.expect("primary provider failure was recorded"));
					}
					_ => (None, None),
				};
				value = fallback.0;
				if value.is_some() {
					source_provider = fallback.1;
				}
			}

			if value.is_none()
				&& secret_config
					.generate
					.as_ref()
					.is_some_and(crate::config::GenerateConfig::is_enabled)
			{
				generated = true;
				if materialize == Materialize::Values {
					value = self.try_generate_secret(&name, &secret_config, &profile_name)?;
				}
			}

			if value.is_none()
				&& !generated
				&& let Some(default) = secret_config.default.clone()
			{
				default_applied = true;
				with_defaults.push((name.clone(), default.clone()));
				value = Some(SecretString::new(default.into()));
			}

			let status = if value.is_some() || generated {
				ResolutionStatus::Resolved
			} else if required {
				missing_required.push(name.clone());
				ResolutionStatus::MissingRequired
			} else {
				missing_optional.push(name.clone());
				ResolutionStatus::MissingOptional
			};

			resolution.push(SecretResolution {
				name: name.clone(),
				status,
				required,
				source_provider,
				default_applied,
				generated,
				as_path,
			});

			if let Some(value) = value {
				if as_path && materialize == Materialize::Values {
					let (temp_file, path) = Self::write_secret_to_temp_file(&value)?;
					temp_files.push(temp_file);
					secrets.insert(name, SecretString::new(path.into()));
				} else {
					secrets.insert(name, value);
				}
			}
		}

		let report_provider_uri = redact_provider_uri(
			&self.validation_report_provider_uri(override_uri.as_deref(), &secret_primary_uris)?,
		);

		if missing_required.is_empty() {
			Ok(Ok(ValidatedSecrets {
				resolved: Resolved::new(secrets, report_provider_uri, profile_name.clone()),
				missing_optional,
				with_defaults,
				resolution,
				temp_files,
			}))
		} else {
			let mut errors = ValidationErrors::new(
				missing_required,
				missing_optional,
				with_defaults,
				report_provider_uri,
				profile_name,
			);
			errors.resolution = resolution;
			Ok(Err(errors))
		}
	}

	fn split_filter_values(values: &[String]) -> Vec<String> {
		values
			.iter()
			.flat_map(|value| value.split(','))
			.map(str::trim)
			.filter(|value| !value.is_empty())
			.map(str::to_string)
			.collect()
	}

	fn invalid_input(message: impl Into<String>) -> MonosecretError {
		MonosecretError::Io(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
	}

	fn selected_secret_names(
		&self,
		includes: &[String],
		groups: &[String],
	) -> Result<Option<HashSet<String>>> {
		let include_names = Self::split_filter_values(includes);
		let group_names = Self::split_filter_values(groups);

		if include_names.is_empty() && group_names.is_empty() {
			return Ok(None);
		}

		let profile_name = self.resolve_profile_name(None);
		let profile = self.resolve_profile(Some(&profile_name))?;
		let mut selected = HashSet::new();

		for name in include_names {
			if !profile.secrets.contains_key(&name) {
				return Err(Self::invalid_input(format!(
					"Included secret '{name}' is not defined in profile '{profile_name}'"
				)));
			}
			selected.insert(name);
		}

		for group in group_names {
			if !self
				.config
				.declared_groups()
				.is_some_and(|declared| declared.contains_key(&group))
			{
				return Err(Self::invalid_input(format!(
					"Group '{group}' is not declared in the top-level [groups] table"
				)));
			}

			let mut matched = false;
			for (name, secret) in &profile.secrets {
				let effective = self
					.resolve_secret_config(name, Some(&profile_name))
					.unwrap_or_else(|| secret.clone());
				if effective
					.groups
					.as_ref()
					.is_some_and(|groups| groups.iter().any(|candidate| candidate == &group))
				{
					matched = true;
					selected.insert(name.clone());
				}
			}

			if !matched {
				return Err(Self::invalid_input(format!(
					"Group '{group}' does not match any secrets in profile '{profile_name}'"
				)));
			}
		}

		Ok(Some(selected))
	}

	/// Runs a command with secrets injected as environment variables
	///
	/// This method validates that all required secrets are present, then runs
	/// the specified command with all secrets injected as environment variables.
	///
	/// # Arguments
	///
	/// * `command` - The command and arguments to run
	/// * `provider_arg` - Optional provider to use
	/// * `profile` - Optional profile to use
	///
	/// # Returns
	///
	/// This method executes the command and exits with the command's exit code.
	/// It only returns an error if validation fails or the command cannot be started.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - No command is specified
	/// - Required secrets are missing
	/// - The command cannot be executed
	///
	/// # Example
	///
	/// ```no_run
	/// use monosecret::Secrets;
	///
	/// let mut spec = Secrets::load().unwrap();
	/// spec.run(vec!["npm".to_string(), "start".to_string()]).unwrap();
	/// ```
	#[allow(clippy::needless_pass_by_value)]
	pub fn run(&self, command: Vec<String>) -> Result<()> {
		self.ensure_reason()?;
		let exit_code = self.run_command(&command)?;
		std::process::exit(exit_code);
	}

	#[allow(clippy::needless_pass_by_value)]
	pub fn run_filtered(
		&self,
		command: Vec<String>,
		includes: &[String],
		groups: &[String],
	) -> Result<()> {
		let exit_code = self.run_command_filtered(&command, includes, groups)?;
		std::process::exit(exit_code);
	}

	/// Resolves the selected (or all) secrets for the active profile and returns
	/// them as `(name, value)` pairs, sorted by name. Enforces the
	/// `require_reason` policy the same way [`Self::run`] does, so coding agents
	/// must supply a reason.
	///
	/// This is the programmatic backing for `monosecret env`, which emits these
	/// pairs as shell-native `export` / `set` / `$env:` declarations (or appends
	/// them to `$GITHUB_ENV` / a GitLab dotenv artifact) so a single command can
	/// load every secret into the surrounding shell or CI environment.
	///
	/// # `as_path` secrets
	///
	/// Secrets resolved with `as_path = true` are backed by temporary files
	/// whose lifetime is tied to the [`ValidatedSecrets`] returned by validation.
	/// This method drops that handle once the values are collected, so the temp
	/// files are removed before the caller can act on an emitted path. For
	/// `as_path` secrets, prefer [`Self::run`], which keeps the files alive for
	/// the child process; use `env` for ordinary value secrets.
	pub fn env_vars(
		&self,
		includes: &[String],
		groups: &[String],
	) -> Result<Vec<(String, String)>> {
		self.ensure_reason()?;
		let selected = self.selected_secret_names(includes, groups)?;
		let validation = self.ensure_secrets_selected(None, None, false, selected.as_ref())?;
		let mut pairs: Vec<(String, String)> = validation
			.resolved
			.secrets
			.iter()
			.map(|(k, v)| (k.clone(), v.expose_secret().to_string()))
			.collect();
		pairs.sort_by(|a, b| a.0.cmp(&b.0));
		Ok(pairs)
	}

	/// Runs a command with secrets injected and returns its exit code.
	///
	/// Splitting this out from [`Self::run`] ensures that any temporary files
	/// backing `as_path` secrets are dropped (and removed from disk) before
	/// `std::process::exit` is called — `exit` does not run destructors.
	pub(crate) fn run_command(&self, command: &[String]) -> Result<i32> {
		self.run_command_with_selection(command, None)
	}

	pub(crate) fn run_command_filtered(
		&self,
		command: &[String],
		includes: &[String],
		groups: &[String],
	) -> Result<i32> {
		let selected = self.selected_secret_names(includes, groups)?;
		self.run_command_with_selection(command, selected.as_ref())
	}

	fn run_command_with_selection(
		&self,
		command: &[String],
		selected_names: Option<&HashSet<String>>,
	) -> Result<i32> {
		if command.is_empty() {
			return Err(MonosecretError::Io(io::Error::new(
				io::ErrorKind::InvalidInput,
				"No command specified. Usage: monosecret run -- <command> [args...]",
			)));
		}

		// Ensure all secrets are available (will error out if missing).
		// `validation_result` owns the temp files for `as_path` secrets and
		// must stay alive until the child process has terminated.
		let validation_result = self.ensure_secrets_selected(None, None, false, selected_names)?;

		let mut env_vars = env::vars().collect::<HashMap<_, _>>();
		for (key, secret) in &validation_result.resolved.secrets {
			env_vars.insert(key.clone(), secret.expose_secret().to_string());
		}

		let mut cmd = Command::new(&command[0]);
		cmd.args(&command[1..]);
		cmd.envs(&env_vars);

		let status = cmd.status()?;
		Ok(status.code().unwrap_or(1))
	}
}

#[cfg(test)]
mod provider_uri_redaction_tests {
	use super::redact_provider_uri;

	#[test]
	fn provider_uri_redaction_handles_plain_invalid_and_credentials() {
		assert_eq!(redact_provider_uri("keyring://"), "keyring://");
		assert_eq!(redact_provider_uri("not a uri"), "not a uri");

		let redacted = redact_provider_uri("onepassword+token://secret-token@Development/dotfiles");
		assert!(!redacted.contains("secret-token"));
		assert!(redacted.contains("redacted"));

		let redacted = redact_provider_uri("https://user:pass@example.com/path");
		assert!(!redacted.contains("user"));
		assert!(!redacted.contains("pass"));
		assert!(redacted.contains("redacted"));
	}
}

#[cfg(test)]
mod policy_tests {
	use super::*;

	#[test]
	fn policy_decision_matrix() {
		use RequireReason::*;
		assert!(!policy_requires_reason(Never, true));
		assert!(!policy_requires_reason(Never, false));
		assert!(policy_requires_reason(Always, false));
		assert!(policy_requires_reason(Always, true));
		assert!(policy_requires_reason(Agents, true));
		assert!(!policy_requires_reason(Agents, false));
	}

	#[test]
	fn normalize_reason_trims_and_blanks_to_none() {
		assert_eq!(
			normalize_reason("  deploy web  "),
			Some("deploy web".to_string())
		);
		assert_eq!(normalize_reason("deploy"), Some("deploy".to_string()));
		assert_eq!(normalize_reason(""), None);
		assert_eq!(normalize_reason("   "), None);
		assert_eq!(normalize_reason("\t\n"), None);
	}
}
