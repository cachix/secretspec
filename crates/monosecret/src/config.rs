//! # Monosecret Core Configuration Types
//!
//! This module provides the core type definitions and parsing logic for the Monosecret
//! configuration system.
//!
//! Monosecret uses a declarative TOML-based configuration format to define secrets
//! and their requirements across different environments (profiles). The type system
//! supports configuration inheritance, allowing projects to extend shared configurations
//! while maintaining type safety and preventing circular dependencies.
//!
//! ## Key Features
//!
//! - **Profile-based configuration**: Define different sets of secrets for development, staging, production, etc.
//! - **Configuration inheritance**: Extend other configurations to share common secrets
//! - **Provider abstraction**: Support for multiple secret storage backends
//! - **Type-safe parsing**: Strong typing with comprehensive error handling
//!
//! ## Configuration Structure
//!
//! A typical `monosecret.toml` file has this structure:
//!
//! ```toml
//! [project]
//! name = "my-app"
//! revision = "1.0"
//! extends = ["../shared/common"]  # Optional inheritance
//!
//! [profiles.default]
//! DATABASE_URL = { description = "PostgreSQL connection string", required = true }
//! API_KEY = { description = "External API key", required = false, default = "dev-key" }
//!
//! [profiles.production]
//! DATABASE_URL = { description = "Production database", required = true }
//! ```

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;

// ── Provider config & references ────────────────────────────────────────────

/// A single entry in `[providers]`.
///
/// TOML deserialization is [`serde::untagged`], so:
///
/// | TOML                                      | Rust variant                            |
/// |-------------------------------------------|-----------------------------------------|
/// | `keyring = "keyring://"`               | `ProviderConfig::Alias("keyring://")`  |
/// | `[providers.op]\nuri = "…"`            | `ProviderConfig::Structured { … }`      |
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderConfig {
	/// Legacy / simple alias — just a URI string.
	Alias(String),
	/// Structured provider with optional dependency declarations.
	Structured(ProviderConfigStructured),
}

impl ProviderConfig {
	/// Returns the provider URI regardless of variant.
	pub fn uri(&self) -> &str {
		match self {
			ProviderConfig::Alias(uri) => uri.as_str(),
			ProviderConfig::Structured(s) => s.uri.as_str(),
		}
	}

	/// Returns a reference to the dependency list, if structured.
	pub fn depends_on(&self) -> Option<&[ProviderDependency]> {
		match self {
			ProviderConfig::Alias(_) => None,
			ProviderConfig::Structured(s) if s.depends_on.is_empty() => None,
			ProviderConfig::Structured(s) => Some(&s.depends_on),
		}
	}
}

/// Structured provider configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderConfigStructured {
	/// The provider URI (required).
	pub uri: String,
	/// Required secrets that must be resolved before this provider is usable.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub depends_on: Vec<ProviderDependency>,
}

/// A single dependency declaration under `[[providers.<name>.depends_on]]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderDependency {
	/// The Monosecret secret name that provides the value
	/// (e.g. `OP_SERVICE_ACCOUNT_TOKEN`).
	pub secret: String,
	/// Environment variable name to inject the resolved value as.
	/// Defaults to the secret name when omitted.
	#[serde(default, skip_serializing_if = "Option::is_none", rename = "as")]
	pub as_name: Option<String>,
}

impl ProviderDependency {
	/// Returns the effective env-var name for this dependency.
	///
	/// When `as` is set, returns that value. Otherwise defaults to the
	/// [`secret`](Self::secret) name.
	pub fn effective_as(&self) -> &str {
		self.as_name.as_deref().unwrap_or(&self.secret)
	}
}

/// A single entry in a secret's `providers` list.
///
/// TOML deserialization is [`serde::untagged`]:
///
/// | TOML                                                       | Rust variant                       |
/// |------------------------------------------------------------|------------------------------------|
/// | `"env"`                                                 | `ProviderRef::Alias("env")`       |
/// | `{ provider = "op", path = ["GH"], key = "t" }`    | `ProviderRef::Detail { … }`         |
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderRef {
	/// Simple alias reference (backward compat).
	Alias(String),
	/// Detailed provider reference with relative location.
	Detail(ProviderRefDetail),
}

impl ProviderRef {
	/// Returns the provider alias name regardless of variant.
	pub fn provider_alias(&self) -> &str {
		match self {
			ProviderRef::Alias(name) => name.as_str(),
			ProviderRef::Detail(d) => d.provider.as_str(),
		}
	}
}

impl From<String> for ProviderRef {
	fn from(s: String) -> Self {
		ProviderRef::Alias(s)
	}
}

impl<'a> From<&'a str> for ProviderRef {
	fn from(s: &'a str) -> Self {
		ProviderRef::Alias(s.to_string())
	}
}

/// Detailed provider reference with relative location within the provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderRefDetail {
	/// The provider alias name (resolved against `[providers]`).
	pub provider: String,
	/// Optional path segments within the provider's store
	/// (e.g. section name, folder).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub path: Option<Vec<String>>,
	/// Optional key within that path.
	/// Defaults to the Monosecret secret name when absent.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub key: Option<String>,
}

/// Carries provider-relative location hints for secret lookups.
///
/// Created from a [`ProviderRef::Detail`] during resolution.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecretRequest {
	/// Path segments within the provider (e.g. `["GitHub"]`).
	pub path: Option<Vec<String>>,
	/// Key at that path. Defaults to the secret name.
	pub key: Option<String>,
}

impl SecretRequest {
	/// Create a [`SecretRequest`] from a [`ProviderRef`].
	///
	/// For [`ProviderRef::Alias`] this returns a default (empty) request.
	/// For [`ProviderRef::Detail`] it copies `path` and `key`.
	pub fn from_provider_ref(r: &ProviderRef) -> Self {
		match r {
			ProviderRef::Alias(_) => Self::default(),
			ProviderRef::Detail(d) => {
				Self {
					path: d.path.clone(),
					key: d.key.clone(),
				}
			}
		}
	}
}

// ── Main config types ──────────────────────────────────────────────────────

/// The root configuration structure for a Monosecret project.
///
/// This is the top-level type that represents the entire `monosecret.toml` file.
/// It contains project metadata and profile-specific secret definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	/// Project metadata including name, revision, and optional inheritance
	pub project: Project,
	/// Map of profile names to their configurations (e.g., "default", "production", "staging")
	pub profiles: HashMap<String, Profile>,
	/// Project-level provider aliases that map alias names to provider URIs.
	///
	/// Take precedence over aliases in the user-global config
	/// (`~/.config/monosecret/config.toml`), so teams can check vault mappings
	/// into version control instead of replicating them on every machine.
	/// Can be a simple alias (`"keyring://"`) or a structured table with
	/// dependency declarations (`{ uri = "…", depends_on = [ … ] }`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub providers: Option<HashMap<String, ProviderConfig>>,
	/// Declared secret groups. Secrets may only reference groups declared here.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub groups: Option<HashMap<String, String>>,
}

/// Secret-value-free manifest for SDK code generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
	/// Project metadata from `[project]`.
	pub project: ManifestProject,
	/// Effective profiles, with default profile fallback and profile defaults applied.
	pub profiles: BTreeMap<String, ManifestProfile>,
	/// Declared groups from `[groups]`; values are group descriptions.
	pub groups: BTreeMap<String, String>,
}

/// Project metadata included in a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestProject {
	/// Project name.
	pub name: String,
	/// Configuration revision.
	pub revision: String,
}

/// Effective profile metadata included in a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestProfile {
	/// Effective secret declarations for this profile.
	pub secrets: BTreeMap<String, ManifestSecret>,
}

/// Effective secret metadata included in a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSecret {
	/// Whether the secret is required in this effective profile.
	pub required: bool,
	/// Whether the secret has a default value. The value itself is intentionally omitted.
	pub has_default: bool,
	/// Whether Monosecret resolves this secret to a temporary file path.
	pub as_path: bool,
	/// Groups this secret belongs to.
	pub groups: Vec<String>,
}

impl Config {
	pub(crate) fn declared_groups(&self) -> Option<&HashMap<String, String>> {
		self.groups.as_ref()
	}

	/// Returns a secret-value-free manifest suitable for SDK code generation.
	pub fn to_manifest(&self) -> Manifest {
		let mut profiles = BTreeMap::new();
		for profile_name in self.profiles.keys() {
			profiles.insert(profile_name.clone(), self.manifest_profile(profile_name));
		}

		Manifest {
			project: ManifestProject {
				name: self.project.name.clone(),
				revision: self.project.revision.clone(),
			},
			profiles,
			groups: self
				.groups
				.clone()
				.unwrap_or_default()
				.into_iter()
				.collect(),
		}
	}

	fn manifest_profile(&self, profile_name: &str) -> ManifestProfile {
		let mut secrets = BTreeMap::new();
		let current_profile = self.profiles.get(profile_name);
		let default_profile = (profile_name != "default")
			.then(|| self.profiles.get("default"))
			.flatten();

		let mut secret_names = HashSet::new();
		if let Some(profile) = current_profile {
			secret_names.extend(profile.secrets.keys().cloned());
		}
		if let Some(profile) = default_profile {
			secret_names.extend(profile.secrets.keys().cloned());
		}

		for secret_name in secret_names {
			if let Some(secret) = self.manifest_secret(&secret_name, profile_name) {
				secrets.insert(secret_name, secret);
			}
		}

		ManifestProfile { secrets }
	}

	fn manifest_secret(&self, name: &str, profile_name: &str) -> Option<ManifestSecret> {
		let current_profile = self.profiles.get(profile_name);
		let current_secret = current_profile.and_then(|profile| profile.secrets.get(name));
		let current_defaults = current_profile.and_then(|profile| profile.defaults.as_ref());
		let default_secret = if profile_name == "default" {
			None
		} else {
			self.profiles
				.get("default")
				.and_then(|profile| profile.secrets.get(name))
		};

		if current_secret.is_none() && default_secret.is_none() {
			return None;
		}

		Some(ManifestSecret {
			required: current_secret
				.and_then(|secret| secret.required)
				.or_else(|| default_secret.and_then(|secret| secret.required))
				.or_else(|| current_defaults.and_then(|defaults| defaults.required))
				.unwrap_or(true),
			has_default: current_secret.is_some_and(|secret| secret.default.is_some())
				|| default_secret.is_some_and(|secret| secret.default.is_some())
				|| current_defaults.is_some_and(|defaults| defaults.default.is_some()),
			as_path: current_secret
				.and_then(|secret| secret.as_path)
				.or_else(|| default_secret.and_then(|secret| secret.as_path))
				.unwrap_or(false),
			groups: current_secret
				.and_then(|secret| secret.groups.clone())
				.or_else(|| default_secret.and_then(|secret| secret.groups.clone()))
				.unwrap_or_default(),
		})
	}

	/// Validate the configuration.
	///
	/// Ensures that:
	/// - Project name is not empty
	/// - At least one profile is defined
	/// - All secrets have valid configurations
	/// - Secret names are valid identifiers
	///
	/// # Errors
	///
	/// Returns a `ParseError` if validation fails.
	pub fn validate(&self) -> Result<(), ParseError> {
		if self.project.name.is_empty() {
			return Err(ParseError::Validation(
				"Project name cannot be empty".into(),
			));
		}

		if self.profiles.is_empty() {
			return Err(ParseError::Validation(
				"At least one profile must be defined".into(),
			));
		}

		// Validate each profile. Non-default profiles are partial overlays, so
		// validate their effective secret after inheriting omitted fields from the
		// default profile rather than rejecting a valid override in isolation.
		for (profile_name, profile) in &self.profiles {
			if profile.secrets.is_empty() {
				return Err(ParseError::Validation(format!(
					"Profile '{profile_name}': Profile must define at least one secret"
				)));
			}

			for (secret_name, secret) in &profile.secrets {
				if !is_valid_identifier(secret_name) {
					return Err(ParseError::Validation(format!(
						"Profile '{profile_name}': Invalid secret name '{secret_name}': must be a valid identifier (alphanumeric and underscores, not starting with a number)"
					)));
				}

				let mut effective = secret.clone();
				if profile_name != "default"
					&& let Some(default) = self
						.profiles
						.get("default")
						.and_then(|profile| profile.secrets.get(secret_name))
				{
					effective.description = effective
						.description
						.or_else(|| default.description.clone());
					effective.required = effective.required.or(default.required);
					effective.default = effective.default.or_else(|| default.default.clone());
					effective.groups = effective.groups.or_else(|| default.groups.clone());
					effective.providers = effective.providers.or_else(|| default.providers.clone());
					effective.reference = effective.reference.or_else(|| default.reference.clone());
					effective.as_path = effective.as_path.or(default.as_path);
					effective.secret_type = effective
						.secret_type
						.or_else(|| default.secret_type.clone());
					effective.generate = effective.generate.or_else(|| default.generate.clone());
				}
				effective.validate().map_err(|error| {
					ParseError::Validation(format!(
						"Profile '{profile_name}': Secret '{secret_name}': {error}"
					))
				})?;

				if let Some(groups) = &secret.groups {
					let declared = self.declared_groups().ok_or_else(|| {
						ParseError::Validation(format!(
							"Secret '{profile_name}.{secret_name}' references groups but no top-level [groups] table is declared"
						))
					})?;

					for group in groups {
						if declared.contains_key(group) {
							continue;
						}

						return Err(ParseError::Validation(format!(
							"Secret '{profile_name}.{secret_name}' references undeclared group '{group}'"
						)));
					}
				}
			}
		}

		Ok(())
	}

	/// Get a profile by name.
	pub fn get_profile(&self, name: &str) -> Option<&Profile> {
		self.profiles.get(name)
	}

	/// Get a mutable profile by name.
	pub fn get_profile_mut(&mut self, name: &str) -> Option<&mut Profile> {
		self.profiles.get_mut(name)
	}

	/// Merge another configuration into this one.
	///
	/// The current configuration takes precedence - values from `other`
	/// are only used if not already present.
	pub fn merge_with(&mut self, other: Config) {
		// Inherit the reason policy from the parent when this config leaves it
		// unspecified. `name`/`revision`/`extends` stay per-project and are not
		// merged, but `require_reason` is a security policy meant to apply
		// uniformly, so a shared base config can set it for everything that
		// extends it.
		if self.project.require_reason.is_none() {
			self.project.require_reason = other.project.require_reason;
		}

		// Merge profiles
		for (profile_name, profile_config) in other.profiles {
			match self.profiles.get_mut(&profile_name) {
				Some(existing_profile) => {
					existing_profile.merge_with(profile_config);
				}
				None => {
					self.profiles.insert(profile_name, profile_config);
				}
			}
		}

		// Merge provider aliases — current entries win.
		if let Some(other_providers) = other.providers {
			let merged = self.providers.get_or_insert_with(HashMap::new);
			for (alias, config) in other_providers {
				merged.entry(alias).or_insert(config);
			}
		}

		// Merge group declarations — current entries win.
		if let Some(other_groups) = other.groups {
			let merged = self.groups.get_or_insert_with(HashMap::new);
			for (name, description) in other_groups {
				merged.entry(name).or_insert(description);
			}
		}
	}

	// Internal methods

	fn from_path_with_visited(
		path: &Path,
		visited: &mut HashSet<PathBuf>,
	) -> Result<Self, ParseError> {
		// Get canonical path to handle symlinks and relative paths consistently
		let canonical_path = path.canonicalize().map_err(|e| {
			ParseError::Io(io::Error::new(
				e.kind(),
				format!("Failed to resolve path {}: {}", path.display(), e),
			))
		})?;

		// Check for circular dependency
		if !visited.insert(canonical_path.clone()) {
			return Err(ParseError::CircularDependency(format!(
				"Configuration file {} is part of a circular dependency chain",
				canonical_path.display()
			)));
		}

		let content = fs::read_to_string(path)?;
		Self::from_str_with_visited(&content, Some(path), visited)
	}

	fn from_str_with_visited(
		content: &str,
		base_path: Option<&Path>,
		visited: &mut HashSet<PathBuf>,
	) -> Result<Self, ParseError> {
		let mut config: Config = toml::from_str(content)?;

		// Validate revision
		if config.project.revision != "1.0" {
			return Err(ParseError::UnsupportedRevision(config.project.revision));
		}

		// Process extends if present
		if let Some(extends_paths) = config.project.extends.clone()
			&& let Some(base) = base_path
		{
			let base_dir = base.parent().unwrap_or(Path::new("."));
			config = Self::merge_extended_configs(config, &extends_paths, base_dir, visited)?;
		}

		Ok(config)
	}

	fn merge_extended_configs(
		mut base_config: Config,
		extends_paths: &[String],
		base_dir: &Path,
		visited: &mut HashSet<PathBuf>,
	) -> Result<Config, ParseError> {
		for extend_path in extends_paths {
			// If path ends with .toml, use it as-is; otherwise append monosecret.toml
			let joined_path = base_dir.join(extend_path);
			let has_toml_extension = Path::new(extend_path)
				.extension()
				.and_then(|extension| extension.to_str())
				.is_some_and(|extension| extension.eq_ignore_ascii_case("toml"));
			let full_path = if has_toml_extension {
				joined_path
			} else {
				let monosecret_path = joined_path.join("monosecret.toml");
				if monosecret_path.exists() {
					monosecret_path
				} else {
					joined_path.join("secretspec.toml")
				}
			};

			if !full_path.exists() {
				return Err(ParseError::ExtendedConfigNotFound(
					full_path.display().to_string(),
				));
			}

			let extended_config = Self::from_path_with_visited(&full_path, visited)?;
			base_config.merge_with(extended_config);
		}

		Ok(base_config)
	}
}

impl FromStr for Config {
	type Err = ParseError;

	/// Parse configuration from a TOML string.
	///
	/// Note: Configuration inheritance (`extends`) is not supported when parsing
	/// from a string since there's no base path to resolve relative paths.
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut visited = HashSet::new();
		Self::from_str_with_visited(s, None, &mut visited)
	}
}

impl TryFrom<&Path> for Config {
	type Error = ParseError;

	/// Load configuration from a file path.
	///
	/// This supports configuration inheritance via `extends` and circular dependency detection.
	fn try_from(path: &Path) -> Result<Self, Self::Error> {
		let mut visited = HashSet::new();
		Self::from_path_with_visited(path, &mut visited)
	}
}

/// When monosecret requires a reason for secret access.
///
/// Parsed from `[project].require_reason`, which accepts a boolean or the string
/// `"agents"`. Defaults to [`RequireReason::Agents`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequireReason {
	/// Never require a reason.
	Never,
	/// Require a reason only when an AI agent is detected (the default).
	#[default]
	Agents,
	/// Require a reason from every caller.
	Always,
}

impl Serialize for RequireReason {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		match self {
			RequireReason::Never => serializer.serialize_bool(false),
			RequireReason::Always => serializer.serialize_bool(true),
			RequireReason::Agents => serializer.serialize_str("agents"),
		}
	}
}

impl<'de> Deserialize<'de> for RequireReason {
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct RequireReasonVisitor;

		impl serde::de::Visitor<'_> for RequireReasonVisitor {
			type Value = RequireReason;

			fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				f.write_str(r#"a boolean or the string "agents""#)
			}

			fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<RequireReason, E> {
				Ok(if v {
					RequireReason::Always
				} else {
					RequireReason::Never
				})
			}

			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<RequireReason, E> {
				match v {
					"agents" => Ok(RequireReason::Agents),
					other => {
						Err(E::custom(format!(
							"invalid require_reason value '{other}': expected true, false, or \"agents\""
						)))
					}
				}
			}
		}

		deserializer.deserialize_any(RequireReasonVisitor)
	}
}

/// Project metadata and inheritance configuration.
///
/// Contains essential project information and optional configuration inheritance.
/// The `extends` field allows projects to inherit secrets from other configurations,
/// enabling shared configuration patterns across multiple projects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
	/// The name of the project, used for identification and namespacing
	pub name: String,
	/// Configuration format revision (currently must be "1.0")
	pub revision: String,
	/// Optional list of relative paths to other Monosecret projects to inherit from
	#[serde(skip_serializing_if = "Option::is_none")]
	pub extends: Option<Vec<String>>,
	/// Policy controlling when secret access must supply a reason. Accepts a boolean
	/// or `"agents"`; enforced by [`crate::Secrets`]. `None` means "unspecified": it
	/// resolves to [`RequireReason::default`] unless a parent config supplies a value
	/// via `extends` (see [`Config::merge_with`]).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub require_reason: Option<RequireReason>,
}

impl Default for Project {
	fn default() -> Self {
		Self {
			name: String::new(),
			revision: "1.0".to_string(),
			extends: None,
			require_reason: None,
		}
	}
}

/// Configuration for a specific profile (environment).
///
/// A profile represents a specific environment or context (e.g., "default", "production", "staging").
/// Each profile contains its own set of secret definitions with their requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
	/// Default configuration for secrets in this profile
	#[serde(skip_serializing_if = "Option::is_none")]
	pub defaults: Option<ProfileDefaults>,
	/// Map of secret names to their configurations, flattened in TOML for cleaner syntax
	#[serde(flatten)]
	pub secrets: HashMap<String, Secret>,
}

/// Default configuration for a profile.
///
/// Provides defaults that apply to all secrets within the profile.
/// Individual secrets can override any of these defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDefaults {
	/// Default value for the required field of secrets in this profile.
	/// If not specified, secrets default to required=true.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub required: Option<bool>,

	/// Default value to use for secrets in this profile if they are not found.
	/// Individual secrets can override this with their own default value.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub default: Option<String>,

	/// List of provider aliases to use for secrets in this profile.
	/// Providers are tried in order until one has the secret.
	/// Individual secrets can override this with their own providers field.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub providers: Option<Vec<String>>,
}

impl Profile {
	/// Create a new empty profile configuration.
	pub fn new() -> Self {
		Self {
			defaults: None,
			secrets: HashMap::new(),
		}
	}

	/// Validate the profile configuration.
	///
	/// Ensures all secrets have valid names and configurations.
	pub fn validate(&self) -> Result<(), String> {
		if self.secrets.is_empty() {
			return Err("Profile must define at least one secret".into());
		}

		for (name, secret) in &self.secrets {
			// Validate secret name is a valid identifier
			if !is_valid_identifier(name) {
				return Err(format!(
					"Invalid secret name '{name}': must be a valid identifier (alphanumeric and underscores, not starting with a number)"
				));
			}

			secret
				.validate()
				.map_err(|e| format!("Secret '{name}': {e}"))?;
		}

		Ok(())
	}

	/// Merge another profile configuration into this one.
	///
	/// The current profile takes precedence - secrets from `other`
	/// are only added if they don't already exist.
	pub fn merge_with(&mut self, other: Profile) {
		for (secret_name, secret_config) in other.secrets {
			self.secrets.entry(secret_name).or_insert(secret_config);
		}
	}

	/// Returns an iterator over the secrets in this profile.
	///
	/// The iterator yields (&String, &Secret) pairs, where the string is the secret name
	/// and the Secret contains the configuration for that secret.
	pub fn iter(&self) -> hash_map::Iter<'_, String, Secret> {
		self.secrets.iter()
	}
}

impl Default for Profile {
	fn default() -> Self {
		Self::new()
	}
}

impl<'a> IntoIterator for &'a Profile {
	type IntoIter = hash_map::Iter<'a, String, Secret>;
	type Item = (&'a String, &'a Secret);

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		self.secrets.iter()
	}
}

impl IntoIterator for Profile {
	type IntoIter = hash_map::IntoIter<String, Secret>;
	type Item = (String, Secret);

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		self.secrets.into_iter()
	}
}

/// Configuration for auto-generation of a secret.
///
/// Can be either a simple boolean (`generate = true`) or a table with
/// type-specific options (`generate = { length = 64 }`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GenerateConfig {
	/// Simple boolean flag to enable/disable generation with defaults
	Bool(bool),
	/// Detailed generation options
	Options(GenerateOptions),
}

impl GenerateConfig {
	/// Returns true if generation is enabled.
	pub fn is_enabled(&self) -> bool {
		match self {
			GenerateConfig::Bool(b) => *b,
			GenerateConfig::Options(_) => true,
		}
	}
}

/// Type-specific options for secret generation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GenerateOptions {
	/// Length of generated password (for `password` type)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub length: Option<usize>,
	/// Number of random bytes (for `hex` and `base64` types)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub bytes: Option<usize>,
	/// Character set for password generation ("alphanumeric" or "ascii")
	#[serde(skip_serializing_if = "Option::is_none")]
	pub charset: Option<String>,
	/// Shell command to run (for `command` type)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub command: Option<String>,
	/// Key size in bits (for `rsa` type, default 2048)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub bits: Option<usize>,
}

/// Native coordinates of one externally managed secret: the value of a
/// secret's canonical `ref` field. Coordinates name a secret, while provider
/// selection and fallback remain controlled by `providers` and CLI overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
pub struct NativeAddress {
	/// Store-native item, path, service, secret id, or variable name.
	pub item: String,
	/// Optional field within the item (for example a JSON key or account).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub field: Option<String>,
	/// Optional 1Password vault override.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub vault: Option<String>,
	/// Optional 1Password section.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub section: Option<String>,
	/// Optional provider-native version (currently GCP Secret Manager).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub version: Option<String>,
}

impl NativeAddress {
	pub(crate) fn coordinates(&self) -> [(&'static str, Option<&str>); 5] {
		[
			("vault", self.vault.as_deref()),
			("item", Some(self.item.as_str())),
			("section", self.section.as_deref()),
			("field", self.field.as_deref()),
			("version", self.version.as_deref()),
		]
	}

	/// Canonical, value-free rendering used by diagnostics and audit metadata.
	pub fn render(&self) -> String {
		self.coordinates()
			.into_iter()
			.filter_map(|(name, value)| value.map(|value| format!("{name}={value}")))
			.collect::<Vec<_>>()
			.join(" ")
	}
}

/// Derived deserialization target for [`NativeAddress`]. Table input delegates
/// here so serde retains precise unknown-field diagnostics, while string input
/// can provide a useful translation hint.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeAddressFields {
	item: String,
	field: Option<String>,
	vault: Option<String>,
	section: Option<String>,
	version: Option<String>,
}

impl From<NativeAddressFields> for NativeAddress {
	fn from(fields: NativeAddressFields) -> Self {
		Self {
			item: fields.item,
			field: fields.field,
			vault: fields.vault,
			section: fields.section,
			version: fields.version,
		}
	}
}

/// Render the canonical inline TOML table used in reference diagnostics.
pub(crate) fn ref_table_hint(
	vault: Option<&str>,
	item: &str,
	section: Option<&str>,
	field: Option<&str>,
) -> String {
	let coordinates = NativeAddress {
		item: item.to_string(),
		field: field.map(str::to_string),
		vault: vault.map(str::to_string),
		section: section.map(str::to_string),
		version: None,
	};
	let rendered = coordinates
		.coordinates()
		.into_iter()
		.filter_map(|(name, value)| value.map(|value| format!(r#"{name} = "{value}""#)))
		.collect::<Vec<_>>();
	format!("ref = {{ {} }}", rendered.join(", "))
}

fn ref_string_hint(value: &str) -> String {
	if let Some(reference) = value.strip_prefix("op://") {
		let segments = reference.split('/').collect::<Vec<_>>();
		match segments.as_slice() {
			[vault, item, field] if !vault.is_empty() && !item.is_empty() && !field.is_empty() => {
				return format!(
					"`ref` takes a table of coordinates, not a URI. Use: {}",
					ref_table_hint(Some(vault), item, None, Some(field))
				);
			}
			[vault, item, section, field]
				if !vault.is_empty()
					&& !item.is_empty()
					&& !section.is_empty()
					&& !field.is_empty() =>
			{
				return format!(
					"`ref` takes a table of coordinates, not a URI. Use: {}",
					ref_table_hint(Some(vault), item, Some(section), Some(field))
				);
			}
			_ => {}
		}
	}
	format!(
		"`ref` takes a table of native secret coordinates, not a string: got '{value}'. \
		 Write e.g. {}; which store resolves the coordinates comes from `providers` \
		 (or the default provider).",
		ref_table_hint(None, "db", None, Some("password"))
	)
}

impl<'de> Deserialize<'de> for NativeAddress {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		struct AddressVisitor;

		impl<'de> serde::de::Visitor<'de> for AddressVisitor {
			type Value = NativeAddress;

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				formatter.write_str(
					r#"a table of native secret coordinates like { item = "db", field = "password" }"#,
				)
			}

			fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
			where
				A: serde::de::MapAccess<'de>,
			{
				NativeAddressFields::deserialize(serde::de::value::MapAccessDeserializer::new(map))
					.map(NativeAddress::from)
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: serde::de::Error,
			{
				Err(E::custom(ref_string_hint(value)))
			}
		}

		deserializer.deserialize_any(AddressVisitor)
	}
}

/// Configuration for an individual secret.
///
/// Defines the properties of a secret including its documentation,
/// whether it's required, an optional default value, and optionally
/// which providers to use for retrieving this secret (in fallback order).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Secret {
	/// Human-readable description of what this secret is used for
	pub description: Option<String>,
	/// Whether this secret must be provided (no default value)
	/// If not specified, defaults to true unless overridden by profile defaults
	#[serde(skip_serializing_if = "Option::is_none")]
	pub required: Option<bool>,
	/// Optional default value if the secret is not provided
	#[serde(skip_serializing_if = "Option::is_none")]
	pub default: Option<String>,
	/// Optional list of group names this secret belongs to.
	/// Groups must be declared in the top-level `[groups]` table.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub groups: Option<Vec<String>>,
	/// Optional list of provider references for retrieving this secret.
	/// Providers are tried in order until one has the secret.
	/// If not specified, uses the profile defaults.providers or global provider.
	/// Each entry is resolved against the providers map in the project/global config.
	///
	/// Accepts both simple alias strings (`"keyring"`) and detailed references
	/// (`{ provider = "op", path = ["GitHub"], key = "token" }`).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub providers: Option<Vec<ProviderRef>>,
	/// Provider-independent native coordinates. Routing still follows
	/// [`Self::providers`] and provider overrides.
	#[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
	pub reference: Option<NativeAddress>,
	/// Whether to write the secret value to a temporary file and return the path.
	/// If true, the secret will be written to a temporary file and the field
	/// will contain the path to that file instead of the secret value.
	/// The temporary file will be cleaned up when the resolved secrets are dropped.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub as_path: Option<bool>,
	/// The type of secret, used for generation (e.g., "password", "hex", "base64", "uuid", "command", "`rsa_private_key`")
	#[serde(rename = "type", skip_serializing_if = "Option::is_none")]
	pub secret_type: Option<String>,
	/// Auto-generation configuration. Either `true` for defaults or a table with options.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub generate: Option<GenerateConfig>,
}

impl Secret {
	/// Validate the secret configuration.
	///
	/// Ensures that required secrets don't have default values,
	/// and that generation config is consistent with type.
	pub fn validate(&self) -> Result<(), String> {
		if let Some(desc) = &self.description {
			if desc.is_empty() {
				return Err("description cannot be empty".into());
			}
		} else {
			return Err("missing description".into());
		}

		// If required is explicitly true and default is set, that's an error
		if self.required == Some(true) && self.default.is_some() {
			return Err("Required secrets cannot have default values".into());
		}

		if let Some(reference) = &self.reference {
			for (name, value) in reference.coordinates() {
				if value.is_some_and(|value| value.trim().is_empty()) {
					return Err(format!(
						"`ref` coordinate `{name}` cannot be empty or whitespace"
					));
				}
			}
		}

		// Validate generate config
		if let Some(ref gen_config) = self.generate
			&& gen_config.is_enabled()
		{
			// generate requires type
			if self.secret_type.is_none() {
				return Err(
					"'generate' requires 'type' to be set (e.g., type = \"password\")".into(),
				);
			}

			// generate + default is a conflict
			if self.default.is_some() {
				return Err("'generate' and 'default' cannot both be set".into());
			}

			// type = "command" requires generate = { command = "..." }
			if self.secret_type.as_deref() == Some("command") {
				match gen_config {
					GenerateConfig::Bool(true) => {
						return Err(
							"type = \"command\" requires generate = { command = \"...\" }".into(),
						);
					}
					GenerateConfig::Options(opts) if opts.command.is_none() => {
						return Err(
							"type = \"command\" requires generate = { command = \"...\" }".into(),
						);
					}
					_ => {}
				}
			}

			// Validate known types
			if let Some(ref t) = self.secret_type {
				match t.as_str() {
					"password" | "hex" | "base64" | "uuid" | "command" | "rsa_private_key" => {}
					unknown => {
						return Err(format!("unknown secret type '{unknown}'"));
					}
				}
			}
		}

		// Validate type even without generate
		if let Some(ref t) = self.secret_type
			&& (self.generate.is_none() || self.generate.as_ref().is_some_and(|g| !g.is_enabled()))
		{
			// Type is informational when not generating, but still validate known values
			match t.as_str() {
				"password" | "hex" | "base64" | "uuid" | "command" | "rsa_private_key" => {}
				unknown => {
					return Err(format!("unknown secret type '{unknown}'"));
				}
			}
		}

		Ok(())
	}
}

/// Check if a string is a valid identifier.
fn is_valid_identifier(s: &str) -> bool {
	if s.is_empty() {
		return false;
	}

	let mut chars = s.chars();
	if let Some(first) = chars.next()
		&& !first.is_alphabetic()
		&& first != '_'
	{
		return false;
	}

	chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// Global user configuration for Monosecret.
///
/// This configuration is stored in the user's config directory and provides
/// defaults that apply across all projects.
/// Audit logging configuration, parsed from the top-level `[audit]` table in the
/// user-global config (`~/.config/monosecret/config.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
	/// Whether to record secret access. Defaults to `true`.
	pub enabled: bool,
	/// Where to write the JSON Lines log. Must be an absolute path; `~` is expanded.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub path: Option<PathBuf>,
	/// Hard cap on the log file size in bytes.
	pub max_size_bytes: u64,
}

impl Default for AuditConfig {
	fn default() -> Self {
		Self {
			enabled: true,
			path: None,
			max_size_bytes: 1_048_576,
		}
	}
}

impl AuditConfig {
	/// The resolved on-disk path: the configured `path` (with a leading `~`
	/// expanded to the home directory), or the default per-user audit log location.
	pub fn resolved_path(&self) -> Option<PathBuf> {
		match self.path.clone() {
			Some(path) => Some(expand_tilde(path)).filter(|path| path.is_absolute()),
			None => default_audit_path(),
		}
	}

	/// Whether a configured path is relative after `~` expansion.
	pub fn has_relative_path(&self) -> bool {
		self.path
			.clone()
			.map(expand_tilde)
			.is_some_and(|path| !path.is_absolute())
	}
}

fn default_audit_path() -> Option<PathBuf> {
	use etcetera::app_strategy::AppStrategy;
	use etcetera::app_strategy::choose_app_strategy;
	let strategy = choose_app_strategy(etcetera::app_strategy::AppStrategyArgs {
		top_level_domain: "dev".into(),
		author: "monosecret".into(),
		app_name: "monosecret".into(),
	})
	.ok()?;
	let dir = strategy.state_dir().unwrap_or_else(|| strategy.data_dir());
	Some(dir.join("audit.log"))
}

fn expand_tilde(path: PathBuf) -> PathBuf {
	let s = path.to_string_lossy();
	if s == "~" {
		return etcetera::home_dir().unwrap_or(path);
	}
	if let Some(rest) = s.strip_prefix("~/")
		&& let Ok(home) = etcetera::home_dir()
	{
		return home.join(rest);
	}
	path
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[doc(hidden)]
pub struct GlobalConfig {
	/// Default settings
	#[serde(default)]
	pub defaults: GlobalDefaults,
	/// Audit logging configuration (top-level `[audit]` table). Auditing is a
	/// per-machine/operator concern, so it lives here rather than in the project's
	/// `monosecret.toml`. `None` means "unspecified" and resolves to
	/// [`AuditConfig::default`] (auditing on).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub audit: Option<AuditConfig>,
}

/// Default settings in the global configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[doc(hidden)]
pub struct GlobalDefaults {
	/// Default provider to use when not specified
	#[serde(skip_serializing_if = "Option::is_none")]
	pub provider: Option<String>,
	/// Default profile to use when not specified
	#[serde(skip_serializing_if = "Option::is_none")]
	pub profile: Option<String>,
	/// Named provider aliases that map alias names to provider URIs.
	/// Used by per-secret provider configuration to avoid storing sensitive
	/// provider details in monosecret.toml. Example user config:
	/// ```toml
	/// [defaults.providers]
	/// shared = "onepassword://vault/Shared"
	/// local = "dotenv://.env.local"
	/// ```
	#[serde(skip_serializing_if = "Option::is_none")]
	pub providers: Option<HashMap<String, String>>,
}

impl GlobalConfig {
	/// Gets the path to the global configuration file.
	///
	/// The configuration file is stored in the system's config directory,
	/// typically `~/.config/monosecret/config.toml` on Unix systems.
	///
	/// # Returns
	///
	/// The path to the global configuration file
	///
	/// # Errors
	///
	/// Returns an error if the config directory cannot be determined
	#[allow(clippy::collapsible_if)]
	pub fn path() -> Result<PathBuf, io::Error> {
		use etcetera::app_strategy::AppStrategy;
		use etcetera::app_strategy::AppStrategyArgs;
		use etcetera::app_strategy::choose_app_strategy;
		let strategy = choose_app_strategy(AppStrategyArgs {
			top_level_domain: String::new(),
			author: String::new(),
			app_name: "monosecret".into(),
		})
		.map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
		Ok(strategy.config_dir().join("config.toml"))
	}

	fn legacy_path() -> Result<PathBuf, io::Error> {
		use etcetera::app_strategy::AppStrategy;
		use etcetera::app_strategy::AppStrategyArgs;
		use etcetera::app_strategy::choose_app_strategy;
		let strategy = choose_app_strategy(AppStrategyArgs {
			top_level_domain: String::new(),
			author: String::new(),
			app_name: "secretspec".into(),
		})
		.map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
		Ok(strategy.config_dir().join("config.toml"))
	}

	/// Loads the global user configuration.
	///
	/// This method looks for the configuration file in the system's config
	/// directory. If the file doesn't exist, it returns `Ok(None)`.
	///
	/// # Returns
	///
	/// The loaded global configuration, or `None` if not found
	///
	/// # Errors
	///
	/// Returns an error if the config path cannot be checked/read or if parsing fails
	pub fn load() -> Result<Option<Self>, ParseError> {
		let config_path = Self::path().map_err(ParseError::Io)?;

		#[cfg(target_os = "macos")]
		let config_path = Self::migrate_macos_config(&config_path).map_err(ParseError::Io)?;

		let config_path = if config_path.try_exists().map_err(ParseError::Io)? {
			config_path
		} else {
			let legacy_path = Self::legacy_path().map_err(ParseError::Io)?;
			if legacy_path.try_exists().map_err(ParseError::Io)? {
				legacy_path
			} else {
				return Ok(None);
			}
		};
		let content = fs::read_to_string(&config_path).map_err(ParseError::Io)?;
		toml::from_str(&content).map(Some).map_err(ParseError::Toml)
	}

	/// Saves the global configuration to disk.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The config directory cannot be created
	/// - The file cannot be written
	/// - The configuration cannot be serialized
	pub fn save(&self) -> Result<(), io::Error> {
		let config_path = Self::path()?;

		// Ensure the parent directory exists
		if let Some(parent) = config_path.parent() {
			fs::create_dir_all(parent)?;
		}

		let content = toml::to_string_pretty(self)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
		fs::write(&config_path, content)?;

		Ok(())
	}

	/// Migrate config from the old macOS location (~/Library/Application Support/monosecret/)
	/// to the XDG location (~/.config/monosecret/).
	///
	/// Returns the path that should be used for loading.
	/// If migration fails, the legacy path is returned as a fallback when available.
	///
	/// # Errors
	///
	/// Returns an error if the new path cannot be checked and no legacy fallback can be determined.
	#[cfg(target_os = "macos")]
	fn migrate_macos_config(new_path: &Path) -> Result<PathBuf, io::Error> {
		match new_path.try_exists() {
			Ok(true) => return Ok(new_path.to_path_buf()),
			Ok(false) => {}
			Err(err) => {
				if let Ok(home) = etcetera::home_dir() {
					let old_path = home
						.join("Library/Application Support/monosecret")
						.join("config.toml");
					if old_path.exists() {
						return Ok(old_path);
					}
				}
				return Err(err);
			}
		}

		let old_path = match etcetera::home_dir() {
			Ok(home) => {
				home.join("Library/Application Support/monosecret")
					.join("config.toml")
			}
			Err(_) => return Ok(new_path.to_path_buf()),
		};

		match old_path.try_exists() {
			Ok(true) => {}
			Ok(false) => return Ok(new_path.to_path_buf()),
			Err(err) => {
				eprintln!(
					"Warning: failed to check legacy config path {}: {}. Continuing to use legacy path.",
					old_path.display(),
					err
				);
				return Ok(old_path);
			}
		}

		// Create parent directories for the new path
		#[allow(clippy::collapsible_if)]
		if let Some(parent) = new_path.parent() {
			if let Err(err) = fs::create_dir_all(parent) {
				eprintln!(
					"Warning: failed to create config directory {} while migrating from {}: {}. Continuing to use legacy config path.",
					parent.display(),
					old_path.display(),
					err
				);
				return Ok(old_path);
			}
		}

		// Copy old config to new location
		if let Err(err) = fs::copy(&old_path, new_path) {
			eprintln!(
				"Warning: failed to migrate config from {} to {}: {}. Continuing to use legacy config path.",
				old_path.display(),
				new_path.display(),
				err
			);
			return Ok(old_path);
		}

		// Rename old file to indicate it has been migrated
		let old_backup = old_path.with_extension("toml.old");
		if let Err(err) = fs::rename(&old_path, &old_backup) {
			eprintln!(
				"Warning: migrated config to {}, but failed to back up {} to {}: {}",
				new_path.display(),
				old_path.display(),
				old_backup.display(),
				err
			);
		}

		eprintln!(
			"Migrated config from {} to {}",
			old_path.display(),
			new_path.display()
		);
		Ok(new_path.to_path_buf())
	}
}

/// Container for resolved secrets with their context.
///
/// This generic struct wraps the actual secret values along with
/// information about which provider and profile were used to retrieve them.
/// The generic parameter `T` is typically a struct generated by the
/// `monosecret_derive` macro containing the actual secret values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolved<T> {
	/// The actual secret values, typically a generated struct
	pub secrets: T,
	/// The provider name that was used to retrieve these secrets
	pub provider: String,
	/// The profile that was active when retrieving these secrets
	pub profile: String,
}

impl<T> Resolved<T> {
	/// Create a new container for secrets with their retrieval context.
	///
	/// # Arguments
	///
	/// * `secrets` - The actual secret values
	/// * `provider` - The provider name used to retrieve the secrets
	/// * `profile` - The active profile when the secrets were retrieved
	pub fn new(secrets: T, provider: String, profile: String) -> Self {
		Self {
			secrets,
			provider,
			profile,
		}
	}
}

/// Errors that can occur when parsing Monosecret configuration files.
///
/// This enum represents various failure modes when loading and parsing
/// configuration files, including I/O errors, TOML syntax errors,
/// validation failures, and circular dependency detection.
#[derive(Debug)]
pub enum ParseError {
	/// I/O error when reading configuration files
	Io(io::Error),
	/// TOML parsing error
	Toml(toml::de::Error),
	/// Unsupported configuration revision
	UnsupportedRevision(String),
	/// Circular dependency detected in configuration inheritance
	CircularDependency(String),
	/// Validation error
	Validation(String),
	/// Extended configuration file not found
	ExtendedConfigNotFound(String),
}

impl std::fmt::Display for ParseError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ParseError::Io(e) => write!(f, "I/O error: {e}"),
			ParseError::Toml(e) => write!(f, "TOML parsing error: {e}"),
			ParseError::UnsupportedRevision(rev) => {
				write!(f, "Unsupported revision '{rev}'. Only '1.0' is supported.")
			}
			ParseError::CircularDependency(msg) => {
				write!(f, "Circular dependency detected: {msg}")
			}
			ParseError::Validation(msg) => write!(f, "Validation error: {msg}"),
			ParseError::ExtendedConfigNotFound(path) => {
				write!(f, "Extended config file not found: {path}")
			}
		}
	}
}

impl std::error::Error for ParseError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			ParseError::Io(e) => Some(e),
			ParseError::Toml(e) => Some(e),
			_ => None,
		}
	}
}

impl From<io::Error> for ParseError {
	fn from(e: io::Error) -> Self {
		ParseError::Io(e)
	}
}

impl From<toml::de::Error> for ParseError {
	fn from(e: toml::de::Error) -> Self {
		ParseError::Toml(e)
	}
}

#[cfg(test)]
mod validation_tests {
	use super::*;

	fn secret(description: Option<&str>) -> Secret {
		Secret {
			description: description.map(String::from),
			..Default::default()
		}
	}

	fn config_with(name: &str, profiles: Vec<(&str, Vec<(&str, Secret)>)>) -> Config {
		let profiles = profiles
			.into_iter()
			.map(|(pname, secrets)| {
				let secrets = secrets
					.into_iter()
					.map(|(k, v)| (k.to_string(), v))
					.collect();
				(
					pname.to_string(),
					Profile {
						defaults: None,
						secrets,
					},
				)
			})
			.collect();
		Config {
			project: Project {
				name: name.to_string(),
				revision: "1.0".to_string(),
				extends: None,
				require_reason: None,
			},
			profiles,
			providers: None,
			groups: None,
		}
	}

	#[test]
	fn is_valid_identifier_accepts_and_rejects() {
		for ok in ["ok", "_ok", "VALID_NAME9", "a"] {
			assert!(is_valid_identifier(ok), "expected valid: {ok}");
		}
		for bad in ["", "1abc", "a-b", "has space", "a.b"] {
			assert!(!is_valid_identifier(bad), "expected invalid: {bad}");
		}
	}

	#[test]
	fn config_validate_rejects_empty_name() {
		let err = config_with("", vec![("default", vec![("A", secret(Some("d")))])])
			.validate()
			.unwrap_err();
		assert!(matches!(err, ParseError::Validation(_)));
		assert!(err.to_string().contains("name cannot be empty"));
	}

	#[test]
	fn config_validate_rejects_no_profiles() {
		let err = config_with("proj", vec![]).validate().unwrap_err();
		assert!(err.to_string().contains("At least one profile"));
	}

	#[test]
	fn config_validate_rejects_empty_profile() {
		let err = config_with("proj", vec![("default", vec![])])
			.validate()
			.unwrap_err();
		assert!(err.to_string().contains("at least one secret"));
	}

	#[test]
	fn config_validate_rejects_invalid_secret_name() {
		let err = config_with("proj", vec![("default", vec![("1BAD", secret(Some("d")))])])
			.validate()
			.unwrap_err();
		assert!(err.to_string().contains("Invalid secret name"));
	}

	#[test]
	fn config_validate_accepts_valid_config() {
		assert!(
			config_with(
				"proj",
				vec![("default", vec![("API_KEY", secret(Some("d")))])]
			)
			.validate()
			.is_ok()
		);
	}

	#[test]
	fn config_validate_accepts_partial_profile_override() {
		assert!(
			config_with(
				"proj",
				vec![
					("default", vec![("API_KEY", secret(Some("inherited")))]),
					("production", vec![("API_KEY", secret(None))]),
				]
			)
			.validate()
			.is_ok()
		);
	}

	#[test]
	fn secret_validate_requires_nonempty_description() {
		assert_eq!(secret(None).validate().unwrap_err(), "missing description");
		assert_eq!(
			secret(Some("")).validate().unwrap_err(),
			"description cannot be empty"
		);
	}

	#[test]
	fn secret_validate_rejects_required_with_default() {
		let s = Secret {
			description: Some("d".to_string()),
			required: Some(true),
			default: Some("v".to_string()),
			..Default::default()
		};
		assert!(
			s.validate()
				.unwrap_err()
				.contains("Required secrets cannot have default")
		);
	}

	#[test]
	fn secret_validate_generate_requires_type() {
		let s = Secret {
			description: Some("d".to_string()),
			generate: Some(GenerateConfig::Bool(true)),
			..Default::default()
		};
		assert!(s.validate().unwrap_err().contains("requires 'type'"));
	}

	#[test]
	fn secret_validate_rejects_unknown_type() {
		let s = Secret {
			description: Some("d".to_string()),
			secret_type: Some("banana".to_string()),
			..Default::default()
		};
		assert!(s.validate().unwrap_err().contains("unknown secret type"));
	}

	#[test]
	fn secret_validate_command_type_requires_command() {
		let s = Secret {
			description: Some("d".to_string()),
			secret_type: Some("command".to_string()),
			generate: Some(GenerateConfig::Bool(true)),
			..Default::default()
		};
		assert!(
			s.validate()
				.unwrap_err()
				.contains("requires generate = { command")
		);
	}

	#[test]
	fn generate_config_is_enabled() {
		assert!(!GenerateConfig::Bool(false).is_enabled());
		assert!(GenerateConfig::Bool(true).is_enabled());
		assert!(GenerateConfig::Options(GenerateOptions::default()).is_enabled());
	}

	#[test]
	fn manifest_applies_profile_defaults_and_default_profile_fallback() {
		let config: Config = r#"
[project]
name = "demo"
revision = "1.0"

[groups]
backend = "Backend services"

[providers]
private = "op+token://vault/item"

[profiles.default]
DATABASE_URL = { description = "Database", required = true, groups = ["backend"] }
LOG_LEVEL = { description = "Log level", required = false, default = "info" }
TLS_CERT = { description = "TLS certificate", as_path = true }

[profiles.development.defaults]
required = false

[profiles.development]
DATABASE_URL = { description = "Development database", default = "sqlite://dev.db" }
DEBUG_TOKEN = { description = "Debug token" }

[profiles.production]
API_KEY = { description = "API key", required = true }
"#
		.parse()
		.expect("valid config");

		let manifest = config.to_manifest();
		let manifest_json = serde_json::to_value(&manifest).unwrap();

		assert!(
			!serde_json::to_string(&manifest)
				.unwrap()
				.contains("op+token")
		);
		insta::assert_json_snapshot!(manifest_json);
	}

	#[test]
	fn manifest_secret_returns_none_for_unknown_secret() {
		let config = config_with(
			"demo",
			vec![("default", vec![("TOKEN", secret(Some("Token")))])],
		);

		assert_eq!(config.manifest_secret("MISSING", "default"), None);
	}

	#[test]
	fn manifest_serializes_camel_case_metadata() {
		let config = config_with(
			"demo",
			vec![(
				"default",
				vec![(
					"TOKEN",
					Secret {
						description: Some("Token".to_string()),
						as_path: Some(true),
						..Default::default()
					},
				)],
			)],
		);

		let json = serde_json::to_value(config.to_manifest()).unwrap();
		insta::assert_json_snapshot!(json);
	}
}
