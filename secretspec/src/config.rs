//! # SecretSpec Core Configuration Types
//!
//! This module provides the core type definitions and parsing logic for the SecretSpec
//! configuration system.
//!
//! SecretSpec uses a declarative TOML-based configuration format to define secrets
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
//! A typical `secretspec.toml` file has this structure:
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

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, hash_map};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// The root configuration structure for a SecretSpec project.
///
/// This is the top-level type that represents the entire `secretspec.toml` file.
/// It contains project metadata and profile-specific secret definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Project metadata including name, revision, and optional inheritance
    pub project: Project,
    /// Map of profile names to their configurations (e.g., "default", "production", "staging")
    pub profiles: HashMap<String, Profile>,
}

impl Config {
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

        // Validate each profile
        for (profile_name, profile) in &self.profiles {
            profile.validate().map_err(|e| {
                ParseError::Validation(format!("Profile '{}': {}", profile_name, e))
            })?;
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
            // If path ends with .toml, use it as-is; otherwise append secretspec.toml
            let joined_path = base_dir.join(extend_path);
            let full_path = if extend_path.ends_with(".toml") {
                joined_path
            } else {
                joined_path.join("secretspec.toml")
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
    /// Optional list of relative paths to other SecretSpec projects to inherit from
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<Vec<String>>,
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
                    "Invalid secret name '{}': must be a valid identifier (alphanumeric and underscores, not starting with a number)",
                    name
                ));
            }

            secret
                .validate()
                .map_err(|e| format!("Secret '{}': {}", name, e))?;
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
    type Item = (&'a String, &'a Secret);
    type IntoIter = hash_map::Iter<'a, String, Secret>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.secrets.iter()
    }
}

impl IntoIterator for Profile {
    type Item = (String, Secret);
    type IntoIter = hash_map::IntoIter<String, Secret>;

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
    /// Optional list of provider aliases for retrieving this secret.
    /// Providers are tried in order until one has the secret.
    /// If not specified, uses the profile defaults.providers or global provider.
    /// Each alias is resolved against the providers map in GlobalConfig.
    /// Example: providers = ["keyring", "env"] will try keyring first, then env.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<String>>,
    /// Whether to write the secret value to a temporary file and return the path.
    /// If true, the secret will be written to a temporary file and the field
    /// will contain the path to that file instead of the secret value.
    /// The temporary file will be cleaned up when the resolved secrets are dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_path: Option<bool>,
    /// The type of secret, used for generation (e.g., "password", "hex", "base64", "uuid", "command")
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
                    "password" | "hex" | "base64" | "uuid" | "command" => {}
                    unknown => {
                        return Err(format!("unknown secret type '{}'", unknown));
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
                "password" | "hex" | "base64" | "uuid" | "command" => {}
                unknown => {
                    return Err(format!("unknown secret type '{}'", unknown));
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

/// Global user configuration for SecretSpec.
///
/// This configuration is stored in the user's config directory and provides
/// defaults that apply across all projects.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[doc(hidden)]
pub struct GlobalConfig {
    /// Default settings
    #[serde(default)]
    pub defaults: GlobalDefaults,
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
    /// provider details in secretspec.toml. Example:
    /// ```toml
    /// [providers]
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
    /// typically `~/.config/secretspec/config.toml` on Unix systems.
    ///
    /// # Returns
    ///
    /// The path to the global configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be determined
    pub fn path() -> Result<PathBuf, io::Error> {
        use etcetera::app_strategy::{AppStrategy, AppStrategyArgs, choose_app_strategy};
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

        if !config_path.try_exists().map_err(ParseError::Io)? {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&config_path).map_err(ParseError::Io)?;
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
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&config_path, content)?;

        Ok(())
    }

    /// Migrate config from the old macOS location (~/Library/Application Support/secretspec/)
    /// to the XDG location (~/.config/secretspec/).
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
                        .join("Library/Application Support/secretspec")
                        .join("config.toml");
                    if old_path.exists() {
                        return Ok(old_path);
                    }
                }
                return Err(err);
            }
        }

        let old_path = match etcetera::home_dir() {
            Ok(home) => home
                .join("Library/Application Support/secretspec")
                .join("config.toml"),
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
        if let Some(parent) = new_path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
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
        if let Err(err) = std::fs::copy(&old_path, new_path) {
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
        if let Err(err) = std::fs::rename(&old_path, &old_backup) {
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
/// `secretspec-derive` macro containing the actual secret values.
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

/// Errors that can occur when parsing SecretSpec configuration files.
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
            ParseError::Io(e) => write!(f, "I/O error: {}", e),
            ParseError::Toml(e) => write!(f, "TOML parsing error: {}", e),
            ParseError::UnsupportedRevision(rev) => {
                write!(
                    f,
                    "Unsupported revision '{}'. Only '1.0' is supported.",
                    rev
                )
            }
            ParseError::CircularDependency(msg) => {
                write!(f, "Circular dependency detected: {}", msg)
            }
            ParseError::Validation(msg) => write!(f, "Validation error: {}", msg),
            ParseError::ExtendedConfigNotFound(path) => {
                write!(f, "Extended config file not found: {}", path)
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
