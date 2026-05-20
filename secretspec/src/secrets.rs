//! Core secrets management functionality

use crate::config::{
    Config, GlobalConfig, Profile, ProviderDependency, ProviderRef, Resolved, SecretRequest,
};
use crate::error::{Result, SecretSpecError};
use crate::provider::{Provider as ProviderTrait, provider_from_spec_with_dependencies};
use crate::validation::{ValidatedSecrets, ValidationErrors};
use colored::Colorize;
use secrecy::{ExposeSecret, SecretString};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::env;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

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
fn warn_provider_failure(uri: &str, secret_name: &str, err: &SecretSpecError) {
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

/// Emits a warning when the primary provider for a batch fetch fails (either
/// during construction or during `get_batch`); affected secrets will still be
/// retried via their per-secret fallback chain below.
fn warn_primary_provider_failure(uri: Option<&str>, err: &SecretSpecError) {
    let uri = uri.map(redact_provider_uri).unwrap_or_else(|| "<default>".to_string());
    tracing::warn!(provider = %uri, error = %err, "primary batch provider failed");
    eprintln!(
        "{} primary provider {} failed: {}; will try fallback chain for affected secrets",
        "warning:".yellow(),
        uri.bold(),
        err
    );
}

/// Walks up from the current directory looking for `secretspec.toml`.
fn find_config_file() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let candidate = dir.join("secretspec.toml");
        if candidate.exists() {
            return Ok(candidate);
        }
        if !dir.pop() {
            return Err(SecretSpecError::NoManifest);
        }
    }
}

/// The main entry point for the secretspec library
///
/// `Secrets` manages the loading, validation, and retrieval of secrets
/// based on the project and global configuration files.
///
/// # Example
///
/// ```no_run
/// use secretspec::Secrets;
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
        }
    }

    /// Loads a `Secrets` by walking up from the current directory to find `secretspec.toml`
    ///
    /// This method searches the current directory and all parent directories for
    /// a `secretspec.toml` file, similar to how `cargo` and `git` find their configs.
    ///
    /// # Returns
    ///
    /// A loaded `Secrets` instance
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No `secretspec.toml` file is found in the current or any parent directory
    /// - Configuration files are invalid
    /// - The project revision is unsupported
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
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
    /// Use this when the path to `secretspec.toml` is known, e.g. via the `--file` flag.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the `secretspec.toml` file
    pub fn load_from(path: &Path) -> Result<Self> {
        let project_config = Config::try_from(path)?;
        let global_config = GlobalConfig::load()?;
        Ok(Self {
            config: project_config,
            global_config,
            provider: None,
            profile: None,
        })
    }

    /// Sets the provider to use for secret operations
    ///
    /// This overrides the provider from global configuration.
    ///
    /// # Arguments
    ///
    /// * `provider` - The provider name or URI (e.g., "keyring", "dotenv:/path/to/.env")
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
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
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// spec.set_profile("production");
    /// spec.check(false).unwrap();
    /// ```
    pub fn set_profile(&mut self, profile: impl Into<String>) {
        self.profile = Some(profile.into());
    }

    /// Get a reference to the project configuration (for testing)
    #[cfg(test)]
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the global configuration (for testing)
    #[cfg(test)]
    pub(crate) fn global_config(&self) -> &Option<GlobalConfig> {
        &self.global_config
    }

    /// Resolves the profile to use based on the provided value and configuration
    ///
    /// Profile resolution order:
    /// 1. Provided profile argument
    /// 2. Profile set via set_profile()
    /// 3. SECRETSPEC_PROFILE environment variable
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
            .map(|p| p.to_string())
            .or_else(|| self.profile.clone())
            .or_else(|| env::var("SECRETSPEC_PROFILE").ok())
            .or_else(|| {
                self.global_config
                    .as_ref()
                    .and_then(|gc| gc.defaults.profile.clone())
            })
            .unwrap_or_else(|| "default".to_string())
    }

    /// Returns the named profile or an `InvalidProfile` error listing the profiles
    /// defined in `secretspec.toml`.
    fn require_profile(&self, profile_name: &str) -> Result<&Profile> {
        self.config.profiles.get(profile_name).ok_or_else(|| {
            let mut available: Vec<&str> =
                self.config.profiles.keys().map(String::as_str).collect();
            available.sort();
            SecretSpecError::InvalidProfile(format!(
                "'{}' is not defined in secretspec.toml. Available profiles: {}",
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
        let profile_name = profile
            .map(str::to_string)
            .unwrap_or_else(|| self.resolve_profile_name(None));
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

        let default_secret = if profile_name != "default" {
            self.config
                .profiles
                .get("default")
                .and_then(|default_profile| default_profile.secrets.get(name))
        } else {
            None
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
                        .or_else(|| current_defaults.and_then(|d| d.providers.clone().map(|v| v.into_iter().map(ProviderRef::from).collect()))),
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
                    providers: secret
                        .providers
                        .clone()
                        .or_else(|| current_defaults.and_then(|d| d.providers.clone().map(|v| v.into_iter().map(ProviderRef::from).collect()))),
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
        uri: String,
        profile_name: &str,
    ) -> Result<Box<dyn ProviderTrait>> {
        let dependencies = self.resolve_provider_requirements(alias, profile_name)?;
        let dependencies = dependencies
            .into_iter()
            .map(|(dep, value)| (dep.effective_as().to_string(), value))
            .collect::<Vec<_>>();

        provider_from_spec_with_dependencies(&uri, &dependencies)
    }

    fn provider_from_uri(&self, uri: String, profile_name: &str) -> Result<Box<dyn ProviderTrait>> {
        match self.alias_for_provider_uri(&uri) {
            Some(alias) => self.provider_from_alias(&alias, uri, profile_name),
            None => Box::<dyn ProviderTrait>::try_from(uri),
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
                    SecretSpecError::SecretNotFound(
                        format!(
                            "Provider '{}' requires secret '{}' but it is not defined in secretspec.toml",
                            alias, secret_name
                        )
                    )
                })?;

            let provider_entries = self.resolve_read_provider_uris(&secret_config, None)?;
            let project_name = &self.config.project.name;

            let value = match provider_entries {
                Some(entries) if !entries.is_empty() => {
                    match self.get_secret_from_providers(
                        project_name,
                        secret_name,
                        profile_name,
                        Some(&entries),
                        None,
                    )? {
                        Some(v) => v,
                        None => {
                            return Err(SecretSpecError::ProviderOperationFailed(format!(
                                "Provider '{}' requires secret '{}' but it was not found",
                                alias, secret_name
                            )));
                        }
                    }
                }
                _ => {
                    // Use default provider.
                    let provider = self.get_provider(None)?;
                    match provider.get(project_name, secret_name, profile_name)? {
                        Some(v) => v,
                        None => {
                            return Err(SecretSpecError::ProviderOperationFailed(format!(
                                "Provider '{}' requires secret '{}' but it was not found",
                                alias, secret_name
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

    /// Resolves a list of [`ProviderRef`]s to (URI, SecretRequest) pairs, preserving order.
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
            match self.lookup_provider_alias(alias) {
                Some(uri) => {
                    let request = SecretRequest::from_provider_ref(r);
                    tracing::debug!(
                        alias = %alias,
                        provider = %redact_provider_uri(&uri),
                        path = ?request.path,
                        key = ?request.key,
                        "resolved provider reference"
                    );
                    entries.push((uri, request));
                }
                None => {
                    let known = self.known_provider_aliases();
                    let msg = if known.is_empty() {
                        format!(
                            "Provider alias '{}' is not defined. Declare it in [providers] in secretspec.toml or in the global config.",
                            alias
                        )
                    } else {
                        format!(
                            "Provider alias '{}' is not defined. Available aliases: {}",
                            alias,
                            known.join(", ")
                        )
                    };
                    return Err(SecretSpecError::ProviderNotFound(msg));
                }
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
            match self.lookup_provider_alias(alias) {
                Some(uri) => uris.push(uri),
                None => {
                    let known = self.known_provider_aliases();
                    let msg = if known.is_empty() {
                        format!(
                            "Provider alias '{}' is not defined. Declare it in [providers] in secretspec.toml or in the global config.",
                            alias
                        )
                    } else {
                        format!(
                            "Provider alias '{}' is not defined. Available aliases: {}",
                            alias,
                            known.join(", ")
                        )
                    };
                    return Err(SecretSpecError::ProviderNotFound(msg));
                }
            }
        }
        Ok(Some(uris))
    }

    /// Returns the explicit provider spec from caller arg, builder, or env, in
    /// that priority order.
    ///
    /// Used as the shared head of provider resolution so the precedence between
    /// the `--provider` flag (forwarded via `set_provider`) and the
    /// `SECRETSPEC_PROVIDER` env var stays consistent across resolvers.
    fn explicit_provider_spec(&self, override_arg: Option<String>) -> Option<String> {
        override_arg
            .or_else(|| self.provider.clone())
            .or_else(|| env::var("SECRETSPEC_PROVIDER").ok())
    }

    /// Returns the explicit provider override resolved to a URI, if one is set.
    ///
    /// Resolves the explicit spec via [`Self::explicit_provider_spec`], then
    /// expands any matching alias via [`Self::lookup_provider_alias`].
    pub(crate) fn resolve_provider_override(&self, override_arg: Option<&str>) -> Option<String> {
        let spec = self.explicit_provider_spec(override_arg.map(|s| s.to_string()))?;
        Some(self.lookup_provider_alias(&spec).unwrap_or(spec))
    }

    /// Resolves the write target for a secret.
    ///
    /// Resolution order:
    /// 1. Explicit override (`--provider` flag, `SECRETSPEC_PROVIDER`, or builder)
    /// 2. First entry of the secret's `providers` chain
    /// 3. Default provider from global config
    pub(crate) fn resolve_write_provider(
        &self,
        secret_config: &crate::config::Secret,
        override_arg: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        let profile_name = self.resolve_profile_name(None);

        if let Some(uri) = self.resolve_provider_override(override_arg) {
            return self.provider_from_uri(uri, &profile_name);
        }
        if let Some(first_ref) = secret_config.providers.as_ref().and_then(|p| p.first()) {
            let alias = first_ref.provider_alias().to_string();
            let provider_uris =
                self.resolve_provider_aliases(Some(std::slice::from_ref(&alias)))?;
            let uri = provider_uris
                .and_then(|uris| uris.into_iter().next())
                .ok_or_else(|| {
                    SecretSpecError::ProviderNotFound(format!(
                        "Provider alias '{}' could not be resolved",
                        alias
                    ))
                })?;
            return self.provider_from_alias(&alias, uri, &profile_name);
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
    /// 3. Environment variable (SECRETSPEC_PROVIDER)
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
        provider_arg: Option<String>,
    ) -> Result<Box<dyn ProviderTrait>> {
        let provider_spec = self
            .explicit_provider_spec(provider_arg)
            .or_else(|| {
                self.global_config
                    .as_ref()
                    .and_then(|gc| gc.defaults.provider.clone())
            })
            .map(|spec| self.lookup_provider_alias(&spec).unwrap_or(spec))
            .ok_or(SecretSpecError::NoProviderConfigured)?;

        let profile_name = self.resolve_profile_name(None);
        self.provider_from_uri(provider_spec, &profile_name)
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
        provider_entries: Option<&[(String, SecretRequest)]>,
        default_provider_arg: Option<String>,
    ) -> Result<Option<SecretString>> {
        // If provider entries are specified, try them in order
        if let Some(entries) = provider_entries {
            let mut last_error: Option<SecretSpecError> = None;
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
                let provider = match self.provider_from_uri(uri.clone(), profile_name) {
                    Ok(p) => p,
                    Err(e) => {
                        warn_provider_failure(uri, secret_name, &e);
                        last_error = Some(e);
                        continue;
                    }
                };
                match provider.get_with_request(project_name, secret_name, profile_name, request) {
                    Ok(Some(value)) => {
                        tracing::debug!(provider = %redact_provider_uri(uri), secret = %secret_name, "provider lookup found secret");
                        return Ok(Some(value));
                    }
                    Ok(None) => {
                        any_healthy = true;
                        continue;
                    }
                    Err(e) => {
                        warn_provider_failure(uri, secret_name, &e);
                        last_error = Some(e);
                        continue;
                    }
                }
            }
            // Surface the last error only if no provider in the chain returned
            // a healthy "not found" — otherwise the secret is genuinely missing.
            match last_error {
                Some(e) if !any_healthy => Err(e),
                _ => Ok(None),
            }
        } else {
            // No per-secret providers, use default provider
            let backend = self.get_provider(default_provider_arg)?;
            backend.get(project_name, secret_name, profile_name)
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
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// spec.set("DATABASE_URL", Some("postgres://localhost".to_string())).unwrap();
    /// ```
    pub fn set(&self, name: &str, value: Option<String>) -> Result<()> {
        // Check if the secret exists in the spec
        let profile_name = self.resolve_profile_name(None);
        self.require_profile(&profile_name)?;

        // Check if the secret exists in the profile or is inherited from default
        let secret_config = match self.resolve_secret_config(name, None) {
            Some(sc) => sc,
            None => {
                let profile = self.resolve_profile(Some(&profile_name))?;
                let mut available_secrets = profile
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>();
                available_secrets.sort();

                return Err(SecretSpecError::SecretNotFound(format!(
                    "Secret '{}' is not defined in profile '{}'. Available secrets: {}",
                    name,
                    profile_name,
                    available_secrets.join(", ")
                )));
            }
        };

        let backend = self.resolve_write_provider(&secret_config, None)?;

        if !backend.allows_set() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
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
            return Err(SecretSpecError::ProviderOperationFailed(
                "Secret value cannot be empty".to_string(),
            ));
        }

        backend.set(&self.config.project.name, name, &value, &profile_name)?;
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
        let profile_name = self.resolve_profile_name(None);
        let secret_config = self
            .resolve_secret_config(name, None)
            .ok_or_else(|| SecretSpecError::SecretNotFound(name.to_string()))?;
        let default = secret_config.default.clone();
        let as_path = secret_config.as_path.unwrap_or(false);

        let provider_uris = self.resolve_read_provider_uris(&secret_config, None)?;

        match self.get_secret_from_providers(
            &self.config.project.name,
            name,
            &profile_name,
            provider_uris.as_deref(),
            None,
        )? {
            Some(value) => {
                if as_path {
                    // Write to temp file and persist it (don't auto-delete)
                    let (temp_file, _path_str) = self.write_secret_to_temp_file(&value)?;
                    let temp_path = temp_file.into_temp_path();
                    let persisted_path = temp_path.keep().map_err(|e| {
                        SecretSpecError::Io(io::Error::other(format!(
                            "Failed to persist temporary file: {}",
                            e
                        )))
                    })?;
                    println!("{}", persisted_path.display());
                } else {
                    // Use expose_secret() to access the actual value for printing
                    println!("{}", value.expose_secret());
                }
                Ok(())
            }
            None => {
                if let Some(default_value) = default {
                    if as_path {
                        // Write default value to temp file and persist it
                        let (temp_file, _) = self
                            .write_secret_to_temp_file(&SecretString::new(default_value.into()))?;
                        let temp_path = temp_file.into_temp_path();
                        let persisted_path = temp_path.keep().map_err(|e| {
                            SecretSpecError::Io(io::Error::other(format!(
                                "Failed to persist temporary file: {}",
                                e
                            )))
                        })?;
                        println!("{}", persisted_path.display());
                    } else {
                        println!("{}", default_value);
                    }
                    Ok(())
                } else {
                    Err(SecretSpecError::SecretNotFound(name.to_string()))
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
    pub fn ensure_secrets(
        &self,
        provider_arg: Option<String>,
        profile: Option<String>,
        interactive: bool,
    ) -> Result<ValidatedSecrets> {
        self.ensure_secrets_selected(provider_arg, profile, interactive, None)
    }

    fn ensure_secrets_selected(
        &self,
        provider_arg: Option<String>,
        profile: Option<String>,
        interactive: bool,
        selected_names: Option<&HashSet<String>>,
    ) -> Result<ValidatedSecrets> {
        let profile_display = self.resolve_profile_name(profile.as_deref());

        // First validate to see what's missing
        let validation_result = self.validate_selected(selected_names)?;

        match validation_result {
            Ok(valid_secrets) => Ok(valid_secrets),
            Err(validation_errors) => {
                // If we're in interactive mode and have missing required secrets, prompt for them
                if interactive && !validation_errors.missing_required.is_empty() {
                    if !io::stdin().is_terminal() {
                        return Err(SecretSpecError::RequiredSecretMissing(
                            validation_errors.missing_required.join(", "),
                        ));
                    }

                    let missing = &validation_errors.missing_required;
                    let total = missing.len();
                    let default_backend = self.get_provider(provider_arg.clone())?;

                    // List all missing secrets upfront
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
                            .resolve_secret_config(secret_name, Some(&profile_display))
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

                    // Prompt for each missing secret
                    for (i, secret_name) in missing.iter().enumerate() {
                        if let Some(secret_config) =
                            self.resolve_secret_config(secret_name, Some(&profile_display))
                        {
                            let prompt_msg =
                                format!("[{}/{}] Enter value for {}:", i + 1, total, secret_name,);
                            let prompt = inquire::Password::new(&prompt_msg).without_confirmation();

                            let value = prompt.prompt()?;

                            let backend = self
                                .resolve_write_provider(&secret_config, provider_arg.as_deref())?;
                            backend.set(
                                &self.config.project.name,
                                secret_name,
                                &SecretString::new(value.into()),
                                &profile_display,
                            )?;
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

                    // Re-validate to get the updated results
                    match self.validate()? {
                        Ok(valid_secrets) => Ok(valid_secrets),
                        Err(still_errors) => Err(SecretSpecError::RequiredSecretMissing(
                            still_errors.missing_required.join(", "),
                        )),
                    }
                } else {
                    // Not interactive or no missing required secrets
                    Err(SecretSpecError::RequiredSecretMissing(
                        validation_errors.missing_required.join(", "),
                    ))
                }
            }
        }
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
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// let validated = spec.check(false).unwrap();
    /// ```
    pub fn check(&self, no_prompt: bool) -> Result<ValidatedSecrets> {
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

        for (name, config) in profile.iter() {
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

        for (name, config) in &profile {
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
    /// use secretspec::Secrets;
    ///
    /// let spec = Secrets::load().unwrap();
    /// spec.import("dotenv://.env.production").unwrap();
    /// ```
    pub fn import(&self, from_provider: &str) -> Result<()> {
        // Resolve profile (checks env var, then global config, then defaults to "default")
        let profile_display = self.resolve_profile_name(None);

        // Create the "from" provider and check availability
        let from_provider_instance =
            self.provider_from_uri(from_provider.to_string(), &profile_display)?;

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
        for (name, config) in profile.into_iter() {
            let secret_config = self
                .resolve_secret_config(&name, Some(&profile_display))
                .expect("Secret should exist since we're iterating over it");

            let to_provider = self.resolve_write_provider(&secret_config, None)?;

            // First check if the secret exists in the "from" provider
            match from_provider_instance.get(&self.config.project.name, &name, &profile_display)? {
                Some(value) => {
                    // Secret exists in "from" provider, check if it exists in "to" provider
                    match to_provider.get(&self.config.project.name, &name, &profile_display)? {
                        Some(_) => {
                            eprintln!(
                                "{} {} - {} {} (→ {})",
                                "○".yellow(),
                                name,
                                config.description.as_deref().unwrap_or("No description"),
                                "(already exists in target)".yellow(),
                                to_provider.name().blue()
                            );
                            already_exists += 1;
                        }
                        None => {
                            // Secret doesn't exist in "to" provider, import it
                            to_provider.set(
                                &self.config.project.name,
                                &name,
                                &value,
                                &profile_display,
                            )?;
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
                }
                None => {
                    // Secret doesn't exist in "from" provider
                    // Check if it exists in the "to" provider
                    match to_provider.get(&self.config.project.name, &name, &profile_display)? {
                        Some(_) => {
                            eprintln!(
                                "{} {} - {} {} (→ {})",
                                "○".blue(),
                                name,
                                config.description.as_deref().unwrap_or("No description"),
                                "(already in target, not in source)".blue(),
                                to_provider.name().blue()
                            );
                            already_exists += 1;
                        }
                        None => {
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
            return Err(SecretSpecError::ProviderOperationFailed(format!(
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
                return Err(SecretSpecError::GenerationFailed(format!(
                    "Secret '{}' has generate config but no type",
                    name
                )));
            }
        };

        let value = crate::generator::generate(secret_type, gen_config)?;

        // Store the generated value
        let backend = self.get_writable_provider_for_secret(secret_config)?;
        backend.set(&self.config.project.name, name, &value, profile_name)?;

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
        &self,
        secret: &SecretString,
    ) -> Result<(tempfile::NamedTempFile, String)> {
        use std::io::Write;

        let mut temp_file = tempfile::NamedTempFile::new().map_err(SecretSpecError::Io)?;

        temp_file
            .write_all(secret.expose_secret().as_bytes())
            .map_err(SecretSpecError::Io)?;

        // Flush to ensure the data is written
        temp_file.flush().map_err(SecretSpecError::Io)?;

        // Set restrictive permissions (0o400) so only the owner can read
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = temp_file
                .as_file()
                .metadata()
                .map_err(SecretSpecError::Io)?
                .permissions();
            perms.set_mode(0o400);
            temp_file
                .as_file()
                .set_permissions(perms)
                .map_err(SecretSpecError::Io)?;
        }

        // Get the path as a string
        let path_str = temp_file
            .path()
            .to_str()
            .ok_or_else(|| {
                SecretSpecError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Temporary file path is not valid UTF-8",
                ))
            })?
            .to_string();

        Ok((temp_file, path_str))
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
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// let result = spec.validate().unwrap();
    /// if let Ok(validated) = result {
    ///     println!("All required secrets are present!");
    /// }
    /// ```
    pub fn validate(&self) -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
        self.validate_selected(None)
    }

    fn validate_selected(
        &self,
        selected_names: Option<&HashSet<String>>,
    ) -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
        let mut secrets: HashMap<String, SecretString> = HashMap::new();
        let mut missing_required = Vec::new();
        let mut missing_optional = Vec::new();
        let mut with_defaults = Vec::new();
        let mut temp_files = Vec::new();

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

        for (name, _) in &all_secrets {
            let secret_config = self
                .resolve_secret_config(name, Some(&profile_name))
                .expect("Secret should exist in config since we're iterating over it");

            let primary_entry = match (&override_uri, secret_config.providers.as_deref()) {
                (Some(uri), _) => Some((uri.clone(), SecretRequest::default())),
                (None, Some([first_ref, ..])) => self
                    .resolve_provider_ref_uris(Some(std::slice::from_ref(first_ref)))?
                    .and_then(|entries| entries.into_iter().next()),
                _ => None,
            };
            let provider_uri = primary_entry.as_ref().map(|(uri, _)| uri.clone());

            secret_primary_uris.insert(name.clone(), provider_uri.clone());

            let can_batch = primary_entry
                .as_ref()
                .map(|(_, request)| request == &SecretRequest::default())
                .unwrap_or(true);

            if can_batch {
                provider_groups
                    .entry(provider_uri)
                    .or_default()
                    .push(name.clone());
                continue;
            }

            let provider_entries = self.resolve_provider_ref_uris(secret_config.providers.as_deref())?;

            if let Some(value) = self.get_secret_from_providers(
                &self.config.project.name,
                name,
                &profile_name,
                provider_entries.as_deref(),
                None,
            )? {
                fetched_values.insert(name.clone(), value);
            }
        }

        // Batch fetch from each provider group. A failure here (e.g. an
        // unauthenticated vault) does not abort validation: secrets that
        // declare a fallback chain are retried per-secret below. Secrets in
        // the failed group with no fallback to try will surface the original
        // error instead of being silently reported as missing.
        let mut failed_primary_uris: HashMap<Option<String>, SecretSpecError> = HashMap::new();

        for (provider_uri, secret_names) in provider_groups {
            let provider_result = if let Some(uri) = provider_uri.clone() {
                self.provider_from_uri(uri, &profile_name)
            } else {
                self.get_provider(None)
            };

            let provider = match provider_result {
                Ok(p) => p,
                Err(e) => {
                    warn_primary_provider_failure(provider_uri.as_deref(), &e);
                    failed_primary_uris.insert(provider_uri, e);
                    continue;
                }
            };

            let keys: Vec<&str> = secret_names.iter().map(|s| s.as_str()).collect();
            match provider.get_batch(&self.config.project.name, &keys, &profile_name) {
                Ok(batch_results) => fetched_values.extend(batch_results),
                Err(e) => {
                    warn_primary_provider_failure(provider_uri.as_deref(), &e);
                    failed_primary_uris.insert(provider_uri, e);
                }
            }
        }

        // Process results - apply defaults, handle as_path, track missing
        for (name, _) in all_secrets {
            let secret_config = self
                .resolve_secret_config(&name, Some(&profile_name))
                .expect("Secret should exist in config since we're iterating over it");
            let required = secret_config.required.unwrap_or(true);
            let default = secret_config.default.clone();
            let as_path = secret_config.as_path.unwrap_or(false);

            match fetched_values.remove(&name) {
                Some(value) => {
                    if as_path {
                        // Write secret to temp file and store the path
                        let (temp_file, path_str) = self.write_secret_to_temp_file(&value)?;
                        temp_files.push(temp_file);
                        secrets.insert(name.clone(), SecretString::new(path_str.into()));
                    } else {
                        secrets.insert(name, value);
                    }
                }
                None => {
                    let primary_uri = &secret_primary_uris[&name];
                    let primary_failed = failed_primary_uris.contains_key(primary_uri);

                    // An explicit override collapses the chain to one provider, so no fallback.
                    let fallback_value =
                        match (override_uri.as_ref(), secret_config.providers.as_deref()) {
                            (None, Some(providers)) if providers.len() > 1 => {
                                let fallback_entries =
                                    self.resolve_provider_ref_uris(Some(&providers[1..]))?;
                                self.get_secret_from_providers(
                                    &self.config.project.name,
                                    &name,
                                    &profile_name,
                                    fallback_entries.as_deref(),
                                    None,
                                )?
                            }
                            // No alternative chain to try and the primary failed: surface the
                            // original error rather than reporting the secret as merely missing.
                            _ if primary_failed => {
                                return Err(failed_primary_uris
                                    .remove(primary_uri)
                                    .expect("primary_failed implies entry present"));
                            }
                            _ => None,
                        };

                    if let Some(value) = fallback_value {
                        if as_path {
                            let (temp_file, path_str) = self.write_secret_to_temp_file(&value)?;
                            temp_files.push(temp_file);
                            secrets.insert(name.clone(), SecretString::new(path_str.into()));
                        } else {
                            secrets.insert(name, value);
                        }
                    } else if let Some(generated) =
                        self.try_generate_secret(&name, &secret_config, &profile_name)?
                    {
                        if as_path {
                            let (temp_file, path_str) =
                                self.write_secret_to_temp_file(&generated)?;
                            temp_files.push(temp_file);
                            secrets.insert(name.clone(), SecretString::new(path_str.into()));
                        } else {
                            secrets.insert(name, generated);
                        }
                    } else if let Some(default_value) = default {
                        if as_path {
                            // Write default value to temp file
                            let (temp_file, path_str) = self.write_secret_to_temp_file(
                                &SecretString::new(default_value.clone().into()),
                            )?;
                            temp_files.push(temp_file);
                            secrets.insert(name.clone(), SecretString::new(path_str.into()));
                        } else {
                            secrets.insert(
                                name.clone(),
                                SecretString::new(default_value.clone().into()),
                            );
                        }
                        with_defaults.push((name, default_value));
                    } else if required {
                        missing_required.push(name);
                    } else {
                        missing_optional.push(name);
                    }
                }
            }
        }

        let report_provider_uri =
            self.validation_report_provider_uri(override_uri.as_deref(), &secret_primary_uris)?;

        // Check if there are any missing required secrets
        if !missing_required.is_empty() {
            Ok(Err(ValidationErrors::new(
                missing_required,
                missing_optional,
                with_defaults,
                report_provider_uri,
                profile_name.to_string(),
            )))
        } else {
            Ok(Ok(ValidatedSecrets {
                resolved: Resolved::new(secrets, report_provider_uri, profile_name.to_string()),
                missing_optional,
                with_defaults,
                temp_files,
            }))
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

    fn invalid_input(message: impl Into<String>) -> SecretSpecError {
        SecretSpecError::Io(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
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
                    "Included secret '{}' is not defined in profile '{}'",
                    name, profile_name
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
                    "Group '{}' is not declared in the top-level [groups] table",
                    group
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
                    "Group '{}' does not match any secrets in profile '{}'",
                    group, profile_name
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
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// spec.run(vec!["npm".to_string(), "start".to_string()]).unwrap();
    /// ```
    pub fn run(&self, command: Vec<String>) -> Result<()> {
        let exit_code = self.run_command(command)?;
        std::process::exit(exit_code);
    }

    pub fn run_filtered(
        &self,
        command: Vec<String>,
        includes: &[String],
        groups: &[String],
    ) -> Result<()> {
        let exit_code = self.run_command_filtered(command, includes, groups)?;
        std::process::exit(exit_code);
    }

    /// Runs a command with secrets injected and returns its exit code.
    ///
    /// Splitting this out from [`Self::run`] ensures that any temporary files
    /// backing `as_path` secrets are dropped (and removed from disk) before
    /// `std::process::exit` is called — `exit` does not run destructors.
    pub(crate) fn run_command(&self, command: Vec<String>) -> Result<i32> {
        self.run_command_with_selection(command, None)
    }

    pub(crate) fn run_command_filtered(
        &self,
        command: Vec<String>,
        includes: &[String],
        groups: &[String],
    ) -> Result<i32> {
        let selected = self.selected_secret_names(includes, groups)?;
        self.run_command_with_selection(command, selected.as_ref())
    }

    fn run_command_with_selection(
        &self,
        command: Vec<String>,
        selected_names: Option<&HashSet<String>>,
    ) -> Result<i32> {
        if command.is_empty() {
            return Err(SecretSpecError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No command specified. Usage: secretspec run -- <command> [args...]",
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
