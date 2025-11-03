//! Core secrets management functionality

use crate::config::{Config, GlobalConfig, Profile, Resolved};
use crate::error::{Result, SecretSpecError};
use crate::provider::Provider as ProviderTrait;
use crate::validation::{ValidatedSecrets, ValidationErrors};
use colored::Colorize;
use secrecy::{ExposeSecret, SecretString};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::env;
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::Command;

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
/// spec.check().unwrap();
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

    /// Loads a `Secrets` using default configuration paths
    ///
    /// This method looks for:
    /// - `secretspec.toml` in the current directory for project configuration
    /// - User configuration in the system config directory
    ///
    /// # Returns
    ///
    /// A loaded `Secrets` instance
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No `secretspec.toml` file is found
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
    /// spec.check().unwrap();
    /// ```
    pub fn load() -> Result<Self> {
        let project_config = Config::try_from(Path::new("secretspec.toml"))?;
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
    /// spec.check().unwrap();
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
    /// spec.check().unwrap();
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
        let mut profile_config = self
            .config
            .profiles
            .get(&profile_name)
            .cloned()
            .ok_or_else(|| {
                SecretSpecError::SecretNotFound(format!("Profile '{}' not found", profile_name))
            })?;

        // If not the default profile, also add secrets from default profile
        if profile_name != "default" {
            if let Some(default_profile) = self.config.profiles.get("default").cloned() {
                profile_config.merge_with(default_profile);
            }
        }

        Ok(profile_config)
    }

    /// Resolves the configuration for a specific secret
    ///
    /// This method looks for the secret in the specified profile, falling back
    /// to the default profile if not found. If the secret exists in both profiles,
    /// fields are merged with the current profile taking precedence.
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

        let current_secret = self
            .config
            .profiles
            .get(&profile_name)
            .and_then(|profile_config| profile_config.secrets.get(name));

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
                // Merge: current profile takes precedence
                Some(crate::config::Secret {
                    description: current
                        .description
                        .clone()
                        .or_else(|| default.description.clone()),
                    required: current.required,
                    default: current.default.clone(),
                    providers: current
                        .providers
                        .clone()
                        .or_else(|| default.providers.clone()),
                })
            }
            (Some(secret), None) | (None, Some(secret)) => Some(secret.clone()),
            (None, None) => None,
        }
    }

    /// Resolves a list of provider aliases to their URIs using the global config providers map.
    ///
    /// Returns a list of provider URIs in the same order. Used for fallback chain resolution.
    ///
    /// # Arguments
    ///
    /// * `provider_aliases` - Optional list of provider aliases to resolve
    ///
    /// # Returns
    ///
    /// A list of provider URIs in the same order, or None if no aliases were provided
    ///
    /// # Errors
    ///
    /// Returns an error if any alias is not found in the providers map.
    pub(crate) fn resolve_provider_aliases(
        &self,
        provider_aliases: Option<&[String]>,
    ) -> Result<Option<Vec<String>>> {
        if let Some(aliases) = provider_aliases {
            let mut uris = Vec::new();

            for alias in aliases {
                // If a per-secret provider alias is specified, resolve it from the global config
                if let Some(global_config) = &self.global_config {
                    if let Some(providers_map) = &global_config.defaults.providers {
                        if let Some(uri) = providers_map.get(alias) {
                            uris.push(uri.clone());
                        } else {
                            return Err(SecretSpecError::ProviderNotFound(format!(
                                "Provider alias '{}' is not defined in the global config. Available aliases: {}",
                                alias,
                                providers_map
                                    .keys()
                                    .map(|s| s.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )));
                        }
                    } else {
                        return Err(SecretSpecError::ProviderNotFound(format!(
                            "Provider alias '{}' specified but no providers are configured in global config",
                            alias
                        )));
                    }
                } else {
                    return Err(SecretSpecError::ProviderNotFound(format!(
                        "Provider alias '{}' specified but no global config is loaded",
                        alias
                    )));
                }
            }

            return Ok(Some(uris));
        }
        Ok(None)
    }

    /// Gets the provider instance to use for secret operations
    ///
    /// Provider resolution order:
    /// 1. Provided provider argument
    /// 2. Provider set via builder
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
        let provider_spec = provider_arg
            .or_else(|| env::var("SECRETSPEC_PROVIDER").ok())
            .or_else(|| self.provider.clone())
            .or_else(|| {
                self.global_config
                    .as_ref()
                    .and_then(|gc| gc.defaults.provider.clone())
            })
            .ok_or(SecretSpecError::NoProviderConfigured)?;

        let provider = Box::<dyn ProviderTrait>::try_from(provider_spec)?;

        Ok(provider)
    }

    /// Gets a secret from a list of providers with fallback.
    ///
    /// Tries each provider in order until one has the secret.
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
        provider_uris: Option<&[String]>,
        default_provider_arg: Option<String>,
    ) -> Result<Option<SecretString>> {
        // If provider URIs are specified, try them in order
        if let Some(uris) = provider_uris {
            for uri in uris {
                let provider = Box::<dyn ProviderTrait>::try_from(uri.clone())?;
                match provider.get(project_name, secret_name, profile_name)? {
                    Some(value) => return Ok(Some(value)),
                    None => continue, // Try next provider
                }
            }
            // Not found in any provider, return None
            Ok(None)
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
        let _profile_config = self.config.profiles.get(&profile_name).ok_or_else(|| {
            SecretSpecError::SecretNotFound(format!(
                "Profile '{}' is not defined in secretspec.toml. Available profiles: {}",
                profile_name,
                self.config
                    .profiles
                    .keys()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;

        // Check if the secret exists in the profile or is inherited from default
        let secret_config = self.resolve_secret_config(name, None);
        if secret_config.is_none() {
            // Collect available secrets from both current profile and default
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

        // Resolve provider: use first provider in list if specified, otherwise use default
        let backend = if let Some(provider_aliases) = secret_config
            .as_ref()
            .and_then(|sc| sc.providers.as_ref())
            .and_then(|p| p.first())
        {
            let provider_uris = self.resolve_provider_aliases(Some(&[provider_aliases.clone()]))?;
            let uri = provider_uris.and_then(|uris| uris.first().cloned()).ok_or(
                SecretSpecError::ProviderNotFound(format!(
                    "Provider alias '{}' could not be resolved",
                    provider_aliases
                )),
            )?;
            Box::<dyn ProviderTrait>::try_from(uri)?
        } else {
            self.get_provider(None)?
        };

        // Check if the provider supports setting values
        if !backend.allows_set() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Provider '{}' is read-only and does not support setting values",
                backend.name()
            )));
        }

        let value = if let Some(v) = value {
            SecretString::new(v.into())
        } else if io::stdin().is_terminal() {
            // Use rpassword for single-line input (most common case)
            // For multiline secrets, users should pipe the content
            let secret = rpassword::prompt_password(format!(
                "Enter value for {name} (profile: {profile_name}): "
            ))?;
            SecretString::new(secret.into())
        } else {
            // Read from stdin when input is piped
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            SecretString::new(buffer.trim().to_string().into())
        };

        backend.set(&self.config.project.name, name, &value, &profile_name)?;
        println!(
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

        // Resolve per-secret provider aliases to URIs
        let provider_uris = self.resolve_provider_aliases(secret_config.providers.as_deref())?;

        // Try to get the secret from configured providers with fallback
        match self.get_secret_from_providers(
            &self.config.project.name,
            name,
            &profile_name,
            provider_uris.as_deref(),
            None,
        )? {
            Some(value) => {
                // Use expose_secret() to access the actual value for printing
                println!("{}", value.expose_secret());
                Ok(())
            }
            None => {
                if let Some(default_value) = default {
                    println!("{}", default_value);
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
    fn ensure_secrets(
        &self,
        provider_arg: Option<String>,
        profile: Option<String>,
        interactive: bool,
    ) -> Result<ValidatedSecrets> {
        let profile_display = self.resolve_profile_name(profile.as_deref());

        // First validate to see what's missing
        let validation_result = self.validate()?;

        match validation_result {
            Ok(valid_secrets) => Ok(valid_secrets),
            Err(validation_errors) => {
                // If we're in interactive mode and have missing required secrets, prompt for them
                if interactive && !validation_errors.missing_required.is_empty() {
                    println!("\nThe following required secrets are missing:");
                    for secret_name in &validation_errors.missing_required {
                        if let Some(secret_config) =
                            self.resolve_secret_config(secret_name, Some(&profile_display))
                        {
                            let description = secret_config
                                .description
                                .as_deref()
                                .unwrap_or("No description");
                            println!("\n{} - {}", secret_name.bold(), description);
                            let value = if io::stdin().is_terminal() {
                                print!(
                                    "Enter value for {} (profile: {}): ",
                                    secret_name, profile_display
                                );
                                io::stdout().flush()?;
                                rpassword::read_password()?
                            } else {
                                // When stdin is not a terminal, we can't prompt interactively
                                return Err(SecretSpecError::RequiredSecretMissing(
                                    validation_errors.missing_required.join(", "),
                                ));
                            };

                            // Get the provider for this specific secret
                            // Use first provider in list if specified, otherwise use CLI provider or default
                            let backend = if let Some(provider_aliases) =
                                secret_config.providers.as_ref().and_then(|p| p.first())
                            {
                                let provider_uris = self
                                    .resolve_provider_aliases(Some(&[provider_aliases.clone()]))?;
                                let uri = provider_uris
                                    .and_then(|uris| uris.first().cloned())
                                    .ok_or(SecretSpecError::ProviderNotFound(format!(
                                        "Provider alias '{}' could not be resolved",
                                        provider_aliases
                                    )))?;
                                Box::<dyn ProviderTrait>::try_from(uri)?
                            } else {
                                self.get_provider(provider_arg.clone())?
                            };
                            backend.set(
                                &self.config.project.name,
                                secret_name,
                                &SecretString::new(value.into()),
                                &profile_display,
                            )?;
                            println!(
                                "{} Secret '{}' saved to {} (profile: {})",
                                "✓".green(),
                                secret_name,
                                backend.name(),
                                profile_display
                            );
                        }
                    }

                    println!("\nAll required secrets have been set.");

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

    /// Checks the status of all secrets and prompts for missing required ones
    ///
    /// This method displays the status of all secrets defined in the specification,
    /// showing which are present, missing, or using defaults. It then prompts
    /// the user to provide values for any missing required secrets.
    ///
    /// # Arguments
    ///
    /// * `provider_arg` - Optional provider to use
    /// * `profile` - Optional profile to use
    ///
    /// # Returns
    ///
    /// `Ok(())` if all required secrets are present after prompting
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provider cannot be initialized
    /// - Storage operations fail
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// let validated = spec.check().unwrap();
    /// ```
    pub fn check(&self) -> Result<ValidatedSecrets> {
        let profile_display = self.resolve_profile_name(None);

        println!(
            "Checking secrets in {} (profile: {})...\n",
            self.config.project.name.bold(),
            profile_display.cyan()
        );

        // Validate and display results
        match self.validate()? {
            Ok(valid) => {
                self.display_validation_success(&valid)?;
            }
            Err(errors) => {
                self.display_validation_errors(&errors)?;
            }
        }

        // Now ensure all secrets are present (will prompt if needed)
        let validated = self.ensure_secrets(None, None, true)?;

        Ok(validated)
    }

    /// Display validation success results
    fn display_validation_success(&self, valid: &ValidatedSecrets) -> Result<()> {
        let profile = self.resolve_profile(Some(&valid.resolved.profile))?;
        let mut found_count = 0;
        let default_names = valid
            .with_defaults
            .iter()
            .map(|(name, _)| name)
            .collect::<HashSet<_>>();

        for (name, config) in profile.iter() {
            found_count += 1;
            if config.default.is_some() && default_names.contains(&name) {
                println!(
                    "{} {} - {} {}",
                    "○".yellow(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(has default)".yellow()
                );
            } else {
                println!(
                    "{} {} - {}",
                    "✓".green(),
                    name,
                    config.description.as_deref().unwrap_or("No description")
                );
            }
        }

        println!(
            "\nSummary: {} found, {} missing",
            found_count.to_string().green(),
            0.to_string().red()
        );

        Ok(())
    }

    /// Display validation error results
    fn display_validation_errors(&self, errors: &ValidationErrors) -> Result<()> {
        let profile = self.resolve_profile(Some(&errors.profile))?;
        let mut found_count = 0;
        let mut missing_count = 0;
        let default_names = errors
            .with_defaults
            .iter()
            .map(|(name, _)| name)
            .collect::<HashSet<_>>();

        for (name, config) in &profile {
            if errors.missing_required.contains(&name) {
                missing_count += 1;
                println!(
                    "{} {} - {} {}",
                    "✗".red(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(required)".red()
                );
            } else if errors.missing_optional.contains(&name) {
                found_count += 1;
                println!(
                    "{} {} - {} {}",
                    "○".blue(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(optional)".blue()
                );
            } else {
                found_count += 1;
                if default_names.contains(name) {
                    println!(
                        "{} {} - {} {}",
                        "○".yellow(),
                        name,
                        config.description.as_deref().unwrap_or("No description"),
                        "(has default)".yellow()
                    );
                } else {
                    println!(
                        "{} {} - {}",
                        "✓".green(),
                        name,
                        config.description.as_deref().unwrap_or("No description")
                    );
                }
            }
        }

        println!(
            "\nSummary: {} found, {} missing",
            found_count.to_string().green(),
            missing_count.to_string().red()
        );

        Ok(())
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

        // Create the "from" provider
        let from_provider_instance = Box::<dyn ProviderTrait>::try_from(from_provider.to_string())?;

        println!(
            "Importing secrets from {} (profile: {})...\n",
            from_provider.blue(),
            profile_display.cyan()
        );

        // Get the profile configuration
        let _profile_config = self.config.profiles.get(&profile_display).ok_or_else(|| {
            SecretSpecError::SecretNotFound(format!("Profile '{}' not found", profile_display))
        })?;

        let mut imported = 0;
        let mut already_exists = 0;
        let mut not_found = 0;

        // Collect all secrets to import - from current profile and default profile
        // This ensures we can import secrets defined in default profile when using other profiles
        let profile = self.resolve_profile(Some(&profile_display))?;

        // Process each secret using proper profile resolution
        for (name, config) in profile.into_iter() {
            // Get the target provider for this secret
            let secret_config = self
                .resolve_secret_config(&name, Some(&profile_display))
                .expect("Secret should exist since we're iterating over it");

            // Use first provider in list if specified, otherwise use default
            let to_provider = if let Some(provider_aliases) =
                secret_config.providers.as_ref().and_then(|p| p.first())
            {
                let provider_uris =
                    self.resolve_provider_aliases(Some(&[provider_aliases.clone()]))?;
                let uri = provider_uris.and_then(|uris| uris.first().cloned()).ok_or(
                    SecretSpecError::ProviderNotFound(format!(
                        "Provider alias '{}' could not be resolved",
                        provider_aliases
                    )),
                )?;
                Box::<dyn ProviderTrait>::try_from(uri)?
            } else {
                self.get_provider(None)?
            };

            // First check if the secret exists in the "from" provider
            match from_provider_instance.get(&self.config.project.name, &name, &profile_display)? {
                Some(value) => {
                    // Secret exists in "from" provider, check if it exists in "to" provider
                    match to_provider.get(&self.config.project.name, &name, &profile_display)? {
                        Some(_) => {
                            println!(
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
                            println!(
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
                            println!(
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
                            println!(
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

        println!(
            "\nSummary: {} imported, {} already exists, {} not found in source",
            imported.to_string().green(),
            already_exists.to_string().yellow(),
            not_found.to_string().red()
        );

        if imported > 0 {
            println!(
                "\n{} Successfully imported {} secrets from {}",
                "✓".green(),
                imported,
                from_provider,
            );
        }

        Ok(())
    }

    /// Validates all secrets in the specification
    ///
    /// This method checks all secrets defined in the current profile (and default
    /// profile if different) and returns detailed information about their status.
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
        let mut secrets: HashMap<String, SecretString> = HashMap::new();
        let mut missing_required = Vec::new();
        let mut missing_optional = Vec::new();
        let mut with_defaults = Vec::new();

        let profile_name = self.resolve_profile_name(None);
        let profile = self.resolve_profile(Some(&profile_name))?;

        // Collect all secrets to check - from current profile and default profile
        let all_secrets = profile
            .into_iter()
            .map(|(name, _)| name)
            .collect::<HashSet<_>>();

        // Now check all secrets, each with their own provider(s) or fallback to default
        for name in all_secrets {
            let secret_config = self
                .resolve_secret_config(&name, Some(&profile_name))
                .expect("Secret should exist in config since we're iterating over it");
            let required = secret_config.required;
            let default = secret_config.default.clone();

            // Resolve per-secret provider aliases to URIs
            let provider_uris =
                self.resolve_provider_aliases(secret_config.providers.as_deref())?;

            // Try to get the secret from configured providers with fallback
            match self.get_secret_from_providers(
                &self.config.project.name,
                &name,
                &profile_name,
                provider_uris.as_deref(),
                None,
            )? {
                Some(value) => {
                    secrets.insert(name.clone(), value);
                }
                None => {
                    if let Some(default_value) = default {
                        secrets.insert(
                            name.clone(),
                            SecretString::new(default_value.clone().into()),
                        );
                        with_defaults.push((name.clone(), default_value));
                    } else if required {
                        missing_required.push(name.clone());
                    } else {
                        missing_optional.push(name.clone());
                    }
                }
            }
        }

        // Use default provider for error reporting
        let primary_provider = self.get_provider(None)?;

        // Check if there are any missing required secrets
        if !missing_required.is_empty() {
            Ok(Err(ValidationErrors::new(
                missing_required,
                missing_optional,
                with_defaults,
                primary_provider.uri(),
                profile_name.to_string(),
            )))
        } else {
            Ok(Ok(ValidatedSecrets {
                resolved: Resolved::new(
                    secrets,
                    primary_provider.uri(),
                    profile_name.to_string(),
                ),
                missing_optional,
                with_defaults,
            }))
        }
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
        if command.is_empty() {
            return Err(SecretSpecError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No command specified. Usage: secretspec run -- <command> [args...]",
            )));
        }

        // Ensure all secrets are available (will error out if missing)
        let validation_result = self.ensure_secrets(None, None, false)?;

        let mut env_vars = env::vars().collect::<HashMap<_, _>>();
        // Convert SecretString values to regular strings for environment variables
        for (key, secret) in validation_result.resolved.secrets {
            env_vars.insert(key, secret.expose_secret().to_string());
        }

        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..]);
        cmd.envs(&env_vars);

        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}
