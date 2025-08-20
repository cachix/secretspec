//! Core secrets management functionality

use crate::config::{Config, GlobalConfig, Resolved};
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
    pub(crate) fn resolve_profile(&self, profile: Option<&str>) -> String {
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
        let profile_name = self.resolve_profile(profile);

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
                })
            }
            (Some(secret), None) | (None, Some(secret)) => Some(secret.clone()),
            (None, None) => None,
        }
    }

    /// Gets the provider instance to use for secret operations
    ///
    /// Provider resolution order:
    /// 1. Provided provider argument
    /// 2. Provider set via builder
    /// 3. Global configuration default provider
    /// 4. Error if no provider is configured
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
        let profile_name = self.resolve_profile(None);
        let profile_config = self.config.profiles.get(&profile_name).ok_or_else(|| {
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
        if self.resolve_secret_config(name, None).is_none() {
            // Collect available secrets from both current profile and default
            let mut available_secrets = profile_config.secrets.keys().cloned().collect::<Vec<_>>();
            if profile_name != "default" {
                if let Some(default_profile) = self.config.profiles.get("default") {
                    for key in default_profile.secrets.keys() {
                        if !available_secrets.contains(key) {
                            available_secrets.push(key.clone());
                        }
                    }
                }
            }
            available_secrets.sort();

            return Err(SecretSpecError::SecretNotFound(format!(
                "Secret '{}' is not defined in profile '{}'. Available secrets: {}",
                name,
                profile_name,
                available_secrets.join(", ")
            )));
        }

        let backend = self.get_provider(None)?;
        let profile_display = self.resolve_profile(None);

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
            print!("Enter value for {} (profile: {}): ", name, profile_display);
            io::stdout().flush()?;
            SecretString::new(rpassword::read_password()?.into())
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
            profile_display
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
        let backend = self.get_provider(None)?;
        let profile_name = self.resolve_profile(None);
        let secret_config = self
            .resolve_secret_config(name, None)
            .ok_or_else(|| SecretSpecError::SecretNotFound(name.to_string()))?;
        let default = secret_config.default.clone();

        match backend.get(&self.config.project.name, name, &profile_name)? {
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
        let backend = self.get_provider(provider_arg.clone())?;
        let profile_display = self.resolve_profile(profile.as_deref());

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
    /// spec.check().unwrap();
    /// ```
    pub fn check(&self) -> Result<()> {
        let provider = self.get_provider(None)?;
        let profile_display = self.resolve_profile(None);

        println!(
            "Checking secrets in {} using {} (profile: {})...\n",
            self.config.project.name.bold(),
            provider.name().blue(),
            profile_display.cyan()
        );

        // First get the initial validation result to display status
        let initial_validation_result = self.validate()?;

        // We need to handle both success and error cases for display
        let empty_map = HashMap::new();
        let (secrets_map, missing_required, missing_optional, with_defaults) =
            match &initial_validation_result {
                Ok(valid) => (
                    &valid.resolved.secrets,
                    vec![],
                    valid.missing_optional.clone(),
                    valid.with_defaults.clone(),
                ),
                Err(errors) => (
                    &empty_map,
                    errors.missing_required.clone(),
                    errors.missing_optional.clone(),
                    errors.with_defaults.clone(),
                ),
            };

        // Display status for each secret
        let profile_name = self.resolve_profile(None);
        let profile_config = self.config.profiles.get(&profile_name).ok_or_else(|| {
            SecretSpecError::SecretNotFound(format!("Profile '{}' not found", profile_name))
        })?;

        // Collect all secrets to display - from current profile and default profile
        let mut all_secrets_to_display = Vec::new();

        // Add secrets from the current profile
        for (name, config) in &profile_config.secrets {
            all_secrets_to_display.push((name.clone(), config.clone()));
        }

        // If not the default profile, also add secrets from default profile
        if profile_name != "default" {
            if let Some(default_profile) = self.config.profiles.get("default") {
                for (name, config) in &default_profile.secrets {
                    // Only add if not already in current profile
                    if !profile_config.secrets.contains_key(name) {
                        all_secrets_to_display.push((name.clone(), config.clone()));
                    }
                }
            }
        }

        // Sort by name for consistent display
        all_secrets_to_display.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, config) in all_secrets_to_display {
            if secrets_map.contains_key(&name) {
                if with_defaults.iter().any(|(n, _)| n == &name) {
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
            } else if missing_required.contains(&name) {
                println!(
                    "{} {} - {} {}",
                    "✗".red(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(required)".red()
                );
            } else if missing_optional.contains(&name) {
                println!(
                    "{} {} - {} {}",
                    "○".blue(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(optional)".blue()
                );
            }
        }

        let found_count = secrets_map.len() - with_defaults.len();
        let missing_count = missing_required.len();

        println!(
            "\nSummary: {} found, {} missing",
            found_count.to_string().green(),
            missing_count.to_string().red()
        );

        // Now ensure all secrets are present (will prompt if needed)
        self.ensure_secrets(None, None, true)?;

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
        // Get the "to" provider from global config (default)
        let to_provider = self.get_provider(None)?;

        // Resolve profile (checks env var, then global config, then defaults to "default")
        let profile_display = self.resolve_profile(None);

        // Create the "from" provider
        let from_provider_instance = Box::<dyn ProviderTrait>::try_from(from_provider.to_string())?;

        println!(
            "Importing secrets from {} to {} (profile: {})...\n",
            from_provider.blue(),
            to_provider.name().blue(),
            profile_display.cyan()
        );

        // Get the profile configuration
        let profile_config = self.config.profiles.get(&profile_display).ok_or_else(|| {
            SecretSpecError::SecretNotFound(format!("Profile '{}' not found", profile_display))
        })?;

        let mut imported = 0;
        let mut already_exists = 0;
        let mut not_found = 0;

        // Process each secret in the profile
        for (name, config) in &profile_config.secrets {
            // First check if the secret exists in the "from" provider
            match from_provider_instance.get(&self.config.project.name, name, &profile_display)? {
                Some(value) => {
                    // Secret exists in "from" provider, check if it exists in "to" provider
                    match to_provider.get(&self.config.project.name, name, &profile_display)? {
                        Some(_) => {
                            println!(
                                "{} {} - {} {}",
                                "○".yellow(),
                                name,
                                config.description.as_deref().unwrap_or("No description"),
                                "(already exists in target)".yellow()
                            );
                            already_exists += 1;
                        }
                        None => {
                            // Secret doesn't exist in "to" provider, import it
                            to_provider.set(
                                &self.config.project.name,
                                name,
                                &value,
                                &profile_display,
                            )?;
                            println!(
                                "{} {} - {}",
                                "✓".green(),
                                name,
                                config.description.as_deref().unwrap_or("No description")
                            );
                            imported += 1;
                        }
                    }
                }
                None => {
                    // Secret doesn't exist in "from" provider
                    // Check if it exists in the "to" provider
                    match to_provider.get(&self.config.project.name, name, &profile_display)? {
                        Some(_) => {
                            println!(
                                "{} {} - {} {}",
                                "○".blue(),
                                name,
                                config.description.as_deref().unwrap_or("No description"),
                                "(already in target, not in source)".blue()
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
                "\n{} Successfully imported {} secrets from {} to {}",
                "✓".green(),
                imported,
                from_provider,
                to_provider.name()
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
        let backend = self.get_provider(None)?;
        let mut secrets: HashMap<String, SecretString> = HashMap::new();
        let mut missing_required = Vec::new();
        let mut missing_optional = Vec::new();
        let mut with_defaults = Vec::new();

        let profile_name = self.resolve_profile(None);
        let profile_config = self.config.profiles.get(&profile_name).ok_or_else(|| {
            SecretSpecError::SecretNotFound(format!("Profile '{}' not found", profile_name))
        })?;

        // Collect all secrets to check - from current profile and default profile
        let mut all_secrets = HashSet::new();

        // Add secrets from the current profile
        for name in profile_config.secrets.keys() {
            all_secrets.insert(name.clone());
        }

        // If not the default profile, also add secrets from default profile
        if profile_name != "default" {
            if let Some(default_profile) = self.config.profiles.get("default") {
                for name in default_profile.secrets.keys() {
                    all_secrets.insert(name.clone());
                }
            }
        }

        // Now check all secrets
        for name in all_secrets {
            let secret_config = self
                .resolve_secret_config(&name, None)
                .expect("Secret should exist in config since we're iterating over it");
            let required = secret_config.required;
            let default = secret_config.default.clone();

            match backend.get(&self.config.project.name, &name, &profile_name)? {
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

        // Check if there are any missing required secrets
        if !missing_required.is_empty() {
            Ok(Err(ValidationErrors::new(
                missing_required,
                missing_optional,
                with_defaults,
                backend.name().to_string(),
                profile_name.to_string(),
            )))
        } else {
            Ok(Ok(ValidatedSecrets {
                resolved: Resolved::new(
                    secrets,
                    backend.name().to_string(),
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
