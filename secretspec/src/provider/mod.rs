//! # Provider System
//!
//! The provider module implements a trait-based plugin architecture for managing secrets
//! across different storage backends. Providers handle the actual storage and retrieval
//! of secrets, supporting everything from local files to cloud-based secret managers.
//!
//! ## Architecture
//!
//! The provider system is built around the [`Provider`] trait, which defines a common
//! interface for all storage backends. Each provider implementation handles:
//!
//! - Profile-aware storage (e.g., development vs production secrets)
//! - Project isolation (secrets are namespaced by project)
//! - Optional write support (some providers are read-only)
//!
//! ## Available Providers
//!
//! - [`KeyringProvider`]: System keyring integration (default)
//! - [`DotEnvProvider`]: `.env` file support
//! - [`EnvProvider`]: Environment variables (read-only)
//! - [`OnePasswordProvider`]: OnePassword integration
//! - [`LastPassProvider`]: LastPass integration
//!
//! ## URI-Based Configuration
//!
//! Providers support URI-based configuration for flexibility:
//!
//! ```text
//! keyring://
//! dotenv://.env.production
//! onepassword://vault/items
//! lastpass://folder
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use secretspec::provider::Provider;
//! use std::convert::TryFrom;
//!
//! // Create a provider from a URI string
//! let provider = Box::<dyn Provider>::try_from("keyring://")?;
//!
//! // Store a secret
//! provider.set("myproject", "API_KEY", "secret123", "production")?;
//!
//! // Retrieve a secret
//! if let Some(value) = provider.get("myproject", "API_KEY", "production")? {
//!     println!("API_KEY: {}", value);
//! }
//! ```

use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use std::collections::HashMap;
use std::convert::TryFrom;
use url::Url;

pub mod dotenv;
pub mod env;
#[cfg(feature = "keyring")]
pub mod keyring;
pub mod lastpass;
pub mod onepassword;
#[macro_use]
pub mod macros;

#[cfg(test)]
pub(crate) mod tests;

/// Information about a secret storage provider.
///
/// Contains metadata used for displaying available providers to users,
/// including the provider's name, description, and example URIs.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// The canonical name of the provider (e.g., "keyring", "1password").
    pub name: &'static str,
    /// A human-readable description of what the provider does.
    pub description: &'static str,
    /// Example URIs showing how to configure this provider.
    pub examples: &'static [&'static str],
}

impl ProviderInfo {
    /// Formats the provider information for display, including examples if available.
    ///
    /// # Returns
    ///
    /// A formatted string in one of two formats:
    /// - Without examples: "name: description"
    /// - With examples: "name: description (e.g., example1, example2)"
    ///
    /// # Example
    ///
    /// ```ignore
    /// let info = ProviderInfo {
    ///     name: "onepassword",
    ///     description: "OnePassword password manager",
    ///     examples: &["onepassword://vault", "onepassword://work@Production"],
    /// };
    /// assert_eq!(
    ///     info.display_with_examples(),
    ///     "onepassword: OnePassword password manager (e.g., onepassword://vault, onepassword://work@Production)"
    /// );
    /// ```
    pub fn display_with_examples(&self) -> String {
        if self.examples.is_empty() {
            format!("{}: {}", self.name, self.description)
        } else {
            format!(
                "{}: {} (e.g., {})",
                self.name,
                self.description,
                self.examples.join(", ")
            )
        }
    }
}

/// Macro support types
pub use macros::{PROVIDER_REGISTRY, ProviderRegistration};

/// Returns a list of all available providers with their metadata.
///
/// This includes the provider name, description, and example URIs for each
/// supported provider type.
///
/// # Returns
///
/// A vector of `ProviderInfo` structs containing metadata for each provider.
pub fn providers() -> Vec<ProviderInfo> {
    PROVIDER_REGISTRY
        .iter()
        .map(|reg| reg.info.clone())
        .collect()
}

/// Trait defining the interface for secret storage providers.
///
/// All secret storage backends must implement this trait to integrate with SecretSpec.
/// The trait is designed to be flexible enough to support various storage mechanisms
/// while maintaining a consistent interface.
///
/// # Thread Safety
///
/// Providers must be `Send + Sync` as they may be used across thread boundaries
/// in multi-threaded applications.
///
/// # Profile Support
///
/// Providers should support profile-based secret isolation, allowing different values
/// for the same key across environments (e.g., development, staging, production).
///
/// # Implementation Guidelines
///
/// - Providers should handle their own error cases and return appropriate `Result` types
/// - Storage paths should follow the pattern: `{provider}/{project}/{profile}/{key}`
/// - Providers may choose to be read-only by overriding [`allows_set`](Provider::allows_set)
/// - Provider names should be lowercase and descriptive
pub trait Provider: Send + Sync {
    /// Retrieves a secret value from the provider.
    ///
    /// # Arguments
    ///
    /// * `project` - The project namespace for the secret
    /// * `key` - The secret key/name to retrieve
    /// * `profile` - The profile context (e.g., "default", "production")
    ///
    /// # Returns
    ///
    /// - `Ok(Some(value))` if the secret exists
    /// - `Ok(None)` if the secret doesn't exist
    /// - `Err` if there was an error accessing the provider
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// match provider.get("myapp", "DATABASE_URL", "production")? {
    ///     Some(url) => println!("Database URL: {}", url),
    ///     None => println!("DATABASE_URL not found"),
    /// }
    /// ```
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>>;

    /// Stores a secret value in the provider.
    ///
    /// # Arguments
    ///
    /// * `project` - The project namespace for the secret
    /// * `key` - The secret key/name to store
    /// * `value` - The secret value to store
    /// * `profile` - The profile context (e.g., "default", "production")
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the secret was successfully stored
    /// - `Err` if there was an error or the provider is read-only
    ///
    /// # Errors
    ///
    /// This method should return an error if [`allows_set`](Provider::allows_set) returns `false`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// provider.set("myapp", "API_KEY", "secret123", "production")?;
    /// ```
    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()>;

    /// Returns whether this provider supports setting values.
    ///
    /// By default, providers are assumed to support writing. Read-only providers
    /// (like environment variables) should override this to return `false`.
    ///
    /// # Returns
    ///
    /// - `true` if the provider supports [`set`](Provider::set) operations
    /// - `false` if the provider is read-only
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if provider.allows_set() {
    ///     provider.set("myapp", "TOKEN", "value", "default")?;
    /// } else {
    ///     eprintln!("Provider is read-only");
    /// }
    /// ```
    fn allows_set(&self) -> bool {
        true
    }

    /// Returns the name of this provider.
    ///
    /// This should match the name registered with the provider macro.
    fn name(&self) -> &'static str;

    /// Returns the full URI representation of this provider.
    ///
    /// This includes any configuration like vault names, paths, etc.
    /// For example: "onepassword://VaultName" or "dotenv://.env.production"
    fn uri(&self) -> String;

    /// Discovers and returns all secrets available in this provider.
    ///
    /// This method is used to introspect the provider and find all available secrets.
    /// It's particularly useful for importing secrets from external sources.
    ///
    /// # Returns
    ///
    /// A HashMap where keys are secret names and values are `Secret` configurations.
    /// The default implementation returns an empty map, indicating the provider
    /// doesn't support reflection.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let secrets = provider.reflect()?;
    /// for (name, secret) in secrets {
    ///     println!("Found secret: {} = {:?}", name, secret);
    /// }
    /// ```
    fn reflect(&self) -> Result<HashMap<String, crate::config::Secret>> {
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Provider '{}' does not support reflection",
            self.name()
        )))
    }
}

impl TryFrom<String> for Box<dyn Provider> {
    type Error = SecretSpecError;

    /// Creates a provider instance from a URI string.
    ///
    /// This function handles various URI formats and normalizes them before parsing.
    /// It supports both full URIs and shorthand notations.
    ///
    /// # URI Formats
    ///
    /// - **Full URI**: `scheme://authority/path` (e.g., `onepassword://vault/Production`)
    ///
    /// # Special Cases
    ///
    /// - **1password**: Will error suggesting to use `onepassword` instead
    /// - **Bare provider names**: Automatically converted to `provider://`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::convert::TryFrom;
    ///
    /// // Simple provider name
    /// let provider = Box::<dyn Provider>::try_from("keyring".to_string())?;
    ///
    /// // Full URI with configuration
    /// let provider = Box::<dyn Provider>::try_from("onepassword://vault/Production".to_string())?;
    ///
    /// // Dotenv with path
    /// let provider = Box::<dyn Provider>::try_from("dotenv:.env.production".to_string())?;
    /// ```
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(&s as &str)
    }
}

impl TryFrom<&str> for Box<dyn Provider> {
    type Error = SecretSpecError;

    fn try_from(s: &str) -> Result<Self> {
        // Parse the scheme from the input string
        let (scheme, rest) = if let Some(pos) = s.find(':') {
            let scheme = &s[..pos];
            let rest = &s[pos + 1..];
            (scheme, rest)
        } else {
            // Just a provider name, no URI components
            (s, "")
        };

        // Validate scheme first
        if scheme == "1password" {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Invalid scheme '1password'. Use 'onepassword' instead (e.g., onepassword://vault/path)".to_string()
            ));
        }

        // Check if the scheme is registered
        let is_valid_scheme = PROVIDER_REGISTRY
            .iter()
            .any(|reg| reg.schemes.contains(&scheme));

        if !is_valid_scheme {
            // Check if it's a known provider name to give a better error
            if PROVIDER_REGISTRY.iter().any(|reg| reg.info.name == scheme) {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Provider '{}' exists but URI parsing failed",
                    scheme
                )));
            } else {
                return Err(SecretSpecError::ProviderNotFound(scheme.to_string()));
            }
        }

        // Build a proper URL with the correct scheme
        let url_string = match rest {
            // Just scheme name (e.g., "keyring")
            "" | ":" => format!("{}://", scheme),
            // Standard URI format already has // (e.g., "onepassword://vault/path")
            s if s.starts_with("//") => format!("{}:{}", scheme, s),
            // Path only format (e.g., "dotenv:/path/to/.env")
            s if s.starts_with('/') => format!("{}://{}", scheme, s),
            // Everything else - assume it's a host or path component
            s => format!("{}://{}", scheme, s),
        };

        let proper_url = Url::parse(&url_string).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Invalid provider specification '{}': {}",
                s, e
            ))
        })?;

        Self::try_from(&proper_url)
    }
}

impl TryFrom<&Url> for Box<dyn Provider> {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> Result<Self> {
        let scheme = url.scheme();

        // Find the provider registration for this scheme
        let registration = PROVIDER_REGISTRY
            .iter()
            .find(|reg| reg.schemes.contains(&scheme))
            .ok_or_else(|| SecretSpecError::ProviderNotFound(scheme.to_string()))?;

        // Use the factory function to create the provider
        (registration.factory)(url)
    }
}
