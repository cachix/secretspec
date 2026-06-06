#![allow(clippy::indexing_slicing, unsafe_code)]

//! Monosecret - A declarative secrets manager for development workflows
//!
//! This library provides a type-safe, declarative way to manage secrets and environment
//! variables across different environments and storage backends.
//!
//! # Features
//!
//! - **Declarative Configuration**: Define secrets in `monosecret.toml`
//! - **Multiple Providers**: Keyring, dotenv, environment variables, `OnePassword`, `LastPass`
//! - **Profile Support**: Different configurations for development, staging, production
//! - **Type Safety**: Optional compile-time code generation for strongly-typed access
//! - **Validation**: Ensure all required secrets are present before running applications
//!
//! # Example
//!
//! ```ignore
//! // Generate typed structs from monosecret.toml
//! monosecret_derive::declare_secrets!("monosecret.toml");
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load secrets and configure provider/profile
//!     let mut spec = Secrets::load()?;
//!     spec.set_provider("keyring");  // Can use provider name or URI like "dotenv:/path/to/.env"
//!     spec.set_profile("development");
//!     
//!     // Validate and get secrets
//!     let secrets = match spec.validate()? {
//!         Ok(validated) => validated,
//!         Err(errors) => return Err(format!("Missing secrets: {}", errors).into()),
//!     };
//!
//!     // Access secrets (field names are lowercased)
//!     println!("Database: {}", secrets.resolved.secrets.get("DATABASE_URL").unwrap());
//!
//!     // Access profile and provider information
//!     println!("Using profile: {}", secrets.resolved.profile);
//!     println!("Using provider: {}", secrets.resolved.provider);
//!
//!     Ok(())
//! }
//! ```

// Internal modules
mod config;
mod error;
pub(crate) mod generator;
mod secrets;
mod validation;

pub(crate) mod provider;

// CLI module (feature-gated)
#[cfg(feature = "cli")]
pub mod cli;

// Re-export only the types needed by users and generated code
pub use config::ProviderConfig;
pub use config::ProviderConfigStructured;
pub use config::ProviderDependency;
pub use config::ProviderRef;
pub use config::ProviderRefDetail;
pub use config::Resolved;
pub use config::SecretRequest;
// Re-export config types for CLI usage only - these are marked #[doc(hidden)]
#[doc(hidden)]
pub use config::{Config, GlobalConfig, GlobalDefaults, Profile, ProfileDefaults, Project};
// Re-export Secret and generation types for monosecret_derive
#[doc(hidden)]
pub use config::{GenerateConfig, GenerateOptions, Secret};
// Public API exports
pub use error::{MonosecretError, Result};
pub use provider::Provider;
pub use secrets::Secrets;
pub use validation::ValidatedSecrets;

#[cfg(test)]
mod tests;
