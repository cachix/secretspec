//! SecretSpec - A declarative secrets manager for development workflows
//!
//! This library provides a type-safe, declarative way to manage secrets and environment
//! variables across different environments and storage backends.
//!
//! # Features
//!
//! - **Declarative Configuration**: Define secrets in `secretspec.toml`
//! - **Rust-first Declarations**: Build a [`Spec`] directly in Rust (0.20+)
//! - **Multiple Providers**: Keyring, dotenv, environment variables, Keeper Secrets Manager (0.18+)
//! - **Profile Support**: Different configurations for development, staging, production
//! - **Type Safety**: Optional compile-time code generation for strongly-typed access
//! - **Validation**: Ensure all required secrets are present before running applications
//!
//! # Example
//!
//! ```ignore
//! // Generate typed structs from secretspec.toml
//! secretspec_derive::declare_secrets!("secretspec.toml");
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
mod audit;
mod cache;
mod caller;
mod codegen;
mod compiled_spec;
mod composition;
mod config;
mod error;
pub(crate) mod generator;
pub(crate) mod ini_field;
pub(crate) mod json_field;
mod native;
mod plan;
mod report;
mod resolve;
mod secret_value;
mod secrets;
mod spec;
mod spec_edit;
mod validation;

pub(crate) mod provider;

// CLI module (feature-gated)
#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod integration;

// Re-export only the types needed by users and generated code
pub use caller::CallerContext;
pub use config::Resolved;
pub use secret_value::SecretBytes;

/// Implementation details shared with `secretspec-derive`.
///
/// These document types are not part of the supported Rust SDK. Use [`Spec`]
/// and its builder API instead.
#[doc(hidden)]
pub mod __private {
    // Generated code uses these re-exports so applications do not need to
    // depend on the implementation crates just to compile the macro output.
    pub use ::secrecy;
    pub use ::serde;

    pub mod codegen {
        pub use crate::codegen::{CodegenIr, IrField, IrProfile, build_ir, capitalize};
    }

    pub use crate::config::{
        Config, GenerateConfig, GenerateOptions, Profile, ProfileDefaults, Project,
        ProjectDefaults, Secret,
    };
    pub use crate::spec::load_for_codegen;
}

// Public API exports
pub use config::{
    CredentialSource, ExtractFormat, NativeAddress, NativeAddressTemplate, ProviderAlias,
    ProviderCache, RequireReason, SecretEncoding, SecretExtract,
};
pub use error::{Result, SecretSpecError};
pub use native::{INLINE_SPEC_SCHEMA_VERSION, NATIVE_CALL_REQUEST_VERSION, call_json};
pub use provider::{DiscoveryContext, ProducedValuePersistence, Provider, ProviderValue};
pub use report::{
    RESOLUTION_REPORT_SCHEMA_VERSION, ResolutionReport, ResolutionStatus, SecretResolution,
};
pub use resolve::{
    NamedResolution, RESOLVE_SCHEMA_VERSION, ResolveResponse, ResolvedSecret, ResolvedSource,
    resolve_json,
};
pub use secrets::ExportFormat;
pub use secrets::Secrets;
pub use spec::{
    Generation, OpenPgpAlgorithm, OpenPgpCapability, PasswordCharset, Profile, Secret, Spec,
    SpecBuilder, SshKeyAlgorithm,
};
pub use validation::{ConstraintKind, ConstraintViolation, ValidatedSecrets, ValidationErrors};

#[cfg(test)]
mod tests;
