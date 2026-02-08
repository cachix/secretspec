//! Error types for secretspec operations

use miette::Diagnostic;
use std::io;
use thiserror::Error;

// Internal use only
use crate::config::ParseError;
use crate::validation::ValidationErrors;

/// The main error type for secretspec operations
///
/// This enum represents all possible errors that can occur when working with
/// the secretspec library.
#[derive(Error, Debug, Diagnostic)]
pub enum SecretSpecError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error(
        "Unsupported secretspec revision '{0}'. This version of secretspec only supports revision '1.0'"
    )]
    UnsupportedRevision(String),
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[cfg(feature = "keyring")]
    #[error("Keyring error: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("Dotenv error: {0}")]
    Dotenv(#[from] dotenvy::Error),
    #[error(
        "No provider backend configured.\n\nTo fix this, either:\n  1. Run 'secretspec config init' to set up your default provider\n  2. Use --provider flag (e.g., 'secretspec check --provider keyring')"
    )]
    NoProviderConfigured,
    #[error("Provider backend '{0}' not found")]
    ProviderNotFound(String),
    #[error("Secret '{0}' not found")]
    SecretNotFound(String),
    #[error("Secret '{0}' is required but not set")]
    RequiredSecretMissing(String),
    #[error("No secretspec.toml found in current directory")]
    NoManifest,
    #[error("Extended config file not found: {0}")]
    ExtendedConfigNotFound(String),
    #[error("Project name not found in secretspec.toml")]
    NoProjectName,
    #[error("Provider operation failed: {0}")]
    ProviderOperationFailed(String),
    #[error("User interaction error: {0}")]
    InquireError(#[from] inquire::InquireError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid profile: {0}")]
    InvalidProfile(String),
    #[error("Validation failed: {0}")]
    ValidationFailed(ValidationErrors),
    #[error("Secret generation failed: {0}")]
    GenerationFailed(String),
}

/// A type alias for `Result<T, SecretSpecError>`
///
/// This provides a convenient shorthand for functions that return
/// a result with a `SecretSpecError` as the error type.
pub type Result<T> = std::result::Result<T, SecretSpecError>;

impl From<ParseError> for SecretSpecError {
    fn from(err: ParseError) -> Self {
        match err {
            ParseError::Io(io_err) => {
                if io_err.kind() == io::ErrorKind::NotFound {
                    SecretSpecError::NoManifest
                } else {
                    SecretSpecError::Io(io_err)
                }
            }
            ParseError::Toml(toml_err) => SecretSpecError::Toml(toml_err),
            ParseError::UnsupportedRevision(rev) => SecretSpecError::UnsupportedRevision(rev),
            ParseError::CircularDependency(msg) => {
                SecretSpecError::Io(io::Error::new(io::ErrorKind::InvalidData, msg))
            }
            ParseError::Validation(msg) => {
                SecretSpecError::Io(io::Error::new(io::ErrorKind::InvalidData, msg))
            }
            ParseError::ExtendedConfigNotFound(path) => {
                SecretSpecError::ExtendedConfigNotFound(path)
            }
        }
    }
}
