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
    #[error("No secretspec.toml found in current or any parent directory")]
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
    #[error(
        "Accessing secrets requires a reason. Provide one with --reason \"<why you are accessing \
         these secrets>\", the SECRETSPEC_REASON environment variable, or Secrets::with_reason() in \
         the SDK. (Policy: require_reason in [project] of secretspec.toml — defaults to \"agents\"; \
         set it to false to disable.)"
    )]
    ReasonRequired,
}

impl SecretSpecError {
    /// A stable, non-sensitive token identifying the error variant, for audit logs.
    ///
    /// Returns only the variant name, never the error message: messages can embed
    /// secret names, provider URIs, or backend detail that must not reach the log.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            SecretSpecError::Io(_) => "io",
            SecretSpecError::Toml(_) => "toml",
            SecretSpecError::UnsupportedRevision(_) => "unsupported_revision",
            SecretSpecError::TomlSer(_) => "toml_ser",
            #[cfg(feature = "keyring")]
            SecretSpecError::Keyring(_) => "keyring",
            SecretSpecError::Dotenv(_) => "dotenv",
            SecretSpecError::NoProviderConfigured => "no_provider_configured",
            SecretSpecError::ProviderNotFound(_) => "provider_not_found",
            SecretSpecError::SecretNotFound(_) => "secret_not_found",
            SecretSpecError::RequiredSecretMissing(_) => "required_secret_missing",
            SecretSpecError::NoManifest => "no_manifest",
            SecretSpecError::ExtendedConfigNotFound(_) => "extended_config_not_found",
            SecretSpecError::NoProjectName => "no_project_name",
            SecretSpecError::ProviderOperationFailed(_) => "provider_operation_failed",
            SecretSpecError::InquireError(_) => "inquire",
            SecretSpecError::Json(_) => "json",
            SecretSpecError::InvalidProfile(_) => "invalid_profile",
            SecretSpecError::ValidationFailed(_) => "validation_failed",
            SecretSpecError::GenerationFailed(_) => "generation_failed",
            SecretSpecError::ReasonRequired => "reason_required",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `kind()` returns a stable token per variant and never the (possibly
    /// secret-bearing) error message.
    #[test]
    fn kind_returns_stable_non_sensitive_tokens() {
        let cases: Vec<(SecretSpecError, &str)> = vec![
            (io::Error::other("boom").into(), "io"),
            (
                SecretSpecError::UnsupportedRevision("9.9".into()),
                "unsupported_revision",
            ),
            (
                SecretSpecError::NoProviderConfigured,
                "no_provider_configured",
            ),
            (
                SecretSpecError::ProviderNotFound("vault".into()),
                "provider_not_found",
            ),
            (
                SecretSpecError::SecretNotFound("X".into()),
                "secret_not_found",
            ),
            (
                SecretSpecError::RequiredSecretMissing("X".into()),
                "required_secret_missing",
            ),
            (SecretSpecError::NoManifest, "no_manifest"),
            (
                SecretSpecError::ExtendedConfigNotFound("../x".into()),
                "extended_config_not_found",
            ),
            (SecretSpecError::NoProjectName, "no_project_name"),
            (
                SecretSpecError::ProviderOperationFailed("nope".into()),
                "provider_operation_failed",
            ),
            (
                SecretSpecError::InvalidProfile("ghost".into()),
                "invalid_profile",
            ),
            (
                SecretSpecError::GenerationFailed("rng".into()),
                "generation_failed",
            ),
            (SecretSpecError::ReasonRequired, "reason_required"),
        ];

        for (err, expected) in cases {
            assert_eq!(err.kind(), expected);
        }
    }

    #[test]
    fn kind_tags_wrapped_parse_errors() {
        let json: SecretSpecError = serde_json::from_str::<serde_json::Value>("nope")
            .unwrap_err()
            .into();
        assert_eq!(json.kind(), "json");

        let toml: SecretSpecError = "= bad".parse::<toml::Table>().unwrap_err().into();
        assert_eq!(toml.kind(), "toml");
    }
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
