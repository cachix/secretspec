//! Error types for monosecret operations

use std::io;

use miette::Diagnostic;
use thiserror::Error;

// Internal use only
use crate::config::ParseError;
use crate::validation::ValidationErrors;

/// The main error type for monosecret operations
///
/// This enum represents all possible errors that can occur when working with
/// the monosecret library.
#[derive(Error, Debug, Diagnostic)]
pub enum MonosecretError {
	#[error("IO error: {0}")]
	Io(#[from] std::io::Error),
	#[error("TOML parsing error: {0}")]
	Toml(#[from] toml::de::Error),
	#[error(
		"Unsupported monosecret revision '{0}'. This version of monosecret only supports revision '1.0'"
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
		"No provider backend configured.\n\nTo fix this, either:\n  1. Run 'monosecret config init' to set up your default provider\n  2. Use --provider flag (e.g., 'monosecret check --provider keyring')"
	)]
	NoProviderConfigured,
	#[error("Provider backend '{0}' not found")]
	ProviderNotFound(String),
	#[error("Secret '{0}' not found")]
	SecretNotFound(String),
	#[error("Secret '{0}' is required but not set")]
	RequiredSecretMissing(String),
	#[error("No monosecret.toml found in current or any parent directory")]
	NoManifest,
	#[error("Extended config file not found: {0}")]
	ExtendedConfigNotFound(String),
	#[error("Project name not found in monosecret.toml")]
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
		 these secrets>\", the MONOSECRET_REASON environment variable, or Secrets::with_reason() in \
		 the SDK. (Policy: require_reason in [project] of monosecret.toml — defaults to \"agents\"; \
		 set it to false to disable.)"
	)]
	ReasonRequired,
}

/// A type alias for `Result<T, MonosecretError>`
///
/// This provides a convenient shorthand for functions that return
/// a result with a `MonosecretError` as the error type.
pub type Result<T> = std::result::Result<T, MonosecretError>;

impl From<ParseError> for MonosecretError {
	fn from(err: ParseError) -> Self {
		match err {
			ParseError::Io(io_err) => {
				if io_err.kind() == io::ErrorKind::NotFound {
					MonosecretError::NoManifest
				} else {
					MonosecretError::Io(io_err)
				}
			}
			ParseError::Toml(toml_err) => MonosecretError::Toml(toml_err),
			ParseError::UnsupportedRevision(rev) => MonosecretError::UnsupportedRevision(rev),
			ParseError::CircularDependency(msg) => {
				MonosecretError::Io(io::Error::new(io::ErrorKind::InvalidData, msg))
			}
			ParseError::Validation(msg) => {
				MonosecretError::Io(io::Error::new(io::ErrorKind::InvalidData, msg))
			}
			ParseError::ExtendedConfigNotFound(path) => {
				MonosecretError::ExtendedConfigNotFound(path)
			}
		}
	}
}
