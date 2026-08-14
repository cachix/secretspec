//! Error types for monosecret operations

use std::io;

use miette::Diagnostic;
use thiserror::Error;

// Internal use only
use crate::config::ParseError;
use crate::validation::ValidationErrors;

/// Renders an error and each distinct source in its cause chain.
///
/// Most error types intentionally keep [`std::fmt::Display`] short. That is
/// useful while the error remains structured, but providers and the JSON SDK
/// boundary ultimately have to turn errors into strings. Walking `source()`
/// here preserves transport, TLS, DNS, parsing, and other underlying causes
/// without dumping verbose `Debug` representations or repeating a cause an
/// outer error already included in its own display.
pub(crate) fn display_error_chain(error: &(dyn std::error::Error + 'static)) -> String {
	let mut message = error.to_string();
	let mut source = error.source();
	while let Some(cause) = source {
		let cause_message = cause.to_string();
		if !cause_message.is_empty() && !message.ends_with(&cause_message) {
			message.push_str(": ");
			message.push_str(&cause_message);
		}
		source = cause.source();
	}
	message
}

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
		"No provider backend configured.\n\nTo fix this, either:\n  1. Run 'monosecret config global init' to set up your default provider\n  2. Use --provider flag (e.g., 'monosecret check --provider keyring')"
	)]
	NoProviderConfigured,
	#[error("Provider backend '{0}' not found")]
	ProviderNotFound(String),
	#[error("Secret '{0}' not found")]
	SecretNotFound(String),
	#[error("Secret '{0}' is required but not set")]
	RequiredSecretMissing(String),
	#[error(
		"Secret '{0}' requires an interactive prompt, but no controlling terminal is available"
	)]
	PromptUnavailable(String),
	#[error("Prompted value for secret '{0}' cannot be empty")]
	PromptValueEmpty(String),
	#[error(
		"Composed secret '{0}' is derived from other secrets and has no stored value to change"
	)]
	ComposedSecretReadOnly(String),
	#[error(
		"Secret '{0}' uses `extract` and is read-only; update its containing document in the source provider instead"
	)]
	ExtractedSecretReadOnly(String),
	#[error("Failed to compose secret: {0}")]
	CompositionFailed(String),
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
	#[error("Invalid scope: {0}")]
	InvalidScope(String),
	#[error("Validation failed: {0}")]
	ValidationFailed(Box<ValidationErrors>),
	#[error("Secret generation failed: {0}")]
	GenerationFailed(String),
	#[error("Failed to decode secret '{name}' using {encoding}: {reason}")]
	DecodeFailed {
		name: String,
		encoding: &'static str,
		reason: String,
	},
	#[error(
		"Accessing secrets requires a reason. Provide one with --reason \"<why you are accessing \
         these secrets>\", the MONOSECRET_REASON environment variable, or Secrets::with_reason() in \
         the SDK. (Policy: require_reason in [project] of monosecret.toml — defaults to \"agents\"; \
         set it to false to disable.)"
	)]
	ReasonRequired,
}

impl MonosecretError {
	/// A stable, non-sensitive token identifying the error variant, for audit
	/// logs and typed handling by other-language SDKs over the FFI boundary.
	///
	/// Returns only the variant name, never the error message: messages can embed
	/// secret names, provider URIs, or backend detail that must not reach the log.
	pub fn kind(&self) -> &'static str {
		match self {
			MonosecretError::Io(_) => "io",
			MonosecretError::Toml(_) => "toml",
			MonosecretError::UnsupportedRevision(_) => "unsupported_revision",
			MonosecretError::TomlSer(_) => "toml_ser",
			#[cfg(feature = "keyring")]
			MonosecretError::Keyring(_) => "keyring",
			MonosecretError::Dotenv(_) => "dotenv",
			MonosecretError::NoProviderConfigured => "no_provider_configured",
			MonosecretError::ProviderNotFound(_) => "provider_not_found",
			MonosecretError::SecretNotFound(_) => "secret_not_found",
			MonosecretError::RequiredSecretMissing(_) => "required_secret_missing",
			MonosecretError::PromptUnavailable(_) => "prompt_unavailable",
			MonosecretError::PromptValueEmpty(_) => "prompt_value_empty",
			MonosecretError::ComposedSecretReadOnly(_) => "composed_secret_read_only",
			MonosecretError::ExtractedSecretReadOnly(_) => "extracted_secret_read_only",
			MonosecretError::CompositionFailed(_) => "composition_failed",
			MonosecretError::NoManifest => "no_manifest",
			MonosecretError::ExtendedConfigNotFound(_) => "extended_config_not_found",
			MonosecretError::NoProjectName => "no_project_name",
			MonosecretError::ProviderOperationFailed(_) => "provider_operation_failed",
			MonosecretError::InquireError(_) => "inquire",
			MonosecretError::Json(_) => "json",
			MonosecretError::InvalidProfile(_) => "invalid_profile",
			MonosecretError::InvalidScope(_) => "invalid_scope",
			MonosecretError::ValidationFailed(_) => "validation_failed",
			MonosecretError::GenerationFailed(_) => "generation_failed",
			MonosecretError::DecodeFailed { .. } => "decode_failed",
			MonosecretError::ReasonRequired => "reason_required",
		}
	}
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn display_error_chain_includes_distinct_causes_without_repeating_them() {
		#[derive(Debug, Error)]
		#[error("request failed")]
		struct RequestError {
			#[source]
			source: io::Error,
		}

		let error = RequestError {
			source: io::Error::other("DNS lookup failed"),
		};
		assert_eq!(
			display_error_chain(&error),
			"request failed: DNS lookup failed"
		);

		let error: MonosecretError = io::Error::other("disk failed").into();
		assert_eq!(display_error_chain(&error), "IO error: disk failed");
	}

	/// `kind()` returns a stable token per variant and never the (possibly
	/// secret-bearing) error message.
	#[test]
	fn kind_returns_stable_non_sensitive_tokens() {
		let cases: Vec<(MonosecretError, &str)> = vec![
			(io::Error::other("boom").into(), "io"),
			(
				MonosecretError::UnsupportedRevision("9.9".into()),
				"unsupported_revision",
			),
			(
				MonosecretError::NoProviderConfigured,
				"no_provider_configured",
			),
			(
				MonosecretError::ProviderNotFound("vault".into()),
				"provider_not_found",
			),
			(
				MonosecretError::SecretNotFound("X".into()),
				"secret_not_found",
			),
			(
				MonosecretError::RequiredSecretMissing("X".into()),
				"required_secret_missing",
			),
			(
				MonosecretError::PromptUnavailable("X".into()),
				"prompt_unavailable",
			),
			(
				MonosecretError::PromptValueEmpty("X".into()),
				"prompt_value_empty",
			),
			(
				MonosecretError::ComposedSecretReadOnly("X".into()),
				"composed_secret_read_only",
			),
			(
				MonosecretError::ExtractedSecretReadOnly("X".into()),
				"extracted_secret_read_only",
			),
			(
				MonosecretError::CompositionFailed("too large".into()),
				"composition_failed",
			),
			(MonosecretError::NoManifest, "no_manifest"),
			(
				MonosecretError::ExtendedConfigNotFound("../x".into()),
				"extended_config_not_found",
			),
			(MonosecretError::NoProjectName, "no_project_name"),
			(
				MonosecretError::ProviderOperationFailed("nope".into()),
				"provider_operation_failed",
			),
			(
				MonosecretError::InvalidProfile("ghost".into()),
				"invalid_profile",
			),
			(
				MonosecretError::GenerationFailed("rng".into()),
				"generation_failed",
			),
			(
				MonosecretError::DecodeFailed {
					name: "VALUE".into(),
					encoding: "base64",
					reason: "invalid length".into(),
				},
				"decode_failed",
			),
			(MonosecretError::ReasonRequired, "reason_required"),
		];

		for (err, expected) in cases {
			assert_eq!(err.kind(), expected);
		}
	}

	#[test]
	fn kind_tags_wrapped_parse_errors() {
		let json: MonosecretError = serde_json::from_str::<serde_json::Value>("nope")
			.unwrap_err()
			.into();
		assert_eq!(json.kind(), "json");

		let toml: MonosecretError = "= bad".parse::<toml::Table>().unwrap_err().into();
		assert_eq!(toml.kind(), "toml");
	}
}
