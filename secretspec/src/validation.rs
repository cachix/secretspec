//! Validation results for secret checking

use crate::config::Resolved;
use secrecy::SecretString;
use std::collections::HashMap;
use std::fmt;

/// Container for validated secrets with metadata
///
/// This struct contains the validated secrets along with information about
/// which secrets are present, missing, or using default values.
pub struct ValidatedSecrets {
    /// Resolved secrets with provider and profile information
    pub resolved: Resolved<HashMap<String, SecretString>>,
    /// List of optional secrets that are missing
    pub missing_optional: Vec<String>,
    /// List of secrets using their default values (name, default_value)
    pub with_defaults: Vec<(String, String)>,
}

/// Container for validation errors
///
/// This struct contains all the validation errors that occurred when
/// validating secrets, including missing required secrets and other issues.
#[derive(Debug, Clone)]
pub struct ValidationErrors {
    /// List of required secrets that are missing
    pub missing_required: Vec<String>,
    /// List of optional secrets that are missing
    pub missing_optional: Vec<String>,
    /// List of secrets using their default values (name, default_value)
    pub with_defaults: Vec<(String, String)>,
    /// The provider name that was used
    pub provider: String,
    /// The profile that was used
    pub profile: String,
}

impl ValidationErrors {
    /// Create a new ValidationErrors instance
    pub fn new(
        missing_required: Vec<String>,
        missing_optional: Vec<String>,
        with_defaults: Vec<(String, String)>,
        provider: String,
        profile: String,
    ) -> Self {
        Self {
            missing_required,
            missing_optional,
            with_defaults,
            provider,
            profile,
        }
    }

    /// Check if there are any critical errors (missing required secrets)
    pub fn has_errors(&self) -> bool {
        !self.missing_required.is_empty()
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.missing_required.is_empty() {
            write!(
                f,
                "Missing required secrets: {}",
                self.missing_required.join(", ")
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}
