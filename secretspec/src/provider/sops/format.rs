use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::SecretSpecError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SopsFormat {
    /// YAML configuration files (.yaml, .yml)
    #[default]
    Yaml,
    /// JSON configuration files (.json)
    Json,
    /// Environment variable files (.env)
    Env,
    /// INI configuration files (.ini)
    Ini,
    /// Binary files (encrypted as base64 under tree['data'] in JSON format)
    Binary,
}

impl fmt::Display for SopsFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml => write!(f, "yaml"),
            Self::Json => write!(f, "json"),
            Self::Env => write!(f, "env"),
            Self::Ini => write!(f, "ini"),
            Self::Binary => write!(f, "binary"),
        }
    }
}

impl FromStr for SopsFormat {
    type Err = SecretSpecError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "yaml" | "yml" => Ok(Self::Yaml),
            "json" => Ok(Self::Json),
            "env" | "dotenv" => Ok(Self::Env),
            "ini" => Ok(Self::Ini),
            "binary" | "bin" => Ok(Self::Binary),
            _ => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Unsupported SOPS format: {}. Supported formats: yaml, json, env, ini, binary",
                s
            ))),
        }
    }
}

impl SopsFormat {
    /// Detect format from file extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "yml" | "yaml" => Self::Yaml,
            "json" => Self::Json,
            "env" => Self::Env,
            "ini" => Self::Ini,
            // Any other extension is treated as binary
            _ => Self::Binary,
        }
    }

    /// Get the canonical string representation for SOPS CLI
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Env => "env",
            Self::Ini => "ini",
            Self::Binary => "binary",
        }
    }

    /// Get common file extensions for this format
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            Self::Yaml => &["yaml", "yml"],
            Self::Json => &["json"],
            Self::Env => &["env"],
            Self::Ini => &["ini"],
            Self::Binary => &["bin", "dat", "key", "cert", "p12", "pfx"], // Common binary file extensions
        }
    }

    /// Check if this format supports structured data (key-value lookup)
    pub fn is_structured(&self) -> bool {
        matches!(self, Self::Yaml | Self::Json | Self::Env | Self::Ini)
    }
}
