use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::SecretSpecError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SopsFormat {
    #[default]
    Yaml,
    Json,
    Env,
    Ini,
}

impl fmt::Display for SopsFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml => write!(f, "yaml"),
            Self::Json => write!(f, "json"),
            Self::Env => write!(f, "env"),
            Self::Ini => write!(f, "ini"),
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
            _ => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Unsupported SOPS format: {}. Supported formats: yaml, json, env, ini",
                s
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sops_format_from_str() {
        assert_eq!(SopsFormat::from_str("yaml").unwrap(), SopsFormat::Yaml);
        assert_eq!(SopsFormat::from_str("yml").unwrap(), SopsFormat::Yaml);
        assert_eq!(SopsFormat::from_str("json").unwrap(), SopsFormat::Json);
        assert_eq!(SopsFormat::from_str("env").unwrap(), SopsFormat::Env);
        assert_eq!(SopsFormat::from_str("dotenv").unwrap(), SopsFormat::Env);
        assert_eq!(SopsFormat::from_str("ini").unwrap(), SopsFormat::Ini);

        assert!(SopsFormat::from_str("unknown").is_err());
    }
}
