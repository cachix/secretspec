use super::Provider;
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use url::Url;

/// Configuration for the dotenv provider.
///
/// This struct holds the configuration for accessing .env files,
/// primarily the path to the .env file to read from and write to.
///
/// # Examples
///
/// ```ignore
/// use std::path::PathBuf;
/// use secretspec::provider::dotenv::DotEnvConfig;
///
/// let config = DotEnvConfig {
///     path: PathBuf::from(".env.production"),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotEnvConfig {
    /// Path to the .env file.
    ///
    /// Can be either an absolute path (e.g., `/etc/secrets/.env`)
    /// or a relative path (e.g., `.env`, `config/.env.local`).
    pub path: PathBuf,
}

impl Default for DotEnvConfig {
    /// Creates a default configuration with path set to `.env`.
    ///
    /// This is the conventional default location for dotenv files
    /// in the current working directory.
    fn default() -> Self {
        Self {
            path: PathBuf::from(".env"),
        }
    }
}

impl TryFrom<&Url> for DotEnvConfig {
    type Error = SecretSpecError;

    /// Creates a DotEnvConfig from a URL.
    ///
    /// Parses a URL in the format `dotenv://[path]` to extract
    /// the path to the .env file. The URL parsing handles several cases:
    ///
    /// # URL Formats
    ///
    /// - `dotenv:///absolute/path` - Absolute path
    /// - `dotenv://.env` - Relative path (authority as filename)
    /// - `dotenv://` - Uses default `.env` in current directory
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use url::Url;
    /// use secretspec::provider::dotenv::DotEnvConfig;
    ///
    /// let url = Url::parse("dotenv:///.env.production").unwrap();
    /// let config: DotEnvConfig = (&url).try_into().unwrap();
    /// assert_eq!(config.path.to_str().unwrap(), "/.env.production");
    /// ```
    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "dotenv" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for dotenv provider",
                url.scheme()
            )));
        }

        // For dotenv URLs:
        // - dotenv:///absolute/path -> url.path() = "/absolute/path"
        // - dotenv://.env -> url.host_str() = ".env", url.path() = ""
        // - dotenv:// -> url.host_str() = None, url.path() = ""

        let path = if url.path() != "" && url.path() != "/" {
            // Check if this is an absolute path (starts with /) or has a host
            if let Some(host) = url.host_str() {
                // Case like dotenv://config/.env.local -> host="config", path="/.env.local"
                // We want "config/.env.local"
                format!("{}{}", host, url.path())
            } else {
                // Absolute path from dotenv:///path
                url.path().to_string()
            }
        } else if let Some(host) = url.host_str() {
            // Relative path from dotenv://filename
            host.to_string()
        } else {
            // Default case dotenv://
            ".env".to_string()
        };

        Ok(Self {
            path: PathBuf::from(path),
        })
    }
}

/// Provider for managing secrets in .env files.
///
/// The DotEnvProvider implements the Provider trait to enable reading
/// and writing secrets from/to .env files. It uses the dotenvy crate
/// for parsing and serde-envfile for serialization to ensure proper
/// handling of special characters and escaping.
///
/// # Features
///
/// - Reads environment variables from .env files
/// - Writes new or updated variables back to .env files
/// - Preserves existing variables when updating
/// - Handles proper escaping of values with special characters
/// - Supports both relative and absolute file paths
///
/// # Note
///
/// This provider ignores the project and profile parameters as .env files
/// typically don't have built-in namespacing. All secrets are stored
/// flat in the file.
pub struct DotEnvProvider {
    /// Configuration containing the path to the .env file
    config: DotEnvConfig,
}

crate::register_provider! {
    struct: DotEnvProvider,
    config: DotEnvConfig,
    name: "dotenv",
    description: "Traditional .env files",
    schemes: ["dotenv"],
    examples: ["dotenv://.env", "dotenv://.env.production"],
}

impl DotEnvProvider {
    /// Creates a new DotEnvProvider with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration specifying the .env file path
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use secretspec::provider::dotenv::{DotEnvProvider, DotEnvConfig};
    ///
    /// let config = DotEnvConfig::default();
    /// let provider = DotEnvProvider::new(config);
    /// ```
    pub fn new(config: DotEnvConfig) -> Self {
        Self { config }
    }
}

impl Provider for DotEnvProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }
    
    fn uri(&self) -> String {
        // Dotenv uses single colon format: dotenv:path
        // The path can be relative or absolute
        let path_str = self.config.path.display().to_string();
        
        if path_str == ".env" {
            // Default case - just return "dotenv" 
            "dotenv".to_string()
        } else if path_str.starts_with('/') {
            // Absolute path
            format!("dotenv:{}", path_str)
        } else {
            // Relative path
            format!("dotenv:{}", path_str)
        }
    }

    /// Retrieves a secret value from the .env file.
    ///
    /// Reads the .env file and returns the value for the specified key.
    /// The project and profile parameters are ignored as .env files
    /// don't support namespacing.
    ///
    /// # Arguments
    ///
    /// * `_project` - Ignored, .env files don't support project namespacing
    /// * `key` - The environment variable name to look up
    /// * `_profile` - Ignored, .env files don't support profile namespacing
    ///
    /// # Returns
    ///
    /// * `Ok(Some(String))` - The value if the key exists
    /// * `Ok(None)` - If the key doesn't exist or the file doesn't exist
    /// * `Err(SecretSpecError)` - If reading the file fails
    ///
    /// # Implementation Details
    ///
    /// Uses the dotenvy crate for parsing to ensure compatibility with
    /// standard .env file formats and proper handling of quoted values,
    /// multiline strings, and escape sequences.
    fn get(&self, _project: &str, key: &str, _profile: &str) -> Result<Option<SecretString>> {
        if !self.config.path.exists() {
            return Ok(None);
        }

        // Use dotenvy for reading to ensure compatibility
        let mut vars = HashMap::new();
        let env_vars = dotenvy::from_path_iter(&self.config.path)?;
        for item in env_vars {
            let (k, v) = item?;
            vars.insert(k, v);
        }

        Ok(vars.get(key).map(|v| SecretString::new(v.clone().into())))
    }

    /// Sets a secret value in the .env file.
    ///
    /// Updates or adds a key-value pair in the .env file. If the file
    /// doesn't exist, it will be created. Existing variables are preserved.
    ///
    /// # Arguments
    ///
    /// * `_project` - Ignored, .env files don't support project namespacing
    /// * `key` - The environment variable name to set
    /// * `value` - The value to store
    /// * `_profile` - Ignored, .env files don't support profile namespacing
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the value was successfully written
    /// * `Err(SecretSpecError)` - If reading or writing the file fails
    ///
    /// # Implementation Details
    ///
    /// 1. Loads existing variables using dotenvy to preserve them
    /// 2. Updates or adds the new key-value pair
    /// 3. Serializes back using serde-envfile for proper escaping
    fn set(&self, _project: &str, key: &str, value: &SecretString, _profile: &str) -> Result<()> {
        // Load existing vars using dotenvy
        let mut vars = HashMap::new();
        if self.config.path.exists() {
            let env_vars = dotenvy::from_path_iter(&self.config.path)?;
            for item in env_vars {
                let (k, v) = item?;
                vars.insert(k, v);
            }
        }

        // Update the value
        vars.insert(key.to_string(), value.expose_secret().to_string());

        // Save back to file using serde-envfile for proper escaping
        let content = serde_envfile::to_string(&vars).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to serialize .env file: {}",
                e
            ))
        })?;

        fs::write(&self.config.path, content)?;
        Ok(())
    }

    fn reflect(&self) -> Result<HashMap<String, crate::config::Secret>> {
        use crate::config::Secret;

        if !self.config.path.exists() {
            return Ok(HashMap::new());
        }

        // Check if path is a directory
        if self.config.path.is_dir() {
            return Err(SecretSpecError::Io(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                format!(
                    "Expected file but found directory: {}",
                    self.config.path.display()
                ),
            )));
        }

        let mut secrets = HashMap::new();
        let env_vars = dotenvy::from_path_iter(&self.config.path)?;
        for item in env_vars {
            let (key, _value) = item?;
            secrets.insert(
                key.clone(),
                Secret {
                    description: Some(format!("{} secret", key)),
                    required: true,
                    default: None,
                },
            );
        }

        Ok(secrets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dotenv_url_parsing() {
        // Test with absolute path using three slashes - this is the main syntax we want to support
        let url = Url::parse("dotenv:///tmp/test/.env").unwrap();
        let config: DotEnvConfig = (&url).try_into().unwrap();
        assert_eq!(config.path.to_str().unwrap(), "/tmp/test/.env");

        // Test with relative path using two slashes - authority as filename
        let url = Url::parse("dotenv://.env").unwrap();
        let config: DotEnvConfig = (&url).try_into().unwrap();
        assert_eq!(config.path.to_str().unwrap(), ".env");

        // Test with relative path in subdirectory
        let url = Url::parse("dotenv://config/.env.local").unwrap();
        let config: DotEnvConfig = (&url).try_into().unwrap();
        assert_eq!(config.path.to_str().unwrap(), "config/.env.local");

        // Test with default (empty after //)
        let url = Url::parse("dotenv://").unwrap();
        let config: DotEnvConfig = (&url).try_into().unwrap();
        assert_eq!(config.path.to_str().unwrap(), ".env");

        // Test with relative path - host part becomes first part of path
        let url = Url::parse("dotenv://foobar/custom/path/.env").unwrap();
        let config: DotEnvConfig = (&url).try_into().unwrap();
        assert_eq!(config.path.to_str().unwrap(), "foobar/custom/path/.env");
    }

    #[test]
    fn test_default_config() {
        let config = DotEnvConfig::default();
        assert_eq!(config.path.to_str().unwrap(), ".env");
    }

    #[test]
    fn test_reflect() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env");

        let mut file = std::fs::File::create(&env_file).unwrap();
        writeln!(file, "API_KEY=test123").unwrap();
        writeln!(file, "DATABASE_URL=postgres://localhost").unwrap();

        let provider = DotEnvProvider::new(DotEnvConfig {
            path: env_file.clone(),
        });

        let secrets = provider.reflect().unwrap();
        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains_key("API_KEY"));
        assert!(secrets.contains_key("DATABASE_URL"));

        let api_key_config = &secrets["API_KEY"];
        assert_eq!(
            api_key_config.description,
            Some("API_KEY secret".to_string())
        );
        assert!(api_key_config.required);
        assert!(api_key_config.default.is_none());
    }

    #[test]
    fn test_reflect_nonexistent_file() {
        let provider = DotEnvProvider::new(DotEnvConfig {
            path: PathBuf::from("/tmp/nonexistent/.env"),
        });

        let secrets = provider.reflect().unwrap();
        assert!(secrets.is_empty());
    }
}
