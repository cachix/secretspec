//! Secret value generation
//!
//! This module provides generation of secret values based on type and configuration.
//! Supported types: password, hex, base64, uuid, command.

use crate::SecretSpecError;
use crate::config::GenerateConfig;
use data_encoding::{BASE64, HEXLOWER};
use rand::Rng;
use secrecy::SecretString;

/// Generate a secret value based on the secret type and generation config.
pub fn generate(secret_type: &str, config: &GenerateConfig) -> crate::Result<SecretString> {
    match secret_type {
        "password" => generate_password(config),
        "hex" => generate_hex(config),
        "base64" => generate_base64(config),
        "uuid" => generate_uuid(),
        "command" => generate_from_command(config),
        unknown => Err(SecretSpecError::GenerationFailed(format!(
            "unknown secret type '{}'",
            unknown
        ))),
    }
}

fn generate_password(config: &GenerateConfig) -> crate::Result<SecretString> {
    let (length, charset_name) = match config {
        GenerateConfig::Bool(_) => (32, "alphanumeric"),
        GenerateConfig::Options(opts) => (
            opts.length.unwrap_or(32),
            opts.charset.as_deref().unwrap_or("alphanumeric"),
        ),
    };

    let charset: Vec<u8> = match charset_name {
        "alphanumeric" => {
            let mut chars = Vec::new();
            chars.extend(b'a'..=b'z');
            chars.extend(b'A'..=b'Z');
            chars.extend(b'0'..=b'9');
            chars
        }
        "ascii" => (33u8..=126).collect(),
        unknown => {
            return Err(SecretSpecError::GenerationFailed(format!(
                "unknown charset '{}', expected 'alphanumeric' or 'ascii'",
                unknown
            )));
        }
    };

    if charset.is_empty() {
        return Err(SecretSpecError::GenerationFailed(
            "charset is empty".to_string(),
        ));
    }

    let mut rng = rand::rng();
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    Ok(SecretString::new(password.into()))
}

fn generate_hex(config: &GenerateConfig) -> crate::Result<SecretString> {
    let bytes = match config {
        GenerateConfig::Bool(_) => 32,
        GenerateConfig::Options(opts) => opts.bytes.unwrap_or(32),
    };

    let mut rng = rand::rng();
    let random_bytes: Vec<u8> = (0..bytes).map(|_| rng.random::<u8>()).collect();
    let hex = HEXLOWER.encode(&random_bytes);

    Ok(SecretString::new(hex.into()))
}

fn generate_base64(config: &GenerateConfig) -> crate::Result<SecretString> {
    let bytes = match config {
        GenerateConfig::Bool(_) => 32,
        GenerateConfig::Options(opts) => opts.bytes.unwrap_or(32),
    };

    let mut rng = rand::rng();
    let random_bytes: Vec<u8> = (0..bytes).map(|_| rng.random::<u8>()).collect();
    let encoded = BASE64.encode(&random_bytes);

    Ok(SecretString::new(encoded.into()))
}

fn generate_uuid() -> crate::Result<SecretString> {
    let id = uuid::Uuid::new_v4().to_string();
    Ok(SecretString::new(id.into()))
}

fn generate_from_command(config: &GenerateConfig) -> crate::Result<SecretString> {
    let command = match config {
        GenerateConfig::Bool(_) => {
            return Err(SecretSpecError::GenerationFailed(
                "type = \"command\" requires generate = { command = \"...\" }".to_string(),
            ));
        }
        GenerateConfig::Options(opts) => opts.command.as_deref().ok_or_else(|| {
            SecretSpecError::GenerationFailed(
                "type = \"command\" requires generate = { command = \"...\" }".to_string(),
            )
        })?,
    };

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|e| {
            SecretSpecError::GenerationFailed(format!(
                "failed to execute command '{}': {}",
                command, e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SecretSpecError::GenerationFailed(format!(
            "command '{}' failed with exit code {}: {}",
            command,
            output.status.code().unwrap_or(-1),
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|_| {
        SecretSpecError::GenerationFailed(format!(
            "command '{}' produced non-UTF-8 output",
            command
        ))
    })?;

    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(SecretSpecError::GenerationFailed(format!(
            "command '{}' produced empty output",
            command
        )));
    }

    Ok(SecretString::new(trimmed.to_string().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GenerateOptions;
    use secrecy::ExposeSecret;

    #[test]
    fn test_generate_password_default() {
        let value = generate("password", &GenerateConfig::Bool(true)).unwrap();
        let s = value.expose_secret();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_password_custom_length() {
        let config = GenerateConfig::Options(GenerateOptions {
            length: Some(64),
            ..Default::default()
        });
        let value = generate("password", &config).unwrap();
        assert_eq!(value.expose_secret().len(), 64);
    }

    #[test]
    fn test_generate_password_ascii_charset() {
        let config = GenerateConfig::Options(GenerateOptions {
            length: Some(100),
            charset: Some("ascii".to_string()),
            ..Default::default()
        });
        let value = generate("password", &config).unwrap();
        let s = value.expose_secret();
        assert_eq!(s.len(), 100);
        assert!(s.bytes().all(|b| (33..=126).contains(&b)));
    }

    #[test]
    fn test_generate_password_unknown_charset() {
        let config = GenerateConfig::Options(GenerateOptions {
            charset: Some("emoji".to_string()),
            ..Default::default()
        });
        let result = generate("password", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown charset"));
    }

    #[test]
    fn test_generate_password_zero_length() {
        let config = GenerateConfig::Options(GenerateOptions {
            length: Some(0),
            ..Default::default()
        });
        let value = generate("password", &config).unwrap();
        assert_eq!(value.expose_secret().len(), 0);
    }

    #[test]
    fn test_generate_password_large_length() {
        let config = GenerateConfig::Options(GenerateOptions {
            length: Some(10000),
            ..Default::default()
        });
        let value = generate("password", &config).unwrap();
        assert_eq!(value.expose_secret().len(), 10000);
    }

    #[test]
    fn test_generate_hex_default() {
        let value = generate("hex", &GenerateConfig::Bool(true)).unwrap();
        let s = value.expose_secret();
        // 32 bytes = 64 hex chars
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_hex_custom_bytes() {
        let config = GenerateConfig::Options(GenerateOptions {
            bytes: Some(16),
            ..Default::default()
        });
        let value = generate("hex", &config).unwrap();
        assert_eq!(value.expose_secret().len(), 32);
    }

    #[test]
    fn test_generate_hex_zero_bytes() {
        let config = GenerateConfig::Options(GenerateOptions {
            bytes: Some(0),
            ..Default::default()
        });
        let value = generate("hex", &config).unwrap();
        assert_eq!(value.expose_secret().len(), 0);
    }

    #[test]
    fn test_generate_base64_default() {
        let value = generate("base64", &GenerateConfig::Bool(true)).unwrap();
        let s = value.expose_secret();
        // 32 bytes base64 encoded = 44 chars (with padding)
        assert_eq!(s.len(), 44);
        assert!(
            s.chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        );
    }

    #[test]
    fn test_generate_base64_custom_bytes() {
        let config = GenerateConfig::Options(GenerateOptions {
            bytes: Some(64),
            ..Default::default()
        });
        let value = generate("base64", &config).unwrap();
        // 64 bytes = 88 chars base64
        assert_eq!(value.expose_secret().len(), 88);
    }

    #[test]
    fn test_generate_uuid() {
        let value = generate("uuid", &GenerateConfig::Bool(true)).unwrap();
        let s = value.expose_secret();
        // UUID v4 format: 8-4-4-4-12 = 36 chars
        assert_eq!(s.len(), 36);
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        // Version nibble = 4
        assert!(parts[2].starts_with('4'));
    }

    #[test]
    fn test_generate_command() {
        let config = GenerateConfig::Options(GenerateOptions {
            command: Some("echo hello".to_string()),
            ..Default::default()
        });
        let value = generate("command", &config).unwrap();
        assert_eq!(value.expose_secret(), "hello");
    }

    #[test]
    fn test_generate_command_failing() {
        let config = GenerateConfig::Options(GenerateOptions {
            command: Some("false".to_string()),
            ..Default::default()
        });
        let result = generate("command", &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed with exit code")
        );
    }

    #[test]
    fn test_generate_command_empty_output() {
        let config = GenerateConfig::Options(GenerateOptions {
            command: Some("echo -n ''".to_string()),
            ..Default::default()
        });
        let result = generate("command", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty output"));
    }

    #[test]
    fn test_generate_command_not_found() {
        let config = GenerateConfig::Options(GenerateOptions {
            command: Some("nonexistent_command_xyz_12345".to_string()),
            ..Default::default()
        });
        let result = generate("command", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_command_bool_config_fails() {
        let result = generate("command", &GenerateConfig::Bool(true));
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_unknown_type() {
        let result = generate("unknown_type", &GenerateConfig::Bool(true));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown secret type")
        );
    }

    #[test]
    fn test_generate_uniqueness() {
        let v1 = generate("password", &GenerateConfig::Bool(true)).unwrap();
        let v2 = generate("password", &GenerateConfig::Bool(true)).unwrap();
        assert_ne!(v1.expose_secret(), v2.expose_secret());
    }
}
