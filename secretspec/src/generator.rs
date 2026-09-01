//! Secret value generation
//!
//! This module provides generation of secret values based on type and configuration.
//! Supported types: password, hex, base64, uuid, command, rsa_private_key,
//! openpgp_private_key, ssh_private_key.

use crate::SecretSpecError;
use crate::config::{
    GenerateConfig, OPENPGP_RSA_DEFAULT_BITS, OPENPGP_RSA_MAX_BITS, OPENPGP_RSA_MIN_BITS,
    SSH_RSA_DEFAULT_BITS, SSH_RSA_MAX_BITS, SSH_RSA_MIN_BITS,
};
use data_encoding::{BASE64, HEXLOWER};
use pgp::composed::{
    ArmorOptions, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder,
};
use pgp::crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::types::{CompressionAlgorithm, KeyVersion};
use rand::RngExt;
use rand_08::rngs::OsRng as OpenPgpOsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use secrecy::SecretString;
use smallvec::smallvec;
use ssh_key::private::{KeypairData as SshKeypairData, RsaKeypair as SshRsaKeypair};
use ssh_key::{
    Algorithm as SshAlgorithm, LineEnding as SshLineEnding, PrivateKey as SshPrivateKey,
};

/// Generate a secret value based on the secret type and generation config.
pub fn generate(secret_type: &str, config: &GenerateConfig) -> crate::Result<SecretString> {
    match secret_type {
        "password" => generate_password(config),
        "hex" => generate_hex(config),
        "base64" => generate_base64(config),
        "uuid" => generate_uuid(),
        "command" => generate_from_command(config),
        "rsa_private_key" => generate_rsa(config),
        "openpgp_private_key" => generate_openpgp(config),
        "ssh_private_key" => generate_ssh(config),
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

fn generate_rsa(config: &GenerateConfig) -> crate::Result<SecretString> {
    let bits = match config {
        GenerateConfig::Bool(_) => 2048,
        GenerateConfig::Options(opts) => opts.bits.unwrap_or(2048),
    };

    let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).map_err(|e| {
        SecretSpecError::GenerationFailed(format!("failed to generate RSA key: {}", e))
    })?;

    let pem = private_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .map_err(|e| {
            SecretSpecError::GenerationFailed(format!("failed to encode RSA key as PEM: {}", e))
        })?;

    Ok(SecretString::new(pem.to_string().into()))
}

/// Generates a broadly interoperable OpenPGP v4 transferable secret key.
///
/// The certification-only primary key is Ed25519. Requested signing and
/// encryption capabilities are placed on separate Ed25519 and Curve25519
/// subkeys, respectively, so routine operations do not use the primary key.
fn generate_openpgp(config: &GenerateConfig) -> crate::Result<SecretString> {
    let opts = match config {
        GenerateConfig::Options(opts) => opts,
        GenerateConfig::Bool(_) => {
            return Err(SecretSpecError::GenerationFailed(
                "type = \"openpgp_private_key\" requires generate = { user_id = \"Name <email>\" }"
                    .to_string(),
            ));
        }
    };

    let user_id = opts.user_id.as_deref().ok_or_else(|| {
        SecretSpecError::GenerationFailed(
            "type = \"openpgp_private_key\" requires generate.user_id".to_string(),
        )
    })?;
    if user_id.trim().is_empty() {
        return Err(SecretSpecError::GenerationFailed(
            "generate.user_id cannot be empty or whitespace".to_string(),
        ));
    }
    if user_id.chars().any(char::is_control) {
        return Err(SecretSpecError::GenerationFailed(
            "generate.user_id cannot contain control characters".to_string(),
        ));
    }

    let (primary_key_type, signing_key_type, encryption_key_type) =
        match opts.algorithm.as_deref().unwrap_or("ed25519") {
            "ed25519" => {
                if opts.bits.is_some() {
                    return Err(SecretSpecError::GenerationFailed(
                        "generate.bits is only valid when generate.algorithm = \"rsa\"".to_string(),
                    ));
                }
                (
                    KeyType::Ed25519Legacy,
                    KeyType::Ed25519Legacy,
                    KeyType::ECDH(ECCCurve::Curve25519Legacy),
                )
            }
            "rsa" => {
                let bits = opts.bits.unwrap_or(OPENPGP_RSA_DEFAULT_BITS);
                if !(OPENPGP_RSA_MIN_BITS..=OPENPGP_RSA_MAX_BITS).contains(&bits) {
                    return Err(SecretSpecError::GenerationFailed(
                        "OpenPGP RSA generate.bits must be between 2048 and 8192".to_string(),
                    ));
                }
                let bits = u32::try_from(bits).map_err(|_| {
                    SecretSpecError::GenerationFailed(
                        "OpenPGP RSA generate.bits is too large".to_string(),
                    )
                })?;
                (KeyType::Rsa(bits), KeyType::Rsa(bits), KeyType::Rsa(bits))
            }
            algorithm => {
                return Err(SecretSpecError::GenerationFailed(format!(
                    "unknown OpenPGP algorithm '{algorithm}'; expected `ed25519` or `rsa`"
                )));
            }
        };

    let (sign, encrypt) = match opts.capabilities.as_deref() {
        None => (true, true),
        Some([]) => {
            return Err(SecretSpecError::GenerationFailed(
                "generate.capabilities must contain `sign`, `encrypt`, or both".to_string(),
            ));
        }
        Some(capabilities) => {
            let mut sign = false;
            let mut encrypt = false;
            for capability in capabilities {
                let selected = match capability.as_str() {
                    "sign" => &mut sign,
                    "encrypt" => &mut encrypt,
                    _ => {
                        return Err(SecretSpecError::GenerationFailed(
                            "generate.capabilities accepts only `sign` and `encrypt`".to_string(),
                        ));
                    }
                };
                if *selected {
                    return Err(SecretSpecError::GenerationFailed(format!(
                        "generate.capabilities contains duplicate capability '{capability}'"
                    )));
                }
                *selected = true;
            }
            (sign, encrypt)
        }
    };

    let mut subkeys = Vec::with_capacity(usize::from(sign) + usize::from(encrypt));
    if sign {
        subkeys.push(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V4)
                .key_type(signing_key_type)
                .can_sign(true)
                .build()
                .map_err(|error| {
                    SecretSpecError::GenerationFailed(format!(
                        "failed to configure OpenPGP signing subkey: {error}"
                    ))
                })?,
        );
    }
    if encrypt {
        subkeys.push(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V4)
                .key_type(encryption_key_type)
                .can_encrypt(EncryptionCaps::All)
                .build()
                .map_err(|error| {
                    SecretSpecError::GenerationFailed(format!(
                        "failed to configure OpenPGP encryption subkey: {error}"
                    ))
                })?,
        );
    }

    let mut builder = SecretKeyParamsBuilder::default();
    builder
        .version(KeyVersion::V4)
        .key_type(primary_key_type)
        .can_certify(true)
        .can_sign(false)
        .primary_user_id(user_id.to_string())
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha512, HashAlgorithm::Sha256])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::Uncompressed,
        ])
        .subkeys(subkeys);

    let key = builder
        .build()
        .map_err(|error| {
            SecretSpecError::GenerationFailed(format!(
                "failed to configure OpenPGP private key: {error}"
            ))
        })?
        .generate(OpenPgpOsRng)
        .map_err(|error| {
            SecretSpecError::GenerationFailed(format!(
                "failed to generate OpenPGP private key: {error}"
            ))
        })?;
    key.verify_bindings().map_err(|error| {
        SecretSpecError::GenerationFailed(format!(
            "generated OpenPGP private key failed self-verification: {error}"
        ))
    })?;
    let armored = key
        .to_armored_string(ArmorOptions::default())
        .map_err(|error| {
            SecretSpecError::GenerationFailed(format!(
                "failed to armor OpenPGP private key: {error}"
            ))
        })?;

    Ok(SecretString::new(armored.into()))
}

/// Generates an unencrypted OpenSSH private key using a modern Ed25519 default
/// or a configurable RSA compatibility profile.
fn generate_ssh(config: &GenerateConfig) -> crate::Result<SecretString> {
    let opts = match config {
        GenerateConfig::Bool(_) => None,
        GenerateConfig::Options(opts) => Some(opts),
    };
    let algorithm = opts
        .and_then(|options| options.algorithm.as_deref())
        .unwrap_or("ed25519");
    let comment = opts
        .and_then(|options| options.comment.as_deref())
        .unwrap_or_default();
    if comment.chars().any(char::is_control) {
        return Err(SecretSpecError::GenerationFailed(
            "generate.comment cannot contain control characters".to_string(),
        ));
    }

    let mut rng = OpenPgpOsRng;
    let mut key = match algorithm {
        "ed25519" => {
            if opts.is_some_and(|options| options.bits.is_some()) {
                return Err(SecretSpecError::GenerationFailed(
                    "generate.bits is only valid when generate.algorithm = \"rsa\"".to_string(),
                ));
            }
            SshPrivateKey::random(&mut rng, SshAlgorithm::Ed25519).map_err(|error| {
                SecretSpecError::GenerationFailed(format!(
                    "failed to generate Ed25519 SSH private key: {error}"
                ))
            })?
        }
        "rsa" => {
            let bits = opts
                .and_then(|options| options.bits)
                .unwrap_or(SSH_RSA_DEFAULT_BITS);
            if !(SSH_RSA_MIN_BITS..=SSH_RSA_MAX_BITS).contains(&bits) {
                return Err(SecretSpecError::GenerationFailed(
                    "SSH RSA generate.bits must be between 2048 and 8192".to_string(),
                ));
            }
            let keypair = SshRsaKeypair::random(&mut rng, bits).map_err(|error| {
                SecretSpecError::GenerationFailed(format!(
                    "failed to generate RSA SSH private key: {error}"
                ))
            })?;
            SshPrivateKey::new(SshKeypairData::Rsa(keypair), comment).map_err(|error| {
                SecretSpecError::GenerationFailed(format!(
                    "failed to assemble RSA SSH private key: {error}"
                ))
            })?
        }
        algorithm => {
            return Err(SecretSpecError::GenerationFailed(format!(
                "unknown SSH algorithm '{algorithm}'; expected `ed25519` or `rsa`"
            )));
        }
    };
    key.set_comment(comment);
    let encoded = key.to_openssh(SshLineEnding::LF).map_err(|error| {
        SecretSpecError::GenerationFailed(format!("failed to encode OpenSSH private key: {error}"))
    })?;
    Ok(SecretString::new(encoded.to_string().into()))
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
    use pgp::composed::{Deserializable, SignedSecretKey};
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::types::KeyDetails as _;
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
        // `echo -n ''` is not POSIX-portable: macOS /bin/sh prints "-n"
        // literally instead of suppressing the newline. Use `printf ''`
        // which produces zero bytes on every platform.
        let config = GenerateConfig::Options(GenerateOptions {
            command: Some("printf ''".to_string()),
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
    fn test_generate_rsa_default() {
        let value = generate("rsa_private_key", &GenerateConfig::Bool(true)).unwrap();
        let s = value.expose_secret();
        assert!(s.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(s.trim().ends_with("-----END RSA PRIVATE KEY-----"));
    }

    #[test]
    fn test_generate_rsa_custom_bits() {
        let config = GenerateConfig::Options(GenerateOptions {
            bits: Some(4096),
            ..Default::default()
        });
        let value = generate("rsa_private_key", &config).unwrap();
        let s = value.expose_secret();
        assert!(s.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        // 4096-bit key PEM is longer than 2048-bit
        assert!(s.len() > 1700);
    }

    #[test]
    fn test_generate_rsa_uniqueness() {
        let v1 = generate("rsa_private_key", &GenerateConfig::Bool(true)).unwrap();
        let v2 = generate("rsa_private_key", &GenerateConfig::Bool(true)).unwrap();
        assert_ne!(v1.expose_secret(), v2.expose_secret());
    }

    fn openpgp_config(
        algorithm: Option<&str>,
        bits: Option<usize>,
        capabilities: Option<Vec<&str>>,
    ) -> GenerateConfig {
        GenerateConfig::Options(GenerateOptions {
            user_id: Some("SecretSpec Test <test@example.invalid>".to_string()),
            algorithm: algorithm.map(ToString::to_string),
            bits,
            capabilities: capabilities
                .map(|values| values.into_iter().map(ToString::to_string).collect()),
            ..Default::default()
        })
    }

    fn parse_openpgp(config: &GenerateConfig) -> SignedSecretKey {
        let value = generate("openpgp_private_key", config).unwrap();
        assert!(
            value
                .expose_secret()
                .starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----")
        );
        assert!(
            value
                .expose_secret()
                .trim()
                .ends_with("-----END PGP PRIVATE KEY BLOCK-----")
        );
        let (key, _) =
            SignedSecretKey::from_armor_single(value.expose_secret().as_bytes()).unwrap();
        key.verify_bindings().unwrap();
        key
    }

    #[test]
    fn test_generate_openpgp_default_profile() {
        let key = parse_openpgp(&openpgp_config(None, None, None));
        assert_eq!(key.primary_key.algorithm(), PublicKeyAlgorithm::EdDSALegacy);
        assert_eq!(key.primary_key.version(), KeyVersion::V4);
        assert_eq!(key.secret_subkeys.len(), 2);
        let algorithms = key
            .secret_subkeys
            .iter()
            .map(|subkey| subkey.algorithm())
            .collect::<Vec<_>>();
        assert_eq!(
            algorithms,
            vec![PublicKeyAlgorithm::EdDSALegacy, PublicKeyAlgorithm::ECDH]
        );

        let public = key.to_public_key();
        public.verify_bindings().unwrap();
        assert_eq!(
            public.primary_key.fingerprint(),
            key.primary_key.fingerprint()
        );
    }

    #[test]
    fn test_generate_openpgp_capability_profiles() {
        let signing = parse_openpgp(&openpgp_config(None, None, Some(vec!["sign"])));
        assert_eq!(signing.secret_subkeys.len(), 1);
        assert_eq!(
            signing.secret_subkeys[0].algorithm(),
            PublicKeyAlgorithm::EdDSALegacy
        );

        let encryption = parse_openpgp(&openpgp_config(None, None, Some(vec!["encrypt"])));
        assert_eq!(encryption.secret_subkeys.len(), 1);
        assert_eq!(
            encryption.secret_subkeys[0].algorithm(),
            PublicKeyAlgorithm::ECDH
        );
    }

    #[test]
    fn test_generate_openpgp_rsa_profile() {
        let key = parse_openpgp(&openpgp_config(Some("rsa"), Some(2048), Some(vec!["sign"])));
        assert_eq!(key.primary_key.algorithm(), PublicKeyAlgorithm::RSA);
        assert_eq!(key.primary_key.version(), KeyVersion::V4);
        assert_eq!(key.secret_subkeys.len(), 1);
        assert_eq!(key.secret_subkeys[0].algorithm(), PublicKeyAlgorithm::RSA);
    }

    #[test]
    fn test_generate_openpgp_rejects_incomplete_or_invalid_options() {
        for config in [
            GenerateConfig::Bool(true),
            GenerateConfig::Options(GenerateOptions::default()),
            openpgp_config(None, None, Some(vec![])),
            openpgp_config(None, None, Some(vec!["authenticate"])),
            openpgp_config(None, None, Some(vec!["sign", "sign"])),
            openpgp_config(Some("dsa"), None, None),
            openpgp_config(Some("ed25519"), Some(3072), None),
            openpgp_config(Some("rsa"), Some(1024), None),
            openpgp_config(Some("rsa"), Some(16384), None),
        ] {
            assert!(generate("openpgp_private_key", &config).is_err());
        }
    }

    #[test]
    fn test_generate_openpgp_uniqueness() {
        let config = openpgp_config(None, None, Some(vec!["sign"]));
        let first = parse_openpgp(&config);
        let second = parse_openpgp(&config);
        assert_ne!(
            first.primary_key.fingerprint(),
            second.primary_key.fingerprint()
        );
    }

    fn parse_ssh(config: &GenerateConfig) -> SshPrivateKey {
        let value = generate("ssh_private_key", config).unwrap();
        assert!(
            value
                .expose_secret()
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert!(
            value
                .expose_secret()
                .trim()
                .ends_with("-----END OPENSSH PRIVATE KEY-----")
        );
        SshPrivateKey::from_openssh(value.expose_secret()).unwrap()
    }

    #[test]
    fn test_generate_ssh_default_ed25519_profile() {
        let key = parse_ssh(&GenerateConfig::Bool(true));
        assert_eq!(key.algorithm(), SshAlgorithm::Ed25519);
        assert_eq!(key.comment(), "");
        assert!(!key.is_encrypted());
    }

    #[test]
    fn test_generate_ssh_custom_rsa_profile() {
        let config = GenerateConfig::Options(GenerateOptions {
            algorithm: Some("rsa".to_string()),
            bits: Some(2048),
            comment: Some("deploy@example.com".to_string()),
            ..Default::default()
        });
        let key = parse_ssh(&config);
        assert!(matches!(key.algorithm(), SshAlgorithm::Rsa { .. }));
        assert_eq!(key.comment(), "deploy@example.com");
        let SshKeypairData::Rsa(keypair) = key.key_data() else {
            panic!("expected RSA keypair");
        };
        let bits = keypair
            .public
            .n
            .as_positive_bytes()
            .map_or(0, |modulus| modulus.len() * 8);
        assert_eq!(bits, 2048);
    }

    #[test]
    fn test_generate_ssh_rejects_invalid_profiles() {
        for config in [
            GenerateConfig::Options(GenerateOptions {
                algorithm: Some("ecdsa".to_string()),
                ..Default::default()
            }),
            GenerateConfig::Options(GenerateOptions {
                algorithm: Some("ed25519".to_string()),
                bits: Some(3072),
                ..Default::default()
            }),
            GenerateConfig::Options(GenerateOptions {
                algorithm: Some("rsa".to_string()),
                bits: Some(1024),
                ..Default::default()
            }),
            GenerateConfig::Options(GenerateOptions {
                comment: Some("bad\ncomment".to_string()),
                ..Default::default()
            }),
        ] {
            assert!(generate("ssh_private_key", &config).is_err());
        }
    }

    #[test]
    fn test_generate_ssh_uniqueness() {
        let first = parse_ssh(&GenerateConfig::Bool(true));
        let second = parse_ssh(&GenerateConfig::Bool(true));
        assert_ne!(first.public_key(), second.public_key());
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
