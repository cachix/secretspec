//! Secret value generation
//!
//! This module provides generation of secret values based on type and configuration.
//! Supported types: password, passphrase, mnemonic, hex, base64, uuid, command,
//! rsa_private_key, openpgp_private_key, ssh_private_key,
//! wireguard_private_key, jwk_private_key, age_identity, and (through the
//! binary identity generator) x509_identity.

use crate::SecretSpecError;
use crate::config::{
    GenerateConfig, JWK_RSA_DEFAULT_BITS, JWK_RSA_MAX_BITS, JWK_RSA_MIN_BITS,
    MNEMONIC_DEFAULT_WORDS, MNEMONIC_WORD_COUNTS, OPENPGP_RSA_DEFAULT_BITS, OPENPGP_RSA_MAX_BITS,
    OPENPGP_RSA_MIN_BITS, PASSPHRASE_DEFAULT_WORDS, PASSPHRASE_MAX_WORDS, PASSPHRASE_MIN_WORDS,
    SSH_RSA_DEFAULT_BITS, SSH_RSA_MAX_BITS, SSH_RSA_MIN_BITS,
};
use bip39::{Language, Mnemonic};
use data_encoding::{BASE64, BASE64URL_NOPAD, HEXLOWER};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pgp::composed::{
    ArmorOptions, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder,
};
use pgp::crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::types::{CompressionAlgorithm, KeyVersion};
use rand::RngExt;
use rand_08::RngCore as _;
use rand_08::rngs::OsRng as OsRng08;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use secrecy::SecretString;
use secrecy::zeroize::Zeroizing;
use smallvec::smallvec;
use ssh_key::private::{KeypairData as SshKeypairData, RsaKeypair as SshRsaKeypair};
use ssh_key::{
    Algorithm as SshAlgorithm, LineEnding as SshLineEnding, PrivateKey as SshPrivateKey,
};

/// Generate a secret value based on the secret type and generation config.
pub fn generate(secret_type: &str, config: &GenerateConfig) -> crate::Result<SecretString> {
    match secret_type {
        "password" => generate_password(config),
        "passphrase" => generate_passphrase(config),
        "mnemonic" => generate_mnemonic(config),
        "hex" => generate_hex(config),
        "base64" => generate_base64(config),
        "uuid" => generate_uuid(),
        "command" => generate_from_command(config),
        "rsa_private_key" => generate_rsa(config),
        "openpgp_private_key" => generate_openpgp(config),
        "ssh_private_key" => generate_ssh(config),
        "wireguard_private_key" => generate_wireguard(),
        "jwk_private_key" => generate_jwk(config),
        "age_identity" => generate_age_identity(),
        unknown => Err(SecretSpecError::GenerationFailed(format!(
            "unknown secret type '{}'",
            unknown
        ))),
    }
}

fn fill_os_random(bytes: &mut [u8], purpose: &str) -> crate::Result<()> {
    OsRng08.try_fill_bytes(bytes).map_err(|error| {
        SecretSpecError::GenerationFailed(format!(
            "operating-system randomness failed while generating {purpose}: {error}"
        ))
    })
}

fn protect_generated_string(value: String) -> SecretString {
    // Copy into an exactly sized protected allocation, then wipe the temporary
    // String. This avoids leaving a serialized private credential in a normal
    // String allocation after returning it to the caller.
    let value = Zeroizing::new(value);
    SecretString::new(value.as_str().into())
}

fn generate_passphrase(config: &GenerateConfig) -> crate::Result<SecretString> {
    let (words, separator) = match config {
        GenerateConfig::Bool(_) => (PASSPHRASE_DEFAULT_WORDS, "-"),
        GenerateConfig::Options(opts) => (
            opts.words.unwrap_or(PASSPHRASE_DEFAULT_WORDS),
            opts.separator.as_deref().unwrap_or("-"),
        ),
    };
    if !(PASSPHRASE_MIN_WORDS..=PASSPHRASE_MAX_WORDS).contains(&words) {
        return Err(SecretSpecError::GenerationFailed(format!(
            "passphrase generate.words must be between {PASSPHRASE_MIN_WORDS} and {PASSPHRASE_MAX_WORDS}"
        )));
    }
    if separator.is_empty() || separator.chars().any(char::is_control) {
        return Err(SecretSpecError::GenerationFailed(
            "passphrase generate.separator must be non-empty and contain no control characters"
                .to_string(),
        ));
    }

    // Seven independently selected BIP-39 English words provide 77 bits of
    // entropy by default. This is a passphrase, not a BIP-39 mnemonic: there
    // is deliberately no checksum or wallet-seed interpretation.
    let wordlist = Language::English.word_list();
    let mut entropy = Zeroizing::new(vec![0_u8; words * 2]);
    fill_os_random(&mut entropy, "passphrase")?;
    let value = entropy
        .chunks_exact(2)
        // The word list has 2048 entries, which divides the 16-bit input
        // domain exactly, so this reduction introduces no modulo bias.
        .map(|bytes| {
            let index = usize::from(u16::from_le_bytes([bytes[0], bytes[1]])) % wordlist.len();
            wordlist[index]
        })
        .collect::<Vec<_>>()
        .join(separator);
    Ok(protect_generated_string(value))
}

fn generate_mnemonic(config: &GenerateConfig) -> crate::Result<SecretString> {
    let (algorithm, words, language) = match config {
        GenerateConfig::Bool(_) => ("bip39", MNEMONIC_DEFAULT_WORDS, "english"),
        GenerateConfig::Options(opts) => (
            opts.algorithm.as_deref().unwrap_or("bip39"),
            opts.words.unwrap_or(MNEMONIC_DEFAULT_WORDS),
            opts.language.as_deref().unwrap_or("english"),
        ),
    };
    if algorithm != "bip39" {
        return Err(SecretSpecError::GenerationFailed(format!(
            "unknown mnemonic algorithm '{algorithm}'; expected 'bip39'"
        )));
    }
    if language != "english" {
        return Err(SecretSpecError::GenerationFailed(format!(
            "unknown mnemonic language '{language}'; expected 'english'"
        )));
    }
    if !MNEMONIC_WORD_COUNTS.contains(&words) {
        return Err(SecretSpecError::GenerationFailed(
            "mnemonic generate.words must be one of 12, 15, 18, 21, or 24".to_string(),
        ));
    }

    // BIP-39 maps these word counts to 128, 160, 192, 224, or 256 bits of
    // entropy respectively, then appends the checksum encoded by Mnemonic.
    let mut entropy = Zeroizing::new(vec![0_u8; (words / 3) * 4]);
    fill_os_random(&mut entropy, "BIP-39 mnemonic")?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).map_err(|error| {
        SecretSpecError::GenerationFailed(format!("failed to encode BIP-39 mnemonic: {error}"))
    })?;
    Ok(protect_generated_string(mnemonic.to_string()))
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

/// Generates the Base64-encoded, clamped Curve25519 scalar accepted by
/// `wg(8)` as a WireGuard private key.
fn generate_wireguard() -> crate::Result<SecretString> {
    let mut key = Zeroizing::new([0_u8; 32]);
    fill_os_random(&mut key[..], "WireGuard private key")?;
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    Ok(protect_generated_string(BASE64.encode(&*key)))
}

fn jwk_base64(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

fn jwk_integer(bytes: &[u8]) -> String {
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    if first_nonzero == bytes.len() {
        jwk_base64(&[0])
    } else {
        jwk_base64(&bytes[first_nonzero..])
    }
}

#[derive(serde::Serialize)]
struct OkpPrivateJwk<'a> {
    kty: &'static str,
    crv: &'static str,
    alg: &'static str,
    #[serde(rename = "use")]
    usage: &'static str,
    key_ops: [&'static str; 1],
    x: String,
    d: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct EcPrivateJwk<'a> {
    kty: &'static str,
    crv: &'static str,
    alg: &'static str,
    #[serde(rename = "use")]
    usage: &'static str,
    key_ops: [&'static str; 1],
    x: String,
    y: String,
    d: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct RsaPrivateJwk<'a> {
    kty: &'static str,
    alg: &'static str,
    #[serde(rename = "use")]
    usage: &'static str,
    key_ops: [&'static str; 1],
    n: String,
    e: String,
    d: &'a str,
    p: &'a str,
    q: &'a str,
    dp: &'a str,
    dq: &'a str,
    qi: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

/// Generates a private signing JWK. The output includes its public parameters
/// so it can be consumed directly by ordinary JOSE libraries.
fn generate_jwk(config: &GenerateConfig) -> crate::Result<SecretString> {
    let opts = match config {
        GenerateConfig::Bool(_) => None,
        GenerateConfig::Options(opts) => Some(opts),
    };
    let algorithm = opts
        .and_then(|options| options.algorithm.as_deref())
        .unwrap_or("ed25519");
    let kid = opts.and_then(|options| options.kid.as_deref());
    if kid.is_some_and(|kid| kid.trim().is_empty() || kid.chars().any(char::is_control)) {
        return Err(SecretSpecError::GenerationFailed(
            "JWK generate.kid must be non-empty and contain no control characters".to_string(),
        ));
    }

    let encoded = match algorithm {
        "ed25519" => {
            if opts.is_some_and(|options| options.bits.is_some()) {
                return Err(SecretSpecError::GenerationFailed(
                    "generate.bits is only valid when generate.algorithm = \"rsa\"".to_string(),
                ));
            }
            let signing = ed25519_dalek::SigningKey::generate(&mut OsRng08);
            let private = Zeroizing::new(jwk_base64(&signing.to_bytes()));
            serde_json::to_string(&OkpPrivateJwk {
                kty: "OKP",
                crv: "Ed25519",
                // RFC 9864 deprecates the polymorphic `EdDSA` identifier.
                alg: "Ed25519",
                usage: "sig",
                key_ops: ["sign"],
                x: jwk_base64(signing.verifying_key().as_bytes()),
                d: private.as_str(),
                kid,
            })
        }
        "p256" => {
            if opts.is_some_and(|options| options.bits.is_some()) {
                return Err(SecretSpecError::GenerationFailed(
                    "generate.bits is only valid when generate.algorithm = \"rsa\"".to_string(),
                ));
            }
            let secret = p256::SecretKey::random(&mut OsRng08);
            let point = secret.public_key().to_encoded_point(false);
            let (x, y) = point.x().zip(point.y()).ok_or_else(|| {
                SecretSpecError::GenerationFailed(
                    "generated P-256 JSON Web Key has no affine coordinates".to_string(),
                )
            })?;
            let private = Zeroizing::new(jwk_base64(&secret.to_bytes()));
            serde_json::to_string(&EcPrivateJwk {
                kty: "EC",
                crv: "P-256",
                alg: "ES256",
                usage: "sig",
                key_ops: ["sign"],
                x: jwk_base64(x),
                y: jwk_base64(y),
                d: private.as_str(),
                kid,
            })
        }
        "rsa" => {
            let bits = opts
                .and_then(|options| options.bits)
                .unwrap_or(JWK_RSA_DEFAULT_BITS);
            if !(JWK_RSA_MIN_BITS..=JWK_RSA_MAX_BITS).contains(&bits) {
                return Err(SecretSpecError::GenerationFailed(
                    "JWK RSA generate.bits must be between 2048 and 8192".to_string(),
                ));
            }
            let mut key =
                RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).map_err(|error| {
                    SecretSpecError::GenerationFailed(format!(
                        "failed to generate RSA JSON Web Key: {error}"
                    ))
                })?;
            key.precompute().map_err(|error| {
                SecretSpecError::GenerationFailed(format!(
                    "failed to compute RSA JSON Web Key parameters: {error}"
                ))
            })?;
            let primes = key.primes();
            let (p, q) = primes.first().zip(primes.get(1)).ok_or_else(|| {
                SecretSpecError::GenerationFailed(
                    "generated RSA JSON Web Key has fewer than two primes".to_string(),
                )
            })?;
            let dp = key.dp().ok_or_else(|| {
                SecretSpecError::GenerationFailed(
                    "generated RSA JSON Web Key has no first CRT exponent".to_string(),
                )
            })?;
            let dq = key.dq().ok_or_else(|| {
                SecretSpecError::GenerationFailed(
                    "generated RSA JSON Web Key has no second CRT exponent".to_string(),
                )
            })?;
            let qi = key
                .qinv()
                .ok_or_else(|| {
                    SecretSpecError::GenerationFailed(
                        "generated RSA JSON Web Key has no CRT coefficient".to_string(),
                    )
                })?
                .to_biguint()
                .ok_or_else(|| {
                    SecretSpecError::GenerationFailed(
                        "failed to encode RSA JSON Web Key q inverse".to_string(),
                    )
                })?;
            let d = Zeroizing::new(jwk_integer(&key.d().to_bytes_be()));
            let p = Zeroizing::new(jwk_integer(&p.to_bytes_be()));
            let q = Zeroizing::new(jwk_integer(&q.to_bytes_be()));
            let dp = Zeroizing::new(jwk_integer(&dp.to_bytes_be()));
            let dq = Zeroizing::new(jwk_integer(&dq.to_bytes_be()));
            let qi = Zeroizing::new(jwk_integer(&qi.to_bytes_be()));
            serde_json::to_string(&RsaPrivateJwk {
                kty: "RSA",
                alg: "RS256",
                usage: "sig",
                key_ops: ["sign"],
                n: jwk_integer(&key.n().to_bytes_be()),
                e: jwk_integer(&key.e().to_bytes_be()),
                d: d.as_str(),
                p: p.as_str(),
                q: q.as_str(),
                dp: dp.as_str(),
                dq: dq.as_str(),
                qi: qi.as_str(),
                kid,
            })
        }
        algorithm => {
            return Err(SecretSpecError::GenerationFailed(format!(
                "unknown JWK algorithm '{algorithm}'; expected `ed25519`, `p256`, or `rsa`"
            )));
        }
    }
    .map_err(|error| {
        SecretSpecError::GenerationFailed(format!("failed to encode JSON Web Key: {error}"))
    })?;
    Ok(protect_generated_string(encoded))
}

fn generate_age_identity() -> crate::Result<SecretString> {
    let mut scalar = Zeroizing::new([0_u8; 32]);
    fill_os_random(&mut scalar[..], "age identity")?;
    let secret = x25519_dalek::StaticSecret::from(*scalar);
    let hrp = bech32::Hrp::parse("AGE-SECRET-KEY-").map_err(|error| {
        SecretSpecError::GenerationFailed(format!("failed to configure age identity: {error}"))
    })?;
    let encoded = bech32::encode::<bech32::Bech32>(hrp, secret.as_bytes())
        .map_err(|error| {
            SecretSpecError::GenerationFailed(format!("failed to encode age identity: {error}"))
        })?
        .to_uppercase();
    Ok(protect_generated_string(encoded))
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
        .generate(OsRng08)
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

    let mut rng = OsRng08;
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
    fn test_generate_passphrase_default_and_custom_separator() {
        let value = generate("passphrase", &GenerateConfig::Bool(true)).unwrap();
        let words = value.expose_secret().split('-').collect::<Vec<_>>();
        assert_eq!(words.len(), PASSPHRASE_DEFAULT_WORDS);
        assert!(
            words
                .iter()
                .all(|word| Language::English.word_list().contains(word))
        );

        let custom = generate(
            "passphrase",
            &GenerateConfig::Options(GenerateOptions {
                words: Some(8),
                separator: Some(".".to_string()),
                ..Default::default()
            }),
        )
        .unwrap();
        assert_eq!(custom.expose_secret().split('.').count(), 8);
    }

    #[test]
    fn test_generate_passphrase_rejects_unsafe_options() {
        for config in [
            GenerateOptions {
                words: Some(5),
                ..Default::default()
            },
            GenerateOptions {
                separator: Some(String::new()),
                ..Default::default()
            },
            GenerateOptions {
                separator: Some("\n".to_string()),
                ..Default::default()
            },
        ] {
            assert!(generate("passphrase", &GenerateConfig::Options(config)).is_err());
        }
    }

    #[test]
    fn test_generate_mnemonic_default_is_valid_bip39() {
        let first = generate("mnemonic", &GenerateConfig::Bool(true)).unwrap();
        let second = generate("mnemonic", &GenerateConfig::Bool(true)).unwrap();
        assert_ne!(first.expose_secret(), second.expose_secret());

        let parsed = Mnemonic::parse_in_normalized(Language::English, first.expose_secret())
            .expect("generated mnemonic must have a valid BIP-39 checksum");
        assert_eq!(parsed.word_count(), MNEMONIC_DEFAULT_WORDS);
    }

    #[test]
    fn test_generate_mnemonic_supports_every_bip39_word_count() {
        for &words in MNEMONIC_WORD_COUNTS {
            let value = generate(
                "mnemonic",
                &GenerateConfig::Options(GenerateOptions {
                    algorithm: Some("bip39".to_string()),
                    words: Some(words),
                    language: Some("english".to_string()),
                    ..Default::default()
                }),
            )
            .unwrap();
            let parsed = Mnemonic::parse_in_normalized(Language::English, value.expose_secret())
                .expect("generated mnemonic must have a valid BIP-39 checksum");
            assert_eq!(parsed.word_count(), words);
        }
    }

    #[test]
    fn test_generate_mnemonic_rejects_invalid_options() {
        for config in [
            GenerateOptions {
                words: Some(13),
                ..Default::default()
            },
            GenerateOptions {
                algorithm: Some("electrum".to_string()),
                ..Default::default()
            },
            GenerateOptions {
                language: Some("spanish".to_string()),
                ..Default::default()
            },
        ] {
            assert!(generate("mnemonic", &GenerateConfig::Options(config)).is_err());
        }
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

    #[test]
    fn test_generate_wireguard_private_key() {
        let first = generate("wireguard_private_key", &GenerateConfig::Bool(true)).unwrap();
        let second = generate("wireguard_private_key", &GenerateConfig::Bool(true)).unwrap();
        let decoded = BASE64.decode(first.expose_secret().as_bytes()).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded[0] & 7, 0);
        assert_eq!(decoded[31] & 0x80, 0);
        assert_eq!(decoded[31] & 0x40, 0x40);
        assert_ne!(first.expose_secret(), second.expose_secret());
    }

    fn parse_jwk(config: &GenerateConfig) -> serde_json::Value {
        let value = generate("jwk_private_key", config).unwrap();
        serde_json::from_str(value.expose_secret()).unwrap()
    }

    fn decode_jwk_field(jwk: &serde_json::Value, field: &str) -> Vec<u8> {
        BASE64URL_NOPAD
            .decode(jwk[field].as_str().unwrap().as_bytes())
            .unwrap()
    }

    #[test]
    fn test_generate_ed25519_private_jwk() {
        let jwk = parse_jwk(&GenerateConfig::Options(GenerateOptions {
            kid: Some("release-2026".to_string()),
            ..Default::default()
        }));
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "Ed25519");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["key_ops"], serde_json::json!(["sign"]));
        assert_eq!(jwk["kid"], "release-2026");

        let secret: [u8; 32] = decode_jwk_field(&jwk, "d").try_into().unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        assert_eq!(
            signing.verifying_key().as_bytes(),
            decode_jwk_field(&jwk, "x").as_slice()
        );
    }

    #[test]
    fn test_generate_p256_private_jwk() {
        let jwk = parse_jwk(&GenerateConfig::Options(GenerateOptions {
            algorithm: Some("p256".to_string()),
            ..Default::default()
        }));
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");

        let secret = p256::SecretKey::from_slice(&decode_jwk_field(&jwk, "d")).unwrap();
        let public = secret.public_key().to_encoded_point(false);
        assert_eq!(public.x().unwrap().as_slice(), decode_jwk_field(&jwk, "x"));
        assert_eq!(public.y().unwrap().as_slice(), decode_jwk_field(&jwk, "y"));
    }

    #[test]
    fn test_generate_rsa_private_jwk() {
        let jwk = parse_jwk(&GenerateConfig::Options(GenerateOptions {
            algorithm: Some("rsa".to_string()),
            bits: Some(2048),
            ..Default::default()
        }));
        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["alg"], "RS256");
        for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            assert!(!decode_jwk_field(&jwk, field).is_empty(), "{field}");
        }
        let mut key = RsaPrivateKey::from_components(
            rsa::BigUint::from_bytes_be(&decode_jwk_field(&jwk, "n")),
            rsa::BigUint::from_bytes_be(&decode_jwk_field(&jwk, "e")),
            rsa::BigUint::from_bytes_be(&decode_jwk_field(&jwk, "d")),
            vec![
                rsa::BigUint::from_bytes_be(&decode_jwk_field(&jwk, "p")),
                rsa::BigUint::from_bytes_be(&decode_jwk_field(&jwk, "q")),
            ],
        )
        .unwrap();
        key.validate().unwrap();
        key.precompute().unwrap();
        assert_eq!(jwk["dp"], jwk_integer(&key.dp().unwrap().to_bytes_be()));
        assert_eq!(jwk["dq"], jwk_integer(&key.dq().unwrap().to_bytes_be()));
        assert_eq!(
            jwk["qi"],
            jwk_integer(&key.qinv().unwrap().to_biguint().unwrap().to_bytes_be())
        );
    }

    #[test]
    fn test_generate_jwk_rejects_invalid_profiles() {
        for config in [
            GenerateOptions {
                algorithm: Some("ed25519".to_string()),
                bits: Some(3072),
                ..Default::default()
            },
            GenerateOptions {
                algorithm: Some("rsa".to_string()),
                bits: Some(1024),
                ..Default::default()
            },
            GenerateOptions {
                algorithm: Some("secp256k1".to_string()),
                ..Default::default()
            },
            GenerateOptions {
                kid: Some(" ".to_string()),
                ..Default::default()
            },
        ] {
            assert!(generate("jwk_private_key", &GenerateConfig::Options(config)).is_err());
        }
    }

    #[test]
    fn test_generate_age_identity() {
        let first = generate("age_identity", &GenerateConfig::Bool(true)).unwrap();
        let second = generate("age_identity", &GenerateConfig::Bool(true)).unwrap();
        assert!(first.expose_secret().starts_with("AGE-SECRET-KEY-1"));
        let (hrp, bytes) = bech32::decode(first.expose_secret()).unwrap();
        assert_eq!(hrp, bech32::Hrp::parse("AGE-SECRET-KEY-").unwrap());
        let secret = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(bytes).unwrap());
        assert_ne!(x25519_dalek::PublicKey::from(&secret).as_bytes(), &[0; 32]);
        #[cfg(feature = "age")]
        assert!(
            first
                .expose_secret()
                .parse::<age::x25519::Identity>()
                .is_ok()
        );
        assert_ne!(first.expose_secret(), second.expose_secret());
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
