//! X.509 identity generation, PKCS#12 decoding, and typed projections.
//!
//! An `x509_identity` is canonically a PKCS#12 archive holding one private key,
//! its leaf certificate, and an optional issuer chain. This module generates
//! such archives, opens stored ones (with the configured password or an empty
//! one, never guessing), validates them strictly, and projects them into the
//! `pkcs12`, `pkcs8_private_key`, `x509_certificate`, `x509_certificate_chain`,
//! and `x509_issuer_chain` targets of the type registry.

use crate::SecretSpecError;
use crate::config::{GenerateConfig, GenerateOptions};
use crate::typed::{Format, Projection};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509NameBuilder};
use secrecy::zeroize::Zeroizing;
use secrecy::{SecretSlice, SecretString};
use std::cmp::Ordering;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_IDENTITY_BYTES: usize = 10 * 1024 * 1024;
const MAX_CHAIN_CERTIFICATES: usize = 16;
// Current CA/Browser Forum TLS Baseline Requirements cap publicly trusted
// subscriber certificates at 200 days (effective 2026-03-15). Self-signed
// development certificates are outside that policy, but using the same ceiling
// keeps generated lifetimes conservative.
const MAX_VALID_DAYS: u32 = 200;
const PFX_ITERATIONS: u32 = 100_000;
const FRIENDLY_NAME: &str = "SecretSpec X.509 identity";

/// A value projected from an identity: PEM text or DER/PFX bytes.
pub(crate) enum ProjectedValue {
    Text(SecretString),
    Binary(SecretSlice<u8>),
}

fn generation_failed(context: &str, error: impl std::fmt::Display) -> SecretSpecError {
    SecretSpecError::GenerationFailed(format!("{context}: {error}"))
}

fn decode_failed(name: &str, error: impl std::fmt::Display) -> SecretSpecError {
    SecretSpecError::DecodeFailed {
        name: name.to_string(),
        encoding: "pkcs12",
        reason: error.to_string(),
    }
}

/// The first reason in an OpenSSL error stack, without the library, function,
/// and file context of the full stack, which can echo caller-supplied data.
fn short_reason(error: &ErrorStack) -> String {
    error
        .errors()
        .first()
        .and_then(|error| error.reason())
        .unwrap_or("malformed data")
        .to_string()
}

pub(crate) fn parse_valid_days(value: Option<&str>) -> Result<u32, String> {
    let value = value.unwrap_or("30d");
    let days = value
        .strip_suffix('d')
        .ok_or_else(|| {
            "generate.valid_for must be a whole number of days such as `30d`".to_string()
        })?
        .parse::<u32>()
        .map_err(|_| {
            "generate.valid_for must be a whole number of days such as `30d`".to_string()
        })?;
    if !(1..=MAX_VALID_DAYS).contains(&days) {
        return Err(format!(
            "X.509 generate.valid_for must be between 1d and {MAX_VALID_DAYS}d"
        ));
    }
    Ok(days)
}

pub(crate) fn validate_san(value: &str) -> Result<(), String> {
    if let Some(dns) = value.strip_prefix("dns:") {
        validate_dns_name(dns)
    } else if let Some(ip) = value.strip_prefix("ip:") {
        ip.parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| format!("invalid X.509 IP SAN `{value}`"))
    } else {
        Err(format!(
            "invalid X.509 SAN `{value}`; expected `dns:name` or `ip:address`"
        ))
    }
}

fn validate_dns_name(name: &str) -> Result<(), String> {
    let ordinary = name.strip_prefix("*.").unwrap_or(name);
    if ordinary.is_empty()
        || ordinary.len() > 253
        || !ordinary.is_ascii()
        || ordinary.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(format!("invalid X.509 DNS SAN `dns:{name}`"));
    }
    Ok(())
}

fn options(config: &GenerateConfig) -> Result<&GenerateOptions, SecretSpecError> {
    match config {
        GenerateConfig::Options(options) => Ok(options),
        GenerateConfig::Bool(_) => Err(SecretSpecError::GenerationFailed(
            "type = \"x509_identity\" requires generate = { san = [\"dns:localhost\"] }"
                .to_string(),
        )),
    }
}

/// Serialize an identity as a PKCS#12 archive using one explicit modern
/// profile: PBES2/PBKDF2 with HMAC-SHA-256, AES-256-CBC for key and
/// certificate privacy, and HMAC-SHA-256 integrity, each with a fixed high
/// iteration count. Never RC2, 3DES, or SHA-1, whatever OpenSSL's platform
/// default is. An empty password yields an interchange container, not a
/// security boundary; the caller decides which it needs.
fn build_archive(
    key: &PKey<Private>,
    certificate: &X509,
    chain: &[X509],
    password: &str,
) -> Result<SecretSlice<u8>, ErrorStack> {
    let mut builder = Pkcs12::builder();
    builder
        .name(FRIENDLY_NAME)
        .pkey(key)
        .cert(certificate)
        .key_algorithm(Nid::AES_256_CBC)
        .cert_algorithm(Nid::AES_256_CBC)
        .key_iter(PFX_ITERATIONS)
        .mac_iter(PFX_ITERATIONS)
        .mac_md(MessageDigest::sha256());
    if !chain.is_empty() {
        let mut issuers = Stack::new()?;
        for issuer in chain {
            issuers.push(issuer.clone())?;
        }
        builder.ca(issuers);
    }
    let archive = builder.build2(password)?;
    let der = Zeroizing::new(archive.to_der()?);
    Ok(der.as_slice().to_vec().into())
}

pub(crate) fn generate(config: &GenerateConfig) -> crate::Result<SecretSlice<u8>> {
    let options = options(config)?;
    let valid_days = parse_valid_days(options.valid_for.as_deref())
        .map_err(SecretSpecError::GenerationFailed)?;
    let sans = options.san.as_deref().ok_or_else(|| {
        SecretSpecError::GenerationFailed("X.509 generation requires generate.san".to_string())
    })?;
    for san in sans {
        validate_san(san).map_err(SecretSpecError::GenerationFailed)?;
    }

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|error| generation_failed("failed to select P-256", error))?;
    let ec_key = EcKey::generate(&group)
        .map_err(|error| generation_failed("failed to generate P-256 private key", error))?;
    let private_key = PKey::from_ec_key(ec_key)
        .map_err(|error| generation_failed("failed to prepare P-256 private key", error))?;

    let common_name = sans
        .iter()
        .find_map(|san| san.strip_prefix("dns:"))
        .filter(|name| name.len() <= 64)
        .unwrap_or("SecretSpec generated identity");
    let mut subject = X509NameBuilder::new()
        .map_err(|error| generation_failed("failed to create X.509 subject", error))?;
    subject
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .map_err(|error| generation_failed("failed to set X.509 common name", error))?;
    let subject = subject.build();

    let mut serial = BigNum::new()
        .map_err(|error| generation_failed("failed to allocate X.509 serial", error))?;
    serial
        .rand(128, MsbOption::ONE, false)
        .map_err(|error| generation_failed("failed to generate X.509 serial", error))?;
    let serial = Asn1Integer::from_bn(&serial)
        .map_err(|error| generation_failed("failed to encode X.509 serial", error))?;

    let mut certificate = X509::builder()
        .map_err(|error| generation_failed("failed to create X.509 certificate", error))?;
    certificate
        .set_version(2)
        .and_then(|_| certificate.set_serial_number(&serial))
        .and_then(|_| certificate.set_subject_name(&subject))
        .and_then(|_| certificate.set_issuer_name(&subject))
        .and_then(|_| certificate.set_pubkey(&private_key))
        .map_err(|error| generation_failed("failed to initialize X.509 certificate", error))?;
    // A small backdate tolerates clock skew between the generating machine and
    // a local TLS peer without extending the requested total validity period.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| generation_failed("system clock is before the Unix epoch", error))?
        .as_secs();
    let not_before_unix = now.saturating_sub(300);
    let not_after_unix = not_before_unix + u64::from(valid_days) * 86_400;
    let not_before = Asn1Time::from_unix(not_before_unix as i64)
        .map_err(|error| generation_failed("failed to set X.509 start time", error))?;
    let not_after = Asn1Time::from_unix(not_after_unix as i64)
        .map_err(|error| generation_failed("failed to set X.509 expiry", error))?;
    certificate
        .set_not_before(&not_before)
        .and_then(|_| certificate.set_not_after(&not_after))
        .map_err(|error| generation_failed("failed to set X.509 validity", error))?;

    let basic_constraints = BasicConstraints::new()
        .critical()
        .build()
        .map_err(|error| generation_failed("failed to build basic constraints", error))?;
    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .map_err(|error| generation_failed("failed to build key usage", error))?;
    certificate
        .append_extension(basic_constraints)
        .and_then(|_| certificate.append_extension(key_usage))
        .map_err(|error| generation_failed("failed to add X.509 key constraints", error))?;

    let default_usages = ["server_auth".to_string()];
    let usages = options.usages.as_deref().unwrap_or(&default_usages);
    let mut extended = ExtendedKeyUsage::new();
    for usage in usages {
        match usage.as_str() {
            "server_auth" => {
                extended.server_auth();
            }
            "client_auth" => {
                extended.client_auth();
            }
            _ => unreachable!("generation options are validated before generation"),
        }
    }
    certificate
        .append_extension(
            extended
                .build()
                .map_err(|error| generation_failed("failed to build extended key usage", error))?,
        )
        .map_err(|error| generation_failed("failed to add extended key usage", error))?;

    let mut san_extension = SubjectAlternativeName::new();
    for san in sans {
        if let Some(dns) = san.strip_prefix("dns:") {
            san_extension.dns(dns);
        } else if let Some(ip) = san.strip_prefix("ip:") {
            san_extension.ip(ip);
        }
    }
    {
        let context = certificate.x509v3_context(None, None);
        let san = san_extension.build(&context).map_err(|error| {
            generation_failed("failed to build subject alternative names", error)
        })?;
        let subject_key = SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(|error| generation_failed("failed to build subject key identifier", error))?;
        certificate
            .append_extension(san)
            .and_then(|_| certificate.append_extension(subject_key))
            .map_err(|error| generation_failed("failed to add X.509 extensions", error))?;
    }
    certificate
        .sign(&private_key, MessageDigest::sha256())
        .map_err(|error| generation_failed("failed to sign X.509 certificate", error))?;
    let certificate = certificate.build();

    // The canonical stored archive uses an empty password on purpose: the
    // provider protects the identity at rest, and a consumer that needs a
    // protected PFX derives one with `type = "pkcs12"` and its own password.
    build_archive(&private_key, &certificate, &[], "")
        .map_err(|error| generation_failed("failed to build PKCS#12 identity", error))
}

/// A decoded and validated identity: the private key, its leaf certificate,
/// and the issuer chain in leaf-to-root order.
pub(crate) struct Identity {
    key: PKey<Private>,
    certificate: X509,
    chain: Vec<X509>,
}

impl std::fmt::Debug for Identity {
    /// Never prints key or certificate material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Open a PKCS#12 archive with the configured password, or the empty
    /// password when none is configured. There is no fallback between the
    /// two: a protected archive without a bound password fails, and so does a
    /// wrong password.
    pub(crate) fn decode(bytes: &[u8], password: Option<&str>, name: &str) -> crate::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_IDENTITY_BYTES {
            return Err(decode_failed(
                name,
                format!("PKCS#12 identity must be between 1 and {MAX_IDENTITY_BYTES} bytes"),
            ));
        }
        let archive = Pkcs12::from_der(bytes).map_err(|error| {
            decode_failed(
                name,
                format!("invalid PKCS#12 identity: {}", short_reason(&error)),
            )
        })?;
        let archive = archive
            .parse2(password.unwrap_or(""))
            .map_err(|_| {
                decode_failed(
                    name,
                    if password.is_some() {
                        "PKCS#12 identity could not be opened with the configured password"
                    } else {
                        "PKCS#12 identity could not be opened with an empty password; bind its password with `credentials = { password = \"...\" }` if the archive is protected"
                    },
                )
            })?;
        let key = archive
            .pkey
            .ok_or_else(|| decode_failed(name, "PKCS#12 identity has no private key"))?;
        let certificate = archive
            .cert
            .ok_or_else(|| decode_failed(name, "PKCS#12 identity has no leaf certificate"))?;
        let mut remaining: Vec<X509> = archive
            .ca
            .map(|certificates| {
                certificates
                    .into_iter()
                    .map(|cert| cert.to_owned())
                    .collect()
            })
            .unwrap_or_default();
        if remaining.len() > MAX_CHAIN_CERTIFICATES {
            return Err(decode_failed(
                name,
                format!(
                    "PKCS#12 identity has more than {MAX_CHAIN_CERTIFICATES} chain certificates"
                ),
            ));
        }
        let certificate_key = certificate.public_key().map_err(|error| {
            decode_failed(
                name,
                format!("leaf certificate has no usable public key: {error}"),
            )
        })?;
        if !certificate_key.public_eq(&key) {
            return Err(decode_failed(
                name,
                "leaf certificate does not match the private key",
            ));
        }

        let now = Asn1Time::days_from_now(0).map_err(|error| {
            decode_failed(name, format!("failed to read current time: {error}"))
        })?;
        if certificate
            .not_before()
            .compare(&now)
            .map_err(|error| decode_failed(name, error))?
            == Ordering::Greater
        {
            return Err(decode_failed(name, "leaf certificate is not valid yet"));
        }
        if certificate
            .not_after()
            .compare(&now)
            .map_err(|error| decode_failed(name, error))?
            == Ordering::Less
        {
            return Err(decode_failed(name, "leaf certificate has expired"));
        }

        for chain_certificate in &remaining {
            if chain_certificate
                .not_before()
                .compare(&now)
                .map_err(|error| decode_failed(name, error))?
                == Ordering::Greater
                || chain_certificate
                    .not_after()
                    .compare(&now)
                    .map_err(|error| decode_failed(name, error))?
                    == Ordering::Less
            {
                return Err(decode_failed(
                    name,
                    "PKCS#12 certificate chain contains a certificate outside its validity period",
                ));
            }
        }

        // Certificate bags in PKCS#12 are a set, not an ordered chain.
        // Reconstruct the leaf-to-root order by issuer/subject name and verify
        // every signature; reject unrelated or ambiguous bags instead of
        // silently exporting them.
        let mut chain = Vec::with_capacity(remaining.len());
        let mut child = certificate.clone();
        while !remaining.is_empty() {
            let child_issuer = child
                .issuer_name()
                .to_der()
                .map_err(|error| decode_failed(name, error))?;
            let mut matching = Vec::new();
            for (index, candidate) in remaining.iter().enumerate() {
                if candidate
                    .subject_name()
                    .to_der()
                    .map_err(|error| decode_failed(name, error))?
                    != child_issuer
                {
                    continue;
                }
                let issuer_key = candidate.public_key().map_err(|error| {
                    decode_failed(
                        name,
                        format!("chain certificate has no usable public key: {error}"),
                    )
                })?;
                if child.verify(&issuer_key).map_err(|error| {
                    decode_failed(name, format!("failed to verify certificate chain: {error}"))
                })? {
                    matching.push(index);
                }
            }
            if matching.len() != 1 {
                return Err(decode_failed(
                    name,
                    "PKCS#12 certificate bags do not form one unambiguous, coherent chain",
                ));
            }
            child = remaining.remove(matching[0]);
            chain.push(child.clone());
        }

        if certificate
            .issuer_name()
            .to_der()
            .and_then(|issuer| {
                certificate
                    .subject_name()
                    .to_der()
                    .map(|subject| issuer == subject)
            })
            .map_err(|error| decode_failed(name, error))?
        {
            let leaf_key = certificate.public_key().map_err(|error| {
                decode_failed(
                    name,
                    format!("leaf certificate has no usable public key: {error}"),
                )
            })?;
            if !certificate
                .verify(&leaf_key)
                .map_err(|error| decode_failed(name, error))?
            {
                return Err(decode_failed(
                    name,
                    "self-signed leaf certificate has an invalid signature",
                ));
            }
        }

        Ok(Self {
            key,
            certificate,
            chain,
        })
    }

    /// Number of issuer certificates behind the leaf.
    #[cfg(test)]
    pub(crate) fn chain_len(&self) -> usize {
        self.chain.len()
    }

    /// Repackage the identity as a PKCS#12 archive protected by `password`
    /// (empty when `None`), keeping the complete issuer chain.
    pub(crate) fn to_pkcs12(
        &self,
        password: Option<&str>,
        name: &str,
    ) -> crate::Result<SecretSlice<u8>> {
        build_archive(
            &self.key,
            &self.certificate,
            &self.chain,
            password.unwrap_or(""),
        )
        .map_err(|error| {
            decode_failed(
                name,
                format!("failed to build PKCS#12 archive: {}", short_reason(&error)),
            )
        })
    }

    /// Produce one registry target from this identity. `password` applies to
    /// [`Projection::Pkcs12`] only; `format` selects PEM or DER where the
    /// target offers both and defaults to PEM.
    pub(crate) fn project(
        &self,
        projection: Projection,
        format: Option<Format>,
        password: Option<&str>,
        name: &str,
    ) -> crate::Result<ProjectedValue> {
        let format = format.unwrap_or(Format::Pem);
        match projection {
            Projection::Pkcs12 => self.to_pkcs12(password, name).map(ProjectedValue::Binary),
            Projection::Pkcs8PrivateKey => match format {
                Format::Der => self
                    .key
                    .private_key_to_pkcs8()
                    .map(protected_binary)
                    .map(ProjectedValue::Binary)
                    .map_err(|error| {
                        decode_failed(name, format!("failed to encode PKCS#8 DER: {error}"))
                    }),
                Format::Pem => self
                    .key
                    .private_key_to_pem_pkcs8()
                    .map_err(|error| {
                        decode_failed(name, format!("failed to encode PKCS#8 PEM: {error}"))
                    })
                    .and_then(|bytes| protected_text(bytes, name))
                    .map(ProjectedValue::Text),
            },
            Projection::Certificate => match format {
                Format::Der => self
                    .certificate
                    .to_der()
                    .map(protected_binary)
                    .map(ProjectedValue::Binary)
                    .map_err(|error| {
                        decode_failed(name, format!("failed to encode certificate DER: {error}"))
                    }),
                Format::Pem => self
                    .certificate
                    .to_pem()
                    .map_err(|error| {
                        decode_failed(name, format!("failed to encode certificate PEM: {error}"))
                    })
                    .and_then(|bytes| protected_text(bytes, name))
                    .map(ProjectedValue::Text),
            },
            Projection::CertificateChain => {
                let mut pem = self.certificate.to_pem().map_err(|error| {
                    decode_failed(name, format!("failed to encode certificate PEM: {error}"))
                })?;
                pem.extend(self.issuer_pem(name)?);
                protected_text(pem, name).map(ProjectedValue::Text)
            }
            Projection::IssuerChain => {
                protected_text(self.issuer_pem(name)?, name).map(ProjectedValue::Text)
            }
        }
    }

    fn issuer_pem(&self, name: &str) -> crate::Result<Vec<u8>> {
        let mut pem = Vec::new();
        for certificate in &self.chain {
            pem.extend(certificate.to_pem().map_err(|error| {
                decode_failed(
                    name,
                    format!("failed to encode chain certificate PEM: {error}"),
                )
            })?);
        }
        Ok(pem)
    }
}

/// Validate a stored archive that no credential unlocks. Used where the value
/// is inspected without resolving its dependencies, such as `import`.
pub(crate) fn validate(bytes: &[u8], name: &str) -> crate::Result<()> {
    Identity::decode(bytes, None, name).map(|_| ())
}

fn protected_text(bytes: Vec<u8>, name: &str) -> crate::Result<SecretString> {
    let bytes = Zeroizing::new(bytes);
    let text = std::str::from_utf8(bytes.as_slice()).map_err(|error| {
        decode_failed(name, format!("OpenSSL produced invalid PEM text: {error}"))
    })?;
    Ok(SecretString::new(text.to_owned().into()))
}

fn protected_binary(bytes: Vec<u8>) -> SecretSlice<u8> {
    let bytes = Zeroizing::new(bytes);
    bytes.as_slice().to_vec().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GenerateOptions;
    use openssl::x509::X509Name;
    use secrecy::ExposeSecret;

    fn config() -> GenerateConfig {
        GenerateConfig::Options(GenerateOptions {
            algorithm: Some("p256".to_string()),
            san: Some(vec![
                "dns:localhost".to_string(),
                "ip:127.0.0.1".to_string(),
            ]),
            usages: Some(vec!["server_auth".to_string()]),
            valid_for: Some("30d".to_string()),
            ..Default::default()
        })
    }

    fn p256() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn name(common_name: &str) -> X509Name {
        let mut builder = X509NameBuilder::new().unwrap();
        builder
            .append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        builder.build()
    }

    /// A certificate for `subject`, signed by `issuer` (self-signed when
    /// `None`), valid from `not_before` to `not_after` seconds relative to now.
    fn certificate(
        subject: &str,
        key: &PKey<Private>,
        issuer: Option<(&PKey<Private>, &X509)>,
        ca: bool,
        not_before: i64,
        not_after: i64,
    ) -> X509 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let subject = name(subject);
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::ONE, false).unwrap();
        builder
            .set_serial_number(&Asn1Integer::from_bn(&serial).unwrap())
            .unwrap();
        builder.set_subject_name(&subject).unwrap();
        builder
            .set_issuer_name(issuer.map_or(&subject, |(_, cert)| cert.subject_name()))
            .unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(now + not_before).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(now + not_after).unwrap())
            .unwrap();
        let mut constraints = BasicConstraints::new();
        if ca {
            constraints.ca();
        }
        builder
            .append_extension(constraints.critical().build().unwrap())
            .unwrap();
        builder
            .sign(issuer.map_or(key, |(key, _)| key), MessageDigest::sha256())
            .unwrap();
        builder.build()
    }

    const DAY: i64 = 86_400;

    /// Root -> intermediate -> leaf, all currently valid.
    struct Chain {
        root: X509,
        intermediate: X509,
        leaf_key: PKey<Private>,
        leaf: X509,
    }

    fn chain() -> Chain {
        let root_key = p256();
        let root = certificate("Test Root", &root_key, None, true, -DAY, 365 * DAY);
        let intermediate_key = p256();
        let intermediate = certificate(
            "Test Intermediate",
            &intermediate_key,
            Some((&root_key, &root)),
            true,
            -DAY,
            180 * DAY,
        );
        let leaf_key = p256();
        let leaf = certificate(
            "leaf.example",
            &leaf_key,
            Some((&intermediate_key, &intermediate)),
            false,
            -DAY,
            30 * DAY,
        );
        Chain {
            root,
            intermediate,
            leaf_key,
            leaf,
        }
    }

    fn archive(key: &PKey<Private>, leaf: &X509, bags: &[X509], password: &str) -> Vec<u8> {
        build_archive(key, leaf, bags, password)
            .unwrap()
            .expose_secret()
            .to_vec()
    }

    #[test]
    fn generates_and_projects_a_matching_identity() {
        let identity = generate(&config()).unwrap();
        validate(identity.expose_secret(), "TLS_IDENTITY").unwrap();
        let identity = Identity::decode(identity.expose_secret(), None, "TLS_IDENTITY").unwrap();
        assert_eq!(identity.chain_len(), 0);

        let ProjectedValue::Text(key) = identity
            .project(Projection::Pkcs8PrivateKey, None, None, "TLS_KEY")
            .unwrap()
        else {
            panic!("expected PEM text")
        };
        assert!(
            key.expose_secret()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        let ProjectedValue::Binary(key_der) = identity
            .project(
                Projection::Pkcs8PrivateKey,
                Some(Format::Der),
                None,
                "TLS_KEY_DER",
            )
            .unwrap()
        else {
            panic!("expected DER bytes")
        };
        let from_der = PKey::private_key_from_pkcs8(key_der.expose_secret()).unwrap();
        assert!(from_der.public_eq(&identity.key));

        let ProjectedValue::Text(certificate) = identity
            .project(Projection::Certificate, None, None, "TLS_CERTIFICATE")
            .unwrap()
        else {
            panic!("expected PEM text")
        };
        assert!(
            certificate
                .expose_secret()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        let ProjectedValue::Text(chain) = identity
            .project(Projection::CertificateChain, None, None, "TLS_CHAIN")
            .unwrap()
        else {
            panic!("expected PEM text")
        };
        assert_eq!(
            chain.expose_secret(),
            certificate.expose_secret(),
            "a self-signed identity's chain is just its leaf"
        );
        let ProjectedValue::Text(issuers) = identity
            .project(Projection::IssuerChain, None, None, "TLS_ISSUERS")
            .unwrap()
        else {
            panic!("expected PEM text")
        };
        assert!(issuers.expose_secret().is_empty());
    }

    #[test]
    fn generation_uses_fallback_cn_for_long_valid_dns_san() {
        let long_dns = format!("{}.example.internal", "a".repeat(63));
        assert!(long_dns.len() > 64);
        let generated = generate(&GenerateConfig::Options(GenerateOptions {
            san: Some(vec![format!("dns:{long_dns}")]),
            ..Default::default()
        }))
        .unwrap();
        let identity = Identity::decode(generated.expose_secret(), None, "TLS_IDENTITY").unwrap();
        let common_name = identity
            .certificate
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .to_string()
            .unwrap();
        assert_eq!(common_name, "SecretSpec generated identity");
    }

    #[test]
    fn protected_archives_open_only_with_their_password() {
        let generated = generate(&config()).unwrap();
        let identity = Identity::decode(generated.expose_secret(), None, "ID").unwrap();
        let protected = identity
            .to_pkcs12(Some("correct horse battery staple"), "PFX")
            .unwrap();

        // The configured password opens it and the identity is intact.
        let reopened = Identity::decode(
            protected.expose_secret(),
            Some("correct horse battery staple"),
            "PFX",
        )
        .unwrap();
        assert!(reopened.key.public_eq(&identity.key));
        assert_eq!(
            reopened.certificate.to_der().unwrap(),
            identity.certificate.to_der().unwrap()
        );

        // Neither a wrong password nor a missing one falls back to guessing.
        let wrong = Identity::decode(protected.expose_secret(), Some("wrong"), "PFX")
            .unwrap_err()
            .to_string();
        assert!(wrong.contains("configured password"), "{wrong}");
        assert!(
            !wrong.contains("wrong"),
            "must not echo the password: {wrong}"
        );
        let missing = Identity::decode(protected.expose_secret(), None, "PFX")
            .unwrap_err()
            .to_string();
        assert!(missing.contains("empty password"), "{missing}");
        assert!(missing.contains("credentials"), "{missing}");

        // And a password is not accepted for an archive that has none.
        let unprotected = Identity::decode(generated.expose_secret(), Some("x"), "ID")
            .unwrap_err()
            .to_string();
        assert!(unprotected.contains("configured password"), "{unprotected}");
    }

    #[test]
    fn rewrapping_replaces_the_password_and_keeps_the_chain() {
        let chain = chain();
        let legacy = archive(
            &chain.leaf_key,
            &chain.leaf,
            &[chain.intermediate.clone(), chain.root.clone()],
            "legacy",
        );
        let identity = Identity::decode(&legacy, Some("legacy"), "LEGACY").unwrap();
        assert_eq!(identity.chain_len(), 2);

        let rewrapped = identity.to_pkcs12(Some("fresh"), "NEW").unwrap();
        assert!(Identity::decode(rewrapped.expose_secret(), Some("legacy"), "NEW").is_err());
        let reopened = Identity::decode(rewrapped.expose_secret(), Some("fresh"), "NEW").unwrap();
        assert_eq!(reopened.chain_len(), 2);
        assert_eq!(
            reopened.chain[0].to_der().unwrap(),
            chain.intermediate.to_der().unwrap()
        );
        assert_eq!(
            reopened.chain[1].to_der().unwrap(),
            chain.root.to_der().unwrap()
        );
    }

    #[test]
    fn unordered_bags_are_reconstructed_into_one_leaf_to_root_chain() {
        let chain = chain();
        // Root before intermediate: the bag order is not the chain order.
        let bytes = archive(
            &chain.leaf_key,
            &chain.leaf,
            &[chain.root.clone(), chain.intermediate.clone()],
            "",
        );
        let identity = Identity::decode(&bytes, None, "ID").unwrap();
        assert_eq!(
            identity
                .chain
                .iter()
                .map(|cert| cert.to_der().unwrap())
                .collect::<Vec<_>>(),
            vec![
                chain.intermediate.to_der().unwrap(),
                chain.root.to_der().unwrap()
            ]
        );

        let ProjectedValue::Text(full) = identity
            .project(Projection::CertificateChain, None, None, "CHAIN")
            .unwrap()
        else {
            panic!("expected PEM text")
        };
        let ProjectedValue::Text(issuers) = identity
            .project(Projection::IssuerChain, None, None, "ISSUERS")
            .unwrap()
        else {
            panic!("expected PEM text")
        };
        let leaf_pem = String::from_utf8(chain.leaf.to_pem().unwrap()).unwrap();
        let intermediate_pem = String::from_utf8(chain.intermediate.to_pem().unwrap()).unwrap();
        let root_pem = String::from_utf8(chain.root.to_pem().unwrap()).unwrap();
        assert_eq!(
            full.expose_secret(),
            format!("{leaf_pem}{intermediate_pem}{root_pem}")
        );
        assert_eq!(
            issuers.expose_secret(),
            format!("{intermediate_pem}{root_pem}")
        );
        assert_eq!(full.expose_secret().matches("BEGIN CERTIFICATE").count(), 3);
    }

    #[test]
    fn unrelated_duplicate_and_expired_chain_bags_are_rejected() {
        let chain = chain();

        let stranger_key = p256();
        let stranger = certificate("Stranger", &stranger_key, None, true, -DAY, DAY);
        let unrelated = archive(
            &chain.leaf_key,
            &chain.leaf,
            &[chain.intermediate.clone(), chain.root.clone(), stranger],
            "",
        );
        let error = Identity::decode(&unrelated, None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unambiguous, coherent chain"), "{error}");

        let duplicated = archive(
            &chain.leaf_key,
            &chain.leaf,
            &[
                chain.intermediate.clone(),
                chain.intermediate.clone(),
                chain.root.clone(),
            ],
            "",
        );
        let error = Identity::decode(&duplicated, None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unambiguous, coherent chain"), "{error}");

        let root_key = p256();
        let expired_root = certificate("Old Root", &root_key, None, true, -3 * DAY, -DAY);
        let leaf_key = p256();
        let leaf = certificate(
            "leaf.example",
            &leaf_key,
            Some((&root_key, &expired_root)),
            false,
            -DAY,
            DAY,
        );
        let expired_issuer = archive(&leaf_key, &leaf, &[expired_root], "");
        let error = Identity::decode(&expired_issuer, None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside its validity period"), "{error}");
    }

    #[test]
    fn leaf_validity_and_key_match_are_enforced() {
        let key = p256();
        let expired = certificate("expired.example", &key, None, false, -3 * DAY, -DAY);
        let error = Identity::decode(&archive(&key, &expired, &[], ""), None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("has expired"), "{error}");

        let future = certificate("future.example", &key, None, false, DAY, 3 * DAY);
        let error = Identity::decode(&archive(&key, &future, &[], ""), None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not valid yet"), "{error}");

        // OpenSSL's own builder refuses a leaf that does not match the key, so
        // a mismatched archive can only come from another tool; the decoder's
        // check stays as defense in depth and is exercised by the builder here.
        let other_key = p256();
        let mismatched = certificate("other.example", &other_key, None, false, -DAY, DAY);
        assert!(build_archive(&key, &mismatched, &[], "").is_err());
    }

    #[test]
    fn oversized_empty_and_overlong_chain_archives_are_rejected() {
        let empty = Identity::decode(&[], None, "ID").unwrap_err().to_string();
        assert!(empty.contains("between 1 and"), "{empty}");
        let huge = vec![0u8; MAX_IDENTITY_BYTES + 1];
        let oversized = Identity::decode(&huge, None, "ID").unwrap_err().to_string();
        assert!(oversized.contains("between 1 and"), "{oversized}");
        let garbage = Identity::decode(b"not a pfx", None, "ID")
            .unwrap_err()
            .to_string();
        assert!(garbage.contains("invalid PKCS#12 identity"), "{garbage}");

        // Seventeen issuer bags exceed the chain cap before any chain walk.
        let mut issuers = Vec::new();
        let mut parent: Option<(PKey<Private>, X509)> = None;
        for index in 0..=MAX_CHAIN_CERTIFICATES {
            let key = p256();
            let cert = certificate(
                &format!("CA {index}"),
                &key,
                parent.as_ref().map(|(key, cert)| (key, cert)),
                true,
                -DAY,
                DAY,
            );
            issuers.push(cert.clone());
            parent = Some((key, cert));
        }
        let (issuer_key, issuer) = parent.unwrap();
        let leaf_key = p256();
        let leaf = certificate(
            "leaf.example",
            &leaf_key,
            Some((&issuer_key, &issuer)),
            false,
            -DAY,
            DAY,
        );
        let error = Identity::decode(&archive(&leaf_key, &leaf, &issuers, ""), None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("more than 16 chain certificates"), "{error}");
    }

    #[test]
    fn validates_san_and_validity_bounds() {
        assert!(validate_san("dns:*.example.com").is_ok());
        assert!(validate_san("ip:::1").is_ok());
        assert!(validate_san("example.com").is_err());
        assert!(validate_san("dns:bad_name").is_err());
        assert!(parse_valid_days(Some("200d")).is_ok());
        assert!(parse_valid_days(Some("201d")).is_err());
    }
}
