//! X.509 identity generation, bag-preserving PKCS#12 decoding, and projections.
//! Rust certificate and archive APIs share the application's AWS-LC backend.

use crate::SecretSpecError;
use crate::config::{GenerateConfig, GenerateOptions};
use crate::typed::{Format, Projection};
use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm, Pkcs12Archive,
    PrivateKey, PrivateKeyChain,
};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType,
};
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, X509Certificate};

const MAX_IDENTITY_BYTES: usize = 10 * 1024 * 1024;
const MAX_CHAIN_CERTIFICATES: usize = 16;
const MAX_VALID_DAYS: u32 = 200;
const PFX_ITERATIONS: u32 = 100_000;
const FRIENDLY_NAME: &str = "SecretSpec X.509 identity";

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

/// Emit the same modern encryption and integrity profile on every platform.
fn build_archive(
    key: &[u8],
    certificate: &Certificate,
    chain: &[Certificate],
    password: &str,
) -> Result<SecretSlice<u8>, p12_keystore::error::Error> {
    let mut store = KeyStore::new();
    store.add_entry(
        FRIENDLY_NAME,
        KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
            "identity",
            PrivateKey::from_der(key)?,
            std::iter::once(certificate.clone()).chain(chain.iter().cloned()),
        )),
    );
    let der = Zeroizing::new(
        store
            .writer(password)
            .encryption_algorithm(EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
            .encryption_iterations(PFX_ITERATIONS)
            .mac_algorithm(MacAlgorithm::HmacSha256)
            .mac_iterations(PFX_ITERATIONS)
            .write()?,
    );
    Ok(der.as_slice().to_vec().into())
}

pub(crate) fn generate(config: &GenerateConfig) -> crate::Result<SecretSlice<u8>> {
    let options = options(config)?;
    let valid_days = parse_valid_days(options.valid_for.as_deref())
        .map_err(SecretSpecError::GenerationFailed)?;
    let sans = options
        .san
        .as_deref()
        .filter(|sans| !sans.is_empty())
        .ok_or_else(|| {
            SecretSpecError::GenerationFailed("X.509 generation requires generate.san".into())
        })?;
    let mut params = CertificateParams::default();
    for san in sans {
        validate_san(san).map_err(SecretSpecError::GenerationFailed)?;
        params
            .subject_alt_names
            .push(if let Some(dns) = san.strip_prefix("dns:") {
                SanType::DnsName(
                    dns.try_into()
                        .map_err(|error| generation_failed("invalid DNS SAN", error))?,
                )
            } else {
                SanType::IpAddress(
                    san.strip_prefix("ip:")
                        .expect("validated IP SAN")
                        .parse()
                        .expect("validated IP address"),
                )
            });
    }
    let common_name = sans
        .iter()
        .find_map(|san| san.strip_prefix("dns:"))
        .filter(|name| name.len() <= 64)
        .unwrap_or("SecretSpec generated identity");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let default_usages = ["server_auth".to_string()];
    for usage in options.usages.as_deref().unwrap_or(&default_usages) {
        params.extended_key_usages.push(match usage.as_str() {
            "server_auth" => ExtendedKeyUsagePurpose::ServerAuth,
            "client_auth" => ExtendedKeyUsagePurpose::ClientAuth,
            _ => {
                return Err(SecretSpecError::GenerationFailed(
                    "invalid X.509 extended key usage".into(),
                ));
            }
        });
    }
    let mut serial = [0u8; 16];
    use rand_08::RngCore;
    rand_08::rngs::OsRng
        .try_fill_bytes(&mut serial)
        .map_err(|error| generation_failed("failed to generate X.509 serial", error))?;
    serial[0] |= 0x80;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    params.not_before = OffsetDateTime::now_utc() - Duration::seconds(300);
    params.not_after = params.not_before + Duration::days(i64::from(valid_days));
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|error| generation_failed("failed to generate P-256 private key", error))?;
    let generated = params
        .self_signed(&key)
        .map_err(|error| generation_failed("failed to sign X.509 certificate", error))?;
    let certificate = Certificate::from_der(generated.der())
        .map_err(|error| generation_failed("failed to encode X.509 certificate", error))?;
    // Empty-password storage relies on the provider's protection. Consumers
    // derive a separately protected PKCS#12 archive when they need one.
    build_archive(key.serialized_der(), &certificate, &[], "")
        .map_err(|error| generation_failed("failed to build PKCS#12 identity", error))
}

pub(crate) struct Identity {
    key: SecretSlice<u8>,
    certificate: Certificate,
    chain: Vec<Certificate>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// x509-parser's dispatcher omits P-521 and some SHA-512 combinations.
/// Verify those with the same AWS-LC backend, without accepting a failed
/// signature under a different algorithm or ignoring its named curve.
fn signature_valid(
    certificate: &X509Certificate<'_>,
    issuer: Option<&x509_parser::x509::SubjectPublicKeyInfo<'_>>,
) -> bool {
    use aws_lc_rs::signature;
    if certificate.signature_algorithm != certificate.tbs_certificate.signature {
        return false;
    }
    match certificate.verify_signature(issuer) {
        Ok(()) => return true,
        Err(x509_parser::error::X509Error::SignatureUnsupportedAlgorithm) => {}
        Err(_) => return false,
    }
    let public_key = issuer.unwrap_or_else(|| certificate.public_key());
    if public_key.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1" {
        return false;
    }
    let Some(curve) = public_key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|value| value.as_oid().ok())
    else {
        return false;
    };
    let algorithm: &dyn signature::VerificationAlgorithm = match (
        curve.to_id_string().as_str(),
        certificate
            .signature_algorithm
            .algorithm
            .to_id_string()
            .as_str(),
    ) {
        ("1.2.840.10045.3.1.7", "1.2.840.10045.4.1") => &signature::ECDSA_P256_SHA1_ASN1,
        ("1.2.840.10045.3.1.7", "1.2.840.10045.4.3.4") => &signature::ECDSA_P256_SHA512_ASN1,
        ("1.3.132.0.34", "1.2.840.10045.4.3.4") => &signature::ECDSA_P384_SHA512_ASN1,
        ("1.3.132.0.35", "1.2.840.10045.4.1") => &signature::ECDSA_P521_SHA1_ASN1,
        ("1.3.132.0.35", "1.2.840.10045.4.3.1") => &signature::ECDSA_P521_SHA224_ASN1,
        ("1.3.132.0.35", "1.2.840.10045.4.3.2") => &signature::ECDSA_P521_SHA256_ASN1,
        ("1.3.132.0.35", "1.2.840.10045.4.3.3") => &signature::ECDSA_P521_SHA384_ASN1,
        ("1.3.132.0.35", "1.2.840.10045.4.3.4") => &signature::ECDSA_P521_SHA512_ASN1,
        _ => return false,
    };
    signature::UnparsedPublicKey::new(algorithm, public_key.subject_public_key.data.as_ref())
        .verify(
            certificate.tbs_certificate.as_ref(),
            certificate.signature_value.data.as_ref(),
        )
        .is_ok()
}

fn parsed_certificate<'a>(der: &'a [u8], name: &str) -> crate::Result<X509Certificate<'a>> {
    let (remaining, certificate) = X509Certificate::from_der(der)
        .map_err(|_| decode_failed(name, "invalid X.509 certificate"))?;
    if !remaining.is_empty() {
        return Err(decode_failed(name, "trailing data after X.509 certificate"));
    }
    Ok(certificate)
}

fn password_supported(password: Option<&str>, name: &str) -> crate::Result<()> {
    if let Some(password) = password {
        crate::typed::validate_credential_value("password", password).map_err(|reason| {
            SecretSpecError::CredentialInvalid {
                name: name.into(),
                role: "password".into(),
                reason,
            }
        })?;
    }
    Ok(())
}

impl Identity {
    /// MAC verification and decryption precede application key and chain checks.
    /// No alternate password, linking policy, or certificate filtering is used.
    pub(crate) fn decode(bytes: &[u8], password: Option<&str>, name: &str) -> crate::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_IDENTITY_BYTES {
            return Err(decode_failed(
                name,
                format!("PKCS#12 identity must be between 1 and {MAX_IDENTITY_BYTES} bytes"),
            ));
        }
        password_supported(password, name)?;
        let mut archive = Pkcs12Archive::from_pkcs12(bytes, password.unwrap_or(""))
            .map_err(|error| decode_failed(name, match error {
                p12_keystore::error::Error::DerError(_) | p12_keystore::error::Error::InvalidVersion =>
                    "invalid PKCS#12 identity",
                _ if password.is_some() => "PKCS#12 identity could not be opened with the configured password",
                _ => "PKCS#12 identity could not be opened with an empty password; bind its password with `credentials = { password = \"...\" }` if the archive is protected",
            }))?;
        if archive.keys.len() != 1 {
            return Err(decode_failed(
                name,
                "PKCS#12 identity must hold exactly one private key",
            ));
        }
        if archive.certs.len() > MAX_CHAIN_CERTIFICATES + 1 {
            return Err(decode_failed(
                name,
                format!(
                    "PKCS#12 identity has more than {MAX_CHAIN_CERTIFICATES} chain certificates"
                ),
            ));
        }
        let bag = archive.keys.pop().expect("exactly one private key");
        let key: SecretSlice<u8> = bag.key.as_der().to_vec().into();
        let public_key = KeyPair::try_from(key.expose_secret())
            .map_err(|_| decode_failed(name, "unsupported or invalid PKCS#8 private key; supported keys are RSA, P-256, P-384, P-521, and Ed25519"))?;
        let public_der = public_key.subject_public_key_info();
        let (_, expected_public) =
            x509_parser::x509::SubjectPublicKeyInfo::from_der(&public_der)
                .map_err(|_| decode_failed(name, "invalid private key public component"))?;
        let mut certificate_ders = std::collections::HashSet::new();
        for certificate in &archive.certs {
            if !certificate_ders.insert(certificate.cert.as_der()) {
                return Err(decode_failed(
                    name,
                    "duplicate certificate bags do not form one unambiguous, coherent chain",
                ));
            }
        }
        let mut matching = Vec::new();
        for (index, certificate) in archive.certs.iter().enumerate() {
            let parsed = parsed_certificate(certificate.cert.as_der(), name)?;
            if parsed.public_key().algorithm == expected_public.algorithm
                && parsed.public_key().subject_public_key == expected_public.subject_public_key
            {
                matching.push(index);
            }
        }
        // A CA and its leaf may reuse the same public key. The local key ID
        // identifies the leaf in that case, but never substitutes for matching
        // its actual public key or validating every remaining certificate bag.
        if matching.len() > 1
            && let Some(key_id) = &bag.local_key_id
        {
            matching.retain(|index| {
                archive.certs[*index].local_key_id.as_deref() == Some(key_id.as_ref())
            });
        }
        if matching.len() != 1 {
            return Err(decode_failed(
                name,
                "PKCS#12 identity must hold one leaf certificate that matches the private key",
            ));
        }
        let certificate = archive.certs.remove(matching[0]).cert;
        let mut remaining: Vec<Certificate> =
            archive.certs.into_iter().map(|bag| bag.cert).collect();
        let leaf = parsed_certificate(certificate.as_der(), name)?;
        let now = x509_parser::time::ASN1Time::now();
        if leaf.validity().not_before > now {
            return Err(decode_failed(name, "leaf certificate is not valid yet"));
        }
        if leaf.validity().not_after < now {
            return Err(decode_failed(name, "leaf certificate has expired"));
        }
        for issuer in &remaining {
            if !parsed_certificate(issuer.as_der(), name)?
                .validity()
                .is_valid_at(now)
            {
                return Err(decode_failed(
                    name,
                    "PKCS#12 certificate chain contains a certificate outside its validity period",
                ));
            }
        }
        let mut chain: Vec<Certificate> = Vec::with_capacity(remaining.len());
        while !remaining.is_empty() {
            let child = parsed_certificate(chain.last().unwrap_or(&certificate).as_der(), name)?;
            let mut matching = Vec::new();
            for (index, candidate) in remaining.iter().enumerate() {
                let issuer = parsed_certificate(candidate.as_der(), name)?;
                if issuer.subject() == child.issuer()
                    && signature_valid(&child, Some(issuer.public_key()))
                {
                    matching.push(index);
                }
            }
            if matching.len() != 1 {
                return Err(decode_failed(
                    name,
                    "PKCS#12 certificate bags do not form one unambiguous, coherent chain",
                ));
            }
            chain.push(remaining.remove(matching[0]));
        }
        if leaf.issuer() == leaf.subject() && !signature_valid(&leaf, None) {
            return Err(decode_failed(
                name,
                "self-signed leaf certificate has an invalid signature",
            ));
        }
        Ok(Self {
            key,
            certificate,
            chain,
        })
    }

    #[cfg(test)]
    pub(crate) fn chain_len(&self) -> usize {
        self.chain.len()
    }

    pub(crate) fn to_pkcs12(
        &self,
        password: Option<&str>,
        name: &str,
    ) -> crate::Result<SecretSlice<u8>> {
        password_supported(password, name)?;
        build_archive(
            self.key.expose_secret(),
            &self.certificate,
            &self.chain,
            password.unwrap_or(""),
        )
        .map_err(|_| decode_failed(name, "failed to build PKCS#12 archive"))
    }

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
                Format::Der => Ok(ProjectedValue::Binary(
                    self.key.expose_secret().to_vec().into(),
                )),
                Format::Pem => Ok(ProjectedValue::Text(secret_pem(
                    "PRIVATE KEY",
                    self.key.expose_secret(),
                ))),
            },
            Projection::Certificate => match format {
                Format::Der => Ok(ProjectedValue::Binary(
                    self.certificate.as_der().to_vec().into(),
                )),
                Format::Pem => Ok(ProjectedValue::Text(secret_pem(
                    "CERTIFICATE",
                    self.certificate.as_der(),
                ))),
            },
            Projection::CertificateChain | Projection::IssuerChain => {
                let mut output = Zeroizing::new(String::new());
                if projection == Projection::CertificateChain {
                    output.push_str(
                        secret_pem("CERTIFICATE", self.certificate.as_der()).expose_secret(),
                    );
                }
                for issuer in &self.chain {
                    output.push_str(secret_pem("CERTIFICATE", issuer.as_der()).expose_secret());
                }
                Ok(ProjectedValue::Text(SecretString::new(
                    output.as_str().into(),
                )))
            }
        }
    }
}

pub(crate) fn validate(bytes: &[u8], name: &str) -> crate::Result<()> {
    Identity::decode(bytes, None, name).map(|_| ())
}

fn secret_pem(label: &str, der: &[u8]) -> SecretString {
    let encoded = Zeroizing::new(data_encoding::BASE64.encode(der));
    let mut output = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("Base64 is ASCII"));
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    SecretString::new(output.as_str().into())
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn key_from_pem(bytes: &[u8]) -> Result<KeyPair, rcgen::Error> {
        KeyPair::from_pem(std::str::from_utf8(bytes).unwrap())
    }
    pub(crate) fn cert_from_pem(bytes: &[u8]) -> Result<Certificate, p12_keystore::error::Error> {
        let pem = pem::parse(bytes).unwrap();
        Certificate::from_der(pem.contents())
    }
    pub(crate) fn pem_text(certificate: &Certificate) -> String {
        secret_pem("CERTIFICATE", certificate.as_der())
            .expose_secret()
            .to_owned()
    }
    pub(crate) fn open_pfx(bytes: &[u8], password: &str) -> (KeyPair, Certificate) {
        let mut archive = Pkcs12Archive::from_pkcs12(bytes, password).unwrap();
        assert_eq!(archive.keys.len(), 1);
        let key = KeyPair::try_from(archive.keys.remove(0).key.as_der()).unwrap();
        let leaf = archive
            .certs
            .into_iter()
            .find(|bag| {
                parsed_certificate(bag.cert.as_der(), "fixture")
                    .unwrap()
                    .public_key()
                    .subject_public_key
                    .data
                    .as_ref()
                    == key.public_key_raw()
            })
            .unwrap()
            .cert;
        (key, leaf)
    }
}
#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::config::GenerateOptions;
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

    fn p256() -> KeyPair {
        KeyPair::generate().unwrap()
    }

    fn certificate(
        subject: &str,
        key: &KeyPair,
        issuer: Option<(&KeyPair, &Certificate)>,
        ca: bool,
        not_before: i64,
        not_after: i64,
    ) -> Certificate {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, subject);
        params.is_ca = if ca {
            IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        let now = OffsetDateTime::now_utc();
        params.not_before = now + Duration::seconds(not_before);
        params.not_after = now + Duration::seconds(not_after);
        let generated = if let Some((issuer_key, issuer_cert)) = issuer {
            let parsed = parsed_certificate(issuer_cert.as_der(), "fixture").unwrap();
            let common_name = parsed
                .subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap();
            let mut issuer_params = CertificateParams::default();
            issuer_params.distinguished_name = DistinguishedName::new();
            issuer_params
                .distinguished_name
                .push(DnType::CommonName, common_name);
            params
                .signed_by(key, &rcgen::Issuer::new(issuer_params, issuer_key))
                .unwrap()
        } else {
            params.self_signed(key).unwrap()
        };
        Certificate::from_der(generated.der()).unwrap()
    }

    const DAY: i64 = 86_400;

    /// Root -> intermediate -> leaf, all currently valid.
    struct Chain {
        root: Certificate,
        intermediate: Certificate,
        leaf_key: KeyPair,
        leaf: Certificate,
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

    fn archive(key: &KeyPair, leaf: &Certificate, bags: &[Certificate], password: &str) -> Vec<u8> {
        build_archive(key.serialized_der(), leaf, bags, password)
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
        let from_der = KeyPair::try_from(key_der.expose_secret()).unwrap();
        assert_eq!(
            from_der.public_key_raw(),
            KeyPair::try_from(identity.key.expose_secret())
                .unwrap()
                .public_key_raw()
        );

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
        let parsed = parsed_certificate(identity.certificate.as_der(), "ID").unwrap();
        let common_name = parsed
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
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
        assert_eq!(
            KeyPair::try_from(reopened.key.expose_secret())
                .unwrap()
                .public_key_raw(),
            KeyPair::try_from(identity.key.expose_secret())
                .unwrap()
                .public_key_raw()
        );
        assert_eq!(
            reopened.certificate.as_der().to_vec(),
            identity.certificate.as_der().to_vec()
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
            reopened.chain[0].as_der().to_vec(),
            chain.intermediate.as_der().to_vec()
        );
        assert_eq!(
            reopened.chain[1].as_der().to_vec(),
            chain.root.as_der().to_vec()
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
                .map(|cert| cert.as_der().to_vec())
                .collect::<Vec<_>>(),
            vec![
                chain.intermediate.as_der().to_vec(),
                chain.root.as_der().to_vec()
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
        let leaf_pem = pem_text(&chain.leaf);
        let intermediate_pem = pem_text(&chain.intermediate);
        let root_pem = pem_text(&chain.root);
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

        let other_key = p256();
        let mismatched = certificate("other.example", &other_key, None, false, -DAY, DAY);
        let bytes = archive(&key, &mismatched, &[], "");
        let error = Identity::decode(&bytes, None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("matches the private key"), "{error}");
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
        let mut parent: Option<(KeyPair, Certificate)> = None;
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
    fn local_key_id_identifies_a_leaf_that_reuses_its_issuers_key() {
        let key = p256();
        let root = certificate("Shared-key root", &key, None, true, -DAY, DAY);
        let leaf = certificate("leaf.example", &key, Some((&key, &root)), false, -DAY, DAY);
        let bytes = archive(&key, &leaf, &[root], "");
        let identity = Identity::decode(&bytes, None, "ID").unwrap();
        assert_eq!(identity.certificate.as_der(), leaf.as_der());
        assert_eq!(identity.chain_len(), 1);
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

#[cfg(test)]
mod interoperability_tests {
    use super::*;

    #[test]
    fn imports_openssl_archives_and_preserves_every_supported_key_type() {
        for (archive, expected_certificate) in [
            (
                include_bytes!("../tests/fixtures/x509/p256.pfx").as_slice(),
                include_bytes!("../tests/fixtures/x509/p256.der").as_slice(),
            ),
            (
                include_bytes!("../tests/fixtures/x509/p384.pfx").as_slice(),
                include_bytes!("../tests/fixtures/x509/p384.der").as_slice(),
            ),
            (
                include_bytes!("../tests/fixtures/x509/p521.pfx").as_slice(),
                include_bytes!("../tests/fixtures/x509/p521.der").as_slice(),
            ),
            (
                include_bytes!("../tests/fixtures/x509/rsa.pfx").as_slice(),
                include_bytes!("../tests/fixtures/x509/rsa.der").as_slice(),
            ),
            (
                include_bytes!("../tests/fixtures/x509/ed25519.pfx").as_slice(),
                include_bytes!("../tests/fixtures/x509/ed25519.der").as_slice(),
            ),
            (
                include_bytes!("../tests/fixtures/x509/legacy-3des.pfx").as_slice(),
                include_bytes!("../tests/fixtures/x509/p256.der").as_slice(),
            ),
        ] {
            let identity = Identity::decode(archive, Some("fixture-password"), "ID").unwrap();
            assert_eq!(identity.certificate.as_der(), expected_certificate);
            let rewrapped = identity.to_pkcs12(Some("päss漢字"), "PFX").unwrap();
            let reopened =
                Identity::decode(rewrapped.expose_secret(), Some("päss漢字"), "PFX").unwrap();
            assert_eq!(reopened.certificate.as_der(), expected_certificate);
            assert_eq!(reopened.key.expose_secret(), identity.key.expose_secret());
        }
    }

    #[test]
    fn bmp_passwords_interoperate_and_supplementary_passwords_fail_explicitly() {
        Identity::decode(
            include_bytes!("../tests/fixtures/x509/bmp-password.pfx"),
            Some("päss漢字"),
            "ID",
        )
        .unwrap();
        let error = Identity::decode(
            include_bytes!("../tests/fixtures/x509/supplementary-password.pfx"),
            Some("päss🔑"),
            "ID",
        )
        .unwrap_err();
        assert!(
            matches!(&error, SecretSpecError::CredentialInvalid { name, role, .. } if name == "ID" && role == "password")
        );
        assert!(error.to_string().contains("supplementary Unicode"));
        assert!(!error.to_string().contains("päss"));
        let identity = Identity::decode(
            include_bytes!("../tests/fixtures/x509/p256.pfx"),
            Some("fixture-password"),
            "ID",
        )
        .unwrap();
        assert!(matches!(
            identity.to_pkcs12(Some("päss🔑"), "PFX"),
            Err(SecretSpecError::CredentialInvalid { .. })
        ));
    }

    #[test]
    fn rejects_multiple_keys_and_invalid_self_signatures_without_filtering_bags() {
        let archive = Pkcs12Archive::from_pkcs12(
            include_bytes!("../tests/fixtures/x509/p256.pfx"),
            "fixture-password",
        )
        .unwrap();
        let key = archive.keys[0].key.clone();
        let certificate = archive.certs[0].cert.clone();
        let mut store = KeyStore::new();
        store.add_entry(
            "identity",
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
                "identity",
                key.clone(),
                [certificate.clone()],
            )),
        );
        store.add_entry(
            "extra key",
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new("extra", key.clone(), [])),
        );
        let bytes = store.writer("").write().unwrap();
        let error = Identity::decode(&bytes, None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("exactly one private key"), "{error}");

        let mut corrupt = certificate.as_der().to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        let corrupt = Certificate::from_der(&corrupt).unwrap();
        let bytes = build_archive(key.as_der(), &corrupt, &[], "").unwrap();
        let error = Identity::decode(bytes.expose_secret(), None, "ID")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid signature"), "{error}");
    }
}
