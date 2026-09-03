//! Registry of typed secret contracts (SecretSpec 0.21+).
//!
//! `type` is informational for most secrets. For the types registered here it
//! is authoritative: it decides how a stored value is decoded and validated,
//! which `credentials` roles may unlock or protect it, which declared secrets a
//! `from` target may derive from, how the result is serialized, and how the
//! result is delivered. Every string match on these type names lives here so
//! configuration, planning, and resolution cannot drift.

use crate::config::SecretEncoding;

/// The stored or generated canonical identity type. The only registry type a
/// provider may hold in 0.21.
pub(crate) const X509_IDENTITY: &str = "x509_identity";

/// Longest credential value accepted for a typed secret, in bytes. PKCS#12
/// passwords are re-encoded as BMPString; a bound keeps that allocation and
/// the KDF input small without constraining any realistic password.
pub(crate) const MAX_CREDENTIAL_BYTES: usize = 1024;

/// A serialization for a typed value whose type offers more than one, written
/// as the secret's `format`.
///
/// Available since SecretSpec 0.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// Textual PEM encoding.
    Pem,
    /// Binary DER encoding.
    Der,
}

impl Format {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "pem" => Some(Self::Pem),
            "der" => Some(Self::Der),
            _ => None,
        }
    }

    /// The manifest spelling of this format.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pem => "pem",
            Self::Der => "der",
        }
    }

    pub(crate) const fn is_binary(self) -> bool {
        matches!(self, Self::Der)
    }

    pub(crate) const fn suffix(self) -> &'static str {
        match self {
            Self::Pem => ".pem",
            Self::Der => ".der",
        }
    }
}

/// What a derived registry type produces from its `from` source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Projection {
    /// The complete identity as a PKCS#12/PFX archive, optionally protected by
    /// the `password` credential.
    Pkcs12,
    /// The unencrypted PKCS#8 private key.
    Pkcs8PrivateKey,
    /// The leaf certificate.
    Certificate,
    /// The leaf followed by its ordered issuer chain.
    CertificateChain,
    /// The ordered issuer chain without the leaf.
    IssuerChain,
}

/// One registered type's contract.
#[derive(Debug)]
pub(crate) struct TypeContract {
    /// The manifest spelling.
    pub(crate) name: &'static str,
    /// Accepted `format` values, default first. Empty when the representation
    /// is fixed, in which case `format` is rejected.
    pub(crate) formats: &'static [Format],
    /// Types a `from` source may declare. Empty for stored types.
    pub(crate) sources: &'static [&'static str],
    /// Accepted `credentials` roles.
    pub(crate) roles: &'static [&'static str],
    /// The projection a `from` target produces, or `None` for a stored type.
    pub(crate) projection: Option<Projection>,
    /// Whether a fixed representation is binary.
    fixed_binary: bool,
    /// Preferred file suffix of a fixed representation.
    fixed_suffix: &'static str,
}

impl TypeContract {
    /// Whether providers may hold this type. Every other registry type exists
    /// only as a `from` target.
    pub(crate) fn is_stored(&self) -> bool {
        self.projection.is_none()
    }

    /// Resolve the effective format: the requested one when the type accepts
    /// it, the type's default when none is requested, or `None` for a fixed
    /// representation.
    pub(crate) fn format(&self, requested: Option<&str>) -> Result<Option<Format>, String> {
        match (requested, self.formats.first()) {
            (None, default) => Ok(default.copied()),
            (Some(_), None) => Err(format!(
                "`format` is not valid for type = \"{}\"; its representation is fixed",
                self.name
            )),
            (Some(requested), Some(_)) => Format::parse(requested)
                .filter(|format| self.formats.contains(format))
                .map(Some)
                .ok_or_else(|| {
                    format!(
                        "unknown format '{}' for type = \"{}\"; expected {}",
                        requested,
                        self.name,
                        self.formats
                            .iter()
                            .map(|format| format!("`{}`", format.as_str()))
                            .collect::<Vec<_>>()
                            .join(" or ")
                    )
                }),
        }
    }

    /// Whether the logical value is bytes rather than UTF-8 text.
    pub(crate) fn is_binary(&self, format: Option<Format>) -> bool {
        format.map_or(self.fixed_binary, Format::is_binary)
    }

    /// Preferred file suffix for `as_path` delivery.
    pub(crate) fn suffix(&self, format: Option<Format>) -> &'static str {
        format.map_or(self.fixed_suffix, Format::suffix)
    }

    /// The codec a binary value uses wherever it must be text, when the
    /// declaration does not choose one.
    pub(crate) fn default_encoding(&self, format: Option<Format>) -> Option<SecretEncoding> {
        self.is_binary(format).then_some(SecretEncoding::Base64)
    }

    pub(crate) fn accepts_source(&self, source_type: Option<&str>) -> bool {
        source_type.is_some_and(|source_type| self.sources.contains(&source_type))
    }

    pub(crate) fn accepts_role(&self, role: &str) -> bool {
        self.roles.contains(&role)
    }
}

const CONTRACTS: &[TypeContract] = &[
    TypeContract {
        name: X509_IDENTITY,
        formats: &[],
        sources: &[],
        roles: &["password"],
        projection: None,
        fixed_binary: true,
        fixed_suffix: ".pfx",
    },
    TypeContract {
        name: "pkcs12",
        formats: &[],
        sources: &[X509_IDENTITY],
        roles: &["password"],
        projection: Some(Projection::Pkcs12),
        fixed_binary: true,
        fixed_suffix: ".pfx",
    },
    TypeContract {
        name: "pkcs8_private_key",
        formats: &[Format::Pem, Format::Der],
        sources: &[X509_IDENTITY],
        roles: &[],
        projection: Some(Projection::Pkcs8PrivateKey),
        fixed_binary: false,
        fixed_suffix: ".pem",
    },
    TypeContract {
        name: "x509_certificate",
        formats: &[Format::Pem, Format::Der],
        sources: &[X509_IDENTITY],
        roles: &[],
        projection: Some(Projection::Certificate),
        fixed_binary: false,
        fixed_suffix: ".pem",
    },
    TypeContract {
        name: "x509_certificate_chain",
        formats: &[Format::Pem],
        sources: &[X509_IDENTITY],
        roles: &[],
        projection: Some(Projection::CertificateChain),
        fixed_binary: false,
        fixed_suffix: ".pem",
    },
    TypeContract {
        name: "x509_issuer_chain",
        formats: &[Format::Pem],
        sources: &[X509_IDENTITY],
        roles: &[],
        projection: Some(Projection::IssuerChain),
        fixed_binary: false,
        fixed_suffix: ".pem",
    },
];

/// Look up a registry type. `None` for every informational type such as
/// `password` or `ssh_private_key`.
pub(crate) fn contract(type_name: &str) -> Option<&'static TypeContract> {
    CONTRACTS.iter().find(|contract| contract.name == type_name)
}

/// Types a `from` declaration may convert to, for diagnostics.
pub(crate) fn derivable_type_names() -> impl Iterator<Item = &'static str> {
    CONTRACTS
        .iter()
        .filter(|contract| !contract.is_stored())
        .map(|contract| contract.name)
}

/// Reject a credential value that would silently change meaning or abuse the
/// crypto backend. An empty value is an error rather than "no credential": the
/// declaration bound one and it must be present. NUL is rejected because
/// PKCS#12 consumers disagree about its interpretation.
pub(crate) fn validate_credential_value(role: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!(
            "credential `{role}` resolved to an empty value; omit the binding for an empty credential"
        ));
    }
    if value.contains('\0') {
        return Err(format!("credential `{role}` must not contain NUL"));
    }
    if value.len() > MAX_CREDENTIAL_BYTES {
        return Err(format!(
            "credential `{role}` exceeds {MAX_CREDENTIAL_BYTES} bytes"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_and_derived_contracts_are_distinct() {
        let identity = contract(X509_IDENTITY).unwrap();
        assert!(identity.is_stored());
        assert!(identity.sources.is_empty());
        assert!(identity.accepts_role("password"));
        assert!(identity.is_binary(None));
        assert_eq!(identity.suffix(None), ".pfx");
        assert_eq!(
            identity.default_encoding(None),
            Some(SecretEncoding::Base64)
        );

        for name in derivable_type_names() {
            let target = contract(name).unwrap();
            assert!(!target.is_stored(), "{name}");
            assert!(target.accepts_source(Some(X509_IDENTITY)), "{name}");
            assert!(!target.accepts_source(Some("pkcs12")), "{name} chains");
            assert!(!target.accepts_source(None), "{name} untyped");
        }
        assert!(contract("password").is_none());
        assert_eq!(
            derivable_type_names().collect::<Vec<_>>(),
            [
                "pkcs12",
                "pkcs8_private_key",
                "x509_certificate",
                "x509_certificate_chain",
                "x509_issuer_chain",
            ]
        );
    }

    #[test]
    fn formats_default_per_type_and_reject_fixed_representations() {
        let key = contract("pkcs8_private_key").unwrap();
        assert_eq!(key.format(None).unwrap(), Some(Format::Pem));
        assert_eq!(key.format(Some("der")).unwrap(), Some(Format::Der));
        assert!(!key.is_binary(Some(Format::Pem)));
        assert!(key.is_binary(Some(Format::Der)));
        assert_eq!(key.suffix(Some(Format::Der)), ".der");
        assert_eq!(key.default_encoding(Some(Format::Pem)), None);
        assert_eq!(
            key.default_encoding(Some(Format::Der)),
            Some(SecretEncoding::Base64)
        );
        let unknown = key.format(Some("p12")).unwrap_err();
        assert!(unknown.contains("expected `pem` or `der`"), "{unknown}");

        let chain = contract("x509_certificate_chain").unwrap();
        assert_eq!(chain.format(None).unwrap(), Some(Format::Pem));
        let der = chain.format(Some("der")).unwrap_err();
        assert!(der.contains("expected `pem`"), "{der}");

        let pfx = contract("pkcs12").unwrap();
        assert_eq!(pfx.format(None).unwrap(), None);
        let fixed = pfx.format(Some("der")).unwrap_err();
        assert!(fixed.contains("representation is fixed"), "{fixed}");
        assert!(pfx.is_binary(None));
        assert_eq!(pfx.suffix(None), ".pfx");
    }

    #[test]
    fn credential_values_are_bounded() {
        assert!(validate_credential_value("password", "correct horse").is_ok());
        let empty = validate_credential_value("password", "").unwrap_err();
        assert!(empty.contains("empty"), "{empty}");
        let nul = validate_credential_value("password", "a\0b").unwrap_err();
        assert!(nul.contains("NUL"), "{nul}");
        let long = validate_credential_value("password", &"x".repeat(MAX_CREDENTIAL_BYTES + 1))
            .unwrap_err();
        assert!(long.contains("exceeds"), "{long}");
        assert!(validate_credential_value("password", &"x".repeat(MAX_CREDENTIAL_BYTES)).is_ok());
    }
}
