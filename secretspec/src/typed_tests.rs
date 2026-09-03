//! End-to-end coverage for typed, converted, and password protected secrets
//! (0.21+): `type`, `format`, `from`, and `credentials` across configuration
//! validation, resolution, scopes, reports, and the read-only lifecycle.

use crate::config::{Config, GenerateConfig, GenerateOptions};
use crate::report::{Derivation, ResolutionStatus};
use crate::resolve::ResolvedSource;
use crate::tests::scrub_resolution_env;
use crate::x509_identity::Identity;
use crate::{Format, SecretSpecError, Secrets};
use data_encoding::{BASE64, HEXLOWER};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::x509::X509;
use secrecy::ExposeSecret;
use std::fs;
use tempfile::TempDir;

fn manifest(body: &str) -> Config {
    toml::from_str(&format!(
        "[project]\nname = \"typed\"\nrevision = \"1.0\"\n\n{body}"
    ))
    .expect("manifest parses")
}

fn validation_error(body: &str) -> String {
    manifest(body).validate().unwrap_err().to_string()
}

fn assert_valid(body: &str) {
    manifest(body).validate().unwrap_or_else(|error| {
        panic!("expected a valid manifest, got: {error}\n{body}");
    });
}

fn generated_identity() -> Vec<u8> {
    let config = GenerateConfig::Options(GenerateOptions {
        san: Some(vec!["dns:localhost".to_string()]),
        ..Default::default()
    });
    crate::x509_identity::generate(&config)
        .unwrap()
        .expose_secret()
        .to_vec()
}

fn protected_identity(password: &str) -> Vec<u8> {
    let bytes = generated_identity();
    Identity::decode(&bytes, None, "ID")
        .unwrap()
        .to_pkcs12(Some(password), "ID")
        .unwrap()
        .expose_secret()
        .to_vec()
}

/// A spec whose every stored secret lives in one dotenv file.
fn dotenv_spec(body: &str, env: &str) -> (TempDir, Secrets) {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    fs::write(&env_path, env).unwrap();
    let provider = format!("dotenv://{}", env_path.display());
    (
        dir,
        Secrets::new(manifest(body), None, Some(provider), None),
    )
}

fn null_spec(body: &str) -> Secrets {
    Secrets::new(manifest(body), None, Some("null://".to_string()), None)
}

fn open_pfx(bytes: &[u8], password: &str) -> openssl::pkcs12::ParsedPkcs12_2 {
    Pkcs12::from_der(bytes)
        .unwrap()
        .parse2(password)
        .unwrap_or_else(|error| panic!("PFX must open with {password:?}: {error}"))
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn every_target_type_and_format_validates_against_an_identity() {
    assert_valid(
        r#"
[profiles.default]
TLS_IDENTITY = { description = "identity", type = "x509_identity" }
TLS_IDENTITY_HEX = { description = "hex at rest", type = "x509_identity", encoding = "hex" }
TLS_PFX = { description = "pfx", type = "pkcs12", from = "TLS_IDENTITY", as_path = true }
TLS_PFX_B64 = { description = "inline pfx", type = "pkcs12", from = "TLS_IDENTITY" }
TLS_PFX_HEX = { description = "inline hex pfx", type = "pkcs12", from = "TLS_IDENTITY", encoding = "hex" }
TLS_KEY = { description = "key", type = "pkcs8_private_key", from = "TLS_IDENTITY" }
TLS_KEY_PEM = { description = "key", type = "pkcs8_private_key", format = "pem", from = "TLS_IDENTITY", as_path = true }
TLS_KEY_DER = { description = "key", type = "pkcs8_private_key", format = "der", from = "TLS_IDENTITY" }
TLS_CERT = { description = "cert", type = "x509_certificate", from = "TLS_IDENTITY" }
TLS_CERT_DER = { description = "cert", type = "x509_certificate", format = "der", from = "TLS_IDENTITY", as_path = true }
TLS_CHAIN = { description = "chain", type = "x509_certificate_chain", from = "TLS_IDENTITY" }
TLS_CHAIN_PEM = { description = "chain", type = "x509_certificate_chain", format = "pem", from = "TLS_IDENTITY" }
TLS_ISSUERS = { description = "issuers", type = "x509_issuer_chain", from = "TLS_IDENTITY", required = false }
"#,
    );
}

#[test]
fn from_requires_extract_or_a_derivable_type() {
    let bare = validation_error(
        r#"
[profiles.default]
A = { description = "a" }
B = { description = "b", from = "A" }
"#,
    );
    assert!(
        bare.contains("`from` requires `extract` to select from the source or a derivable `type`"),
        "{bare}"
    );

    let informational = validation_error(
        r#"
[profiles.default]
A = { description = "a" }
B = { description = "b", type = "password", from = "A" }
"#,
    );
    assert!(
        informational.contains("type = \"password\" cannot be derived with `from`"),
        "{informational}"
    );
    assert!(informational.contains("`pkcs12`"), "{informational}");
    assert!(
        informational.contains("`x509_issuer_chain`"),
        "{informational}"
    );

    let stored = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
B = { description = "b", type = "x509_identity", from = "A" }
"#,
    );
    assert!(
        stored.contains("type = \"x509_identity\" is stored by a provider and cannot be derived"),
        "{stored}"
    );

    let both = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
B = { description = "b", type = "pkcs12", from = "A", extract = { format = "json", pointer = "/a" } }
"#,
    );
    assert!(
        both.contains(
            "either selects with `extract` or converts with a derivable `type`, not both"
        ),
        "{both}"
    );

    let typed_selection = validation_error(
        r#"
[profiles.default]
A = { description = "a" }
B = { description = "b", type = "password", from = "A", extract = { format = "json", pointer = "/a" } }
"#,
    );
    assert!(
        typed_selection.contains("`from` with `extract` cannot also set `type`"),
        "{typed_selection}"
    );

    let bad_name = validation_error(
        r#"
[profiles.default]
A = { description = "a" }
B = { description = "b", from = "not a name", extract = { format = "json", pointer = "/a" } }
"#,
    );
    assert!(
        bad_name.contains("`from` must name a declared secret using a valid identifier"),
        "{bad_name}"
    );
}

#[test]
fn from_secrets_reject_storage_and_generation_fields() {
    for field in [
        r#"default = "x""#,
        r#"providers = ["keyring"]"#,
        r#"ref = { item = "x" }"#,
        r#"refs = { keyring = { item = "x" } }"#,
        r#"generate = { san = ["dns:localhost"] }"#,
        r#"prompt = true"#,
    ] {
        let error = validation_error(&format!(
            r#"
[profiles.default]
TLS_IDENTITY = {{ description = "identity", type = "x509_identity" }}
TLS_KEY = {{ description = "key", type = "pkcs8_private_key", from = "TLS_IDENTITY", {field} }}
"#
        ));
        assert!(
            error.contains("`from` secrets cannot also set")
                || error.contains("`generate` and `default`")
                || error.contains("'generate' requires 'type'"),
            "{field}: {error}"
        );
    }

    let composed = validation_error(
        r#"
[profiles.default]
A = { description = "a" }
B = { description = "b", composed = "${A}", from = "A", extract = { format = "json", pointer = "/a" } }
"#,
    );
    assert!(
        composed.contains("`composed` secrets cannot also set"),
        "{composed}"
    );
    assert!(composed.contains("`from`"), "{composed}");
}

#[test]
fn format_is_validated_against_the_type() {
    let fixed = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
B = { description = "b", type = "pkcs12", format = "der", from = "A" }
"#,
    );
    assert!(
        fixed.contains("`format` is not valid for type = \"pkcs12\""),
        "{fixed}"
    );

    let chain_der = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
B = { description = "b", type = "x509_certificate_chain", format = "der", from = "A" }
"#,
    );
    assert!(
        chain_der
            .contains("unknown format 'der' for type = \"x509_certificate_chain\"; expected `pem`"),
        "{chain_der}"
    );

    let unknown = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
B = { description = "b", type = "x509_certificate", format = "p7b", from = "A" }
"#,
    );
    assert!(
        unknown.contains(
            "unknown format 'p7b' for type = \"x509_certificate\"; expected `pem` or `der`"
        ),
        "{unknown}"
    );

    let untyped = validation_error(
        r#"
[profiles.default]
A = { description = "a", format = "pem" }
"#,
    );
    assert!(
        untyped.contains("`format` requires a `type` that accepts formats"),
        "{untyped}"
    );

    let informational = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "password", format = "pem" }
"#,
    );
    assert!(
        informational.contains("`format` is not valid for type = \"password\""),
        "{informational}"
    );

    let identity = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity", format = "der" }
"#,
    );
    assert!(identity.contains("representation is fixed"), "{identity}");
}

#[test]
fn credential_roles_and_bindings_are_validated() {
    let unknown_role = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity", credentials = { passphrase = "P" } }
P = { description = "p" }
"#,
    );
    assert!(
        unknown_role.contains(
            "unknown credential role `passphrase` for type = \"x509_identity\"; expected `password`"
        ),
        "{unknown_role}"
    );

    let no_roles = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
K = { description = "k", type = "pkcs8_private_key", from = "A", credentials = { password = "P" } }
P = { description = "p" }
"#,
    );
    assert!(
        no_roles.contains("type = \"pkcs8_private_key\" accepts no credentials"),
        "{no_roles}"
    );

    let untyped = validation_error(
        r#"
[profiles.default]
A = { description = "a", credentials = { password = "P" } }
P = { description = "p" }
"#,
    );
    assert!(
        untyped.contains("`credentials` requires a `type` that accepts credentials"),
        "{untyped}"
    );

    let informational = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "ssh_private_key", credentials = { password = "P" } }
P = { description = "p" }
"#,
    );
    assert!(
        informational.contains("`credentials` is not valid for type = \"ssh_private_key\""),
        "{informational}"
    );

    let table = toml::from_str::<Config>(
        r#"
[project]
name = "typed"
revision = "1.0"

[profiles.default]
A = { description = "a", type = "x509_identity", credentials = { password = { provider = "keyring" } } }
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        table.contains("the `{ provider, ref }` table form is reserved"),
        "{table}"
    );

    let bad_name = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity", credentials = { password = "not a name" } }
"#,
    );
    assert!(
        bad_name
            .contains("credential `password` must name a declared secret using a valid identifier"),
        "{bad_name}"
    );

    let generated = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity", generate = { san = ["dns:localhost"] }, credentials = { password = "P" } }
P = { description = "p" }
"#,
    );
    assert!(
        generated.contains(
            "`credentials` cannot be combined with enabled `generate` for type = \"x509_identity\""
        ),
        "{generated}"
    );

    // A stored identity and a derived archive both accept `password`.
    assert_valid(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity", credentials = { password = "P" } }
B = { description = "b", type = "pkcs12", from = "A", credentials = { password = "Q" } }
P = { description = "p" }
Q = { description = "q" }
"#,
    );
}

#[test]
fn credentials_must_name_text_secrets() {
    let as_path = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity", credentials = { password = "P" } }
P = { description = "p", as_path = true }
"#,
    );
    assert!(
        as_path.contains("credential `password` names 'P', which is delivered as a path"),
        "{as_path}"
    );

    let binary = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
B = { description = "b", type = "pkcs12", from = "A", credentials = { password = "A" } }
"#,
    );
    assert!(
        binary
            .contains("credential `password` names 'A', whose type = \"x509_identity\" is binary"),
        "{binary}"
    );

    // A composed or selected text value is an acceptable credential.
    assert_valid(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
B = { description = "b", type = "pkcs12", from = "A", credentials = { password = "P" } }
DOC = { description = "doc", default = "{\"pw\":\"x\"}" }
P = { description = "p", from = "DOC", extract = { format = "json", pointer = "/pw" } }
"#,
    );
}

#[test]
fn encoding_on_from_secrets_requires_a_binary_result() {
    let pem = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
K = { description = "k", type = "pkcs8_private_key", from = "A", encoding = "base64" }
"#,
    );
    assert!(
        pem.contains("`encoding` on a `from` secret is valid only when the result is binary"),
        "{pem}"
    );

    let selection = validation_error(
        r#"
[profiles.default]
DOC = { description = "doc" }
F = { description = "f", from = "DOC", extract = { format = "json", pointer = "/a" }, encoding = "base64" }
"#,
    );
    assert!(
        selection.contains("`encoding` on a `from` secret is valid only when the result is binary"),
        "{selection}"
    );

    assert_valid(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
K = { description = "k", type = "pkcs8_private_key", format = "der", from = "A", encoding = "base64url" }
P = { description = "p", type = "pkcs12", from = "A", encoding = "hex" }
"#,
    );
}

#[test]
fn target_types_require_from_and_identities_reject_defaults() {
    let stored_target = validation_error(
        r#"
[profiles.default]
P = { description = "p", type = "pkcs12", providers = ["keyring"] }
"#,
    );
    assert!(
        stored_target.contains("type = \"pkcs12\" requires `from`"),
        "{stored_target}"
    );

    let generated_target = validation_error(
        r#"
[profiles.default]
K = { description = "k", type = "pkcs8_private_key" }
"#,
    );
    assert!(
        generated_target.contains("type = \"pkcs8_private_key\" requires `from`"),
        "{generated_target}"
    );

    let defaulted = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity", default = "x" }
"#,
    );
    assert!(
        defaulted.contains(
            "`type = \"x509_identity\"` cannot be combined with `default` or `prompt = true`"
        ),
        "{defaulted}"
    );

    let prompted = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity", prompt = true }
"#,
    );
    assert!(
        prompted.contains(
            "`type = \"x509_identity\"` cannot be combined with `default` or `prompt = true`"
        ),
        "{prompted}"
    );
}

#[test]
fn extract_cannot_select_from_a_binary_source_and_targets_are_not_sources() {
    let identity = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
F = { description = "f", from = "A", extract = { format = "json", pointer = "/a" } }
"#,
    );
    assert!(
        identity.contains(
            "`extract` cannot select from 'A' because its type = \"x509_identity\" is binary"
        ),
        "{identity}"
    );

    let chained = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
P = { description = "p", type = "pkcs12", from = "A" }
K = { description = "k", type = "pkcs8_private_key", from = "P" }
"#,
    );
    assert!(
        chained.contains("`from` source 'P' has type = \"pkcs12\", but type = \"pkcs8_private_key\" derives from type = \"x509_identity\""),
        "{chained}"
    );

    let der_selection = validation_error(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
C = { description = "c", type = "x509_certificate", format = "der", from = "A" }
F = { description = "f", from = "C", extract = { format = "ini", pointer = "/a" } }
"#,
    );
    assert!(
        der_selection.contains(
            "`extract` cannot select from 'C' because its type = \"x509_certificate\" is binary"
        ),
        "{der_selection}"
    );

    // A PEM target is text, so a selection from it is type-valid.
    assert_valid(
        r#"
[profiles.default]
A = { description = "a", type = "x509_identity" }
C = { description = "c", type = "x509_certificate", from = "A" }
F = { description = "f", from = "C", extract = { format = "ini", pointer = "/a" } }
"#,
    );
}

#[test]
fn inheritance_merges_from_format_and_credentials_then_validates() {
    let config = manifest(
        r#"
[profiles.default]
TLS_IDENTITY = { description = "identity", type = "x509_identity" }
TLS_PFX_PASSWORD = { description = "password" }
TLS_PFX = { description = "pfx", type = "pkcs12", from = "TLS_IDENTITY", credentials = { password = "TLS_PFX_PASSWORD" } }
TLS_KEY = { description = "key", type = "pkcs8_private_key", format = "der", from = "TLS_IDENTITY", as_path = true }

[profiles.production]
TLS_PFX = { description = "production pfx" }
TLS_KEY = { format = "pem" }
"#,
    );
    config.validate().unwrap();
    let spec = Secrets::new(config, None, None, Some("production".to_string()));
    let pfx = spec
        .resolve_secret_config("TLS_PFX", Some("production"))
        .unwrap();
    assert_eq!(pfx.description.as_deref(), Some("production pfx"));
    assert_eq!(pfx.from.as_deref(), Some("TLS_IDENTITY"));
    assert_eq!(
        pfx.credential_secrets().collect::<Vec<_>>(),
        vec![("password", "TLS_PFX_PASSWORD")]
    );
    let key = spec
        .resolve_secret_config("TLS_KEY", Some("production"))
        .unwrap();
    assert_eq!(key.format.as_deref(), Some("pem"));
    assert_eq!(key.from.as_deref(), Some("TLS_IDENTITY"));
    assert_eq!(key.as_path, Some(true));

    // The merged view is what gets validated: an override that adds storage
    // to an inherited `from` declaration fails like it would inline.
    let error = validation_error(
        r#"
[profiles.default]
TLS_IDENTITY = { description = "identity", type = "x509_identity" }
TLS_KEY = { description = "key", type = "pkcs8_private_key", from = "TLS_IDENTITY" }

[profiles.production]
TLS_KEY = { providers = ["keyring"] }
"#,
    );
    assert!(error.contains("`from` secrets cannot also set"), "{error}");

    // An override may clear inherited credentials with an empty table.
    let cleared = manifest(
        r#"
[profiles.default]
TLS_IDENTITY = { description = "identity", type = "x509_identity" }
P = { description = "p" }
TLS_PFX = { description = "pfx", type = "pkcs12", from = "TLS_IDENTITY", credentials = { password = "P" } }

[profiles.production]
TLS_PFX = { credentials = {} }
"#,
    );
    cleared.validate().unwrap();
    let spec = Secrets::new(cleared, None, None, Some("production".to_string()));
    let pfx = spec
        .resolve_secret_config("TLS_PFX", Some("production"))
        .unwrap();
    assert_eq!(pfx.credential_secrets().count(), 0);
}

#[test]
fn typed_fields_round_trip_through_toml_and_the_builder() {
    use crate::config::Secret;

    let secret: Secret = toml::from_str(
        r#"description = "pfx"
type = "pkcs12"
from = "TLS_IDENTITY"
credentials = { password = "TLS_PFX_PASSWORD" }
as_path = true"#,
    )
    .unwrap();
    assert_eq!(secret.from.as_deref(), Some("TLS_IDENTITY"));
    assert_eq!(
        secret.credential_secrets().collect::<Vec<_>>(),
        vec![("password", "TLS_PFX_PASSWORD")]
    );
    assert!(secret.is_binary_value());
    assert_eq!(secret.file_suffix(), Some(".pfx"));
    assert_eq!(
        secret.effective_encoding(),
        Some(crate::config::SecretEncoding::Base64)
    );
    let rendered = toml::to_string(&secret).unwrap();
    assert!(rendered.contains("from = \"TLS_IDENTITY\""), "{rendered}");
    assert!(
        rendered.contains("password = \"TLS_PFX_PASSWORD\""),
        "{rendered}"
    );
    assert!(!rendered.contains("format"), "{rendered}");
    let reparsed: Secret = toml::from_str(&rendered).unwrap();
    assert_eq!(reparsed.credentials, secret.credentials);

    let key: Secret = toml::from_str(
        r#"description = "key"
type = "pkcs8_private_key"
format = "der"
from = "TLS_IDENTITY""#,
    )
    .unwrap();
    assert_eq!(key.typed_format(), Some(Format::Der));
    assert!(key.is_binary_value());
    assert_eq!(key.file_suffix(), Some(".der"));
    let pem: Secret = toml::from_str(
        r#"description = "key"
type = "pkcs8_private_key"
from = "TLS_IDENTITY""#,
    )
    .unwrap();
    assert_eq!(pem.typed_format(), Some(Format::Pem));
    assert!(!pem.is_binary_value());
    assert_eq!(pem.effective_encoding(), None);
    assert_eq!(pem.file_suffix(), Some(".pem"));

    let built = crate::spec::Secret::new("Password protected Windows TLS identity")
        .secret_type("pkcs12")
        .from("TLS_IDENTITY")
        .credential("password", "TLS_PFX_PASSWORD")
        .as_path(true)
        .into_config();
    assert_eq!(built.secret_type.as_deref(), Some("pkcs12"));
    assert_eq!(built.from.as_deref(), Some("TLS_IDENTITY"));
    assert_eq!(
        built.credential_secrets().collect::<Vec<_>>(),
        vec![("password", "TLS_PFX_PASSWORD")]
    );
    let der = crate::spec::Secret::new("Leaf certificate as DER")
        .secret_type("x509_certificate")
        .format(Format::Der)
        .from("TLS_IDENTITY")
        .into_config();
    assert_eq!(der.format.as_deref(), Some("der"));
    der.validate().unwrap();

    // The builder no longer has to spell the identity's encoding.
    let identity = crate::spec::Secret::new("identity")
        .generate(crate::spec::Generation::x509_identity(["dns:localhost"]))
        .into_config();
    assert_eq!(identity.encoding, None);
    assert_eq!(
        identity.effective_encoding(),
        Some(crate::config::SecretEncoding::Base64)
    );
    identity.validate().unwrap();
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

const GENERATED_PROFILE: &str = r#"
[profiles.default]
TLS_IDENTITY = { description = "identity", type = "x509_identity", generate = { san = ["dns:localhost", "ip:127.0.0.1"], usages = ["server_auth", "client_auth"], valid_for = "7d" } }
TLS_PFX_PASSWORD = { description = "pfx password", type = "passphrase", generate = true }
TLS_PFX = { description = "protected pfx", type = "pkcs12", from = "TLS_IDENTITY", credentials = { password = "TLS_PFX_PASSWORD" }, as_path = true }
TLS_PFX_B64 = { description = "inline pfx", type = "pkcs12", from = "TLS_IDENTITY", credentials = { password = "TLS_PFX_PASSWORD" } }
TLS_PFX_HEX = { description = "inline hex pfx", type = "pkcs12", from = "TLS_IDENTITY", encoding = "hex" }
TLS_KEY = { description = "key", type = "pkcs8_private_key", from = "TLS_IDENTITY" }
TLS_KEY_DER = { description = "key der", type = "pkcs8_private_key", format = "der", from = "TLS_IDENTITY", as_path = true }
TLS_KEY_DER_B64 = { description = "key der inline", type = "pkcs8_private_key", format = "der", from = "TLS_IDENTITY" }
TLS_CERTIFICATE = { description = "cert", type = "x509_certificate", from = "TLS_IDENTITY", as_path = true }
TLS_CERTIFICATE_DER = { description = "cert der", type = "x509_certificate", format = "der", from = "TLS_IDENTITY", as_path = true }
TLS_CHAIN = { description = "chain", type = "x509_certificate_chain", from = "TLS_IDENTITY" }
TLS_ISSUERS = { description = "issuers", type = "x509_issuer_chain", from = "TLS_IDENTITY" }
TLS_CONFIG = { description = "config", composed = "cert=${TLS_CERTIFICATE};key=${TLS_KEY}" }
"#;

#[test]
fn generated_identity_derives_every_target_in_one_resolve() {
    let _env = scrub_resolution_env();
    let spec = null_spec(GENERATED_PROFILE);
    let response = spec.resolve().unwrap();
    assert!(response.is_ok(), "{:?}", response.missing_required);

    let secrets = &response.secrets;
    // The canonical identity is inline Base64 of an empty-password archive.
    let identity_bytes = BASE64
        .decode(secrets["TLS_IDENTITY"].value.as_deref().unwrap().as_bytes())
        .unwrap();
    let identity = open_pfx(&identity_bytes, "");
    let key = identity.pkey.as_ref().unwrap();
    let certificate = identity.cert.as_ref().unwrap();
    assert_eq!(secrets["TLS_IDENTITY"].source, ResolvedSource::Generated);

    // The protected archive opens only with the generated password and holds
    // the same key and leaf.
    let password = secrets["TLS_PFX_PASSWORD"].value.as_deref().unwrap();
    assert!(
        password.split(|c: char| !c.is_alphanumeric()).count() >= 6,
        "passphrase: {password}"
    );
    let pfx_path = secrets["TLS_PFX"].path.as_deref().unwrap();
    assert!(pfx_path.ends_with(".pfx"), "{pfx_path}");
    assert!(secrets["TLS_PFX"].as_path);
    let pfx_bytes = fs::read(pfx_path).unwrap();
    let protected = open_pfx(&pfx_bytes, password);
    assert!(protected.pkey.as_ref().unwrap().public_eq(key));
    assert_eq!(
        protected.cert.as_ref().unwrap().to_der().unwrap(),
        certificate.to_der().unwrap()
    );
    assert!(
        Pkcs12::from_der(&pfx_bytes).unwrap().parse2("").is_err(),
        "protected archive must not open with an empty password"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(pfx_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "owner-only temp file");
    }

    // Binary targets without `as_path` are inline text in their encoding.
    let inline_pfx = BASE64
        .decode(secrets["TLS_PFX_B64"].value.as_deref().unwrap().as_bytes())
        .unwrap();
    assert!(open_pfx(&inline_pfx, password).pkey.unwrap().public_eq(key));
    let hex_pfx = HEXLOWER
        .decode(secrets["TLS_PFX_HEX"].value.as_deref().unwrap().as_bytes())
        .unwrap();
    assert!(open_pfx(&hex_pfx, "").pkey.unwrap().public_eq(key));
    assert!(!secrets["TLS_PFX_B64"].as_path);

    // Key projections.
    let pem_key = secrets["TLS_KEY"].value.as_deref().unwrap();
    assert!(pem_key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(
        PKey::private_key_from_pem(pem_key.as_bytes())
            .unwrap()
            .public_eq(key)
    );
    let der_path = secrets["TLS_KEY_DER"].path.as_deref().unwrap();
    assert!(der_path.ends_with(".der"), "{der_path}");
    let der_key = PKey::private_key_from_pkcs8(&fs::read(der_path).unwrap()).unwrap();
    assert!(der_key.public_eq(key));
    let inline_der = BASE64
        .decode(
            secrets["TLS_KEY_DER_B64"]
                .value
                .as_deref()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    assert!(
        PKey::private_key_from_pkcs8(&inline_der)
            .unwrap()
            .public_eq(key)
    );

    // Certificate projections.
    let cert_path = secrets["TLS_CERTIFICATE"].path.as_deref().unwrap();
    assert!(cert_path.ends_with(".pem"), "{cert_path}");
    let cert_pem = fs::read(cert_path).unwrap();
    assert_eq!(
        X509::from_pem(&cert_pem).unwrap().to_der().unwrap(),
        certificate.to_der().unwrap()
    );
    let cert_der_path = secrets["TLS_CERTIFICATE_DER"].path.as_deref().unwrap();
    assert!(cert_der_path.ends_with(".der"), "{cert_der_path}");
    assert_eq!(
        fs::read(cert_der_path).unwrap(),
        certificate.to_der().unwrap()
    );
    assert_eq!(
        secrets["TLS_CHAIN"].value.as_deref().unwrap().as_bytes(),
        cert_pem.as_slice(),
        "a self-signed identity's chain is its leaf"
    );
    assert_eq!(secrets["TLS_ISSUERS"].value.as_deref(), Some(""));

    // Derived values feed compositions like any other secret.
    let config = secrets["TLS_CONFIG"].value.as_deref().unwrap();
    assert!(config.starts_with(&format!("cert={cert_path};key=-----BEGIN PRIVATE KEY-----")));

    for name in [
        "TLS_PFX",
        "TLS_PFX_B64",
        "TLS_KEY",
        "TLS_KEY_DER",
        "TLS_CERTIFICATE",
        "TLS_CHAIN",
        "TLS_ISSUERS",
    ] {
        assert_eq!(secrets[name].source, ResolvedSource::Composed, "{name}");
        assert_eq!(secrets[name].source_provider, None, "{name}");
    }
    let names: Vec<&str> = secrets.keys().map(String::as_str).collect();
    assert_eq!(
        names.len(),
        13,
        "every declared name stays a flat field: {names:?}"
    );
}

#[test]
fn a_stored_protected_identity_opens_with_its_declared_password() {
    let _env = scrub_resolution_env();
    let archive = protected_identity("correct horse battery staple");
    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity", credentials = { password = "SERVICE_IDENTITY_PASSWORD" }, as_path = true }
SERVICE_IDENTITY_PASSWORD = { description = "password" }
SERVICE_KEY = { description = "key", type = "pkcs8_private_key", from = "SERVICE_IDENTITY" }
SERVICE_CERTIFICATE = { description = "cert", type = "x509_certificate_chain", from = "SERVICE_IDENTITY" }
"#,
        &format!(
            "SERVICE_IDENTITY={}\nSERVICE_IDENTITY_PASSWORD=correct horse battery staple\n",
            BASE64.encode(&archive)
        ),
    );
    let response = spec.resolve().unwrap();
    assert!(response.is_ok(), "{:?}", response.missing_required);
    let secrets = &response.secrets;

    // The identity is delivered as its stored, still protected, archive.
    let path = secrets["SERVICE_IDENTITY"].path.as_deref().unwrap();
    assert!(path.ends_with(".pfx"), "{path}");
    assert_eq!(fs::read(path).unwrap(), archive);
    assert_eq!(secrets["SERVICE_IDENTITY"].source, ResolvedSource::Provider);

    let expected = open_pfx(&archive, "correct horse battery staple");
    let key =
        PKey::private_key_from_pem(secrets["SERVICE_KEY"].value.as_deref().unwrap().as_bytes())
            .unwrap();
    assert!(expected.pkey.unwrap().public_eq(&key));
    let chain = secrets["SERVICE_CERTIFICATE"].value.as_deref().unwrap();
    assert_eq!(
        X509::from_pem(chain.as_bytes()).unwrap().to_der().unwrap(),
        expected.cert.unwrap().to_der().unwrap()
    );
    assert_eq!(secrets["SERVICE_KEY"].source, ResolvedSource::Composed);
}

#[test]
fn a_wrong_or_unbound_password_never_falls_back_to_guessing() {
    let _env = scrub_resolution_env();
    let archive = BASE64.encode(&protected_identity("right"));

    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity", credentials = { password = "PW" } }
PW = { description = "password" }
SERVICE_KEY = { description = "key", type = "pkcs8_private_key", from = "SERVICE_IDENTITY" }
"#,
        &format!("SERVICE_IDENTITY={archive}\nPW=wrong\n"),
    );
    let error = spec.resolve().unwrap_err();
    assert!(
        matches!(&error, SecretSpecError::DecodeFailed { name, encoding, .. } if name == "SERVICE_IDENTITY" && *encoding == "pkcs12"),
        "{error}"
    );
    let text = error.to_string();
    assert!(text.contains("configured password"), "{text}");
    assert!(
        !text.contains("wrong"),
        "must not echo the password: {text}"
    );

    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity" }
"#,
        &format!("SERVICE_IDENTITY={archive}\n"),
    );
    let text = spec.resolve().unwrap_err().to_string();
    assert!(text.contains("empty password"), "{text}");
    assert!(text.contains("credentials"), "{text}");

    // A bound password on an unprotected archive is equally wrong.
    let unprotected = BASE64.encode(&generated_identity());
    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity", credentials = { password = "PW" } }
PW = { description = "password" }
"#,
        &format!("SERVICE_IDENTITY={unprotected}\nPW=surprise\n"),
    );
    let text = spec.resolve().unwrap_err().to_string();
    assert!(text.contains("configured password"), "{text}");
}

#[test]
fn a_missing_password_secret_makes_the_identity_and_its_projections_missing() {
    let _env = scrub_resolution_env();
    let archive = BASE64.encode(&protected_identity("pw"));

    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity", credentials = { password = "PW" } }
PW = { description = "password" }
SERVICE_KEY = { description = "key", type = "pkcs8_private_key", from = "SERVICE_IDENTITY" }
OTHER = { description = "unrelated" }
"#,
        &format!("SERVICE_IDENTITY={archive}\nOTHER=fine\n"),
    );
    let response = spec.resolve().unwrap();
    assert!(!response.is_ok());
    assert_eq!(
        response.missing_required,
        vec![
            "PW".to_string(),
            "SERVICE_IDENTITY".to_string(),
            "SERVICE_KEY".to_string()
        ]
    );

    // The value-free report agrees, so a CI gate sees the gap.
    let report = spec.report().unwrap();
    let status = |name: &str| {
        report
            .secrets
            .iter()
            .find(|entry| entry.name == name)
            .unwrap()
            .status
            .clone()
    };
    assert_eq!(
        status("SERVICE_IDENTITY"),
        ResolutionStatus::MissingRequired
    );
    assert_eq!(status("SERVICE_KEY"), ResolutionStatus::MissingRequired);
    assert_eq!(status("OTHER"), ResolutionStatus::Resolved);

    // Optional declarations degrade to missing optional instead.
    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity", credentials = { password = "PW" }, required = false }
PW = { description = "password", required = false }
SERVICE_KEY = { description = "key", type = "pkcs8_private_key", from = "SERVICE_IDENTITY", required = false }
"#,
        &format!("SERVICE_IDENTITY={archive}\n"),
    );
    let response = spec.resolve().unwrap();
    assert!(response.is_ok());
    assert!(response.secrets.is_empty(), "{:?}", response.secrets.keys());
    assert_eq!(
        response.missing_optional,
        vec![
            "PW".to_string(),
            "SERVICE_IDENTITY".to_string(),
            "SERVICE_KEY".to_string()
        ]
    );
}

#[test]
fn empty_nul_and_oversized_credential_values_are_rejected() {
    let _env = scrub_resolution_env();
    let cases = [
        ("", "empty"),
        ("with\u{0}nul", "NUL"),
        (&"x".repeat(1025), "exceeds 1024 bytes"),
    ];
    for (password, expected) in cases {
        let escaped = password.replace('\u{0}', "\\u0000");
        let spec = null_spec(&format!(
            r#"
[profiles.default]
TLS_IDENTITY = {{ description = "identity", type = "x509_identity", generate = {{ san = ["dns:localhost"] }} }}
PW = {{ description = "password", default = "{escaped}" }}
TLS_PFX = {{ description = "pfx", type = "pkcs12", from = "TLS_IDENTITY", credentials = {{ password = "PW" }} }}
"#
        ));
        let error = spec.resolve().unwrap_err();
        assert!(
            matches!(&error, SecretSpecError::CredentialInvalid { name, role, .. } if name == "TLS_PFX" && role == "password"),
            "{expected}: {error}"
        );
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(error.kind(), "credential_invalid");
    }

    // An omitted binding is the empty-password archive, not an error.
    let spec = null_spec(
        r#"
[profiles.default]
TLS_IDENTITY = { description = "identity", type = "x509_identity", generate = { san = ["dns:localhost"] } }
TLS_PFX = { description = "pfx", type = "pkcs12", from = "TLS_IDENTITY" }
"#,
    );
    let response = spec.resolve().unwrap();
    let pfx = BASE64
        .decode(
            response.secrets["TLS_PFX"]
                .value
                .as_deref()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    open_pfx(&pfx, "");
}

#[test]
fn scopes_fetch_hidden_sources_and_credentials_without_exposing_them() {
    let _env = scrub_resolution_env();
    let body = format!(
        "{GENERATED_PROFILE}\n[scopes.windows]\nsecrets = [\"TLS_PFX\", \"TLS_PFX_PASSWORD\"]\n\n[scopes.key_only]\nsecrets = [\"TLS_KEY\"]\n"
    );

    let mut spec = null_spec(&body);
    spec.set_scope("windows");
    let response = spec.resolve().unwrap();
    assert!(response.is_ok(), "{:?}", response.missing_required);
    assert_eq!(
        response.secrets.keys().collect::<Vec<_>>(),
        vec!["TLS_PFX", "TLS_PFX_PASSWORD"],
        "the hidden identity is fetched but not exposed"
    );
    let password = response.secrets["TLS_PFX_PASSWORD"]
        .value
        .as_deref()
        .unwrap();
    let pfx = fs::read(response.secrets["TLS_PFX"].path.as_deref().unwrap()).unwrap();
    open_pfx(&pfx, password);
    assert_eq!(response.scope.as_deref(), Some("windows"));

    let mut spec = null_spec(&body);
    spec.set_scope("key_only");
    let response = spec.resolve().unwrap();
    assert!(response.is_ok());
    assert_eq!(response.secrets.keys().collect::<Vec<_>>(), vec!["TLS_KEY"]);
    PKey::private_key_from_pem(
        response.secrets["TLS_KEY"]
            .value
            .as_deref()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
}

#[test]
fn declaration_order_does_not_affect_derived_resolution() {
    let _env = scrub_resolution_env();
    // Targets before their source, credentials after their consumer.
    let spec = null_spec(
        r#"
[profiles.default]
TLS_KEY = { description = "key", type = "pkcs8_private_key", from = "TLS_IDENTITY" }
TLS_PFX = { description = "pfx", type = "pkcs12", from = "TLS_IDENTITY", credentials = { password = "PW" } }
TLS_IDENTITY = { description = "identity", type = "x509_identity", generate = { san = ["dns:localhost"] } }
PW = { description = "password", composed = "${PART_A}-${PART_B}" }
PART_B = { description = "b", default = "beta" }
PART_A = { description = "a", default = "alpha" }
"#,
    );
    let response = spec.resolve().unwrap();
    assert!(response.is_ok(), "{:?}", response.missing_required);
    let pfx = BASE64
        .decode(
            response.secrets["TLS_PFX"]
                .value
                .as_deref()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    let opened = open_pfx(&pfx, "alpha-beta");
    let key = PKey::private_key_from_pem(
        response.secrets["TLS_KEY"]
            .value
            .as_deref()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    assert!(opened.pkey.unwrap().public_eq(&key));
}

#[test]
fn json_and_ini_selection_from_declared_secrets() {
    let _env = scrub_resolution_env();
    let spec = null_spec(
        r#"
[profiles.default]
DOCUMENT = { description = "json", default = "{\"database\":{\"password\":\"from-json\",\"port\":5432}}" }
DATABASE_PASSWORD = { description = "password", from = "DOCUMENT", extract = { format = "json", pointer = "/database/password" } }
DATABASE_PORT = { description = "port", from = "DOCUMENT", extract = { format = "json", pointer = "/database/port" }, as_path = true }
INI_DOCUMENT = { description = "ini", default = "[database]\npassword = from-ini\n", as_path = true }
INI_PASSWORD = { description = "ini password", from = "INI_DOCUMENT", extract = { format = "ini", pointer = "/database/password" } }
MISSING_FIELD = { description = "absent", from = "DOCUMENT", extract = { format = "json", pointer = "/database/nope" }, required = false }
"#,
    );
    let response = spec.resolve();
    // A pointer that does not match is a hard error, not a miss: the document
    // resolved and the declaration is wrong.
    let error = response.unwrap_err().to_string();
    assert!(error.contains("MISSING_FIELD"), "{error}");
    assert!(error.contains("/database/nope"), "{error}");

    let spec = null_spec(
        r#"
[profiles.default]
DOCUMENT = { description = "json", default = "{\"database\":{\"password\":\"from-json\",\"port\":5432}}" }
DATABASE_PASSWORD = { description = "password", from = "DOCUMENT", extract = { format = "json", pointer = "/database/password" } }
DATABASE_PORT = { description = "port", from = "DOCUMENT", extract = { format = "json", pointer = "/database/port" }, as_path = true }
INI_DOCUMENT = { description = "ini", default = "[database]\npassword = from-ini\n", as_path = true }
INI_PASSWORD = { description = "ini password", from = "INI_DOCUMENT", extract = { format = "ini", pointer = "/database/password" } }
"#,
    );
    let response = spec.resolve().unwrap();
    assert!(response.is_ok(), "{:?}", response.missing_required);
    let secrets = &response.secrets;
    assert_eq!(
        secrets["DATABASE_PASSWORD"].value.as_deref(),
        Some("from-json")
    );
    assert_eq!(
        fs::read_to_string(secrets["DATABASE_PORT"].path.as_deref().unwrap()).unwrap(),
        "5432"
    );
    assert_eq!(
        secrets["INI_PASSWORD"].value.as_deref(),
        Some("from-ini"),
        "a selection reads an `as_path` source's file"
    );
    assert_eq!(
        secrets["DATABASE_PASSWORD"].source,
        ResolvedSource::Composed
    );
}

#[test]
fn rewrapping_a_stored_identity_under_a_new_password() {
    let _env = scrub_resolution_env();
    let legacy = protected_identity("legacy");
    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
LEGACY_IDENTITY = { description = "legacy", type = "x509_identity", credentials = { password = "LEGACY_PASSWORD" } }
LEGACY_PASSWORD = { description = "legacy password" }
NEW_PASSWORD = { description = "new password", default = "fresh" }
NEW_PFX = { description = "rewrapped", type = "pkcs12", from = "LEGACY_IDENTITY", credentials = { password = "NEW_PASSWORD" }, as_path = true }
"#,
        &format!(
            "LEGACY_IDENTITY={}\nLEGACY_PASSWORD=legacy\n",
            BASE64.encode(&legacy)
        ),
    );
    let response = spec.resolve().unwrap();
    assert!(response.is_ok(), "{:?}", response.missing_required);
    let rewrapped = fs::read(response.secrets["NEW_PFX"].path.as_deref().unwrap()).unwrap();
    assert!(
        Pkcs12::from_der(&rewrapped)
            .unwrap()
            .parse2("legacy")
            .is_err()
    );
    let opened = open_pfx(&rewrapped, "fresh");
    let original = open_pfx(&legacy, "legacy");
    assert!(opened.pkey.unwrap().public_eq(&original.pkey.unwrap()));
    assert_ne!(rewrapped, legacy, "a rewrapped archive is re-encrypted");
}

#[test]
fn an_optional_identity_that_is_absent_omits_its_projections() {
    let _env = scrub_resolution_env();
    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity", required = false }
SERVICE_KEY = { description = "key", type = "pkcs8_private_key", from = "SERVICE_IDENTITY", required = false }
SERVICE_PFX = { description = "pfx", type = "pkcs12", from = "SERVICE_IDENTITY" }
"#,
        "",
    );
    let response = spec.resolve().unwrap();
    assert!(!response.is_ok());
    assert_eq!(response.missing_required, vec!["SERVICE_PFX".to_string()]);
    assert_eq!(
        response.missing_optional,
        vec!["SERVICE_IDENTITY".to_string(), "SERVICE_KEY".to_string()]
    );
}

#[test]
fn a_stored_identity_with_an_invalid_encoding_or_archive_fails_cleanly() {
    let _env = scrub_resolution_env();
    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity" }
"#,
        "SERVICE_IDENTITY=not*base64!\n",
    );
    let error = spec.resolve().unwrap_err();
    assert!(
        matches!(&error, SecretSpecError::DecodeFailed { encoding, .. } if *encoding == "base64"),
        "{error}"
    );

    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity", encoding = "hex" }
"#,
        &format!("SERVICE_IDENTITY={}\n", HEXLOWER.encode(b"not an archive")),
    );
    let text = spec.resolve().unwrap_err().to_string();
    assert!(text.contains("invalid PKCS#12 identity"), "{text}");
}

// ---------------------------------------------------------------------------
// Reports and provenance
// ---------------------------------------------------------------------------

#[test]
fn value_free_reports_predict_derivation_without_materializing() {
    let _env = scrub_resolution_env();
    let archive = BASE64.encode(&protected_identity("pw"));
    let (dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity", credentials = { password = "PW" }, as_path = true }
PW = { description = "password" }
SERVICE_KEY = { description = "key", type = "pkcs8_private_key", from = "SERVICE_IDENTITY", as_path = true }
DOCUMENT = { description = "doc", default = "{\"a\":1}" }
FIELD = { description = "field", from = "DOCUMENT", extract = { format = "json", pointer = "/a" } }
DSN = { description = "dsn", composed = "x=${FIELD}" }
"#,
        &format!("SERVICE_IDENTITY={archive}\nPW=pw\n"),
    );

    let before: Vec<_> = fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            name.ends_with(".pfx") || name.ends_with(".pem")
        })
        .map(|entry| entry.path())
        .collect();

    let report = spec.report().unwrap();
    let entry = |name: &str| {
        report
            .secrets
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    assert_eq!(entry("SERVICE_IDENTITY").status, ResolutionStatus::Resolved);
    assert!(entry("SERVICE_IDENTITY").derivation.is_none());
    assert_eq!(
        entry("SERVICE_KEY").derivation,
        Some(Derivation::ConvertedFrom("SERVICE_IDENTITY".to_string()))
    );
    assert_eq!(
        entry("FIELD").derivation,
        Some(Derivation::SelectedFrom("DOCUMENT".to_string()))
    );
    assert_eq!(entry("DSN").derivation, Some(Derivation::Composed));
    assert!(entry("SERVICE_KEY").composed);
    assert!(entry("SERVICE_KEY").as_path);
    let explained = report.to_explain_string();
    assert!(
        explained.contains("converted from SERVICE_IDENTITY"),
        "{explained}"
    );
    assert!(explained.contains("selected from DOCUMENT"), "{explained}");
    assert!(explained.contains("ok        composed"), "{explained}");

    let after: Vec<_> = fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            name.ends_with(".pfx") || name.ends_with(".pem")
        })
        .map(|entry| entry.path())
        .filter(|path| !before.contains(path))
        .collect();
    assert!(
        after.is_empty(),
        "report must not materialize files: {after:?}"
    );

    let stripped = spec.resolve_without_values().unwrap();
    assert!(stripped.is_ok());
    assert_eq!(stripped.secrets["SERVICE_KEY"].value, None);
    assert_eq!(stripped.secrets["SERVICE_KEY"].path, None);
    assert_eq!(
        stripped.secrets["SERVICE_KEY"].source,
        ResolvedSource::Composed
    );
    drop(dir);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn derived_secrets_are_read_only_and_name_their_source() {
    let _env = scrub_resolution_env();
    let (_dir, spec) = dotenv_spec(
        r#"
[profiles.default]
SERVICE_IDENTITY = { description = "identity", type = "x509_identity" }
SERVICE_KEY = { description = "key", type = "pkcs8_private_key", from = "SERVICE_IDENTITY" }
DOCUMENT = { description = "doc" }
FIELD = { description = "field", from = "DOCUMENT", extract = { format = "json", pointer = "/a" } }
STORED_FIELD = { description = "stored field", extract = { format = "json", pointer = "/a" }, required = false }
DSN = { description = "dsn", composed = "x=${FIELD}" }
"#,
        "",
    );

    let error = spec
        .set("SERVICE_KEY", Some("value".to_string()))
        .unwrap_err();
    assert!(
        matches!(&error, SecretSpecError::DerivedSecretReadOnly { name, from } if name == "SERVICE_KEY" && from == "SERVICE_IDENTITY"),
        "{error}"
    );
    assert_eq!(error.kind(), "derived_secret_read_only");
    assert!(
        error
            .to_string()
            .contains("change 'SERVICE_IDENTITY' instead")
    );

    let error = spec.set("FIELD", Some("value".to_string())).unwrap_err();
    assert!(
        matches!(&error, SecretSpecError::DerivedSecretReadOnly { from, .. } if from == "DOCUMENT"),
        "a selection names its source, not the extract rule: {error}"
    );
    let error = spec.delete("SERVICE_KEY").unwrap_err();
    assert!(
        matches!(&error, SecretSpecError::DerivedSecretReadOnly { from, .. } if from == "SERVICE_IDENTITY"),
        "{error}"
    );
    let error = spec.delete("FIELD").unwrap_err();
    assert!(
        matches!(&error, SecretSpecError::DerivedSecretReadOnly { .. }),
        "{error}"
    );

    // Existing read-only classes are unchanged.
    assert!(matches!(
        spec.set("STORED_FIELD", Some("v".to_string())).unwrap_err(),
        SecretSpecError::ExtractedSecretReadOnly(_)
    ));
    assert!(matches!(
        spec.set("DSN", Some("v".to_string())).unwrap_err(),
        SecretSpecError::ComposedSecretReadOnly(_)
    ));

    // The source itself is writable, and the identity gets its stored form.
    spec.set("DOCUMENT", Some(r#"{"a":"one"}"#.to_string()))
        .unwrap();
    spec.set(
        "SERVICE_IDENTITY",
        Some(BASE64.encode(&generated_identity())),
    )
    .unwrap();
    let response = spec.resolve().unwrap();
    assert!(response.is_ok(), "{:?}", response.missing_required);
    assert_eq!(response.secrets["FIELD"].value.as_deref(), Some("one"));
    assert!(
        response.secrets["SERVICE_KEY"]
            .value
            .as_deref()
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
}
