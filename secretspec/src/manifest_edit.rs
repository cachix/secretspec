//! Declaration edits to a `secretspec.toml` source string.
//!
//! Split out of the `cli` module, behind its own `manifest-edit` feature, so a
//! caller can perform the edit without taking on the interactive CLI's
//! dependency surface — `clap` and `inquire` come with `cli` and are not
//! something every embedder wants.
//!
//! Everything here is pure: it takes manifest text and returns manifest text,
//! touching no filesystem. Writing is deliberately the caller's problem,
//! because the safe way to write differs by caller — the CLI replaces its
//! manifest atomically through a temporary file, while a caller editing a file
//! whose ownership or mode must survive has to write it in place.
//!
//! [`crate::Spec`] wraps these as `add_secret_to_text` and
//! `remove_secret_from_text`, which additionally revalidate the result. Prefer
//! those unless you specifically want the text without the semantic model.

use miette::{IntoDiagnostic, Result, WrapErr, miette};

/// Rejects names that cannot occupy a flattened secret key in a profile.
pub(crate) fn validate_add_secret_name(name: &str) -> Result<()> {
    if !crate::config::is_valid_identifier(name) {
        return Err(miette!(
            "Invalid secret name '{}': must be a valid identifier (alphanumeric and underscores, not starting with a number)",
            name
        ));
    }
    // `Profile` reserves this key for its defaults table before flattening all
    // remaining keys into secret declarations. Without an explicit check, the
    // edit would be valid TOML but would not actually declare a secret.
    if name == "defaults" {
        return Err(miette!(
            "Secret name 'defaults' is reserved for profile defaults"
        ));
    }
    Ok(())
}

/// Adds one secret to a manifest document without re-serializing the rest.
///
/// `toml_edit` retains the user's comments, whitespace, ordering, and any syntax
/// that is not represented by [`crate::config::Config`]. The caller validates
/// the selected profile against the fully loaded configuration first; this
/// helper creates a local profile table when that profile currently comes only
/// from `extends`.
///
/// Declares only a description, which is what `secretspec add` prompts for. Use
/// [`add_secret_value_to_manifest`] to declare requiredness, a default, a
/// presence group, or any other field.
pub fn add_secret_to_manifest(
    source: &str,
    profile: &str,
    name: &str,
    description: &str,
) -> Result<String> {
    use toml_edit::{InlineTable, Value};

    // Name before description, matching the order this has always reported the
    // two: `insert_declaration` validates the name again, but only after the
    // description check, which would silently reorder the diagnostics a caller
    // sees for input that is wrong in both ways.
    validate_add_secret_name(name)?;
    if description.trim().is_empty() {
        return Err(miette!("Secret description cannot be empty"));
    }

    let mut secret = InlineTable::new();
    secret.insert("description", Value::from(description));
    insert_declaration(source, profile, name, secret)
}

/// Insert a complete [`crate::config::Secret`] declaration into a manifest.
///
/// The general form of [`add_secret_to_manifest`], which covers only the one
/// key the CLI's `add` prompts for. Every other declared field — `required`,
/// `default`,
/// `composed`, `providers`, `ref`/`refs`, `as_path`, `encoding`, `extract`,
/// `generate`, `prompt`, and the presence groups — is emitted by the same serde
/// representation the parser reads, so the written keys and the accepted keys
/// cannot drift apart as the schema grows.
///
/// Unset fields are omitted rather than written as explicit nulls, which is what
/// keeps the emitted declaration a single readable line and keeps the round-trip
/// with [`remove_secret_from_manifest`] byte-exact.
pub fn add_secret_value_to_manifest(
    source: &str,
    profile: &str,
    name: &str,
    secret: &crate::config::Secret,
) -> Result<String> {
    use toml_edit::ser::to_document;

    if secret
        .description
        .as_deref()
        .is_none_or(|description| description.trim().is_empty())
    {
        return Err(miette!("Secret description cannot be empty"));
    }

    // Serialized through a document and then flattened to an inline table: the
    // value serializer refuses a nested table, which `ref`, `refs`, `extract`,
    // `generate`, and a presence group's `required` all produce.
    let document = to_document(secret)
        .into_diagnostic()
        .wrap_err("Failed to render the secret declaration as TOML")?;
    let mut inline = toml_edit::InlineTable::new();
    for (key, item) in document.as_table().iter() {
        let value = item
            .clone()
            .into_value()
            .map_err(|_| miette!("Secret field '{}' has no inline TOML form", key))?;
        inline.insert(key, value);
    }

    insert_declaration(source, profile, name, inline)
}

/// Place `declaration` at `profile.name`, creating the profile table if needed.
fn insert_declaration(
    source: &str,
    profile: &str,
    name: &str,
    declaration: toml_edit::InlineTable,
) -> Result<String> {
    use toml_edit::{DocumentMut, Item, Table};

    validate_add_secret_name(name)?;

    let mut doc = source
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err("Failed to parse secretspec.toml for editing")?;
    let profiles = doc
        .get_mut("profiles")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("secretspec.toml does not contain a [profiles] table"))?;

    if !profiles.contains_key(profile) {
        profiles.insert(profile, Item::Table(Table::new()));
    }
    let profile_table = profiles
        .get_mut(profile)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("Profile '{}' is not a TOML table", profile))?;

    if profile_table.contains_key(name) {
        return Err(miette!(
            "Secret '{}' is already declared in profile '{}'",
            name,
            profile
        ));
    }

    profile_table.insert(name, toml_edit::value(declaration));
    Ok(doc.to_string())
}

/// Whether `source` declares `name` in `profile`.
///
/// Parsed, not searched. A substring test would match the name inside a comment
/// or another secret's description, and the inverse mistake is worse because it
/// is silent — a caller relying on this to protect tracked declarations would
/// get a wrong answer with no indication.
///
/// A malformed manifest is an `Err`, never a `false`. Callers using this as a
/// guard must fail closed, and that decision belongs to them rather than being
/// smuggled in here as a default: "I could not parse it" is not "the name is
/// absent from it".
pub fn declares_secret(source: &str, profile: &str, name: &str) -> Result<bool> {
    use toml_edit::{DocumentMut, Item};

    let doc = source
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err("Failed to parse secretspec.toml")?;
    Ok(doc
        .get("profiles")
        .and_then(Item::as_table_like)
        .and_then(|profiles| profiles.get(profile))
        .and_then(Item::as_table_like)
        .is_some_and(|table| table.contains_key(name)))
}

/// Remove a secret declaration from a `secretspec.toml` source string.
///
/// The inverse of [`add_secret_to_manifest`], and pure for the same reason.
///
/// `toml_edit` preserves the formatting of everything it does not touch, so
/// removing a declaration that `add_secret_to_manifest` inserted restores the
/// original text byte for byte. That matters more than it looks: the downstream
/// boundary's `template-check` compares the runtime manifest against the tracked
/// template as raw bytes, so "undo" has to mean *byte-identical*, not merely
/// semantically equivalent.
///
/// Removing a name that is not declared is an error rather than a silent no-op.
/// A caller undeclaring something already absent has a wrong model of the
/// manifest, and saying so is cheaper than letting them believe they cleaned up
/// state that was never there.
pub fn remove_secret_from_manifest(source: &str, profile: &str, name: &str) -> Result<String> {
    use toml_edit::{DocumentMut, Item};

    validate_add_secret_name(name)?;

    let mut doc = source
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err("Failed to parse secretspec.toml for editing")?;
    let profiles = doc
        .get_mut("profiles")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("secretspec.toml does not contain a [profiles] table"))?;

    let profile_table = profiles
        .get_mut(profile)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("Profile '{}' is not declared in this manifest", profile))?;

    if profile_table.remove(name).is_none() {
        return Err(miette!(
            "Secret '{}' is not declared in profile '{}'",
            name,
            profile
        ));
    }

    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
EXISTING = { description = "already here" }
"#;

    /// Declaration carrying `description` plus `required`, for the tests that
    /// need a longer inline table than `add_secret_to_manifest` can produce.
    fn required_secret(description: &str) -> crate::config::Secret {
        crate::config::Secret {
            description: Some(description.into()),
            required: Some(true),
            ..crate::config::Secret::default()
        }
    }

    #[test]
    fn removing_an_added_declaration_restores_the_original_bytes() {
        // The property that makes "undo" usable by a caller comparing manifests
        // as raw BYTES -- a drift checker diffing a live manifest against a
        // tracked template gets a permanent false positive from anything
        // weaker. toml_edit preserves untouched formatting; this proves it.
        let added = add_secret_to_manifest(MANIFEST, "default", "SCRATCH", "temp").unwrap();
        assert_ne!(added, MANIFEST, "add did not change anything");

        let removed = remove_secret_from_manifest(&added, "default", "SCRATCH").unwrap();

        assert_eq!(removed, MANIFEST);
    }

    #[test]
    fn add_secret_to_manifest_declares_only_a_description() {
        // Asserted on the emitted declaration, not on the whole document: a
        // whole-file `contains("required")` would also be satisfied (or
        // broken) by any sibling or comment carrying that word.
        let added = add_secret_to_manifest(MANIFEST, "default", "SCRATCH", "temp").unwrap();
        assert!(added.contains("SCRATCH = { description = \"temp\" }"));
    }

    #[test]
    fn removing_a_multi_key_declaration_also_restores_the_original_bytes() {
        // A second key makes the edit longer than the single-key path the
        // round-trip test above covers, and the undo has to be just as exact.
        let added =
            add_secret_value_to_manifest(MANIFEST, "default", "SCRATCH", &required_secret("temp"))
                .unwrap();
        assert!(added.contains("required = true"), "{added}");
        assert_ne!(added, MANIFEST, "add did not change anything");

        let removed = remove_secret_from_manifest(&added, "default", "SCRATCH").unwrap();

        assert_eq!(removed, MANIFEST);
    }

    #[test]
    fn round_trip_survives_a_document_with_presence_groups_and_full_tables() {
        // The fixture above is inline-table-only. toml_edit is likeliest to
        // reserialize a document that mixes shapes, so the byte-exact claim is
        // worth proving against one that does: a `required` *table* (presence
        // group), a full `[profiles.x.y]` table, and a dotted key.
        let manifest = r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
GROUPED = { description = "in a group", required = { at_least_one = "auth" } }
"dotted.name" = { description = "quoted key" }

[profiles.default.NESTED]
description = "declared as a full table"
required = false
"#;

        let added = add_secret_to_manifest(manifest, "default", "SCRATCH", "temp").unwrap();
        let removed = remove_secret_from_manifest(&added, "default", "SCRATCH").unwrap();
        assert_eq!(removed, manifest);

        let added =
            add_secret_value_to_manifest(manifest, "default", "SCRATCH", &required_secret("temp"))
                .unwrap();
        let removed = remove_secret_from_manifest(&added, "default", "SCRATCH").unwrap();
        assert_eq!(removed, manifest);
    }

    #[test]
    fn an_added_declaration_actually_compiles_to_what_was_asked_for() {
        // The product claim, asserted through the engine rather than through
        // the emitted text: the written bytes have to parse and validate into a
        // secret carrying the requiredness the caller declared.
        use crate::config::{Config, Secret};

        let optional = Secret {
            description: Some("temp".into()),
            required: Some(false),
            ..Secret::default()
        };
        let added =
            add_secret_value_to_manifest(MANIFEST, "default", "SCRATCH", &optional).unwrap();

        let config: Config = toml::from_str(&added).expect("edited manifest must parse");
        config.validate().expect("edited manifest must validate");
        assert_eq!(
            config.profiles["default"].secrets["SCRATCH"].required,
            Some(false)
        );
    }

    #[test]
    fn removing_a_declaration_that_is_not_there_is_an_error() {
        let err = remove_secret_from_manifest(MANIFEST, "default", "ABSENT").unwrap_err();
        assert!(err.to_string().contains("not declared"), "{err}");
    }

    #[test]
    fn removing_leaves_sibling_declarations_alone() {
        let added = add_secret_to_manifest(MANIFEST, "default", "SCRATCH", "temp").unwrap();
        let removed = remove_secret_from_manifest(&added, "default", "SCRATCH").unwrap();
        assert!(removed.contains("EXISTING"));
    }

    #[test]
    fn declares_secret_sees_a_real_declaration() {
        assert!(declares_secret(MANIFEST, "default", "EXISTING").unwrap());
        assert!(!declares_secret(MANIFEST, "default", "ABSENT").unwrap());
    }

    #[test]
    fn declares_secret_is_not_fooled_by_a_comment_or_a_description() {
        // Why this is parsed rather than searched. Both of these contain the
        // name as text while declaring nothing of the sort.
        let manifest = r#"[project]
name = "demo"

[profiles.default]
# TODO: declare LOOKALIKE next release
OTHER = { description = "unrelated, mentions LOOKALIKE in prose" }
"#;
        assert!(!declares_secret(manifest, "default", "LOOKALIKE").unwrap());
    }

    #[test]
    fn declares_secret_reports_an_unparseable_manifest_rather_than_false() {
        // A guard built on this must fail closed, which it cannot do if a
        // broken file is indistinguishable from an absent name.
        assert!(declares_secret("this is not toml {{{", "default", "ANY").is_err());
    }

    #[test]
    fn the_full_declaration_writer_emits_only_the_fields_that_were_set() {
        // What keeps the emitted declaration a readable single line, and what
        // makes the byte-exact undo possible at all: an unset field must be
        // absent, not written as an explicit null or a default.
        use crate::config::Secret as ConfigSecret;

        let secret = ConfigSecret {
            description: Some("temp".into()),
            required: Some(true),
            ..ConfigSecret::default()
        };

        let added = add_secret_value_to_manifest(MANIFEST, "default", "SCRATCH", &secret).unwrap();

        assert!(added.contains("SCRATCH = { description = \"temp\", required = true }"));
    }

    #[test]
    fn the_full_declaration_writer_round_trips_a_nested_field() {
        // `ref` serializes as a nested table rather than a scalar, so a writer
        // that only knew how to place scalars into an inline table would fail
        // here -- and it has to undo just as exactly as a scalar-only one.
        use crate::config::{NativeAddress, Secret as ConfigSecret};

        let secret = ConfigSecret {
            description: Some("temp".into()),
            reference: Some(NativeAddress {
                item: "db".into(),
                field: Some("password".into()),
                ..NativeAddress::default()
            }),
            ..ConfigSecret::default()
        };

        let added = add_secret_value_to_manifest(MANIFEST, "default", "SCRATCH", &secret).unwrap();
        assert!(added.contains(r#"item = "db""#), "{added}");

        let removed = remove_secret_from_manifest(&added, "default", "SCRATCH").unwrap();

        assert_eq!(removed, MANIFEST);
    }

    #[test]
    fn the_full_declaration_writer_still_requires_a_description() {
        use crate::config::Secret as ConfigSecret;

        let err =
            add_secret_value_to_manifest(MANIFEST, "default", "SCRATCH", &ConfigSecret::default())
                .unwrap_err();

        assert!(err.to_string().contains("description"), "{err}");
    }

    #[test]
    fn declares_secret_is_profile_scoped() {
        let manifest = r#"[project]
name = "demo"

[profiles.default]
ONLY_DEFAULT = { description = "d" }

[profiles.production]
ONLY_PROD = { description = "p" }
"#;
        assert!(declares_secret(manifest, "default", "ONLY_DEFAULT").unwrap());
        assert!(!declares_secret(manifest, "production", "ONLY_DEFAULT").unwrap());
    }
}
