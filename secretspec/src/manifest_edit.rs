//! Declaration edits to a `secretspec.toml` source string.
//!
//! Split out of the `cli` module so a caller can perform the edit without
//! the CLI-only shell-completion tooling `cli` also pulls in
//! (`clap_complete`, `clap_complete_nushell`, `is_executable`). `cli` still
//! depends on this module — nothing about its behavior changes — but a
//! caller that only needs to add a secret declaration can take
//! `manifest-edit` alone.
//!
//! Everything here is pure — it takes manifest text and returns manifest
//! text. Writing is the caller's problem, deliberately: different callers
//! have different write strategies (the CLI replaces its manifest atomically
//! via a temporary file).

use miette::{IntoDiagnostic, Result, WrapErr, miette};

/// Rejects names that cannot occupy a flattened secret key in [`crate::Profile`].
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
/// that is not represented by [`crate::Config`]. The caller validates the selected
/// profile against the fully loaded configuration first; this helper creates a
/// local profile table when that profile currently comes only from `extends`.
///
/// `required` is tri-state, and the third state is why it is not a plain
/// `bool`. `None` writes no `required` key, leaving the secret to inherit
/// `[defaults] required` from its profile. `Some(v)` writes `required = v`
/// explicitly, the same shape `secretspec init`'s generator emits.
///
/// Treating an omitted flag as "required" would be wrong: a profile carrying
/// `defaults = { required = false }` makes an omitted key resolve to
/// *optional*, so without an explicit `Some(true)` there would be no way to
/// declare a required secret in such a profile at all.
///
/// A presence group (`at_least_one`/`exactly_one`) is out of scope here: it
/// spans several secrets at once and does not fit a single-secret declaration.
pub fn add_secret_to_manifest(
    source: &str,
    profile: &str,
    name: &str,
    description: &str,
    required: Option<bool>,
) -> Result<String> {
    use toml_edit::{DocumentMut, InlineTable, Item, Table, Value};

    validate_add_secret_name(name)?;
    if description.trim().is_empty() {
        return Err(miette!("Secret description cannot be empty"));
    }

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

    let mut secret = InlineTable::new();
    secret.insert("description", Value::from(description));
    if let Some(required) = required {
        secret.insert("required", Value::from(required));
    }
    profile_table.insert(name, toml_edit::value(secret));

    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn add_secret_to_manifest_preserves_comments_and_other_tables() {
        let source = r#"# Project documentation
[project]
name = "demo"
revision = "1.0"

[profiles.default]
# Keep this explanation attached to the existing secret.
DATABASE_URL = { description = "Database connection string" }

[providers]
local = "dotenv://.env"
"#;

        let updated =
            add_secret_to_manifest(source, "default", "API_KEY", "API access token", None).unwrap();

        assert!(updated.contains("# Project documentation"));
        assert!(updated.contains("# Keep this explanation attached to the existing secret."));
        assert!(updated.contains("local = \"dotenv://.env\""));
        assert!(updated.contains("API_KEY = { description = \"API access token\" }"));

        let config: Config = toml::from_str(&updated).expect("edited manifest must parse");
        config.validate().expect("edited manifest must validate");
        assert_eq!(
            config.profiles["default"].secrets["API_KEY"]
                .description
                .as_deref(),
            Some("API access token")
        );
    }

    #[test]
    fn add_secret_to_manifest_can_overlay_an_inherited_profile() {
        let source = r#"[project]
name = "demo"
revision = "1.0"
extends = ["../shared"]

[profiles.default]
LOCAL = { description = "Local secret" }
"#;

        let updated =
            add_secret_to_manifest(source, "production", "API_KEY", "API access token", None)
                .unwrap();

        assert!(updated.contains("[profiles.production]"));
        assert!(updated.contains("API_KEY = { description = \"API access token\" }"));
    }

    #[test]
    fn add_secret_to_manifest_rejects_invalid_or_duplicate_declarations() {
        let source = r#"[profiles.default]
API_KEY = { description = "Existing" }
"#;

        let invalid = add_secret_to_manifest(source, "default", "1BAD", "Description", None)
            .unwrap_err()
            .to_string();
        assert!(invalid.contains("Invalid secret name"));

        let reserved = add_secret_to_manifest(source, "default", "defaults", "Description", None)
            .unwrap_err()
            .to_string();
        assert!(reserved.contains("reserved for profile defaults"));

        let duplicate = add_secret_to_manifest(source, "default", "API_KEY", "Description", None)
            .unwrap_err()
            .to_string();
        assert!(duplicate.contains("already declared"));

        let empty = add_secret_to_manifest(source, "default", "NEW_KEY", "   ", None)
            .unwrap_err()
            .to_string();
        assert!(empty.contains("description cannot be empty"));
    }

    const MANIFEST: &str = r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
EXISTING = { description = "already here" }
"#;

    #[test]
    fn add_secret_to_manifest_omits_required_when_unspecified() {
        // Asserted on the emitted declaration rather than the whole document:
        // a document-wide `contains("required")` would also be satisfied, or
        // broken, by any sibling or comment carrying that word.
        let added = add_secret_to_manifest(MANIFEST, "default", "SCRATCH", "temp", None).unwrap();
        assert!(added.contains("SCRATCH = { description = \"temp\" }"));
    }

    #[test]
    fn add_secret_to_manifest_writes_the_requiredness_it_is_given() {
        let optional =
            add_secret_to_manifest(MANIFEST, "default", "SCRATCH", "temp", Some(false)).unwrap();
        assert!(optional.contains("SCRATCH = { description = \"temp\", required = false }"));

        let required =
            add_secret_to_manifest(MANIFEST, "default", "SCRATCH", "temp", Some(true)).unwrap();
        assert!(required.contains("SCRATCH = { description = \"temp\", required = true }"));
    }

    #[test]
    fn an_explicit_requiredness_survives_into_the_loaded_config() {
        // The product claim, asserted through the config model rather than the
        // emitted text: `check` fails on a required-but-unset secret and
        // passes on an optional-but-unset one, so the written bytes have to
        // load as a secret carrying that requiredness.
        for requiredness in [Some(true), Some(false)] {
            let added =
                add_secret_to_manifest(MANIFEST, "default", "SCRATCH", "temp", requiredness)
                    .unwrap();
            let config: Config = toml::from_str(&added).expect("edited manifest must parse");
            config.validate().expect("edited manifest must validate");

            assert_eq!(
                config.profiles["default"].secrets["SCRATCH"].required,
                requiredness
            );
        }
    }

    #[test]
    fn an_explicit_requiredness_leaves_richer_documents_untouched() {
        // The fixtures above are inline-table-only. toml_edit is likeliest to
        // reserialize a document that mixes shapes, so the "touches nothing
        // else" claim is worth proving against one that does: a `required`
        // *table* (presence group), a full `[profiles.x.y]` table, and a
        // quoted dotted key.
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

        for requiredness in [None, Some(true), Some(false)] {
            let added =
                add_secret_to_manifest(manifest, "default", "SCRATCH", "temp", requiredness)
                    .unwrap();

            for untouched in [
                r#"GROUPED = { description = "in a group", required = { at_least_one = "auth" } }"#,
                r#""dotted.name" = { description = "quoted key" }"#,
                "[profiles.default.NESTED]",
                r#"description = "declared as a full table""#,
            ] {
                assert!(
                    added.contains(untouched),
                    "{requiredness:?} lost: {untouched}"
                );
            }
        }
    }
}
