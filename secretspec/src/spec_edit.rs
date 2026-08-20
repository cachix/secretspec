//! Format-preserving edits to a `secretspec.toml` root specification.

use crate::config::Secret;
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use toml_edit::{DocumentMut, InlineTable, Item, Table, Value};

/// Reject names that cannot occupy a flattened secret key in a profile.
pub(crate) fn validate_secret_name(name: &str) -> Result<()> {
    if !crate::config::is_valid_identifier(name) {
        return Err(miette!(
            "Invalid secret name '{}': must be a valid identifier (alphanumeric and underscores, not starting with a number)",
            name
        ));
    }
    if name == "defaults" {
        return Err(miette!(
            "Secret name 'defaults' is reserved for profile defaults"
        ));
    }
    Ok(())
}

/// Add the description-only declaration used by `secretspec add`.
#[cfg(feature = "cli")]
pub(crate) fn add_description(
    source: &str,
    profile: &str,
    name: &str,
    description: &str,
) -> Result<String> {
    validate_secret_name(name)?;
    if description.trim().is_empty() {
        return Err(miette!("Secret description cannot be empty"));
    }

    let mut secret = InlineTable::new();
    secret.insert("description", Value::from(description));
    insert(source, profile, name, secret)
}

/// Add a complete declaration without reformatting the rest of the document.
pub(crate) fn add_secret(
    source: &str,
    profile: &str,
    name: &str,
    secret: &Secret,
) -> Result<String> {
    insert(source, profile, name, secret_inline_table(secret)?)
}

/// Replace a declaration in place, preserving its key decor and table position.
pub(crate) fn replace_secret(
    source: &str,
    profile: &str,
    name: &str,
    secret: &Secret,
) -> Result<String> {
    validate_secret_name(name)?;
    let mut doc = parse(source)?;
    let table = profile_table_mut(&mut doc, profile)?;
    let decor = match table.get(name) {
        Some(Item::Value(value)) => Some(value.decor().clone()),
        Some(Item::Table(table)) => Some(table.decor().clone()),
        Some(Item::ArrayOfTables(_)) | Some(Item::None) => None,
        None => {
            return Err(miette!(
                "Secret '{}' is not declared in profile '{}'",
                name,
                profile
            ));
        }
    };

    let mut replacement = Value::InlineTable(secret_inline_table(secret)?);
    if let Some(decor) = decor {
        *replacement.decor_mut() = decor;
    }
    table.insert(name, Item::Value(replacement));
    Ok(doc.to_string())
}

/// Remove one declaration without reformatting the rest of the document.
pub(crate) fn remove_secret(
    source: &str,
    profile: &str,
    name: &str,
    remove_empty_profile: bool,
) -> Result<String> {
    validate_secret_name(name)?;
    let mut doc = parse(source)?;
    {
        let table = profile_table_mut(&mut doc, profile)?;
        if table.remove(name).is_none() {
            return Err(miette!(
                "Secret '{}' is not declared in profile '{}'",
                name,
                profile
            ));
        }
    }
    if remove_empty_profile {
        let profiles = doc
            .get_mut("profiles")
            .and_then(Item::as_table_like_mut)
            .expect("profile lookup above verified the profiles table");
        let is_empty = profiles
            .get(profile)
            .and_then(Item::as_table_like)
            .is_some_and(toml_edit::TableLike::is_empty);
        if is_empty {
            profiles.remove(profile);
        }
    }
    Ok(doc.to_string())
}

fn insert(source: &str, profile: &str, name: &str, declaration: InlineTable) -> Result<String> {
    validate_secret_name(name)?;
    let mut doc = parse(source)?;
    let profiles = doc
        .get_mut("profiles")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("secretspec.toml does not contain a [profiles] table"))?;
    if !profiles.contains_key(profile) {
        profiles.insert(profile, Item::Table(Table::new()));
    }
    let table = profiles
        .get_mut(profile)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("Profile '{}' is not a TOML table", profile))?;
    if table.contains_key(name) {
        return Err(miette!(
            "Secret '{}' is already declared in profile '{}'",
            name,
            profile
        ));
    }
    table.insert(name, toml_edit::value(declaration));
    Ok(doc.to_string())
}

fn parse(source: &str) -> Result<DocumentMut> {
    source
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err("Failed to parse secretspec.toml for editing")
}

fn profile_table_mut<'a>(
    doc: &'a mut DocumentMut,
    profile: &str,
) -> Result<&'a mut dyn toml_edit::TableLike> {
    doc.get_mut("profiles")
        .and_then(Item::as_table_like_mut)
        .and_then(|profiles| profiles.get_mut(profile))
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("Profile '{}' is not declared in this spec", profile))
}

fn secret_inline_table(secret: &Secret) -> Result<InlineTable> {
    secret
        .validate_description()
        .map_err(|error| miette!(error))?;

    // The value serializer rejects nested tables, which `ref`, `refs`,
    // `extract`, `generate`, and presence-group requiredness can contain.
    let document = toml_edit::ser::to_document(secret)
        .into_diagnostic()
        .wrap_err("Failed to render the secret declaration as TOML")?;
    let mut inline = InlineTable::new();
    for (key, item) in document.as_table().iter() {
        let value = item
            .clone()
            .into_value()
            .map_err(|_| miette!("Secret field '{}' has no inline TOML form", key))?;
        inline.insert(key, value);
    }
    Ok(inline)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_TEXT: &str = r#"[project]
name = "demo"
revision = "1.0"

# Keep this comment and declaration order.
[profiles.default]
FIRST = { description = "first" }
LAST = { description = "last" }

[profiles.default.TABLE]
description = "full table"
required = false
"#;

    fn secret(description: &str) -> Secret {
        Secret {
            description: Some(description.to_string()),
            required: Some(true),
            ..Secret::default()
        }
    }

    #[test]
    fn add_replace_and_remove_restore_the_exact_spec_text() {
        let added = add_secret(SPEC_TEXT, "default", "SCRATCH", &secret("temporary")).unwrap();
        assert!(added.contains("# Keep this comment"));
        assert!(added.find("FIRST").unwrap() < added.find("LAST").unwrap());
        assert!(added.contains("[profiles.default.TABLE]"));

        let replaced =
            replace_secret(&added, "default", "SCRATCH", &secret("replacement")).unwrap();
        assert!(replaced.contains("replacement"));

        let restored = remove_secret(&replaced, "default", "SCRATCH", false).unwrap();
        assert_eq!(restored, SPEC_TEXT);
    }

    #[test]
    fn remove_cleans_up_only_profiles_marked_as_synthesized() {
        let added = add_secret(SPEC_TEXT, "production", "SCRATCH", &secret("temporary")).unwrap();
        let restored = remove_secret(&added, "production", "SCRATCH", true).unwrap();
        assert_eq!(restored, SPEC_TEXT);

        let with_empty_profile = format!("{SPEC_TEXT}\n[profiles.production]\n");
        let added = add_secret(
            &with_empty_profile,
            "production",
            "SCRATCH",
            &secret("temporary"),
        )
        .unwrap();
        let restored = remove_secret(&added, "production", "SCRATCH", false).unwrap();
        assert_eq!(restored, with_empty_profile);
    }

    #[test]
    fn complete_secret_edits_use_the_shared_description_rule() {
        let whitespace = add_secret(SPEC_TEXT, "default", "SPACE", &secret(" "));
        assert!(whitespace.is_ok());

        let empty = add_secret(SPEC_TEXT, "default", "EMPTY", &secret(""))
            .unwrap_err()
            .to_string();
        assert!(empty.contains("description cannot be empty"), "{empty}");
    }

    #[test]
    fn invalid_edit_targets_are_rejected_without_changing_source() {
        let duplicate = add_secret(SPEC_TEXT, "default", "FIRST", &secret("duplicate"))
            .unwrap_err()
            .to_string();
        assert!(duplicate.contains("already declared"), "{duplicate}");

        let missing = replace_secret(SPEC_TEXT, "default", "MISSING", &secret("replacement"))
            .unwrap_err()
            .to_string();
        assert!(missing.contains("not declared"), "{missing}");

        let missing = remove_secret(SPEC_TEXT, "missing", "FIRST", false)
            .unwrap_err()
            .to_string();
        assert!(missing.contains("not declared in this spec"), "{missing}");
    }
}
