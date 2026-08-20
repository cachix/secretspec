//! Format-preserving edits to a `secretspec.toml` root document.

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
pub(crate) fn remove_secret(source: &str, profile: &str, name: &str) -> Result<String> {
    validate_secret_name(name)?;
    let mut doc = parse(source)?;
    let table = profile_table_mut(&mut doc, profile)?;
    if table.remove(name).is_none() {
        return Err(miette!(
            "Secret '{}' is not declared in profile '{}'",
            name,
            profile
        ));
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
        .ok_or_else(|| miette!("Profile '{}' is not declared in this manifest", profile))
}

fn secret_inline_table(secret: &Secret) -> Result<InlineTable> {
    if secret
        .description
        .as_deref()
        .is_none_or(|description| description.trim().is_empty())
    {
        return Err(miette!("Secret description cannot be empty"));
    }

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
