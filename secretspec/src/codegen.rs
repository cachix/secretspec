//! The shared codegen intermediate representation (IR).
//!
//! Every typed-accessor generator computes the *same* decisions from a manifest:
//! which secrets exist, whether a field is optional, whether it is a file path,
//! how profiles map to types. If each generator (the Rust derive macro and the
//! JSON Schema emitter that drives quicktype for other languages) recomputed
//! those decisions, they would drift. This module is the single brain: a
//! manifest is reduced to a language-neutral [`CodegenIr`] once, and each
//! emitter is a thin template over it.
//!
//! The IR deliberately mirrors the two shapes the derive crate exposes:
//! - a **union** field set (`SecretSpec`) safe to use without knowing the
//!   profile: a field is optional if it is optional in, or missing from, *any*
//!   profile, and a path if it is a path in *any* profile;
//! - **per-profile** field sets (`SecretSpecProfile`) with exact, raw types: a
//!   field is optional iff that profile does not mark it `required = true`, and a
//!   path iff that profile sets `as_path = true`. Per-profile sets are NOT
//!   inheritance-merged with the `default` profile, matching the derive macro.
//!
//! Note: the union/per-profile "optional iff not `required = true`" rule means a
//! secret with `required` unspecified is treated as optional here, which is the
//! derive crate's long-standing behavior (and differs from the runtime
//! resolver, where unspecified means required). The IR reproduces the derive
//! behavior so generated code stays stable.

use crate::config::{Config, Secret};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// One field in a generated type. `name` is the canonical `UPPER_SNAKE` env key
/// and the source of truth; each emitter applies its own casing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrField {
    /// The declared secret name (the `UPPER_SNAKE` manifest key).
    pub name: String,
    /// Whether the generated field is optional (nullable) rather than required.
    pub optional: bool,
    /// Whether the value is exposed as a file path rather than inline.
    pub as_path: bool,
    /// The secret's description, when one is declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A profile and its exact (raw, non-merged) field set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrProfile {
    /// The profile name as written in the manifest (e.g. `production`).
    pub name: String,
    /// The profile's fields, sorted by name for deterministic output.
    pub fields: Vec<IrField>,
}

/// The complete, language-neutral codegen description of a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodegenIr {
    /// The project name.
    pub project: String,
    /// Profile names in sorted order; `["default"]` when the manifest declares
    /// none.
    pub profiles: Vec<String>,
    /// Union fields safe across every profile, sorted by name.
    pub union: Vec<IrField>,
    /// Per-profile exact field sets, in the same order as [`Self::profiles`].
    pub profile_fields: Vec<IrProfile>,
}

/// A secret is optional unless the profile explicitly marks it `required = true`.
/// Matches the derive crate (and differs from the runtime resolver default).
fn is_secret_optional(secret: &Secret) -> bool {
    secret.required != Some(true)
}

/// For the union type a field is optional if it is optional in, or absent from,
/// any profile, so the union can safely represent secrets from any profile.
fn is_field_optional_across_profiles(name: &str, config: &Config) -> bool {
    for profile in config.profiles.values() {
        match profile.secrets.get(name) {
            Some(secret) if !is_secret_optional(secret) => {}
            // Optional in this profile, or missing from it.
            _ => return true,
        }
    }
    false
}

/// For the union type a field is a path if any profile declares it `as_path`.
fn is_field_as_path_across_profiles(name: &str, config: &Config) -> bool {
    config
        .profiles
        .values()
        .any(|profile| profile.secrets.get(name).and_then(|s| s.as_path) == Some(true))
}

/// Pick a description for a union field: the first profile (by sorted name) that
/// declares one.
fn union_description(name: &str, config: &Config) -> Option<String> {
    let mut profile_names: Vec<&String> = config.profiles.keys().collect();
    profile_names.sort();
    profile_names.into_iter().find_map(|profile_name| {
        config.profiles[profile_name]
            .secrets
            .get(name)
            .and_then(|s| s.description.clone())
    })
}

/// Build the union field set: every unique secret across all profiles, sorted.
fn build_union(config: &Config) -> Vec<IrField> {
    let names: BTreeSet<&String> = config
        .profiles
        .values()
        .flat_map(|profile| profile.secrets.keys())
        .collect();

    names
        .into_iter()
        .map(|name| IrField {
            name: name.clone(),
            optional: is_field_optional_across_profiles(name, config),
            as_path: is_field_as_path_across_profiles(name, config),
            description: union_description(name, config),
        })
        .collect()
}

/// Build the exact field set for one profile's raw secrets, sorted by name.
fn build_profile_fields(secrets: &HashMap<String, Secret>) -> Vec<IrField> {
    let mut fields: Vec<IrField> = secrets
        .iter()
        .map(|(name, secret)| IrField {
            name: name.clone(),
            optional: is_secret_optional(secret),
            as_path: secret.as_path.unwrap_or(false),
            description: secret.description.clone(),
        })
        .collect();
    fields.sort_by(|a, b| a.name.cmp(&b.name));
    fields
}

/// Reduce a manifest to the language-neutral [`CodegenIr`] every emitter
/// consumes. This is the only place manifest typing decisions are made.
pub fn build_ir(config: &Config) -> CodegenIr {
    let union = build_union(config);

    let profile_fields = if config.profiles.is_empty() {
        // No declared profiles: a single `default` profile carrying every field,
        // matching the derive macro's empty-profile case.
        vec![IrProfile {
            name: "default".to_string(),
            fields: union.clone(),
        }]
    } else {
        let mut names: Vec<&String> = config.profiles.keys().collect();
        names.sort();
        names
            .into_iter()
            .map(|name| IrProfile {
                name: name.clone(),
                fields: build_profile_fields(&config.profiles[name].secrets),
            })
            .collect()
    };

    let profiles = profile_fields.iter().map(|p| p.name.clone()).collect();

    CodegenIr {
        project: config.project.name.clone(),
        profiles,
        union,
        profile_fields,
    }
}

/// JSON Schema emitter.
///
/// Rather than hand-write typed accessors per language, we emit a JSON Schema
/// describing one manifest shape and let [quicktype](https://quicktype.io)
/// generate the idiomatic type and deserializer for any target language. We then
/// maintain only the small generic `fields()` helper in each runtime SDK, which
/// hands quicktype's deserializer a flat `{SECRET_NAME: value}` map.
///
/// The schema is a single-root object so quicktype emits a properly named type
/// with a converter in every language (a wrapper or `$ref` root makes quicktype
/// drop the converter or rename the type). By default it describes the union
/// `SecretSpec` (safe for any profile); with a profile it describes that
/// profile's exact fields. Pair it with `quicktype --top-level <Name>`.
pub mod schema {
    use super::{CodegenIr, IrField};
    use serde_json::{Map, Value, json};

    fn property_type(field: &IrField) -> Value {
        // Every secret is a string; optional secrets are nullable. `as_path`
        // secrets are also strings (the file path), so they need no special type.
        if field.optional {
            json!({ "type": ["string", "null"] })
        } else {
            json!({ "type": "string" })
        }
    }

    fn object_schema(title: &str, fields: &[IrField]) -> Value {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for field in fields {
            properties.insert(field.name.clone(), property_type(field));
            if !field.optional {
                required.push(Value::String(field.name.clone()));
            }
        }
        json!({
            "$schema": "http://json-schema.org/draft-06/schema#",
            "type": "object",
            "additionalProperties": false,
            "title": title,
            "properties": Value::Object(properties),
            "required": required,
        })
    }

    fn capitalize(s: &str) -> String {
        let mut chars = s.chars();
        match chars.next() {
            None => String::new(),
            Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }

    /// Emit the JSON Schema (draft-06, the dialect quicktype consumes) for the
    /// union (`profile = None`) or one profile's fields. Returns an error if the
    /// named profile does not exist.
    pub fn emit(ir: &CodegenIr, profile: Option<&str>) -> Result<String, String> {
        let schema = match profile {
            None => object_schema("SecretSpec", &ir.union),
            Some(name) => {
                let found = ir
                    .profile_fields
                    .iter()
                    .find(|p| p.name == name)
                    .ok_or_else(|| {
                        format!(
                            "unknown profile '{name}'; available: {}",
                            ir.profiles.join(", ")
                        )
                    })?;
                object_schema(&format!("{}Secrets", capitalize(name)), &found.fields)
            }
        };
        Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&schema).unwrap()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Profile, Project};

    fn secret(required: Option<bool>, as_path: Option<bool>, desc: Option<&str>) -> Secret {
        Secret {
            description: desc.map(String::from),
            required,
            as_path,
            ..Default::default()
        }
    }

    fn config_with(profiles: Vec<(&str, Vec<(&str, Secret)>)>) -> Config {
        let mut map = HashMap::new();
        for (name, secrets) in profiles {
            let mut secret_map = HashMap::new();
            for (sname, s) in secrets {
                secret_map.insert(sname.to_string(), s);
            }
            map.insert(
                name.to_string(),
                Profile {
                    defaults: None,
                    secrets: secret_map,
                },
            );
        }
        Config {
            project: Project {
                name: "ir-test".to_string(),
                ..Default::default()
            },
            profiles: map,
            providers: None,
        }
    }

    fn union_field<'a>(ir: &'a CodegenIr, name: &str) -> &'a IrField {
        ir.union.iter().find(|f| f.name == name).unwrap()
    }

    #[test]
    fn union_optional_if_optional_or_missing_in_any_profile() {
        let ir = build_ir(&config_with(vec![
            (
                "development",
                vec![
                    ("DATABASE_URL", secret(Some(true), None, None)),
                    ("API_KEY", secret(Some(false), None, None)),
                ],
            ),
            (
                "production",
                vec![
                    ("DATABASE_URL", secret(Some(true), None, None)),
                    ("API_KEY", secret(Some(true), None, None)),
                    ("REDIS_URL", secret(Some(true), None, None)),
                ],
            ),
        ]));

        // Required in every profile it appears in -> required in the union.
        assert!(!union_field(&ir, "DATABASE_URL").optional);
        // Optional in development -> optional in the union.
        assert!(union_field(&ir, "API_KEY").optional);
        // Missing from development -> optional in the union.
        assert!(union_field(&ir, "REDIS_URL").optional);

        // Union is sorted and complete.
        let names: Vec<&str> = ir.union.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["API_KEY", "DATABASE_URL", "REDIS_URL"]);
    }

    #[test]
    fn union_as_path_if_any_profile_marks_it() {
        let ir = build_ir(&config_with(vec![
            (
                "development",
                vec![("CERT", secret(Some(true), None, None))],
            ),
            (
                "production",
                vec![("CERT", secret(Some(true), Some(true), None))],
            ),
        ]));
        assert!(union_field(&ir, "CERT").as_path);
    }

    #[test]
    fn per_profile_fields_are_raw_and_exact() {
        let ir = build_ir(&config_with(vec![
            (
                "development",
                vec![
                    ("DATABASE_URL", secret(Some(true), None, Some("dev db"))),
                    ("API_KEY", secret(Some(false), None, None)),
                ],
            ),
            (
                "production",
                vec![("DATABASE_URL", secret(Some(true), Some(true), None))],
            ),
        ]));

        assert_eq!(ir.profiles, vec!["development", "production"]);

        let dev = ir
            .profile_fields
            .iter()
            .find(|p| p.name == "development")
            .unwrap();
        let dev_names: Vec<&str> = dev.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(dev_names, vec!["API_KEY", "DATABASE_URL"]);
        // Description flows through per profile.
        assert_eq!(dev.fields[1].description.as_deref(), Some("dev db"));

        // production has only DATABASE_URL, here as a path.
        let prod = ir
            .profile_fields
            .iter()
            .find(|p| p.name == "production")
            .unwrap();
        assert_eq!(prod.fields.len(), 1);
        assert!(prod.fields[0].as_path);
        assert!(!prod.fields[0].optional);
    }

    #[test]
    fn unspecified_required_is_optional_matching_derive() {
        let ir = build_ir(&config_with(vec![(
            "default",
            vec![("TOKEN", secret(None, None, None))],
        )]));
        assert!(union_field(&ir, "TOKEN").optional);
    }

    #[test]
    fn schema_emits_types_and_nullability_for_quicktype() {
        let ir = build_ir(&config_with(vec![
            (
                "development",
                vec![
                    ("DATABASE_URL", secret(Some(true), None, None)),
                    ("API_KEY", secret(Some(false), None, None)),
                ],
            ),
            (
                "production",
                vec![("DATABASE_URL", secret(Some(true), None, None))],
            ),
        ]));

        // Union schema: single-root object titled SecretSpec.
        let union: serde_json::Value =
            serde_json::from_str(&schema::emit(&ir, None).unwrap()).unwrap();
        assert_eq!(union["type"], "object");
        assert_eq!(union["title"], "SecretSpec");

        // Required vs nullable: DATABASE_URL required everywhere; API_KEY optional
        // in development, so optional in the union and nullable in the schema.
        assert_eq!(union["properties"]["DATABASE_URL"]["type"], "string");
        assert_eq!(
            union["properties"]["API_KEY"]["type"],
            serde_json::json!(["string", "null"])
        );
        let required: Vec<&str> = union["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"DATABASE_URL"));
        assert!(!required.contains(&"API_KEY"));

        // A profile schema is titled <Profile>Secrets with that profile's fields.
        let prod: serde_json::Value =
            serde_json::from_str(&schema::emit(&ir, Some("production")).unwrap()).unwrap();
        assert_eq!(prod["title"], "ProductionSecrets");
        assert!(prod["properties"]["DATABASE_URL"].is_object());
        assert!(prod["properties"]["API_KEY"].is_null()); // not in production

        // An unknown profile is an error.
        assert!(schema::emit(&ir, Some("nope")).is_err());
    }

    #[test]
    fn empty_profiles_yield_single_default_with_union_fields() {
        let mut config = config_with(vec![]);
        config.profiles.clear();
        let ir = build_ir(&config);
        assert_eq!(ir.profiles, vec!["default"]);
        assert_eq!(ir.profile_fields.len(), 1);
        assert_eq!(ir.profile_fields[0].name, "default");
        assert!(ir.union.is_empty());
    }
}
