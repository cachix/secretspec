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
//! - **per-profile** field sets (`SecretSpecProfile`) matching the effective
//!   runtime profile, including fields inherited from `default`.
//!
//! Optionality describes successful output presence, not raw TOML spelling: an
//! optional secret is nullable, while required, defaulted, and generated secrets
//! are guaranteed to have a value when resolution succeeds.

use crate::config::Config;
use crate::manifest::{CompiledManifest, CompiledSecret};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

/// A profile and its effective field set.
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

/// Build the union field set: every unique secret across all profiles, sorted.
///
/// Computed in a single pass over every `(profile, secret)` rather than
/// re-scanning all profiles per field. A union field is:
/// - optional if successful resolution may omit it in any profile (because it
///   is absent there or has the compiled `Omit` policy);
/// - a path if *any* profile declares it `as_path`;
/// - described by the first profile, in sorted name order, that declares a
///   description.
fn build_union(manifest: &CompiledManifest) -> Vec<IrField> {
    let total_profiles = manifest.profiles.len();
    struct Acc {
        /// Profiles where successful resolution guarantees the secret.
        guaranteed_count: usize,
        as_path: bool,
        description: Option<String>,
    }
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();

    for profile in manifest.profiles.values() {
        for (name, secret) in &profile.secrets {
            let entry = acc.entry(name.clone()).or_insert(Acc {
                guaranteed_count: 0,
                as_path: false,
                description: None,
            });
            if secret.missing.guaranteed_on_success() {
                entry.guaranteed_count += 1;
            }
            if secret.config.as_path == Some(true) {
                entry.as_path = true;
            }
            if entry.description.is_none() {
                entry.description = secret.config.description.clone();
            }
        }
    }

    acc.into_iter()
        .map(|(name, a)| IrField {
            name,
            optional: a.guaranteed_count != total_profiles,
            as_path: a.as_path,
            description: a.description,
        })
        .collect()
}

/// Capitalize the first character, leaving the rest unchanged. Shared by the
/// JSON Schema emitter (for `<Profile>Secrets` titles) and the derive macro (for
/// `SecretSpecProfile::<Variant>` names) so the two never disagree on casing.
pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Build one effective profile's field set, sorted by name.
fn build_profile_fields(secrets: &BTreeMap<String, CompiledSecret>) -> Vec<IrField> {
    secrets
        .iter()
        .map(|(name, secret)| IrField {
            name: name.clone(),
            optional: !secret.missing.guaranteed_on_success(),
            as_path: secret.config.as_path.unwrap_or(false),
            description: secret.config.description.clone(),
        })
        .collect()
}

/// Reduce a manifest to the language-neutral [`CodegenIr`] every emitter
/// consumes. This is the only place manifest typing decisions are made.
pub fn build_ir(config: &Config) -> CodegenIr {
    let manifest = CompiledManifest::compile(config);
    let union = build_union(&manifest);

    let profile_fields = if manifest.profiles.is_empty() {
        // No declared profiles: a single `default` profile carrying every field,
        // matching the derive macro's empty-profile case.
        vec![IrProfile {
            name: "default".to_string(),
            fields: union.clone(),
        }]
    } else {
        manifest
            .profiles
            .iter()
            .map(|(name, profile)| IrProfile {
                name: name.clone(),
                fields: build_profile_fields(&profile.secrets),
            })
            .collect()
    };

    let profiles = profile_fields.iter().map(|p| p.name.clone()).collect();

    CodegenIr {
        project: manifest.project,
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
    use super::{CodegenIr, IrField, capitalize};
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

    fn object_schema(title: &str, fields: &[IrField], additional_properties: bool) -> Value {
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
            "additionalProperties": additional_properties,
            "title": title,
            "properties": Value::Object(properties),
            "required": required,
        })
    }

    /// Emit the JSON Schema (draft-06, the dialect quicktype consumes) for the
    /// union (`profile = None`) or one profile's fields. Returns an error if the
    /// named profile does not exist.
    ///
    /// Both union and per-profile schemas are exhaustive. Per-profile IR already
    /// includes every effective field inherited from `default`.
    pub fn emit(ir: &CodegenIr, profile: Option<&str>) -> Result<String, String> {
        let schema = match profile {
            None => object_schema("SecretSpec", &ir.union, false),
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
                object_schema(
                    &format!("{}Secrets", capitalize(name)),
                    &found.fields,
                    false,
                )
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
    use crate::config::{Profile, Project, Secret};
    use std::collections::HashMap;

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
            scopes: None,
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
    fn per_profile_fields_are_sorted_and_exact() {
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
    fn unspecified_required_is_non_optional_matching_runtime() {
        let ir = build_ir(&config_with(vec![(
            "default",
            vec![("TOKEN", secret(None, None, None))],
        )]));
        assert!(!union_field(&ir, "TOKEN").optional);
    }

    #[test]
    fn constraint_members_are_optional() {
        let config = config_with(vec![(
            "default",
            vec![
                (
                    "PASSWORD",
                    Secret {
                        at_least_one: Some(vec!["auth".to_string()]),
                        ..secret(None, None, None)
                    },
                ),
                (
                    "TOKEN",
                    Secret {
                        at_least_one: Some(vec!["auth".to_string(), "deploy".to_string()]),
                        exactly_one: Some(vec!["github".to_string()]),
                        ..secret(None, None, None)
                    },
                ),
            ],
        )]);

        let ir = build_ir(&config);
        assert!(union_field(&ir, "PASSWORD").optional);
        assert!(union_field(&ir, "TOKEN").optional);
    }

    #[test]
    fn defaulted_secret_is_non_optional_because_resolution_guarantees_a_value() {
        let mut token = secret(None, None, None);
        token.default = Some("fallback".to_string());

        let ir = build_ir(&config_with(vec![("default", vec![("TOKEN", token)])]));

        assert!(!union_field(&ir, "TOKEN").optional);
    }

    #[test]
    fn profile_fields_include_secrets_inherited_from_default() {
        let ir = build_ir(&config_with(vec![
            (
                "default",
                vec![("SHARED_TOKEN", secret(Some(true), None, None))],
            ),
            (
                "production",
                vec![("PRODUCTION_TOKEN", secret(Some(true), None, None))],
            ),
        ]));

        let production = ir
            .profile_fields
            .iter()
            .find(|profile| profile.name == "production")
            .unwrap();
        let names: Vec<&str> = production
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect();
        assert_eq!(names, vec!["PRODUCTION_TOKEN", "SHARED_TOKEN"]);

        let schema: serde_json::Value =
            serde_json::from_str(&schema::emit(&ir, Some("production")).unwrap()).unwrap();
        assert!(schema["properties"]["SHARED_TOKEN"].is_object());
        assert_eq!(schema["additionalProperties"], false);
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
        // The union is exhaustive across every profile, so it is strict.
        assert_eq!(union["additionalProperties"], false);

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
        // Effective per-profile schemas are exhaustive too.
        assert_eq!(prod["additionalProperties"], false);

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
