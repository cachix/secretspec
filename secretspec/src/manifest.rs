//! Semantic compilation of a parsed manifest.
//!
//! [`Config`](crate::config::Config) is the syntax tree: its `Option` fields
//! record what a particular source/profile wrote. Runtime resolution and
//! generated types instead consume this module's effective view, where profile
//! inheritance and missing-value behavior have already been decided once.

use crate::composition::Template;
use crate::config::{Config, Secret};
use std::collections::{BTreeMap, BTreeSet};

/// What resolution does when no provider returns a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingPolicy {
    /// Absence fails resolution.
    Error,
    /// Absence is a valid optional result.
    Omit,
    /// The committed manifest default supplies the value.
    UseDefault,
    /// The configured generator supplies the value.
    Generate,
}

impl MissingPolicy {
    /// Whether a successful resolution necessarily contains this field.
    pub(crate) fn guaranteed_on_success(self) -> bool {
        self != Self::Omit
    }
}

/// One fully merged secret in an effective profile.
#[derive(Debug, Clone)]
pub(crate) struct CompiledSecret {
    pub(crate) config: Secret,
    pub(crate) missing: MissingPolicy,
    /// The effective `required` flag for reporting. Kept distinct from
    /// `missing`: a required generated/defaulted field is still guaranteed.
    pub(crate) declared_required: bool,
    /// The parsed `composed` template, decided once here so graph validation,
    /// planning, and the executor's render pass all read one parse. A
    /// malformed template compiles to `None`; `Secret::validate_semantics`
    /// rejects it before any of those consumers run.
    pub(crate) composition: Option<Template>,
}

impl CompiledSecret {
    fn new(config: Secret, conditionally_required: bool) -> Self {
        // An inline default makes an omitted `required` behave as false. This
        // preserves the manifest shorthand while keeping an explicit inherited
        // `required = true` visible in reports. Membership in a profile
        // presence constraint likewise replaces the implicit per-secret
        // requirement, while an explicit `required = true` remains independent.
        let declared_required = config
            .required
            .unwrap_or(config.default.is_none() && !conditionally_required);
        let missing = if config.would_generate() {
            MissingPolicy::Generate
        } else if config.default.is_some() {
            MissingPolicy::UseDefault
        } else if declared_required {
            MissingPolicy::Error
        } else {
            MissingPolicy::Omit
        };
        let composition = config
            .composed
            .as_deref()
            .and_then(|source| Template::parse(source).ok());
        Self {
            config,
            missing,
            declared_required,
            composition,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_policy_compiles_presence_once() {
        let required = CompiledSecret::new(Secret::default(), false);
        assert_eq!(required.missing, MissingPolicy::Error);
        assert!(required.declared_required);
        assert!(required.missing.guaranteed_on_success());

        let defaulted = CompiledSecret::new(
            Secret {
                default: Some("fallback".to_string()),
                ..Default::default()
            },
            false,
        );
        assert_eq!(defaulted.missing, MissingPolicy::UseDefault);
        assert!(!defaulted.declared_required);
        assert!(defaulted.missing.guaranteed_on_success());

        let optional = CompiledSecret::new(
            Secret {
                required: Some(false),
                ..Default::default()
            },
            false,
        );
        assert_eq!(optional.missing, MissingPolicy::Omit);
        assert!(!optional.missing.guaranteed_on_success());

        let alternative = CompiledSecret::new(Secret::default(), true);
        assert_eq!(alternative.missing, MissingPolicy::Omit);
        assert!(!alternative.declared_required);
    }
}

/// One effective profile, including fields inherited from `default`.
#[derive(Debug, Clone)]
pub(crate) struct CompiledProfile {
    pub(crate) secrets: BTreeMap<String, CompiledSecret>,
    pub(crate) constraints: CompiledConstraints,
}

/// One named cross-secret presence group.
#[derive(Debug, Clone)]
pub(crate) struct CompiledConstraintGroup {
    pub(crate) name: String,
    pub(crate) members: Vec<String>,
}

/// Named presence groups compiled from each effective secret's membership.
#[derive(Debug, Clone, Default)]
pub(crate) struct CompiledConstraints {
    pub(crate) at_least_one: Vec<CompiledConstraintGroup>,
    pub(crate) exactly_one: Vec<CompiledConstraintGroup>,
}

/// A parsed manifest reduced to the semantics shared by runtime and codegen.
#[derive(Debug, Clone)]
pub(crate) struct CompiledManifest {
    pub(crate) project: String,
    pub(crate) profiles: BTreeMap<String, CompiledProfile>,
}

impl CompiledManifest {
    pub(crate) fn compile(config: &Config) -> Self {
        let default_profile = config.profiles.get("default");
        let mut profiles = BTreeMap::new();

        for (profile_name, profile) in &config.profiles {
            let inherited = (profile_name != "default")
                .then_some(default_profile)
                .flatten();
            // A `BTreeSet` unions the profile's own names with the inherited
            // ones already deduplicated and sorted, which is the deterministic
            // order every surface consuming the manifest expects.
            let mut names: BTreeSet<&String> = profile.secrets.keys().collect();
            if let Some(default) = inherited {
                names.extend(default.secrets.keys());
            }

            let effective: BTreeMap<String, Secret> = names
                .into_iter()
                .map(|name| {
                    let current = profile.secrets.get(name);
                    let default = inherited.and_then(|p| p.secrets.get(name));
                    let effective = Secret::resolved(current, default, profile.defaults.as_ref())
                        .expect("an effective name comes from current or default");
                    (name.clone(), effective)
                })
                .collect();

            let mut at_least_one: BTreeMap<String, Vec<String>> = BTreeMap::new();
            let mut exactly_one: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (name, secret) in &effective {
                if let Some(groups) = &secret.at_least_one {
                    for group in groups {
                        at_least_one
                            .entry(group.clone())
                            .or_default()
                            .push(name.clone());
                    }
                }
                if let Some(groups) = &secret.exactly_one {
                    for group in groups {
                        exactly_one
                            .entry(group.clone())
                            .or_default()
                            .push(name.clone());
                    }
                }
            }
            fn groups(grouped: BTreeMap<String, Vec<String>>) -> Vec<CompiledConstraintGroup> {
                grouped
                    .into_iter()
                    .map(|(name, members)| CompiledConstraintGroup { name, members })
                    .collect()
            }
            let constraints = CompiledConstraints {
                at_least_one: groups(at_least_one),
                exactly_one: groups(exactly_one),
            };

            let secrets = effective
                .into_iter()
                .map(|(name, secret)| {
                    let conditionally_required = secret
                        .at_least_one
                        .as_ref()
                        .is_some_and(|groups| !groups.is_empty())
                        || secret
                            .exactly_one
                            .as_ref()
                            .is_some_and(|groups| !groups.is_empty());
                    (name, CompiledSecret::new(secret, conditionally_required))
                })
                .collect();

            profiles.insert(
                profile_name.clone(),
                CompiledProfile {
                    secrets,
                    constraints,
                },
            );
        }

        Self {
            project: config.project.name.clone(),
            profiles,
        }
    }

    pub(crate) fn profile(&self, name: &str) -> Option<&CompiledProfile> {
        self.profiles.get(name)
    }
}
