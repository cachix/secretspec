//! Semantic compilation of a parsed manifest.
//!
//! [`Config`](crate::config::Config) is the syntax tree: its `Option` fields
//! record what a particular source/profile wrote. Runtime resolution and
//! generated types instead consume this module's effective view, where profile
//! inheritance and missing-value behavior have already been decided once.

use crate::config::{Config, Secret};
use std::collections::BTreeMap;

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
}

impl CompiledSecret {
    fn new(config: Secret) -> Self {
        // An inline default makes an omitted `required` behave as false. This
        // preserves the manifest shorthand while keeping an explicit inherited
        // `required = true` visible in reports.
        let declared_required = config.required.unwrap_or(config.default.is_none());
        let missing = if config
            .generate
            .as_ref()
            .is_some_and(|generate| generate.is_enabled())
        {
            MissingPolicy::Generate
        } else if config.default.is_some() {
            MissingPolicy::UseDefault
        } else if declared_required {
            MissingPolicy::Error
        } else {
            MissingPolicy::Omit
        };
        Self {
            config,
            missing,
            declared_required,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_policy_compiles_presence_once() {
        let required = CompiledSecret::new(Secret::default());
        assert_eq!(required.missing, MissingPolicy::Error);
        assert!(required.declared_required);
        assert!(required.missing.guaranteed_on_success());

        let defaulted = CompiledSecret::new(Secret {
            default: Some("fallback".to_string()),
            ..Default::default()
        });
        assert_eq!(defaulted.missing, MissingPolicy::UseDefault);
        assert!(!defaulted.declared_required);
        assert!(defaulted.missing.guaranteed_on_success());

        let optional = CompiledSecret::new(Secret {
            required: Some(false),
            ..Default::default()
        });
        assert_eq!(optional.missing, MissingPolicy::Omit);
        assert!(!optional.missing.guaranteed_on_success());
    }
}

/// One effective profile, including fields inherited from `default`.
#[derive(Debug, Clone)]
pub(crate) struct CompiledProfile {
    pub(crate) secrets: BTreeMap<String, CompiledSecret>,
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
            let mut names: Vec<&String> = profile.secrets.keys().collect();
            if let Some(default) = inherited {
                names.extend(default.secrets.keys());
            }
            names.sort();
            names.dedup();

            let secrets = names
                .into_iter()
                .map(|name| {
                    let current = profile.secrets.get(name);
                    let default = inherited.and_then(|p| p.secrets.get(name));
                    let effective = Secret::resolved(current, default, profile.defaults.as_ref())
                        .expect("an effective name comes from current or default");
                    (name.clone(), CompiledSecret::new(effective))
                })
                .collect();
            profiles.insert(profile_name.clone(), CompiledProfile { secrets });
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
