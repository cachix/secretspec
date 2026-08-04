use std::{collections::HashSet, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Result, SecretSpecError};

fn extract_placeholders(s: &str) -> Result<Vec<String>> {
    let mut placeholders = Vec::new();
    let mut remainder = s;

    while let Some(start) = remainder.find('{') {
        let after_start = &remainder[start + 1..];
        let end = after_start.find('}').ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Unclosed placeholder in SOPS path '{s}'"
            ))
        })?;
        placeholders.push(after_start[..end].to_string());
        remainder = &after_start[end + 1..];
    }

    if remainder.contains('}') {
        return Err(SecretSpecError::ProviderOperationFailed(format!(
            "Unexpected closing brace in SOPS path '{s}'"
        )));
    }

    Ok(placeholders)
}

fn validate_template(template: &str) -> std::result::Result<(), SecretSpecError> {
    let placeholders = extract_placeholders(template)?;

    if placeholders.len() > 0 {
        let mut expected_placeholders: HashSet<&str> = HashSet::new();

        expected_placeholders.insert("profile");

        expected_placeholders.insert("project");

        for placeholder in &placeholders {
            match placeholder.as_str() {
                "profile" | "project" => {
                    expected_placeholders.take(placeholder.as_str());
                }
                other => {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Unknown placeholder '{{{}}}' in SOPS path",
                        other
                    )));
                }
            }
        }

        if 0 != expected_placeholders.len() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "SOPS provider URL missing templating placeholders: {}",
                expected_placeholders
                    .drain()
                    .map(|p| format!("{{{}}}", p))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SopsPathPattern {
    template: String,
}

impl TryFrom<String> for SopsPathPattern {
    type Error = SecretSpecError;

    fn try_from(template: String) -> Result<Self> {
        let pattern = Self { template };

        pattern.validate()?;

        Ok(pattern)
    }
}

impl TryFrom<&str> for SopsPathPattern {
    type Error = SecretSpecError;

    fn try_from(template: &str) -> Result<Self> {
        let pattern = Self {
            template: template.to_string(),
        };

        pattern.validate()?;

        Ok(pattern)
    }
}

impl SopsPathPattern {
    pub fn validate(&self) -> Result<()> {
        validate_template(&self.template)
    }

    /// Substitutes `{project}` and `{profile}` in a single pass over the
    /// template.
    ///
    /// Sequential `.replace()` calls substitute into their own output, so a
    /// project literally named `{profile}` had the profile substituted into it
    /// by the second call, resolving to a different file on disk than the one
    /// configured. Walking the template once means a substituted value is
    /// copied out, never rescanned.
    ///
    /// Unknown placeholders and unclosed braces are kept as literal text rather
    /// than panicking: [`validate`](Self::validate) rejects both, but
    /// `SopsPathPattern` also derives `Deserialize`, which does not run it.
    pub fn render(&self, project: &str, profile: &str) -> PathBuf {
        let mut rendered = String::with_capacity(self.template.len());
        let mut remainder = self.template.as_str();

        while let Some(start) = remainder.find('{') {
            rendered.push_str(&remainder[..start]);
            let after_start = &remainder[start + 1..];

            let Some(end) = after_start.find('}') else {
                rendered.push_str(&remainder[start..]);
                return PathBuf::from(rendered);
            };

            match &after_start[..end] {
                "project" => rendered.push_str(project),
                "profile" => rendered.push_str(profile),
                other => {
                    rendered.push('{');
                    rendered.push_str(other);
                    rendered.push('}');
                }
            }

            remainder = &after_start[end + 1..];
        }

        rendered.push_str(remainder);

        PathBuf::from(rendered)
    }

    pub fn debug_template(&self) -> String {
        self.template.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(template: &str, project: &str, profile: &str) -> String {
        SopsPathPattern::try_from(template)
            .unwrap()
            .render(project, profile)
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn substitutes_both_placeholders() {
        assert_eq!(
            render("secrets/{project}/{profile}.yaml", "myapp", "production"),
            "secrets/myapp/production.yaml"
        );
    }

    #[test]
    fn a_project_named_like_a_placeholder_is_not_re_substituted() {
        // The sequential `.replace()` chain this replaces resolved to
        // "secrets/production/production.yaml", reading another profile's file.
        assert_eq!(
            render(
                "secrets/{project}/{profile}.yaml",
                "{profile}",
                "production"
            ),
            "secrets/{profile}/production.yaml"
        );
    }

    #[test]
    fn a_profile_named_like_a_placeholder_is_not_re_substituted() {
        assert_eq!(
            render("secrets/{profile}/{project}.yaml", "myapp", "{project}"),
            "secrets/{project}/myapp.yaml"
        );
    }

    #[test]
    fn placeholders_may_repeat_and_reorder() {
        assert_eq!(
            render("{profile}/{project}/{profile}.yaml", "myapp", "prod"),
            "prod/myapp/prod.yaml"
        );
    }

    #[test]
    fn a_template_without_placeholders_renders_verbatim() {
        assert_eq!(
            render("secrets/shared.yaml", "myapp", "prod"),
            "secrets/shared.yaml"
        );
    }

    #[test]
    fn validation_rejects_unknown_and_partial_placeholders() {
        assert!(SopsPathPattern::try_from("{project}/{profile}/{key}.yaml").is_err());
        assert!(SopsPathPattern::try_from("{project}.yaml").is_err());
        assert!(SopsPathPattern::try_from("{project/{profile}.yaml").is_err());
        assert!(SopsPathPattern::try_from("{project}/{profile}}.yaml").is_err());
    }

    /// `validate` rejects these, but `Deserialize` does not run it, so `render`
    /// has to stay total for a pattern that never passed validation.
    #[test]
    fn an_unvalidated_pattern_keeps_bad_placeholders_literal() {
        let pattern: SopsPathPattern =
            serde_json::from_str(r#"{"template":"{project}/{key}/{unclosed.yaml"}"#).unwrap();
        assert_eq!(
            pattern.render("myapp", "prod").to_string_lossy(),
            "myapp/{key}/{unclosed.yaml"
        );
    }
}
