use std::{collections::HashSet, path::PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{Result, SecretSpecError};

fn extract_placeholders(s: &str) -> Vec<String> {
    let re = Regex::new(r"\{([^}]+)\}").unwrap();

    re.captures_iter(s).map(|cap| cap[1].to_string()).collect()
}

fn validate_template(template: &str) -> std::result::Result<(), SecretSpecError> {
    let placeholders = extract_placeholders(template);

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

    pub fn render(&self, project: &str, profile: &str) -> PathBuf {
        let rendered = self
            .template
            .replace("{project}", project)
            .replace("{profile}", profile);

        PathBuf::from(rendered)
    }

    pub fn debug_template(&self) -> String {
        self.template.clone()
    }
}
