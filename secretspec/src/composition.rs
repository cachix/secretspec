//! Strict parsing and one-pass rendering for composed secrets.
//!
//! This deliberately is not a dotenv or shell interpolator. References may
//! name only declared uppercase secrets, inserted values are opaque, and `$$`
//! produces a literal dollar sign.

use std::collections::BTreeSet;

const MAX_RENDERED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Reference(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    parts: Vec<Part>,
    dependencies: Vec<String>,
}

impl Template {
    pub(crate) fn parse(input: &str) -> Result<Self, String> {
        let mut chars = input.chars().peekable();
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut dependencies = BTreeSet::new();

        while let Some(ch) = chars.next() {
            match ch {
                '$' if chars.peek() == Some(&'$') => {
                    chars.next();
                    literal.push('$');
                }
                '$' if chars.peek() == Some(&'{') => {
                    chars.next();
                    if !literal.is_empty() {
                        parts.push(Part::Literal(std::mem::take(&mut literal)));
                    }

                    let mut name = String::new();
                    loop {
                        match chars.next() {
                            Some('}') => break,
                            Some('{') => {
                                return Err(
                                    "nested `{` in a composed reference; references use `${UPPERCASE_NAME}`"
                                        .into()
                                );
                            }
                            Some(ch) => name.push(ch),
                            None => {
                                return Err(
                                    "unclosed `${` in composed template; references use `${UPPERCASE_NAME}`"
                                        .into()
                                );
                            }
                        }
                    }

                    if !is_valid_reference_name(&name) {
                        return Err(format!(
                            "invalid composed reference `${{{name}}}`; names must match `[A-Z][A-Z0-9_]*`"
                        ));
                    }
                    dependencies.insert(name.clone());
                    parts.push(Part::Reference(name));
                }
                other => literal.push(other),
            }
        }

        if !literal.is_empty() {
            parts.push(Part::Literal(literal));
        }
        if dependencies.is_empty() {
            return Err("a composed template must reference at least one declared secret".into());
        }

        Ok(Self {
            parts,
            dependencies: dependencies.into_iter().collect(),
        })
    }

    pub(crate) fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    /// Render once. Values returned by `lookup` are appended as opaque bytes;
    /// braces or reference-looking text inside them are never interpreted.
    pub(crate) fn render<'a>(
        &self,
        mut lookup: impl FnMut(&str) -> Option<&'a str>,
    ) -> Result<String, String> {
        let mut rendered = String::new();
        for part in &self.parts {
            let value = match part {
                Part::Literal(value) => value.as_str(),
                Part::Reference(name) => lookup(name)
                    .ok_or_else(|| format!("composed dependency `{name}` is not resolved"))?,
            };
            if rendered.len() + value.len() > MAX_RENDERED_BYTES {
                return Err(format!(
                    "composed value exceeds the {} MiB limit",
                    MAX_RENDERED_BYTES / 1024 / 1024
                ));
            }
            rendered.push_str(value);
        }
        Ok(rendered)
    }
}

fn is_valid_reference_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z'))
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parses_dollar_references_and_deduplicates_dependencies() {
        let template =
            Template::parse(
                r#"{"dsn":"${USER}:${USER}@${HOST}","pattern":"a{2,4}","env":"$$HOME","literal":"$${EXTERNAL}"}"#,
            )
            .unwrap();
        assert_eq!(
            template.dependencies(),
            &["HOST".to_string(), "USER".to_string()]
        );
        let values = HashMap::from([("USER", "alice"), ("HOST", "db")]);
        assert_eq!(
            template.render(|name| values.get(name).copied()).unwrap(),
            r#"{"dsn":"alice:alice@db","pattern":"a{2,4}","env":"$HOME","literal":"${EXTERNAL}"}"#
        );
    }

    #[test]
    fn inserted_values_are_not_reparsed() {
        let template = Template::parse("value=${A}").unwrap();
        assert_eq!(
            template
                .render(|name| (name == "A").then_some("${B}"))
                .unwrap(),
            "value=${B}"
        );
    }

    #[test]
    fn rejects_operators_lowercase_names_and_malformed_syntax() {
        for invalid in [
            "${A:-fallback}",
            "${A",
            "${}",
            "${A${B}}",
            "${lower}",
            "${Mixed}",
            "${_A}",
            "${1A}",
            "${Ä}",
            "{A}",
        ] {
            assert!(Template::parse(invalid).is_err(), "{invalid} should fail");
        }
    }

    #[test]
    fn missing_value_is_not_replaced_with_empty_text() {
        let template = Template::parse("${A}:${B}").unwrap();
        assert_eq!(
            template.render(|name| (name == "A").then_some("set")),
            Err("composed dependency `B` is not resolved".into())
        );
        assert_eq!(
            template
                .render(|name| match name {
                    "A" => Some("set"),
                    "B" => Some(""),
                    _ => None,
                })
                .unwrap(),
            "set:"
        );
    }
}
