//! Rendering one selected JSON value as a secret.
//!
//! Three call sites select a single value out of a JSON document: the `awssm`
//! and `scaleway` providers, which take a flat `field` key, and
//! `Secrets::extract_stored_value`, which takes a JSON Pointer. Selection
//! differs on purpose and stays with each caller. Rendering the selected value
//! is shared, and each caller states its own policy for a JSON null.

use secrecy::SecretString;

/// Renders a selected JSON value as a secret.
///
/// A string is taken as-is; anything else is serialized, so a port stays `5432`
/// and a flag stays `true`. A null renders as `"null"`, which is what an
/// `extract` pointer wants: it was asked for one specific location, and the
/// document genuinely holds a JSON null there.
pub(crate) fn render(value: &serde_json::Value) -> SecretString {
    match value {
        serde_json::Value::String(text) => SecretString::new(text.clone().into()),
        other => SecretString::new(other.to_string().into()),
    }
}

/// Renders a value selected by a provider's `field`, treating a null as absent.
///
/// A provider answers "is this secret set here?", so a null is no value and the
/// resolver moves on to the next provider in the chain. Rendering it would
/// produce the four-character secret `null`, which satisfies a required secret
/// and reaches the program as a password or token spelled n-u-l-l. The `bw` and
/// `dashlane` providers already treat a null this way.
///
/// This is deliberately not the same policy as [`render`]: an `extract` pointer
/// names one location and reports what is there, while a provider `field` is a
/// lookup that can come up empty.
pub(crate) fn render_field(value: &serde_json::Value) -> Option<SecretString> {
    match value {
        serde_json::Value::Null => None,
        other => Some(render(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn parse(raw: &str) -> serde_json::Value {
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn render_takes_a_string_as_is_and_serializes_the_rest() {
        assert_eq!(render(&parse(r#""s3cret""#)).expose_secret(), "s3cret");
        assert_eq!(render(&parse("5432")).expose_secret(), "5432");
        assert_eq!(render(&parse("true")).expose_secret(), "true");
        assert_eq!(render(&parse(r#"{"a":1}"#)).expose_secret(), r#"{"a":1}"#);
    }

    #[test]
    fn render_keeps_a_null_because_an_extract_pointer_reports_what_is_there() {
        assert_eq!(render(&parse("null")).expose_secret(), "null");
    }

    #[test]
    fn render_field_treats_a_null_as_absent() {
        assert!(render_field(&parse("null")).is_none());
    }

    #[test]
    fn render_field_agrees_with_render_on_everything_else() {
        for raw in [r#""s3cret""#, "5432", "true", r#"{"a":1}"#, r#"["x"]"#] {
            let value = parse(raw);
            assert_eq!(
                render_field(&value).unwrap().expose_secret(),
                render(&value).expose_secret(),
                "{raw}"
            );
        }
    }
}
