//! Versioned requests for the extensible native SDK boundary.
//!
//! This is deliberately separate from the legacy [`crate::resolve_json`]
//! request.  A new SDK must call the new C symbol to use this format: sending
//! an inline declaration to an old `secretspec_resolve` would otherwise let an
//! old library ignore that unknown field and search for an unrelated manifest.

use crate::config::{
    Config, GenerateConfig, GenerateOptions, Profile as ConfigProfile, ProfileDefaults, Project,
    ProviderAlias, RequireReason, Scope, Secret as ConfigSecret, SecretEncoding, SecretExtract,
};
use crate::{CallerContext, Secrets, Spec};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

/// The version of the native call envelope understood by this library.
pub const NATIVE_CALL_REQUEST_VERSION: u32 = 1;
/// The version of the JSON inline-declaration document understood by this library.
pub const INLINE_SPEC_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallRequest {
    request_version: u32,
    operation: Operation,
    source: serde_json::Value,
    #[serde(default)]
    options: Options,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Resolve,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    caller: Option<CallerContext>,
    #[serde(default)]
    no_values: bool,
    #[serde(default)]
    mode: Mode,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    #[default]
    Resolve,
    Report,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchSource {
    #[serde(rename = "kind")]
    _kind: SearchKind,
}

#[derive(Debug, Deserialize)]
enum SearchKind {
    #[serde(rename = "search")]
    Search,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathSource {
    #[serde(rename = "kind")]
    _kind: PathKind,
    path: String,
}

#[derive(Debug, Deserialize)]
enum PathKind {
    #[serde(rename = "path")]
    Path,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineSource {
    #[serde(rename = "kind")]
    _kind: InlineKind,
    spec_version: u32,
    base_dir: String,
    spec: InlineSpec,
}

#[derive(Debug, Deserialize)]
enum InlineKind {
    #[serde(rename = "inline")]
    Inline,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineSpec {
    project: InlineProject,
    profiles: BTreeMap<String, InlineProfile>,
    #[serde(default)]
    providers: Option<HashMap<String, ProviderAlias>>,
    #[serde(default)]
    scopes: Option<HashMap<String, InlineScope>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineProject {
    name: String,
    #[serde(default)]
    revision: Option<String>,
    #[serde(default)]
    extends: Option<Vec<String>>,
    #[serde(default)]
    require_reason: Option<RequireReason>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineProfile {
    #[serde(default)]
    defaults: Option<InlineProfileDefaults>,
    secrets: BTreeMap<String, InlineSecret>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineProfileDefaults {
    #[serde(default)]
    inherit: Option<bool>,
    #[serde(default)]
    required: Option<bool>,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    providers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineScope {
    secrets: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineSecret {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    required: Option<InlineRequired>,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    composed: Option<String>,
    #[serde(default)]
    providers: Option<Vec<String>>,
    #[serde(default, rename = "ref")]
    reference: Option<crate::NativeAddress>,
    #[serde(default)]
    refs: Option<HashMap<String, crate::NativeAddress>>,
    #[serde(default)]
    as_path: Option<bool>,
    #[serde(default)]
    encoding: Option<SecretEncoding>,
    #[serde(default)]
    extract: Option<SecretExtract>,
    #[serde(default, rename = "type")]
    secret_type: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    credentials: Option<BTreeMap<String, crate::config::CredentialBinding>>,
    #[serde(default)]
    generate: Option<InlineGenerate>,
    #[serde(default)]
    prompt: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InlineRequired {
    Bool(bool),
    Groups(InlineRequiredGroups),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineRequiredGroups {
    #[serde(default, deserialize_with = "deserialize_group_names")]
    at_least_one: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_group_names")]
    exactly_one: Option<Vec<String>>,
}

/// Deserialize a presence-group membership as either one name or an array,
/// matching the file-backed configuration syntax.
fn deserialize_group_names<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(Some(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(name) => vec![name],
        OneOrMany::Many(names) => names,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InlineGenerate {
    Bool(bool),
    Options(Box<InlineGenerateOptions>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineGenerateOptions {
    #[serde(default)]
    length: Option<usize>,
    #[serde(default)]
    bytes: Option<usize>,
    #[serde(default)]
    charset: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    bits: Option<usize>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    capabilities: Option<Vec<String>>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    words: Option<usize>,
    #[serde(default)]
    separator: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    san: Option<Vec<String>>,
    #[serde(default)]
    usages: Option<Vec<String>>,
    #[serde(default)]
    valid_for: Option<String>,
}

impl InlineSpec {
    fn into_config(self) -> std::result::Result<Config, String> {
        Ok(Config {
            project: Project {
                name: self.project.name,
                revision: self.project.revision.unwrap_or_else(|| "1.0".to_string()),
                extends: self.project.extends,
                require_reason: self.project.require_reason,
            },
            profiles: self
                .profiles
                .into_iter()
                .map(|(name, profile)| -> std::result::Result<_, String> {
                    let secrets = profile
                        .secrets
                        .into_iter()
                        .map(|(name, secret)| secret.into_config().map(|secret| (name, secret)))
                        .collect::<std::result::Result<_, _>>()?;
                    Ok((
                        name,
                        ConfigProfile {
                            defaults: profile.defaults.map(|defaults| ProfileDefaults {
                                inherit: defaults.inherit,
                                required: defaults.required,
                                default: defaults.default,
                                providers: defaults.providers,
                            }),
                            secrets,
                        },
                    ))
                })
                .collect::<std::result::Result<_, _>>()?,
            providers: self.providers,
            scopes: self.scopes.map(|scopes| {
                scopes
                    .into_iter()
                    .map(|(name, scope)| {
                        (
                            name,
                            Scope {
                                secrets: scope.secrets,
                            },
                        )
                    })
                    .collect()
            }),
        })
    }
}

impl InlineSecret {
    fn into_config(self) -> std::result::Result<ConfigSecret, String> {
        let (required, at_least_one, exactly_one) = match self.required {
            Some(InlineRequired::Bool(required)) => (Some(required), None, None),
            Some(InlineRequired::Groups(groups)) => {
                if groups.at_least_one.is_none() && groups.exactly_one.is_none() {
                    return Err("`required` table must set `at_least_one` or `exactly_one`".into());
                }
                (None, groups.at_least_one, groups.exactly_one)
            }
            None => (None, None, None),
        };
        Ok(ConfigSecret {
            description: self.description,
            required,
            at_least_one,
            exactly_one,
            default: self.default,
            composed: self.composed,
            providers: self.providers,
            reference: self.reference,
            refs: self.refs,
            as_path: self.as_path,
            encoding: self.encoding,
            extract: self.extract,
            secret_type: self.secret_type,
            format: self.format,
            from: self.from,
            credentials: self.credentials,
            generate: self.generate.map(|generate| match generate {
                InlineGenerate::Bool(enabled) => GenerateConfig::Bool(enabled),
                InlineGenerate::Options(options) => GenerateConfig::Options(GenerateOptions {
                    length: options.length,
                    bytes: options.bytes,
                    charset: options.charset,
                    command: options.command,
                    bits: options.bits,
                    algorithm: options.algorithm,
                    user_id: options.user_id,
                    capabilities: options.capabilities,
                    comment: options.comment,
                    words: options.words,
                    separator: options.separator,
                    language: options.language,
                    kid: options.kid,
                    issuer: options.issuer,
                    san: options.san,
                    usages: options.usages,
                    valid_for: options.valid_for,
                }),
            }),
            prompt: self.prompt,
        })
    }
}

fn error_envelope(kind: &str, message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "ok": false, "error": { "kind": kind, "message": message.into() } })
}

fn ok_envelope(response: impl serde::Serialize) -> serde_json::Value {
    serde_json::json!({ "ok": true, "response": response })
}

fn parse_source(value: serde_json::Value) -> Result<Source, String> {
    let kind = value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "source.kind must be \"search\", \"path\", or \"inline\"".to_string())?;
    match kind {
        "search" => serde_json::from_value::<SearchSource>(value)
            .map(|_| Source::Search)
            .map_err(|error| format!("invalid search source: {error}")),
        "path" => serde_json::from_value::<PathSource>(value)
            .map(|source| Source::Path(source.path))
            .map_err(|error| format!("invalid path source: {error}")),
        "inline" => serde_json::from_value::<InlineSource>(value)
            .map(|source| Source::Inline {
                version: source.spec_version,
                base_dir: source.base_dir,
                spec: Box::new(source.spec),
            })
            .map_err(|error| format!("invalid inline source: {error}")),
        _ => Err(format!(
            "unknown source kind '{kind}'; expected search, path, or inline"
        )),
    }
}

enum Source {
    Search,
    Path(String),
    Inline {
        version: u32,
        base_dir: String,
        spec: Box<InlineSpec>,
    },
}

fn apply_options(mut app: Secrets, options: Options) -> serde_json::Value {
    if let Some(provider) = options.provider {
        app.set_provider(provider);
    }
    if let Some(profile) = options.profile {
        app.set_profile(profile);
    }
    if let Some(scope) = options.scope {
        app.set_scope(scope);
    }
    if let Some(reason) = options.reason {
        app = app.with_reason(reason);
    }
    if let Some(caller) = options.caller {
        app = app.with_caller(caller);
    }
    match options.mode {
        Mode::Report => match app.report() {
            Ok(report) => ok_envelope(report),
            Err(error) => error_envelope(error.kind(), crate::error::display_error_chain(&error)),
        },
        Mode::Resolve => match if options.no_values {
            app.resolve_without_values()
        } else {
            app.resolve()
        } {
            Ok(response) => ok_envelope(response),
            Err(error) => error_envelope(error.kind(), crate::error::display_error_chain(&error)),
        },
    }
}

fn dispatch(request_json: &str) -> serde_json::Value {
    let request: CallRequest = match serde_json::from_str(request_json) {
        Ok(request) => request,
        Err(error) => {
            return error_envelope("invalid_request", format!("invalid call JSON: {error}"));
        }
    };
    if request.request_version != NATIVE_CALL_REQUEST_VERSION {
        return error_envelope(
            "unsupported_request_version",
            format!(
                "unsupported request_version {}; expected {}",
                request.request_version, NATIVE_CALL_REQUEST_VERSION
            ),
        );
    }
    match request.operation {
        Operation::Resolve => {}
    }
    let source = match parse_source(request.source) {
        Ok(source) => source,
        Err(error) => return error_envelope("invalid_request", error),
    };
    let loaded = match source {
        Source::Search => Secrets::load(),
        Source::Path(path) => Secrets::load_from(PathBuf::from(path).as_path()),
        Source::Inline {
            version,
            base_dir,
            spec,
        } => {
            if version != INLINE_SPEC_SCHEMA_VERSION {
                return error_envelope(
                    "unsupported_spec_version",
                    format!(
                        "unsupported inline spec_version {version}; expected {INLINE_SPEC_SCHEMA_VERSION}"
                    ),
                );
            }
            let base_dir = PathBuf::from(base_dir);
            let config = match (*spec).into_config() {
                Ok(config) => config,
                Err(error) => return error_envelope("invalid_request", error),
            };
            Config::from_root_in(config, &base_dir)
                .map_err(Into::into)
                .and_then(Spec::from_config_document)
                .and_then(|spec| Secrets::from_spec_at(spec, base_dir))
        }
    };
    match loaded {
        Ok(app) => apply_options(app, request.options),
        Err(error) => error_envelope(error.kind(), crate::error::display_error_chain(&error)),
    }
}

/// Process a versioned native request and return its JSON response envelope.
///
/// This is used by `secretspec_call` in the C ABI. It is intentionally a
/// different entry point from [`crate::resolve_json`] so inline declarations
/// cannot be ignored by an older runtime.
pub fn call_json(request_json: &str) -> String {
    let envelope =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(request_json)))
            .unwrap_or_else(|_| error_envelope("internal", "internal panic during native call"));
    serde_json::to_string(&envelope).unwrap_or_else(|_| {
        "{\"ok\":false,\"error\":{\"kind\":\"serialize\",\"message\":\"failed to serialize response\"}}".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_declaration_rejects_unknown_secret_fields() {
        let response: serde_json::Value = serde_json::from_str(&call_json(r#"{
          "request_version": 1, "operation": "resolve",
          "source": { "kind": "inline", "spec_version": 1, "base_dir": ".", "spec": {
            "project": { "name": "inline" },
            "profiles": { "default": { "secrets": { "TOKEN": { "description": "token", "typo": true } } } }
          }}
        }"#)).unwrap();
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["kind"], "invalid_request");
    }

    #[test]
    fn inline_declaration_preserves_openpgp_generation_options() {
        let secret: InlineSecret = serde_json::from_str(
            r#"{
              "description": "Release key",
              "type": "openpgp_private_key",
                "generate": {
                  "user_id": "Release Bot <releases@example.com>",
                  "algorithm": "rsa",
                  "bits": 2048,
                  "capabilities": ["sign"]
              }
            }"#,
        )
        .unwrap();
        let secret = secret.into_config().unwrap();
        let Some(GenerateConfig::Options(options)) = secret.generate else {
            panic!("expected OpenPGP generation options");
        };
        assert_eq!(
            options.user_id.as_deref(),
            Some("Release Bot <releases@example.com>")
        );
        assert_eq!(options.algorithm.as_deref(), Some("rsa"));
        assert_eq!(options.bits, Some(2048));
        assert_eq!(options.capabilities, Some(vec!["sign".to_string()]));
    }

    #[test]
    fn inline_declaration_preserves_ssh_generation_options() {
        let secret: InlineSecret = serde_json::from_str(
            r#"{
              "description": "Deployment key",
              "type": "ssh_private_key",
              "generate": {
                "algorithm": "rsa",
                "bits": 4096,
                "comment": "deploy@example.com"
              }
            }"#,
        )
        .unwrap();
        let secret = secret.into_config().unwrap();
        let Some(GenerateConfig::Options(options)) = secret.generate else {
            panic!("expected SSH generation options");
        };
        assert_eq!(options.algorithm.as_deref(), Some("rsa"));
        assert_eq!(options.bits, Some(4096));
        assert_eq!(options.comment.as_deref(), Some("deploy@example.com"));
    }

    #[test]
    fn inline_declaration_preserves_new_generation_options() {
        let passphrase: InlineSecret = serde_json::from_str(
            r#"{
              "description": "Recovery phrase",
              "type": "passphrase",
              "generate": { "words": 8, "separator": "." }
            }"#,
        )
        .unwrap();
        let Some(GenerateConfig::Options(options)) = passphrase.into_config().unwrap().generate
        else {
            panic!("expected passphrase generation options");
        };
        assert_eq!(options.words, Some(8));
        assert_eq!(options.separator.as_deref(), Some("."));

        let mnemonic: InlineSecret = serde_json::from_str(
            r#"{
              "description": "Wallet recovery mnemonic",
              "type": "mnemonic",
              "generate": { "algorithm": "bip39", "words": 24, "language": "english" }
            }"#,
        )
        .unwrap();
        let Some(GenerateConfig::Options(options)) = mnemonic.into_config().unwrap().generate
        else {
            panic!("expected mnemonic generation options");
        };
        assert_eq!(options.algorithm.as_deref(), Some("bip39"));
        assert_eq!(options.words, Some(24));
        assert_eq!(options.language.as_deref(), Some("english"));

        let jwk: InlineSecret = serde_json::from_str(
            r#"{
              "description": "Signing key",
              "type": "jwk_private_key",
              "generate": { "algorithm": "rsa", "bits": 4096, "kid": "release-2026" }
            }"#,
        )
        .unwrap();
        let Some(GenerateConfig::Options(options)) = jwk.into_config().unwrap().generate else {
            panic!("expected JWK generation options");
        };
        assert_eq!(options.algorithm.as_deref(), Some("rsa"));
        assert_eq!(options.bits, Some(4096));
        assert_eq!(options.kid.as_deref(), Some("release-2026"));
    }
}
