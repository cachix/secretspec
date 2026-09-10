//! Doppler provider
//!
//! This provider integrates with [Doppler](https://doppler.com) to store and
//! retrieve secrets over its REST API, in SecretSpec 0.21 and later.
//!
//! # Authentication
//!
//! A Doppler token supplied as the `token` provider credential, or via the
//! `DOPPLER_TOKEN` environment variable that Doppler's own CLI uses. Any
//! Doppler token authenticates; two are worth naming:
//!
//! - a **service account** token (`dp.sa.`), scoped to a workplace by grants,
//!   which can reach every project and config it was granted;
//! - a **service token** (`dp.st.`), pinned by Doppler to exactly one project
//!   and config.
//!
//! A personal (`dp.pt.`) or CLI (`dp.ct.`) token also authenticates, but
//! Doppler withholds a `restricted` secret's value from a token tied to a user
//! identity, so such a read is refused rather than answered. See
//! [`SecretState::Withheld`].
//!
//! Every request names its project and config explicitly, so a pinned token
//! asked for coordinates it does not cover is refused by Doppler rather than
//! quietly answered from wherever it happens to point. See [`Call::query`].
//!
//! # URI Format
//!
//! `doppler://PROJECT[/CONFIG]`
//!
//! The project is required. When no config is given, the SecretSpec profile
//! names it, so a `prd` profile reads Doppler's `prd` config. Profile names are
//! free-form, so naming them after the Doppler configs they read needs no
//! mapping at all.
//!
//! Pinning a config instead makes every profile read that one. That is for the
//! manifests whose profiles are named something else already (`production`
//! against a config named `prd`), or spelled in a way Doppler cannot use as a
//! config name at all (`Production`).
//!
//! # Examples
//!
//! - `doppler://myapp` -- the profile names the config
//! - `doppler://myapp/prd` -- every profile reads the `prd` config
//!
//! # Secret Naming
//!
//! A secret is stored under its own key, verbatim, in the config named by the
//! profile:
//!
//! ```text
//! project "myapp", profile "production", key "DATABASE_URL"
//!   -> Doppler project myapp        (from the URI)
//!      Doppler config  production   (the profile)
//!      secret name     DATABASE_URL (verbatim)
//! ```
//!
//! Verbatim names are the point of this provider: an application reads
//! `DATABASE_URL` from its environment, and a convention that stored it as
//! `SECRETSPEC_MYAPP_PRODUCTION_DATABASE_URL` would be useless for that. Doppler
//! has a native environment axis, so mapping the profile onto a config buys real
//! profile isolation *and* verbatim names, which a flat store cannot offer both
//! of at once.
//!
//! Doppler spells secret names in a narrow alphabet (`^[A-Z_][A-Z0-9_]*$`), so a
//! key it cannot store is refused rather than rewritten to fit: rewriting could
//! land two distinct keys on one name, and the collision would be invisible.
//!
//! # Values Doppler Withholds
//!
//! Doppler can answer a secret that exists with HTTP 200 and a *null* value,
//! reporting a visibility (`restricted`) in place of the value. SecretSpec
//! reports that as the refusal it is rather than as an absent secret, because
//! reading it as absent would have `secretspec check` offer to set -- and
//! overwrite -- a secret it was never allowed to read. See [`SecretState`].
//!
//! # Storage Model
//!
//! SecretSpec's own project name is **unused**: the URI names the Doppler
//! project, which provides the namespace. Two SecretSpec projects pointing at
//! one `doppler://project/config` therefore share a namespace, exactly as they
//! do with Bitwarden Secrets Manager. Give them different Doppler projects or
//! configs to keep them apart.
//!
//! Doppler projects and configs must already exist: a write cannot create them,
//! the way a filesystem-shaped store creates a folder.

use super::{Address, Provider, ProviderCredentials, ProviderUrl, flat_item};
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Doppler's API root. Doppler is SaaS-only with a single address, so this is a
/// constant rather than a knob: there is no self-hosted deployment to point
/// elsewhere.
const API_BASE: &str = "https://api.doppler.com/v3";

const TOKEN: &str = "token";
const DOPPLER_TOKEN_ENV: &str = "DOPPLER_TOKEN";

/// Names Doppler injects into every config's secret listing, carrying the
/// config's own coordinates rather than anything a user stored.
///
/// They are filtered from every read: Doppler refuses to *write* a secret with
/// one of these names ("Unable to create/update secret with reserved name"), so
/// a value under one of them can never be SecretSpec's, and serving it would
/// hand back a secret nobody declared.
pub(crate) const RESERVED_NAMES: [&str; 3] =
    ["DOPPLER_PROJECT", "DOPPLER_CONFIG", "DOPPLER_ENVIRONMENT"];

/// Whether Doppler injects this name itself. See [`RESERVED_NAMES`].
fn is_reserved(name: &str) -> bool {
    RESERVED_NAMES.contains(&name)
}

/// Rejects a secret name Doppler cannot store.
///
/// Doppler's rule, measured against the live API, is `^[A-Z_][A-Z0-9_]*$`: a
/// leading underscore is legal, a leading digit is not, and lowercase is not.
/// The two refusals are worded as Doppler words them, so a user searching the
/// message reaches Doppler's own documentation.
///
/// # Errors
///
/// Returns an error naming the key when it is empty, starts with a digit, or
/// contains anything outside uppercase letters, digits and underscores.
fn validate_secret_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(operation_error(
            "Invalid Doppler secret name: the name is empty.",
        ));
    }
    // Checked before the charset, so a name that breaks both rules reports the
    // same one Doppler reports for it.
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(operation_error(format!(
            "Invalid Doppler secret name '{name}': names may not start with a number. \
             Rename the secret in secretspec.toml -- Doppler cannot store this name, so \
             SecretSpec refuses it rather than storing it under a different one."
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(operation_error(format!(
            "Invalid Doppler secret name '{name}': names may only contain uppercase letters, \
             numbers, and underscores. Rename the secret in secretspec.toml -- Doppler cannot \
             store this name, so SecretSpec refuses it rather than storing it under a \
             different one."
        )));
    }
    Ok(())
}

/// Where a config name came from, so a refusal names the thing the user has
/// to edit.
///
/// All three reach [`validate_config_name`], and the fix differs for each: a
/// profile is renamed in `secretspec.toml`, a URI config is corrected in the
/// provider alias, a `ref`'s config is corrected in the `ref` itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSource {
    /// Pinned in the provider URI, as `doppler://myapp/prd`.
    Uri,
    /// Named by the SecretSpec profile, because the URI pinned none.
    Profile,
    /// Named by a secret's `ref`, as `item = "prd/API_KEY"`.
    Ref,
}

impl ConfigSource {
    /// How this source is identified in a refusal.
    fn attribution(self) -> &'static str {
        match self {
            ConfigSource::Uri => "",
            ConfigSource::Profile => " (named by the SecretSpec profile)",
            ConfigSource::Ref => " (named by the secret's ref)",
        }
    }

    /// What the user edits to fix it.
    fn fix(self) -> &'static str {
        match self {
            ConfigSource::Uri => {
                "Correct the config in the provider URI, e.g. doppler://myapp/prd."
            }
            ConfigSource::Profile => {
                "Rename the profile, or pin a config in the provider URI, e.g. doppler://myapp/prd."
            }
            ConfigSource::Ref => "Correct the config in the ref, e.g. item = \"prd/API_KEY\".",
        }
    }
}

/// Rejects a config name Doppler cannot spell.
///
/// Doppler's rule, measured against the live API, is `^[a-z0-9_-]+$`. Validating
/// locally is worth it because Doppler answers a malformed name with "Please
/// provide a valid config.", which does not say what is wrong -- and the
/// refusal can name which of the three places the config came from, which
/// Doppler cannot know. See [`ConfigSource`].
///
/// This is also what makes [`parse_item`]'s encoding unambiguous: a config name
/// can hold no `/`, so `{config}/{NAME}` splits at the first separator.
///
/// # Errors
///
/// Returns an error naming the config and where it came from.
fn validate_config_name(config: &str, source: ConfigSource) -> Result<()> {
    if is_doppler_slug(config) {
        return Ok(());
    }
    Err(operation_error(format!(
        "Invalid Doppler config '{config}'{}: config names may only contain lowercase \
         letters, numbers, underscores and hyphens. {}",
        source.attribution(),
        source.fix()
    )))
}

/// Splits a native `item` into the config holding the secret and its name.
///
/// `item` carries both, so a convention address and a `ref` share one spelling
/// of the layout. A bare name takes `fallback`: the config pinned in the URI,
/// else the active profile -- the same rule a convention address follows, so a
/// bare `ref` reads from the config every other secret in the profile reads.
///
/// The split is at the *first* separator, which is unambiguous because neither
/// half can contain one: config names are validated by
/// [`validate_config_name`], and secret names by [`validate_secret_name`].
///
/// # Errors
///
/// Returns an error when the item names no config and there is no fallback, or
/// when either half is one Doppler cannot spell.
fn parse_item<'i>(
    item: &'i str,
    fallback: Option<(&'i str, ConfigSource)>,
) -> Result<(&'i str, &'i str)> {
    // The source is tracked because all three reach here: a `ref` naming its
    // own config is fixed in the ref, while a bare name falls back to the URI's
    // or the profile's. Reporting the wrong one sends the user to edit a URI
    // that holds no config at all.
    let (config, name, source) = match item.split_once('/') {
        Some((config, name)) => (config, name, ConfigSource::Ref),
        None => match fallback {
            Some((config, source)) => (config, item, source),
            None => {
                return Err(operation_error(format!(
                    "No Doppler config for the ref '{item}'. Name one in the ref as \
                     item = \"config/{item}\", pin one in the provider URI, e.g. \
                     doppler://myapp/prd, or select a profile to name it."
                )));
            }
        },
    };
    validate_config_name(config, source)?;
    validate_secret_name(name)?;
    Ok((config, name))
}

/// Rejects a project name Doppler cannot spell, or spells differently.
///
/// Measured: the rule is `^[a-z0-9_-]+$`, the same alphabet as a config. A `.`,
/// a space or a `/` is refused outright ("Please provide a valid project."),
/// while an uppercase name is *silently lowercased* -- `UPPER` is looked up as
/// `upper`.
///
/// That lowercasing is why an uppercase name is refused here rather than passed
/// on. Doppler would accept it, so `doppler://MyApp` and `doppler://myapp` name
/// one store while rendering two different [`uri`](Provider::uri) strings -- and
/// the cache route fingerprint and the audit log both treat that string as the
/// store's identity. Refusing is a one-word fix for the user and keeps one store
/// to one name.
///
/// Rejecting `/` is also what lets [`uri`](Provider::uri) interpolate the project
/// without escaping: the URI's own delimiter cannot appear in a validated name.
///
/// # Errors
///
/// Returns an error naming the project, and saying which rule it broke.
fn validate_project_name(project: &str) -> Result<()> {
    if project.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(operation_error(format!(
            "Invalid Doppler project '{project}': Doppler lowercases project names, so this \
             would address '{}'. Name it in lowercase, so one store has one URI.",
            project.to_ascii_lowercase()
        )));
    }
    if is_doppler_slug(project) {
        return Ok(());
    }
    Err(operation_error(format!(
        "Invalid Doppler project '{project}': project names may only contain lowercase letters, \
         numbers, underscores and hyphens."
    )))
}

/// Whether Doppler can spell this as a project or config name.
///
/// Measured: both follow `^[a-z0-9_-]+$`. Shared so the two validators cannot
/// drift apart, which [`parse_item`]'s split depends on: neither half may hold
/// a `/`.
fn is_doppler_slug(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Reads Doppler's error envelope, `{"messages":[...],"success":false}`, when
/// the body carries one.
///
/// The messages are quoted verbatim into the error SecretSpec reports, so a user
/// searching the text lands on Doppler's own documentation.
fn envelope_messages(body: &str) -> Option<String> {
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok()?;
    let messages: Vec<&str> = parsed["messages"]
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    (!messages.is_empty()).then(|| messages.join("; "))
}

/// Renders a *failed* response's body: Doppler's own messages when it sent them,
/// and otherwise the body as-is rather than a summary that would hide it.
///
/// Only for a non-success status. A body that came back with HTTP 200 may carry
/// a secret's plaintext, and this error text is printed and audited, so the
/// 200-shape refusals use [`envelope_messages`] and say nothing about a body
/// they did not recognize.
///
/// A body that is not Doppler's envelope is truncated to
/// [`MAX_ERROR_BODY_BYTES`]. It reached this process from something other than
/// Doppler -- a TLS-terminating proxy, a WAF, a gateway error page -- so its
/// size is not bounded by anything Doppler promises, and it lands verbatim in
/// a message that is printed and persisted to the audit log.
fn error_message(body: &str) -> String {
    envelope_messages(body).unwrap_or_else(|| truncate_chars(body, MAX_ERROR_BODY_BYTES))
}

/// The body text an error may quote from a response that is not Doppler's.
const MAX_ERROR_BODY_BYTES: usize = 2 * 1024;

/// `text` if it fits in `limit` bytes, else its longest character-aligned
/// prefix that does, marked as cut.
fn truncate_chars(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let end = (0..=limit)
        .rev()
        .find(|&n| text.is_char_boundary(n))
        .unwrap_or(0);
    format!("{}... (truncated)", &text[..end])
}

/// How many times one [`Call`] is sent before its answer is taken as final,
/// the first attempt included.
const RETRY_ATTEMPTS: u32 = 3;

/// The longest `retry-after` this provider waits out. Doppler's rate-limit
/// buckets reset per minute, so a suggested wait can approach that; stalling a
/// `secretspec run` for most of a minute is worse than reporting the limit, and
/// a wait past this is reported instead.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);

/// The wait before an attempt is repeated, or `None` when its answer stands.
///
/// Doppler answers a rate limit with 429 and a `retry-after` header holding a
/// suggested wait in seconds; that wait is honored up to [`MAX_RETRY_DELAY`].
/// A 5xx is transient by definition and is retried after a short backoff, as
/// is a 429 without a usable header. Nothing else is retried: a 4xx is
/// Doppler's final word on the request, and a redirect is refused outright by
/// the client (see [`DopplerProvider::http`]). Writes are safe to repeat --
/// setting a value or nulling it is idempotent -- so reads and writes share
/// one policy.
///
/// This matters more here than for a per-secret provider: a profile is one
/// listing request, so without a retry a single 429 fails every secret in it.
fn retry_delay(status: StatusCode, retry_after: Option<&str>, attempt: u32) -> Option<Duration> {
    if attempt >= RETRY_ATTEMPTS {
        return None;
    }
    if status != StatusCode::TOO_MANY_REQUESTS && !status.is_server_error() {
        return None;
    }
    let suggested = retry_after
        .and_then(|seconds| seconds.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    match suggested {
        Some(wait) if wait > MAX_RETRY_DELAY => None,
        Some(wait) => Some(wait),
        None => Some(Duration::from_millis(250) * 2u32.pow(attempt - 1)),
    }
}

/// Appends Doppler's own words to a refusal, when the body carried any.
///
/// Used where the body arrived with HTTP 200: see [`error_message`].
fn quoted_messages(body: &str) -> String {
    envelope_messages(body)
        .map(|messages| format!(" Doppler said: {messages}"))
        .unwrap_or_default()
}

/// Reads one secret's value out of a single-read response.
///
/// Doppler answers a *missing* secret with HTTP 200, `success: true` and a null
/// value rather than a 404 (a 404 means the config itself is absent), so the
/// null is what distinguishes an unset secret from a stored one. A secret
/// holding the empty string is `Some("")`, not `None`.
///
/// `computed` is the value read, never `raw`: Doppler interpolates `${...}`
/// references between secrets, and `raw` carries the unresolved template. See
/// [`SecretState`].
///
/// # Errors
///
/// Returns an error when the body is not JSON, does not carry Doppler's `value`
/// object, or carries a value Doppler withheld.
fn parse_secret_value(body: &str, name: &str) -> Result<Option<SecretBytes>> {
    let parsed: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        operation_error(format!(
            "Failed to parse Doppler's response for '{name}': {e}"
        ))
    })?;
    // The `value` object is required rather than indexed straight through:
    // indexing a body of any other shape yields null, which `secret_value`
    // cannot tell from a secret that is simply unset. An HTTP 200 that is not
    // Doppler's answer -- an intercepting proxy's envelope, a renamed field --
    // has to be reported, because a fallback chain treats "unset" as an
    // ordinary miss and serves the next provider's value without a warning.
    if !parsed["value"].is_object() {
        return Err(operation_error(format!(
            "Doppler's response for '{name}' carries no `value` object.{}",
            quoted_messages(body)
        )));
    }
    report(classify(&parsed["value"]), name)
}

/// Reads every secret in a config out of a list response, indexed by name.
///
/// Reserved names are filtered here as well as excluded at the source (see
/// [`Call::query`]): passing one on would report a secret nobody declared --
/// exactly what a parity checker over a Doppler config has to special-case if
/// its source does not. Keeping the local filter is what makes a batch read
/// agree with a single read, which answers a reserved name without asking at
/// all.
///
/// # Errors
///
/// Returns an error when the body is not JSON, carries no `secrets` object,
/// carries an entry that is not a secret object, or carries a value Doppler
/// withheld.
fn parse_config_secrets(body: &str, config: &str) -> Result<HashMap<String, SecretBytes>> {
    let parsed: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        operation_error(format!(
            "Failed to parse Doppler's listing of config '{config}': {e}"
        ))
    })?;
    let secrets = parsed["secrets"].as_object().ok_or_else(|| {
        operation_error(format!(
            "Doppler's listing of config '{config}' carries no `secrets` object."
        ))
    })?;

    let mut listed = HashMap::with_capacity(secrets.len());
    for (name, value) in secrets {
        if is_reserved(name) {
            continue;
        }
        // Required to be an object for the same reason `parse_secret_value`
        // requires one around the whole body: indexing any other shape yields
        // null, which `classify` cannot tell from a secret that is simply
        // unset -- and a batch read must not resolve to "unset" what a single
        // read reports. Named by JSON type only: a 200 body can hold
        // plaintext.
        if !value.is_object() {
            return Err(operation_error(format!(
                "Doppler's listing of config '{config}' carries {} rather than a secret \
                 object under '{name}'.",
                json_type(value)
            )));
        }
        // A withheld value is refused here rather than dropped: omitting it
        // would read as a secret that is simply unset.
        if let Some(value) = report(classify(value), name)? {
            listed.insert(name.clone(), value);
        }
    }
    Ok(listed)
}

/// Reads the secret names out of a names response, dropping the reserved ones.
///
/// # Errors
///
/// Returns an error when the body is not JSON, carries no `names` array, or
/// carries an entry that is not a string. Dropping such an entry instead
/// would have `secretspec import` report a partial list as if the config
/// genuinely held fewer secrets -- the same silent shape drift the value
/// parsers refuse.
fn parse_secret_names(body: &str, config: &str) -> Result<Vec<String>> {
    let parsed: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        operation_error(format!(
            "Failed to parse Doppler's secret names for config '{config}': {e}"
        ))
    })?;
    let names = parsed["names"].as_array().ok_or_else(|| {
        operation_error(format!(
            "Doppler's secret names for config '{config}' carry no `names` array.{}",
            quoted_messages(body)
        ))
    })?;
    let mut listed = Vec::with_capacity(names.len());
    for name in names {
        let name = name.as_str().ok_or_else(|| {
            operation_error(format!(
                "Doppler's secret names for config '{config}' carry {} where a name was \
                 expected.",
                json_type(name)
            ))
        })?;
        if !is_reserved(name) {
            listed.push(name.to_string());
        }
    }
    Ok(listed)
}

/// Rejects a value Doppler cannot store unchanged.
///
/// Doppler interpolates `${...}` references between secrets in a config, and
/// measurement shows there is no way for such a value to survive a round trip:
/// an *unresolvable* reference is refused outright ("The secret "X" cannot
/// resolve the reference ${Y}."), and a *resolvable* one is silently rewritten,
/// so `${DB_HOST}` is read back as the value of `DB_HOST`.
///
/// So the value is refused here rather than written and quietly changed. The
/// case that makes this matter is SecretSpec's own cache: a cache entry wrapping
/// an authoritative secret whose plaintext happens to contain `${...}` would
/// come back as a *different* secret, with the entry's project, profile and
/// route fingerprint all still validating, and be exported as fresh.
///
/// # Errors
///
/// Returns an error naming the secret, never its value.
fn validate_secret_value(name: &str, value: &str) -> Result<()> {
    if !value.contains("${") {
        return Ok(());
    }
    Err(operation_error(format!(
        "Doppler cannot store the value of '{name}' unchanged: it contains '${{', which Doppler \
         reads as a reference to another secret. Doppler refuses a reference it cannot resolve \
         and rewrites one it can, so such a value never reads back as it was written. Store the \
         value in a provider that keeps it verbatim, or remove the '${{'."
    )))
}

/// The greatest length of one `secrets=` filter, in bytes before percent
/// encoding.
///
/// Doppler documents no limit on the filter itself but allows 1,200 secrets in
/// a config, so the filter's length is bounded only by the manifest. It travels
/// in the URI, where the bound is the API edge's request-line limit rather than
/// anything Doppler promises, and exceeding it fails a whole profile's read at
/// once. 4 KiB leaves ample room for the rest of the URI inside the smallest
/// limit an HTTP front end in common use imposes.
const MAX_FILTER_BYTES: usize = 4 * 1024;

/// Splits `wanted` into comma-joined `secrets=` filters that each fit
/// [`MAX_FILTER_BYTES`].
///
/// Chunking is sound because Doppler resolves `${...}` references against the
/// config rather than against the response, so a reference whose target lands
/// in another chunk still resolves. An empty `wanted` yields one empty filter,
/// which reads the whole config: see [`Call::List`].
///
/// A single name longer than the budget still gets its own request rather than
/// being dropped -- Doppler's own limit is 200 characters per name, so the
/// budget cannot actually be exceeded by one.
fn filter_chunks(wanted: &[String]) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut chunk = String::new();
    for name in wanted {
        if !chunk.is_empty() && chunk.len() + 1 + name.len() > MAX_FILTER_BYTES {
            chunks.push(std::mem::take(&mut chunk));
        }
        if !chunk.is_empty() {
            chunk.push(',');
        }
        chunk.push_str(name);
    }
    chunks.push(chunk);
    chunks
}

/// What one of Doppler's secret objects holds, classified before any policy
/// applies.
///
/// [`classify`] is total -- every JSON shape lands in exactly one variant --
/// and [`report`] decides what SecretSpec does about each, so the measured
/// facts (which shape means what) and the policy (what to say about it) are
/// testable separately. The variant docs record the measurements that pin
/// them.
enum SecretState {
    /// A stored value: `computed` is a string.
    ///
    /// `computed`, never `raw`. Doppler resolves `${OTHER_SECRET}` references
    /// between secrets, and the two fields differ exactly when a secret uses
    /// one:
    ///
    /// ```text
    /// raw      = "postgres://${PLAIN_HOST}/app"
    /// computed = "postgres://db.internal/app"    <- what `doppler run` injects
    /// ```
    ///
    /// Serving `raw` would hand the application a plausible-looking connection
    /// string containing a literal `${PLAIN_HOST}`, which fails at connect
    /// time far from its cause, or connects somewhere unintended.
    ///
    /// That guarantee is Doppler's, and it is conditional: when a reference's
    /// *target is deleted*, `computed` was measured to degrade to the
    /// unresolved template -- `computed == raw ==
    /// "pg://${PROBE_TARGET}/app"`, a string, with `masked` visibility and
    /// HTTP 200. So a dangling reference is served through as that literal,
    /// which is what `doppler run` injects for it too. SecretSpec stays
    /// faithful to Doppler rather than second-guessing which `${...}` in a
    /// value is a mistake; reading `raw` would produce the same literal for
    /// *every* reference, resolvable or not, which is the case this field
    /// choice exists to prevent.
    Present(SecretBytes),
    /// No such secret: every field is null, the visibilities included.
    Unset,
    /// A secret object that is not any answer Doppler gives.
    ///
    /// Doppler reports an absent secret by nulling *every* field -- its own
    /// API clients test exactly that, all six fields at once -- so a `raw`
    /// that carries a string while `computed` carries nothing is not an
    /// absent secret. It is a body whose shape this provider does not
    /// recognize: a renamed or dropped field, or an intercepting proxy's
    /// envelope.
    ///
    /// That has to be reported for the same reason the outer `value` guard in
    /// [`parse_secret_value`] exists: resolving it to [`Unset`](Self::Unset)
    /// makes a fallback chain treat it as an ordinary miss and serve the next
    /// provider's value with no warning, and makes `secretspec check` offer
    /// to set -- and overwrite -- a secret that exists.
    Unrecognized,
    /// The secret exists, but Doppler served a visibility in place of its
    /// value.
    ///
    /// The distinction from [`Unset`](Self::Unset) rests on a measured fact:
    /// an unset secret answers with every field null, `computedVisibility`
    /// included. So a visibility without a value cannot mean "unset", and
    /// reporting it as unset would have `secretspec check` offer to set -- and
    /// overwrite -- a secret that exists.
    ///
    /// Doppler documents exactly when this happens: a `restricted` secret's
    /// value "is not returned if the authentication method is tied to a user
    /// identity (like a personal token or CLI token)". So a `DOPPLER_TOKEN`
    /// holding a `dp.pt.` or `dp.ct.` token -- what `doppler login` leaves
    /// behind on a developer machine -- reads a `restricted` secret into this
    /// state, while a service or service account token reads its value
    /// normally. That matches every read measured against the live API: a
    /// value present (any visibility, `masked` included) is
    /// [`Present`](Self::Present), an absent secret is
    /// [`Unset`](Self::Unset), and a `restricted` secret read with a service
    /// account token returned its value.
    ///
    /// The refusal in [`report`] still describes the state rather than
    /// asserting the cause, because the visibility Doppler reports is the only
    /// thing in the response that explains it.
    Withheld { visibility: String },
    /// `computed` is a JSON type this provider has not measured, named by type
    /// so an error can never echo the value.
    NotAString { json_type: &'static str },
}

/// Classifies one of Doppler's secret objects.
///
/// Total, and matched by shape in one place so no shape can fall through to a
/// neighboring diagnosis: a non-string value, for instance, can never read as
/// withheld merely because it also carries a visibility.
fn classify(value: &serde_json::Value) -> SecretState {
    match &value["computed"] {
        serde_json::Value::String(computed) => {
            SecretState::Present(SecretBytes::from_utf8(computed.clone()))
        }
        // A visibility with no value is Doppler declining to serve one; an
        // unset secret carries neither.
        serde_json::Value::Null => match value["computedVisibility"]
            .as_str()
            .or_else(|| value["rawVisibility"].as_str())
        {
            Some(visibility) => SecretState::Withheld {
                visibility: visibility.to_string(),
            },
            // An absent secret nulls every field, `raw` included. A stored
            // `raw` with nothing under `computed` is therefore not Doppler's
            // answer for one: see `SecretState::Unrecognized`.
            None if value["raw"].is_string() => SecretState::Unrecognized,
            None => SecretState::Unset,
        },
        other => SecretState::NotAString {
            json_type: json_type(other),
        },
    }
}

/// SecretSpec's answer for each [`SecretState`].
///
/// A withheld value is an error rather than `None`: reading it as absent
/// would have `secretspec check` offer to set -- and overwrite -- a secret
/// this token was never allowed to read. A non-string value is an error
/// naming the JSON type, never the value: misreporting it as withheld would
/// send the user to fix permissions that are fine, and reporting it as unset
/// would offer to overwrite it.
fn report(state: SecretState, name: &str) -> Result<Option<SecretBytes>> {
    match state {
        SecretState::Present(value) => Ok(Some(value)),
        SecretState::Unset => Ok(None),
        SecretState::Unrecognized => Err(operation_error(format!(
            "Doppler's answer for '{name}' carries a raw value but no computed one, which is \
                 not a shape this provider recognizes -- an absent secret nulls every field. \
                 SecretSpec refuses it rather than reading it as a secret that is not set."
        ))),
        SecretState::Withheld { visibility } => Err(operation_error(format!(
            "Doppler withheld the value of '{name}': the secret exists with visibility \
                 '{visibility}' but Doppler returned no value for it, so this token may see that \
                 it exists but not read it. Doppler does not serve a 'restricted' value to a \
                 token tied to a user identity, so use a service token (dp.st.) or a service \
                 account token (dp.sa.) rather than a personal (dp.pt.) or CLI (dp.ct.) one, or \
                 lower the secret's visibility in Doppler."
        ))),
        SecretState::NotAString { json_type } => Err(operation_error(format!(
            "Doppler returned {json_type} rather than a string as the value of '{name}', \
                 which SecretSpec cannot hand to a process as an environment variable. Store \
                 the secret as a string in Doppler."
        ))),
    }
}

/// A JSON value's type, for an error that must name a value's shape without
/// echoing the value itself.
fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// How a read treats a Doppler config that does not exist.
///
/// Doppler answers an absent config with 404. For a read that is a
/// misconfiguration worth reporting, rather than every secret in the profile
/// quietly reading as unset. For a `delete` it is not: deleting is idempotent,
/// and a config holding nothing holds nothing to delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbsentConfig {
    /// Report it, naming the config.
    IsAnError,
    /// Treat it as an absent secret.
    HoldsNothing,
}

/// Renders a failed response, naming the likely cause for the statuses a
/// user actually hits.
fn http_error(project: &str, status: StatusCode, body: &str, action: &str) -> SecretSpecError {
    let message = error_message(body);
    let detail = match status {
        // Doppler answers 401 before routing, so this is always the token
        // and never a mistyped path.
        StatusCode::UNAUTHORIZED => format!(
            "Doppler rejected the token (401) while {action}: {message}. Check the {TOKEN} \
             credential or {DOPPLER_TOKEN_ENV}."
        ),
        // A token that cannot reach the coordinates lands here, with Doppler
        // naming what it refused. Both token types can: a service account
        // token is limited by its grants, a service token by its pinning.
        StatusCode::BAD_REQUEST => format!(
            "Doppler refused the request (400) while {action}: {message}. This provider \
             addresses project '{project}' explicitly; a service account token reaches only \
             what its grants cover, and a service token (dp.st.) only the one project and \
             config it is pinned to."
        ),
        StatusCode::NOT_FOUND => format!(
            "Doppler has no such project or config (404) while {action}: {message}. \
             Projects and configs must already exist -- SecretSpec does not create them."
        ),
        StatusCode::TOO_MANY_REQUESTS => {
            format!("Doppler rate limit exceeded (429) while {action}: {message}.")
        }
        _ => format!("Doppler returned HTTP {status} while {action}: {message}"),
    };
    operation_error(detail)
}

fn operation_error(message: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.into())
}

/// What one secret's read means, given the status and body it came back with.
///
/// A 200 is parsed ([`parse_secret_value`]); unlike a store that answers 404
/// for a missing secret, Doppler answers 200 with a null value for that,
/// which leaves every error status a real error. A 404 means the *config* is
/// absent -- for `get` a misconfiguration worth reporting, not a profile of
/// secrets silently reading as unset; for `delete`'s probe an absent secret,
/// per [`AbsentConfig`].
fn interpret_read(
    loc: &Location,
    status: StatusCode,
    body: &str,
    absent_config: AbsentConfig,
) -> Result<Option<SecretBytes>> {
    if status == StatusCode::OK {
        return parse_secret_value(body, &loc.name);
    }
    if status == StatusCode::NOT_FOUND && absent_config == AbsentConfig::HoldsNothing {
        return Ok(None);
    }
    Err(http_error(
        &loc.project,
        status,
        body,
        &format!("reading '{}'", loc.name),
    ))
}

/// What a listing of one config means: a 200 is handed to `parse`, anything
/// else is an error naming the config. Both the values listing and the names
/// listing land here.
fn interpret_listing<T>(
    project: &str,
    config: &str,
    status: StatusCode,
    body: &str,
    parse: impl FnOnce(&str, &str) -> Result<T>,
) -> Result<T> {
    if status != StatusCode::OK {
        return Err(http_error(
            project,
            status,
            body,
            &format!("listing config '{config}'"),
        ));
    }
    parse(body, config)
}

/// Configuration for the Doppler provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DopplerConfig {
    /// The Doppler project holding the secrets.
    pub project: String,
    /// The Doppler config to read and write. When `None`, the SecretSpec profile
    /// names it.
    pub config: Option<String>,
}

impl TryFrom<&ProviderUrl> for DopplerConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();
        if scheme != "doppler" {
            return Err(operation_error(format!(
                "Invalid scheme '{scheme}' for doppler provider. Expected 'doppler'."
            )));
        }

        // Doppler takes no URI options, so anything beyond the host and path
        // can only be a mistake -- and a silent one. `doppler://myapp?config=prd`
        // would drop the query and let the profile name the config instead;
        // `doppler://myapp#prd`, a typo of `/` as `#`, likewise; and a port or
        // username would vanish from `uri()`, so two URIs would render as one
        // store identity for the cache route and the audit log. The same
        // reasoning that makes the project mandatory makes each of these an
        // error.
        if !url.username().is_empty()
            || url.password().is_some()
            || url.has_port()
            || url.has_query()
            || url.has_fragment()
        {
            return Err(operation_error(
                "doppler:// takes only a project and an optional config, as the URI host \
                 and path, e.g. doppler://myapp/prd. User information, ports, query \
                 parameters and fragments are not supported.",
            ));
        }

        // The project is the URI host, as in `bws://project-uuid`.
        let project = url.host().filter(|host| !host.is_empty()).ok_or_else(|| {
            operation_error(
                "No Doppler project given. Name it in the URI, e.g. doppler://myapp or \
                 doppler://myapp/prd. The project is required: SecretSpec never lets a \
                 pinned token choose its own coordinates, because a token repointed at \
                 another config would then change which secrets are served silently.",
            )
        })?;
        validate_project_name(&project)?;

        let path = url.path();
        let config = match path.trim_matches('/') {
            "" => None,
            config => {
                if config.contains('/') {
                    return Err(operation_error(format!(
                        "Invalid Doppler config '{config}': expected a single config name, \
                         e.g. doppler://myapp/prd. Doppler configs do not nest."
                    )));
                }
                validate_config_name(config, ConfigSource::Uri)?;
                Some(config.to_string())
            }
        };

        Ok(Self { project, config })
    }
}

/// One secret's full coordinates, in Doppler's own terms.
///
/// Built only by [`locate`](DopplerProvider::locate), so the project a
/// request addresses always came from the URI, never from a call site's own
/// idea of it.
#[derive(Debug)]
struct Location {
    /// The Doppler project, from the URI.
    project: String,
    /// The Doppler config holding the secret.
    config: String,
    /// The secret's name, exactly as Doppler stores it.
    name: String,
}

/// One request to Doppler's API, as data.
///
/// Method, path, query and body all derive from the same value, so what a
/// request says on the wire is decided in one pure place -- testable without
/// a token -- and [`dispatch`](DopplerProvider::dispatch) is the only code
/// that touches the network.
enum Call<'a> {
    /// Read one secret.
    Read(&'a Location),
    /// Read the named secrets in one config. `names` is comma-joined, and
    /// empty reads the whole config: see
    /// [`list_async`](DopplerProvider::list_async) for why it never is.
    List {
        project: &'a str,
        config: &'a str,
        names: &'a str,
    },
    /// The secret names in one config, values untouched.
    Names { project: &'a str, config: &'a str },
    /// Write one secret, or delete it when the value is `None`.
    Write(&'a Location, Option<&'a str>),
}

impl Call<'_> {
    fn method(&self) -> reqwest::Method {
        match self {
            Call::Read(_) | Call::List { .. } | Call::Names { .. } => reqwest::Method::GET,
            Call::Write(..) => reqwest::Method::POST,
        }
    }

    fn path(&self) -> &'static str {
        match self {
            Call::Read(_) => "/configs/config/secret",
            Call::List { .. } | Call::Write(..) => "/configs/config/secrets",
            Call::Names { .. } => "/configs/config/secrets/names",
        }
    }

    /// The query naming which project and config the request addresses.
    ///
    /// Both listings also ask Doppler to leave its own injected names out:
    /// `include_managed_secrets` defaults to *true*, so every listing carries
    /// [`RESERVED_NAMES`] whether or not they were asked for. Excluding them at
    /// the source is what keeps a name Doppler starts injecting *later* out of
    /// discovery, which a fixed local list cannot; the local filter stays as
    /// the belt to this braces, because it is what makes a single read and a
    /// batch read agree.
    ///
    /// Every read names both, and this is load-bearing rather than tidiness.
    /// A service token (`dp.st.`) is pinned to one project and config, and a
    /// request that names neither is answered from wherever the token points:
    /// a token swapped from `dev` to `prd` would silently change which
    /// secrets the application receives, with no error and nothing in the URI
    /// to contradict it. Naming the coordinates converts that into Doppler's
    /// own explicit refusal ("This token does not have access to requested
    /// config 'prd'"). A write names them too, in its body: see
    /// [`Call::body`].
    fn query(&self) -> Vec<(&'static str, &str)> {
        match self {
            Call::Read(loc) => vec![
                ("project", loc.project.as_str()),
                ("config", loc.config.as_str()),
                ("name", loc.name.as_str()),
            ],
            Call::List {
                project,
                config,
                names,
            } => {
                let mut query = vec![
                    ("project", *project),
                    ("config", *config),
                    ("include_managed_secrets", "false"),
                ];
                if !names.is_empty() {
                    query.push(("secrets", *names));
                }
                query
            }
            Call::Names { project, config } => {
                vec![
                    ("project", *project),
                    ("config", *config),
                    ("include_managed_secrets", "false"),
                ]
            }
            Call::Write(..) => Vec::new(),
        }
    }

    /// A write's body. Doppler's write endpoint takes a map of names to
    /// values and *merges* it into the config, so writing one secret leaves
    /// its siblings untouched; a null value deletes. The project and config
    /// ride in the body, which is what [`Call::query`] demands of every other
    /// request in its query.
    fn body(&self) -> Option<serde_json::Value> {
        match self {
            Call::Write(loc, value) => Some(serde_json::json!({
                "project": loc.project,
                "config": loc.config,
                "secrets": {
                    &loc.name: value,
                },
            })),
            _ => None,
        }
    }
}

/// Doppler provider.
pub struct DopplerProvider {
    config: DopplerConfig,
    /// Credentials supplied by the provider alias.
    credentials: ProviderCredentials,
    /// One HTTP client for every request, so a run of secrets reuses the
    /// connection rather than building a pool per call.
    http: OnceLock<reqwest::Client>,
    /// The active SecretSpec profile, when resolution has announced one. Names
    /// the config for a bare `ref` under a URI that pins none: see
    /// [`set_profile`](Provider::set_profile).
    profile: Mutex<Option<String>>,
    /// Doppler's API root. [`API_BASE`] in every build; tests point it at an
    /// in-process fixture to exercise the transport without a token.
    api_base: String,
    /// Lets a test fixture on `127.0.0.1` stand in for Doppler over plain HTTP.
    #[cfg(test)]
    allow_insecure_loopback: bool,
}

crate::register_provider! {
    struct: DopplerProvider,
    config: DopplerConfig,
    metadata: &super::catalog::DOPPLER,
}

impl DopplerProvider {
    /// Creates a new DopplerProvider with the given configuration.
    pub fn new(config: DopplerConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            http: OnceLock::new(),
            profile: Mutex::new(None),
            api_base: API_BASE.to_string(),
            #[cfg(test)]
            allow_insecure_loopback: false,
        }
    }

    /// The profile resolution announced through
    /// [`set_profile`](Provider::set_profile), if any.
    ///
    /// A poisoned lock is read through rather than treated as empty. The lock
    /// guards a plain `Option<String>` that is assigned in one step, so a
    /// panic elsewhere while holding it leaves nothing half-written; dropping
    /// the profile instead would make every bare `ref` fail with "No Doppler
    /// config" for a reason unrelated to Doppler.
    fn session_profile(&self) -> Option<String> {
        self.profile
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .filter(|profile| !profile.is_empty())
    }

    /// The shared HTTP client.
    ///
    /// Redirects are never followed: a write body carries a secret's
    /// plaintext, and a 307/308 would replay it to an origin the *response*
    /// chose rather than Doppler's fixed API address. HTTPS only, for the same
    /// reason.
    fn http(&self) -> Result<&reqwest::Client> {
        if let Some(client) = self.http.get() {
            return Ok(client);
        }
        #[cfg(not(test))]
        let https_only = true;
        #[cfg(test)]
        let https_only = !self.allow_insecure_loopback;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(https_only)
            .build()
            .map_err(|e| {
                operation_error(format!(
                    "Failed to build the Doppler HTTP client: {}",
                    crate::error::display_error_chain(&e)
                ))
            })?;
        Ok(self.http.get_or_init(|| client))
    }

    /// Resolves the Doppler token: the `token` credential, else `DOPPLER_TOKEN`.
    ///
    /// Trimmed, because `DOPPLER_TOKEN=$(cat token.txt)` is how a token usually
    /// arrives in CI: a trailing newline is not a valid HTTP header value, and
    /// reqwest defers that to `send`, where it surfaces as "Failed to connect to
    /// Doppler" -- sending the user to debug DNS and egress rules over one
    /// stray byte.
    ///
    /// # Errors
    ///
    /// Returns an error naming both the credential and the environment variable
    /// when neither supplies one.
    fn token(&self) -> Result<SecretBytes> {
        super::credential_or_env(&self.credentials, TOKEN, DOPPLER_TOKEN_ENV)
            .map(|token| SecretBytes::from_slice(token.expose_secret().trim_ascii()))
            .filter(|token| !token.expose_secret().is_empty())
            .ok_or_else(|| {
                operation_error(format!(
                    "No Doppler token found. Configure the {TOKEN} provider credential, or set \
                     {DOPPLER_TOKEN_ENV}. Any Doppler token works; prefer a service account \
                     token (dp.sa.) or a service token (dp.st.), because Doppler does not serve \
                     a 'restricted' secret's value to a personal (dp.pt.) or CLI (dp.ct.) token."
                ))
            })
    }

    /// Resolves an address to one secret's Doppler location.
    ///
    /// The sole path from an [`Address`] to a [`Location`], and the only
    /// constructor of one: every operation goes through here, so the layout
    /// is spelled once and the project a request addresses always came from
    /// the URI. Pure, no I/O -- an unspellable name is refused before a
    /// request is built.
    ///
    /// # Errors
    ///
    /// Returns an error when the address names something Doppler cannot spell,
    /// or when a `ref` names no config and none is pinned.
    fn locate(&self, addr: Address<'_>) -> Result<Location> {
        let item = flat_item(self, addr)?;
        let session = self.session_profile();
        let fallback = self.implied_config(session.as_deref());
        let (config, name) = parse_item(&item, fallback)?;
        Ok(Location {
            project: self.config.project.clone(),
            config: config.to_string(),
            name: name.to_string(),
        })
    }

    /// The config an address that names none reads from: the one pinned in the
    /// URI, else the one the profile names, else nothing.
    ///
    /// The single owner of that rule. Every path that has to agree on it goes
    /// through here -- [`locate`](Self::locate) for an operation,
    /// [`convention_address`](Provider::convention_address) for a declared
    /// secret, [`reflect_config`](Self::reflect_config) for discovery -- so
    /// `secretspec init --from doppler://myapp` cannot come to discover
    /// declarations in one config while resolving them reads another. The
    /// returned [`ConfigSource`] is what lets a refusal name the place the user
    /// has to edit.
    fn implied_config<'a>(&'a self, profile: Option<&'a str>) -> Option<(&'a str, ConfigSource)> {
        match (&self.config.config, profile) {
            (Some(config), _) => Some((config.as_str(), ConfigSource::Uri)),
            (None, Some(profile)) => Some((profile, ConfigSource::Profile)),
            (None, None) => None,
        }
    }

    /// [`implied_config`](Self::implied_config) where a profile is always known,
    /// validated up front.
    ///
    /// [`locate`](Self::locate) leaves the check to [`parse_item`] instead,
    /// because a `ref` that names its own config never consults the fallback
    /// and must not be refused for a profile it does not use. Here there is no
    /// `ref`: the config the profile names *is* the answer, so an unspellable
    /// one is refused before anything is built from it.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile cannot name a Doppler config.
    fn config_for_profile(&self, profile: &str) -> Result<String> {
        // `Some(profile)` always implies a config; the fallback repeats what
        // `implied_config` would have returned rather than asserting.
        let (config, source) = self
            .implied_config(Some(profile))
            .unwrap_or((profile, ConfigSource::Profile));
        if source == ConfigSource::Profile {
            validate_config_name(config, source)?;
        }
        Ok(config.to_string())
    }

    /// The write policy, applied to an already-resolved [`Location`].
    ///
    /// Split out of [`check_writable`](Provider::check_writable) so `set` can
    /// resolve the address once and still apply exactly the same rule: the trait
    /// requires the two to refuse for the same reason, and one owner of the rule
    /// guarantees that where two calls to [`locate`](Self::locate) only repeat
    /// the work.
    ///
    /// # Errors
    ///
    /// Returns an error when Doppler reserves the name for itself.
    fn check_location(&self, loc: &Location) -> Result<()> {
        // Doppler answers a reserved name with "Unable to create/update secret
        // with reserved name" -- a round trip, and a 400 whose local
        // explanation blames service-token pinning instead. The name is
        // known-unwritable without asking: see RESERVED_NAMES.
        if is_reserved(&loc.name) {
            return Err(operation_error(format!(
                "Doppler reserves the secret name '{}' for itself and refuses to store one \
                 under it, so SecretSpec cannot either -- and a read of it can only ever \
                 return Doppler's own injected value. Rename the secret in secretspec.toml.",
                loc.name
            )));
        }
        Ok(())
    }

    /// The config `reflect` lists: the pinned one, else the profile discovery
    /// is running for.
    ///
    /// This is the same rule [`convention_address`](Provider::convention_address)
    /// applies, so `secretspec init --from doppler://myapp` discovers the
    /// declarations in exactly the config that resolving them would later read.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile cannot name a Doppler config.
    fn reflect_config(&self, context: super::DiscoveryContext<'_>) -> Result<String> {
        self.config_for_profile(context.profile)
    }

    /// Sends one [`Call`] to Doppler.
    ///
    /// The sole path to the network: everything about the request but the
    /// token comes from the [`Call`], already decided and testable without
    /// one, so what remains here is only transport.
    async fn dispatch(&self, call: &Call<'_>) -> Result<reqwest::Response> {
        let token = self.token()?;
        let mut request = self
            .http()?
            .request(call.method(), format!("{}{}", self.api_base, call.path()))
            .header(
                reqwest::header::AUTHORIZATION,
                super::credentials::credential_bearer_header(token.expose_secret())?,
            )
            .query(&call.query());
        if let Some(body) = call.body() {
            request = request.json(&body);
        }
        request.send().await.map_err(|e| {
            operation_error(format!(
                "Failed to connect to Doppler at {}: {}",
                self.api_base,
                crate::error::display_error_chain(&e)
            ))
        })
    }

    /// Sends one [`Call`] and hands back what a pure interpreter takes: the
    /// status and the body.
    ///
    /// A rate limit or a server error is retried per [`retry_delay`]; the
    /// answer handed back is the last attempt's, so an exhausted retry still
    /// reports Doppler's own words.
    ///
    /// The wait is a blocking sleep, as in the Vault provider: every `execute`
    /// runs under its own [`block_on`](super::block_on) with nothing else to
    /// drive meanwhile, and `tokio`'s timers are not built into this crate.
    ///
    /// Every request, writes included, goes through here: [`write_async`]
    /// (Self::write_async) must not reach [`dispatch`](Self::dispatch) on its
    /// own, or a write would be the one request a rate limit fails outright.
    async fn execute(&self, call: &Call<'_>) -> Result<(StatusCode, String)> {
        let mut attempt = 1;
        loop {
            let response = self.dispatch(call).await?;
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = Self::response_body(response).await?;
            match retry_delay(status, retry_after.as_deref(), attempt) {
                Some(wait) => {
                    std::thread::sleep(wait);
                    attempt += 1;
                }
                None => return Ok((status, body)),
            }
        }
    }

    /// Reads a response body without hiding a transport failure behind an empty
    /// string and a later, misleading JSON parse error.
    async fn response_body(response: reqwest::Response) -> Result<String> {
        let status = response.status();
        response.text().await.map_err(|e| {
            operation_error(format!(
                "Failed to read Doppler's HTTP {status} response body: {}",
                crate::error::display_error_chain(&e)
            ))
        })
    }

    /// Reads one secret.
    ///
    /// A reserved name is answered without asking: Doppler serves its own
    /// injected value for one, which is never SecretSpec's to serve, so the
    /// round trip can only ever produce `None`. See [`RESERVED_NAMES`].
    async fn get_async(
        &self,
        loc: &Location,
        absent_config: AbsentConfig,
    ) -> Result<Option<SecretBytes>> {
        if is_reserved(&loc.name) {
            return Ok(None);
        }
        let (status, body) = self.execute(&Call::Read(loc)).await?;
        interpret_read(loc, status, &body, absent_config)
    }

    /// Lists the named secrets in one config, indexed by name.
    ///
    /// One request answers for all of them: Doppler's listing carries no
    /// pagination, so this is the batch read that makes [`get_many`] one round
    /// trip per config -- or, for a manifest too large to name in one URI, per
    /// [`filter_chunks`] batch of names.
    ///
    /// `wanted` narrows the response to the secrets actually declared, via
    /// Doppler's `secrets=` filter. Asking for the whole config instead would
    /// pull the plaintext of every secret in it into this process to serve the
    /// handful that were declared -- indistinguishable, in Doppler's activity
    /// log, from exporting the config. Server-side `${...}` resolution is
    /// unaffected by the filter: a reference whose target is *not* in `wanted`
    /// still resolves (measured), because Doppler resolves against the config
    /// rather than against the response -- which is also what makes chunking
    /// safe.
    ///
    /// [`get_many`]: Provider::get_many
    async fn list_async(
        &self,
        config: &str,
        wanted: &[String],
    ) -> Result<HashMap<String, SecretBytes>> {
        let mut listed = HashMap::with_capacity(wanted.len());
        for names in filter_chunks(wanted) {
            let call = Call::List {
                project: &self.config.project,
                config,
                names: &names,
            };
            let (status, body) = self.execute(&call).await?;
            listed.extend(interpret_listing(
                &self.config.project,
                config,
                status,
                &body,
                parse_config_secrets,
            )?);
        }
        Ok(listed)
    }

    /// The names of every secret in one config, without reading any values.
    ///
    /// `reflect` only needs names, and Doppler has an endpoint that returns just
    /// those. Listing the config instead would transfer, decrypt and materialize
    /// every plaintext value only to discard all of them.
    async fn names_async(&self, config: &str) -> Result<Vec<String>> {
        let call = Call::Names {
            project: &self.config.project,
            config,
        };
        let (status, body) = self.execute(&call).await?;
        interpret_listing(
            &self.config.project,
            config,
            status,
            &body,
            parse_secret_names,
        )
    }

    /// Writes one secret, or deletes it when `value` is `None`. See
    /// [`Call::body`] for the merge semantics.
    ///
    /// The one operation that does not go through
    /// [`execute`](DopplerProvider::execute): a success body is never read, so
    /// a connection dropped mid-body cannot report a failure for a write the
    /// status line already said committed.
    async fn write_async(&self, loc: &Location, value: Option<&str>) -> Result<()> {
        let (status, body) = self.execute(&Call::Write(loc, value)).await?;
        if status.is_success() {
            return Ok(());
        }
        let action = match value {
            Some(_) => format!("writing '{}'", loc.name),
            None => format!("deleting '{}'", loc.name),
        };
        Err(http_error(&loc.project, status, &body, &action))
    }
}

impl Provider for DopplerProvider {
    /// A profile's secrets share one Doppler config, each under its own name,
    /// verbatim.
    ///
    /// `item` carries the config and the name together so a convention address
    /// and a `ref` share one spelling of the layout; [`parse_item`] splits them
    /// back apart. SecretSpec's own project name is unused -- the Doppler
    /// project from the URI is the namespace. Doppler secrets are single values
    /// with no sub-components, so every coordinate but `item` is rejected by
    /// the default `resolve_coords`.
    ///
    /// # Errors
    ///
    /// Returns an error when Doppler cannot spell the key, or cannot spell the
    /// config the profile names.
    fn convention_address(
        &self,
        _project: &str,
        profile: &str,
        key: &str,
    ) -> Result<NativeAddress> {
        validate_secret_name(key)?;
        let config = self.config_for_profile(profile)?;
        Ok(NativeAddress {
            item: format!("{config}/{key}"),
            ..Default::default()
        })
    }

    /// Fills in the config an address left implicit, so the identity a
    /// destructive preflight compares is the entry `get`, `set` and `delete`
    /// actually operate on.
    ///
    /// A `ref` may name a secret alone (`SHARED_CA`) and take its config from
    /// the URI, or from the active profile when the URI pins none. The default
    /// returns
    /// such an address unchanged, which would render two secrets in different
    /// configs as one identity -- and `import --delete-source` consults exactly
    /// that identity before removing a source entry. Every operation resolves
    /// through [`locate`](Self::locate), which supplies the same default, so
    /// this does too.
    fn entry_coordinates<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        let loc = self.locate(addr)?;
        Ok(Cow::Owned(NativeAddress {
            item: format!("{}/{}", loc.config, loc.name),
            ..Default::default()
        }))
    }

    /// Refuses, before anything is removed, every deletion Doppler would refuse
    /// anyway.
    ///
    /// Deleting in Doppler *is* a write -- of a null value -- so the write
    /// policy applies unchanged, and a reserved name is as unwritable to null
    /// as to a value. Without this, a reserved name would pass preflight and
    /// fail at the API partway through a multi-secret deletion, which is the
    /// failure [`Provider::check_deletable`] exists to prevent. [`delete`]
    /// applies the same rule, as the trait requires of the pair.
    ///
    /// [`delete`]: Provider::delete
    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.check_location(&self.locate(addr)?)
    }

    fn supports_delete(&self) -> bool {
        true
    }

    /// Names the config too: it is half the destination, and a bare `ref`
    /// shows no config in its coordinates.
    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        let loc = self.locate(addr)?;
        Ok(format!(
            "Doppler project '{}' config '{}' secret '{}'",
            loc.project, loc.config, loc.name
        ))
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    /// Remembers the active profile so a bare `ref` under an unpinned URI can
    /// take its config from it, as every convention address already does.
    /// Recorded even through a poisoned lock: see
    /// [`session_profile`](Self::session_profile).
    fn set_profile(&self, profile: &str) {
        *self
            .profile
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(profile.to_string());
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    /// The inverse of parsing, and credential-free by construction: the token
    /// lives in a credential or the environment, never in the URI, so there is
    /// nothing here to redact. The audit log and the fallback-chain warnings
    /// both persist this.
    fn uri(&self) -> String {
        // Neither component needs escaping: both are validated to
        // `[a-z0-9_-]+`, which contains no URI delimiter, so this is an exact
        // inverse of parsing. That matters because the cache route fingerprint
        // and the audit log treat this string as the store's identity -- if a
        // project could hold a `/`, two distinct stores would render one URI.
        // `ProviderUrl::encode` could not fix that anyway: it deliberately
        // preserves `/` as a structural delimiter.
        match &self.config.config {
            Some(config) => format!("doppler://{}/{config}", self.config.project),
            None => format!("doppler://{}", self.config.project),
        }
    }

    /// The Doppler *project* holds every entry; which config within it is part
    /// of the resolved coordinates, not of the container.
    ///
    /// This is what makes [`same_entry`](Provider::same_entry) correct across the
    /// two ways one secret can be addressed: `doppler://myapp` under profile
    /// `dev` and `doppler://myapp/dev` are the same secret, and both compile to
    /// the coordinates `dev/API_KEY`. Leaving the config in the container would
    /// report them as different entries, and `secretspec import --delete-source`
    /// consults exactly that before deleting -- so it would write a value to its
    /// destination and then delete the secret it had just written.
    ///
    /// [`storage_identity`](Provider::storage_identity) deliberately keeps the
    /// config: that one is compared without an address, for cache routing, where
    /// `doppler://myapp/cache` and `doppler://myapp/prd` must stay distinct
    /// stores.
    fn entry_container_identity(&self) -> String {
        format!("doppler://{}", self.config.project)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let loc = self.locate(addr)?;
        super::block_on(self.get_async(&loc, AbsentConfig::IsAnError))
    }

    /// Secrets sharing a config are read with one request for the whole config,
    /// rather than one round trip per secret.
    ///
    /// This override is the point of the provider: Doppler answers for every
    /// requested secret in one response, so a 23-secret resolution costs one HTTP
    /// call per config. Falling back to the default would cost 23. Several
    /// configs go out concurrently, in the same capped waves the default uses
    /// for independent addresses, so the cost is one round trip rather than one
    /// per config.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }

        // Every address is resolved before any request is sent, so an
        // unspellable name fails without touching the network. Grouping by
        // config also satisfies the dedup contract: identical addresses land on
        // one entry and share the listing's value.
        let mut by_config: HashMap<String, Vec<(&str, String)>> = HashMap::new();
        for (name, addr) in requests {
            let loc = self.locate(*addr)?;
            by_config
                .entry(loc.config)
                .or_default()
                .push((name, loc.name));
        }

        // Configs are independent listings, so they go out together rather than
        // one after another, in the same capped waves the default `get_many`
        // uses for independent addresses. A manifest whose `ref`s span several
        // Doppler configs otherwise pays one serialized round trip each.
        let groups: Vec<(String, Vec<(&str, String)>)> = by_config.into_iter().collect();
        let listings = super::map_concurrently(&groups, super::get_each_concurrency(), |group| {
            let (config, wanted) = group;
            // Only the declared names are requested, so this reads no secret
            // the manifest did not ask for: see `list_async`.
            let mut names: Vec<String> = wanted.iter().map(|(_, key)| key.clone()).collect();
            names.sort_unstable();
            names.dedup();
            super::block_on(self.list_async(config, &names))
        });

        let mut resolved = HashMap::new();
        for ((_, wanted), listed) in groups.iter().zip(listings) {
            let listed = listed?;
            for (name, key) in wanted {
                if let Some(value) = listed.get(key) {
                    resolved.insert((*name).to_string(), value.clone());
                }
            }
        }
        Ok(resolved)
    }

    /// Refuses, before a caller prompts for a value, every write this provider
    /// would refuse anyway: a name or config Doppler cannot spell, a `ref`
    /// naming no config, a coordinate Doppler has no equivalent for, and a name
    /// Doppler reserves for itself.
    ///
    /// The whole point of the pre-check is that the refusal arrives *before* the
    /// secret is typed (see [`Provider::check_writable`]); leaving it at the
    /// permissive default would let `secretspec set` prompt for a value it is
    /// then guaranteed to throw away.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.check_location(&self.locate(addr)?)
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        // Resolved once and then checked, rather than `check_writable(addr)`
        // followed by a second `locate`: the same rule, without compiling the
        // address twice. See `check_location`.
        let loc = self.locate(addr)?;
        self.check_location(&loc)?;
        // The address is writable but the value may still not be storable
        // unchanged: Doppler stores text, so the bytes must be UTF-8, and
        // must not read as a reference. Neither can live in `check_writable`,
        // which never sees a value. See `validate_secret_value`.
        let value = super::require_utf8("doppler", value)?;
        validate_secret_value(&loc.name, value)?;
        super::block_on(self.write_async(&loc, Some(value)))
    }

    /// Deletes a secret, reporting whether one was there to delete.
    ///
    /// Doppler's write endpoint deletes on a null value and is idempotent about
    /// it, answering the same way whether or not the name existed. The secret is
    /// therefore read first, so the `bool` distinguishes a real invalidation
    /// from a no-op instead of always claiming one.
    ///
    /// That read treats an absent config as an absent secret
    /// ([`AbsentConfig::HoldsNothing`]): deleting is idempotent, and cache
    /// invalidation runs over addresses that may never have been written, so a
    /// config that was never created must answer `Ok(false)` rather than fail.
    ///
    /// The read is an *optimization of the return value*, never a precondition:
    /// a read that fails for any other reason falls through to the deletion.
    /// Doppler withholds the value of a `restricted` secret from a token tied
    /// to a user identity while still accepting a write of it, so failing the
    /// deletion on the read would refuse deletions Doppler would have honored
    /// -- and [`check_deletable`](Provider::check_deletable) cannot foresee
    /// that without a round trip, so preflight would pass and the deletion
    /// abort partway through, which is the failure that pair exists to
    /// prevent.
    ///
    /// A reserved name is refused here rather than at Doppler, so `delete` and
    /// `check_deletable` refuse for the same reason. Resolved once and then
    /// checked, as in [`set`](Provider::set).
    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let loc = self.locate(addr)?;
        self.check_location(&loc)?;
        super::block_on(async {
            if matches!(
                self.get_async(&loc, AbsentConfig::HoldsNothing).await,
                Ok(None)
            ) {
                return Ok(false);
            }
            self.write_async(&loc, None).await?;
            Ok(true)
        })
    }

    /// Names one config's secrets, so `secretspec import` can adopt them.
    ///
    /// Discovery reads the config the URI pins, else the one the profile names,
    /// so it stays in the namespace that resolving those secrets would later
    /// read -- which is what [`DiscoveryContext`] exists for.
    ///
    /// Only names are fetched, never values: importing decides *what* to declare,
    /// and reading every plaintext to build a list of names would put secrets
    /// nobody asked for through this process. See [`names_async`].
    ///
    /// [`names_async`]: DopplerProvider::names_async
    /// [`DiscoveryContext`]: super::DiscoveryContext
    ///
    /// # Errors
    ///
    /// Returns an error when the profile cannot name a Doppler config.
    fn reflect(
        &self,
        context: super::DiscoveryContext<'_>,
    ) -> Result<HashMap<String, crate::Secret>> {
        let config = self.reflect_config(context)?;
        let names = super::block_on(self.names_async(&config))?;
        Ok(names
            .into_iter()
            .map(|name| {
                let secret = crate::Secret::required(format!("{name} Doppler secret"));
                (name, secret)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use url::Url;

    fn config(s: &str) -> DopplerConfig {
        DopplerConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    fn provider(s: &str) -> DopplerProvider {
        DopplerProvider::new(config(s))
    }

    fn native(item: &str) -> NativeAddress {
        NativeAddress {
            item: item.into(),
            ..Default::default()
        }
    }

    fn location(project: &str, config: &str, name: &str) -> Location {
        Location {
            project: project.into(),
            config: config.into(),
            name: name.into(),
        }
    }

    /// A single-read response body, as Doppler returns it.
    fn single_read(raw: &str, computed: &str) -> String {
        serde_json::json!({
            "name": "MONGO_CONNECTION",
            "value": {
                "raw": raw,
                "computed": computed,
                "note": "",
                "rawVisibility": "masked",
                "computedVisibility": "masked",
                "rawValueType": { "type": "string" },
                "computedValueType": { "type": "string" },
            },
            "success": true,
        })
        .to_string()
    }

    /// A read of a secret whose value Doppler declines to serve: a `restricted`
    /// visibility reported with no value. `restricted` is a real Doppler
    /// visibility (measured), and an unset secret reports a *null* visibility,
    /// which is what makes this shape distinguishable from an absent secret.
    fn restricted_read() -> String {
        serde_json::json!({
            "name": "MONGO_CONNECTION",
            "value": {
                "raw": null,
                "computed": null,
                "note": "",
                "rawVisibility": "restricted",
                "computedVisibility": "restricted",
                "rawValueType": { "type": "string" },
                "computedValueType": { "type": "string" },
            },
            "success": true,
        })
        .to_string()
    }

    #[test]
    fn uri_names_the_project_and_optionally_the_config() {
        let c = config("doppler://myapp");
        assert_eq!(c.project, "myapp");
        assert_eq!(c.config, None);

        let c = config("doppler://myapp/prd");
        assert_eq!(c.project, "myapp");
        assert_eq!(c.config.as_deref(), Some("prd"));
    }

    /// The project is required. A bare `doppler://` must not fall back to
    /// anything: a pinned token would then choose its own coordinates, and a
    /// token repointed at another config would change which secrets are served
    /// with nothing in the URI to show it.
    #[test]
    fn uri_without_a_project_is_rejected() {
        let err = DopplerConfig::try_from(&ProviderUrl::new(Url::parse("doppler://").unwrap()))
            .unwrap_err();
        assert!(err.to_string().contains("No Doppler project"), "{err}");
    }

    #[test]
    fn uri_with_a_nested_config_is_rejected() {
        let err = DopplerConfig::try_from(&ProviderUrl::new(
            Url::parse("doppler://myapp/prd/extra").unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("do not nest"), "{err}");
    }

    #[test]
    fn wrong_scheme_is_rejected() {
        let err = DopplerConfig::try_from(&ProviderUrl::new(Url::parse("bws://myapp").unwrap()))
            .unwrap_err();
        assert!(err.to_string().contains("Invalid scheme"), "{err}");
    }

    /// Two spellings of one Doppler config resolve to the same entry.
    ///
    /// `doppler://myapp` under profile `dev` and `doppler://myapp/dev` address
    /// the identical secret. `secretspec import --delete-source` asks
    /// [`Provider::same_entry`] before deleting anything, so answering "different
    /// entry" here would let it write the value to its destination and then
    /// delete the very secret it just wrote.
    ///
    /// The config belongs in the resolved coordinates, not in the container:
    /// `same_entry` compares the container identity *and* the coordinates, and
    /// the coordinates already carry `{config}/{NAME}`.
    #[test]
    fn two_spellings_of_one_config_are_the_same_entry() {
        let unpinned = provider("doppler://myapp");
        let pinned = provider("doppler://myapp/dev");
        let addr = Address::convention("proj", "dev", "API_KEY");

        assert!(
            unpinned.same_entry(&pinned, addr).unwrap(),
            "doppler://myapp under profile dev is the same secret as doppler://myapp/dev"
        );
        assert!(
            pinned.same_entry(&unpinned, addr).unwrap(),
            "and vice versa"
        );

        // A different config in the same project is a different entry: the
        // container matches, the coordinates do not.
        let other = provider("doppler://myapp/prd");
        assert!(
            !pinned.same_entry(&other, addr).unwrap(),
            "dev and prd hold distinct secrets"
        );

        // A different project is a different entry even at identical coords.
        let elsewhere = provider("doppler://other/dev");
        assert!(
            !pinned.same_entry(&elsewhere, addr).unwrap(),
            "one config name in two projects is two secrets"
        );
    }

    /// Cache routing keeps sibling configs apart, so one config may cache
    /// another in the same project.
    ///
    /// This is why the *storage* identity keeps the config while the *container*
    /// identity drops it: the cache-distinctness guard compares storage
    /// identities without any address, so collapsing them to the project would
    /// refuse a legitimate `doppler://myapp/cache` over `doppler://myapp/prd`.
    #[test]
    fn sibling_configs_are_distinct_stores_for_cache_routing() {
        assert_ne!(
            provider("doppler://myapp/cache").storage_identity(),
            provider("doppler://myapp/prd").storage_identity()
        );
    }

    /// The rendered URI round-trips, and carries no credential: the token lives
    /// in a credential or the environment, never in the URI.
    #[test]
    fn uri_round_trips() {
        for spec in ["doppler://myapp", "doppler://myapp/prd"] {
            assert_eq!(provider(spec).uri(), spec);
        }
    }

    /// A project name that would break the `uri()` round trip is rejected, so
    /// `uri()` stays an exact inverse of parsing.
    ///
    /// `doppler://my%2Fapp` decodes to project "my/app" (parsing
    /// percent-*decodes* the host). Rendering that would produce
    /// `doppler://my/app`, which re-parses as project "my" + config "app" -- a
    /// different, perfectly valid store, and byte-identical to the `uri()` of the
    /// genuinely different `doppler://my/app`. Since `uri()` feeds the cache
    /// route fingerprint and the audit log, which treat it as the store's
    /// identity, two stores must never collapse onto one string. Escaping cannot
    /// fix it -- `ProviderUrl::encode` deliberately preserves `/` -- so the name
    /// is refused instead.
    #[test]
    fn a_project_name_that_would_break_the_uri_is_rejected() {
        for spec in [
            "doppler://my%2Fapp",
            "doppler://my.app",
            "doppler://my%20app",
        ] {
            let err = DopplerConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap()))
                .expect_err("a project name Doppler cannot spell must be refused");
            assert!(
                err.to_string().contains("lowercase letters"),
                "{spec}: {err}"
            );
        }
    }

    /// An uppercase project is refused rather than passed on, because Doppler
    /// silently lowercases it: `doppler://MyApp` and `doppler://myapp` would name
    /// one store while rendering two `uri()` strings, and that string is the
    /// store's identity for the cache fingerprint and the audit log.
    #[test]
    fn an_uppercase_project_is_refused_because_doppler_lowercases_it() {
        let err = DopplerConfig::try_from(&ProviderUrl::new(
            Url::parse("doppler://MyApp/prd").unwrap(),
        ))
        .expect_err("an uppercase project must be refused");
        let err = err.to_string();
        assert!(err.contains("lowercases"), "{err}");
        // The message names what it would actually have addressed.
        assert!(err.contains("myapp"), "{err}");
    }

    /// User information and a port are refused rather than dropped: dropped,
    /// `doppler://user@myapp` and `doppler://myapp:8080` would both render as
    /// `doppler://myapp`, and `uri()` is the store's identity for the cache
    /// route and the audit log.
    #[test]
    fn a_uri_userinfo_or_port_is_rejected() {
        for spec in [
            "doppler://user@myapp/prd",
            "doppler://user:pw@myapp/prd",
            "doppler://myapp:8080/prd",
        ] {
            let err = DopplerConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap()))
                .expect_err("userinfo and ports must be refused");
            assert!(err.to_string().contains("not supported"), "{spec}: {err}");
        }
    }

    /// The profile names the config, and the key is stored verbatim -- the whole
    /// reason to want this provider.
    #[test]
    fn the_profile_names_the_config_and_the_key_is_verbatim() {
        let p = provider("doppler://myapp");
        let addr = p
            .convention_address("myapp", "production", "MONGO_CONNECTION")
            .unwrap();
        assert_eq!(addr.item, "production/MONGO_CONNECTION");

        let loc = p
            .locate(Address::convention(
                "myapp",
                "production",
                "MONGO_CONNECTION",
            ))
            .unwrap();
        assert_eq!(loc.project, "myapp");
        assert_eq!(loc.config, "production");
        assert_eq!(loc.name, "MONGO_CONNECTION");
    }

    /// A pinned config wins over the profile, which is what lets a manifest
    /// whose profiles are named something else (`production`) read a Doppler
    /// config named `prd`.
    #[test]
    fn a_pinned_config_wins_over_the_profile() {
        let p = provider("doppler://myapp/prd");
        let coords = p
            .locate(Address::convention("myapp", "production", "API_KEY"))
            .unwrap();
        assert_eq!(coords.config, "prd");
        assert_eq!(coords.name, "API_KEY");
    }

    /// Every profile gets its own config, so profiles cannot collapse onto one
    /// namespace while names stay verbatim.
    #[test]
    fn every_profile_gets_its_own_config() {
        let p = provider("doppler://myapp");
        let dev = p.convention_address("myapp", "dev", "API_KEY").unwrap();
        let prod = p.convention_address("myapp", "prod", "API_KEY").unwrap();
        assert_ne!(dev.item, prod.item);
    }

    /// SecretSpec's project is unused: the Doppler project from the URI is the
    /// namespace, so two SecretSpec projects on one URI share it. Documented
    /// rather than fixed, as with `bws`.
    #[test]
    fn secretspec_projects_share_one_doppler_namespace() {
        let p = provider("doppler://myapp");
        let one = p.convention_address("one", "dev", "API_KEY").unwrap();
        let other = p.convention_address("other", "dev", "API_KEY").unwrap();
        assert_eq!(one.item, other.item);
    }

    /// A name Doppler cannot store is refused, never rewritten: rewriting could
    /// land two distinct keys on one name, and the collision would be invisible.
    /// Both of Doppler's two distinct refusals are reproduced.
    #[test]
    fn unspellable_secret_names_are_refused() {
        let p = provider("doppler://myapp");

        for key in [
            "lowercase_name",
            "Mixed_Case",
            "WITH-HYPHEN",
            "HAS SPACE",
            "HAS.DOT",
            "WITH/SLASH",
            "UNICODE_ÑAME",
        ] {
            let err = p.convention_address("myapp", "dev", key).unwrap_err();
            assert!(
                err.to_string()
                    .contains("may only contain uppercase letters, numbers, and underscores"),
                "{key}: {err}"
            );
        }

        let err = p
            .convention_address("myapp", "dev", "1STARTS_DIGIT")
            .unwrap_err();
        assert!(
            err.to_string().contains("may not start with a number"),
            "{err}"
        );
    }

    /// A leading underscore is legal -- measured against the live API, and worth
    /// pinning so a tightened rule does not reject a name Doppler accepts.
    #[test]
    fn a_leading_underscore_is_accepted() {
        let p = provider("doppler://myapp");
        for key in ["_LEADING_UNDERSCORE", "UPPER_OK", "WITH_9_DIGIT"] {
            assert!(p.convention_address("myapp", "dev", key).is_ok(), "{key}");
        }
    }

    /// A refusal names the place the config actually came from, because the
    /// fix differs: a profile is renamed, a URI config is corrected in the
    /// alias, and a `ref`'s config is corrected in the ref. Sending a user to
    /// "correct the config in the provider URI" for a bad `ref` points at a
    /// URI that may hold no config at all.
    #[test]
    fn a_bad_config_names_the_place_it_came_from() {
        // From a ref's own item, against a URI that pins nothing.
        let p = provider("doppler://myapp");
        let addr = native("Shared/SHARED_CA");
        let err = p.locate(Address::Native(&addr)).unwrap_err().to_string();
        assert!(err.contains("named by the secret's ref"), "{err}");
        assert!(err.contains("item = \"prd/API_KEY\""), "{err}");
        assert!(
            !err.contains("provider URI"),
            "a ref's config is not fixed in the URI: {err}"
        );

        // From the profile.
        let err = p
            .convention_address("myapp", "Production", "API_KEY")
            .unwrap_err()
            .to_string();
        assert!(err.contains("named by the SecretSpec profile"), "{err}");
        assert!(err.contains("Rename the profile"), "{err}");

        // From the URI.
        let err = DopplerConfig::try_from(&ProviderUrl::new(
            Url::parse("doppler://myapp/Production").unwrap(),
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("Correct the config in the provider URI"),
            "{err}"
        );
        assert!(!err.contains("named by"), "{err}");
    }

    /// A `ref` naming an unspellable secret is refused too: its item never
    /// passes through `convention_address`, so it is validated where it is
    /// split.
    #[test]
    fn a_ref_naming_an_unspellable_secret_is_refused() {
        let p = provider("doppler://myapp");
        let addr = native("dev/lowercase");
        let err = p.locate(Address::Native(&addr)).unwrap_err();
        assert!(
            err.to_string()
                .contains("may only contain uppercase letters"),
            "{err}"
        );
    }

    /// A profile Doppler cannot spell as a config is refused with a message
    /// naming the fix. Doppler's own answer is "Please provide a valid config.",
    /// which does not say what is wrong.
    #[test]
    fn a_profile_that_cannot_name_a_config_is_refused() {
        let p = provider("doppler://myapp");
        let err = p
            .convention_address("myapp", "Production", "API_KEY")
            .unwrap_err();
        assert!(err.to_string().contains("lowercase letters"), "{err}");
        assert!(err.to_string().contains("doppler://myapp/prd"), "{err}");

        // ... and a pinned config makes the profile irrelevant.
        let pinned = provider("doppler://myapp/prd");
        assert!(
            pinned
                .convention_address("myapp", "Production", "API_KEY")
                .is_ok()
        );
    }

    /// A ref splits into the config holding the secret and its name; a bare name
    /// uses the pinned config, else the active profile, and with neither there
    /// is nothing to name it.
    #[test]
    fn a_ref_names_its_own_config() {
        let p = provider("doppler://myapp");
        let addr = native("stg/DATABASE_URL");
        let coords = p.locate(Address::Native(&addr)).unwrap();
        assert_eq!(coords.config, "stg");
        assert_eq!(coords.name, "DATABASE_URL");

        let bare = native("DATABASE_URL");
        let err = p.locate(Address::Native(&bare)).unwrap_err();
        assert!(err.to_string().contains("No Doppler config"), "{err}");

        // The active profile names it, exactly as it does for a convention
        // address, so a bare ref reads from the config its profile reads.
        p.set_profile("dev");
        let coords = p.locate(Address::Native(&bare)).unwrap();
        assert_eq!(coords.config, "dev");
        assert_eq!(coords.name, "DATABASE_URL");

        // A profile Doppler cannot spell is refused with the profile named as
        // the source, not the ref or the URI.
        p.set_profile("Production");
        let err = p.locate(Address::Native(&bare)).unwrap_err();
        assert!(
            err.to_string().contains("named by the SecretSpec profile"),
            "{err}"
        );

        // A pinned config wins over the profile, as for every other secret.
        let pinned = provider("doppler://myapp/prd");
        pinned.set_profile("dev");
        let coords = pinned.locate(Address::Native(&bare)).unwrap();
        assert_eq!(coords.config, "prd");
        assert_eq!(coords.name, "DATABASE_URL");
    }

    /// Doppler values have no sub-components, so a `field` has no meaning and is
    /// rejected rather than ignored.
    #[test]
    fn native_address_rejects_field() {
        let p = provider("doppler://myapp/prd");
        let addr = NativeAddress {
            item: "DATABASE_URL".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let err = p.locate(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");

        let versioned = NativeAddress {
            item: "DATABASE_URL".into(),
            version: Some("3".into()),
            ..Default::default()
        };
        let err = p.locate(Address::Native(&versioned)).unwrap_err();
        assert!(err.to_string().contains("`version`"), "{err}");
    }

    /// `computed` is the value read, never `raw`.
    ///
    /// Doppler resolves `${OTHER}` references between secrets. Returning `raw`
    /// would hand the application a plausible-looking connection string
    /// containing a literal `${PLAIN_HOST}`, which fails at connect time far
    /// from its cause. Nothing in the conformance harness catches this.
    #[test]
    fn a_reference_is_read_resolved() {
        let body = single_read("postgres://${PLAIN_HOST}/app", "postgres://db.internal/app");
        let value = parse_secret_value(&body, "MONGO_CONNECTION")
            .unwrap()
            .expect("a stored secret");
        assert_eq!(value.expose_secret(), b"postgres://db.internal/app");
        assert!(
            !value.try_as_utf8().unwrap().contains("${"),
            "the reference stayed"
        );
    }

    /// `set` refuses exactly what the pre-check refuses, with the same message.
    ///
    /// The trait requires this (`Provider::check_writable`): a caller uses the
    /// pre-check to refuse before prompting for a value, so a `set` that did not
    /// route through it would prompt for a secret it is guaranteed to discard.
    /// `versioned_refs_are_read_only` in `infisical.rs` is the same assertion.
    #[test]
    fn set_refuses_whatever_the_pre_check_refuses() {
        let p = provider("doppler://myapp/prd");
        let value = SecretBytes::from_utf8("v");

        // Each of these is refused for a different reason, and no request may be
        // built for any of them.
        let field = NativeAddress {
            item: "DATABASE_URL".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let unpinned = provider("doppler://myapp");
        let bare = native("DATABASE_URL");

        let cases: [(&DopplerProvider, Address<'_>); 4] = [
            (&p, Address::convention("proj", "dev", "lowercase")),
            (&p, Address::convention("proj", "dev", "DOPPLER_CONFIG")),
            (&p, Address::Native(&field)),
            (&unpinned, Address::Native(&bare)),
        ];
        for (provider, addr) in cases {
            let refusal = provider
                .check_writable(addr)
                .expect_err("the pre-check must refuse this address");
            let from_set = provider
                .set(addr, &value)
                .expect_err("set must refuse whatever the pre-check refuses");
            assert_eq!(
                from_set.to_string(),
                refusal.to_string(),
                "set and check_writable must give one reason, not two"
            );
        }
    }

    /// A value Doppler would rewrite is refused rather than silently changed.
    ///
    /// Doppler resolves `${...}` between secrets, so such a value never reads
    /// back as written: an unresolvable reference is refused by Doppler and a
    /// resolvable one is rewritten. The refusal must not echo the value.
    #[test]
    fn a_value_doppler_would_rewrite_is_refused() {
        let p = provider("doppler://myapp/prd");
        let referencing = SecretBytes::from_utf8("postgres://${DB_HOST}/app");

        let refusal = validate_secret_value("DATABASE_URL", referencing.try_as_utf8().unwrap())
            .expect_err("a value Doppler would rewrite must be refused");
        let refusal = refusal.to_string();
        assert!(refusal.contains("DATABASE_URL"), "{refusal}");
        assert!(
            !refusal.contains("postgres://") && !refusal.contains("DB_HOST"),
            "the refusal must not echo the secret value: {refusal}"
        );

        // `set` must give exactly that reason, and give it *before* any request.
        // Compared for equality rather than by substring: a `set` that skipped
        // the check and failed on the network instead would still mention the
        // secret's name, and would satisfy a looser assertion.
        let from_set = p
            .set(
                Address::convention("proj", "dev", "DATABASE_URL"),
                &referencing,
            )
            .expect_err("set must refuse a value Doppler would rewrite");
        assert_eq!(from_set.to_string(), refusal);

        // An ordinary value is untouched by the check.
        validate_secret_value("DATABASE_URL", "postgres://db.internal/app")
            .expect("a value with no reference is storable");
    }

    /// `reflect` reads names only, and drops the names Doppler injects.
    #[test]
    fn reflected_names_exclude_the_reserved_ones() {
        let body = serde_json::json!({
            "names": [
                "DOPPLER_CONFIG", "DOPPLER_ENVIRONMENT", "DOPPLER_PROJECT",
                "DATABASE_URL", "API_KEY",
            ],
            "success": true,
        })
        .to_string();

        let mut names = parse_secret_names(&body, "prd").unwrap();
        names.sort();
        assert_eq!(names, ["API_KEY", "DATABASE_URL"]);
    }

    /// A names entry that is not a string is an error rather than silently
    /// dropped: `secretspec import` reporting a partial list as if the config
    /// held fewer secrets is the same silent shape drift the value parsers
    /// refuse.
    #[test]
    fn an_unrecognized_name_entry_is_an_error() {
        let body = r#"{"names":["API_KEY",{"name":"DATABASE_URL"}],"success":true}"#;
        let err = parse_secret_names(body, "prd").unwrap_err().to_string();
        assert!(err.contains("an object"), "{err}");
        assert!(err.contains("prd"), "{err}");
    }

    /// A reference whose target was deleted reads back as the unresolved
    /// template, because that is what Doppler serves for it.
    ///
    /// Measured live: after deleting `PROBE_TARGET`, a secret holding
    /// `pg://${PROBE_TARGET}/app` answers HTTP 200 with `computed == raw ==`
    /// the template, `masked` visibility -- a *string*, so this is
    /// [`SecretState::Present`] and not withholding. Pinned because it bounds
    /// what reading `computed` guarantees: the resolution promise is
    /// Doppler's, and it lapses when the target goes away. `doppler run`
    /// injects the same literal, so passing it through keeps SecretSpec
    /// faithful to Doppler rather than second-guessing it.
    #[test]
    fn a_dangling_reference_reads_as_the_template_doppler_serves() {
        let dangling = single_read("pg://${PROBE_TARGET}/app", "pg://${PROBE_TARGET}/app");
        let value = parse_secret_value(&dangling, "PROBE_REF")
            .expect("a dangling reference is a value, not a refusal")
            .expect("Doppler serves the template");
        assert_eq!(value.expose_secret(), b"pg://${PROBE_TARGET}/app");
    }

    /// A masked secret is still readable: a freshly written value comes back
    /// `"masked"` with the value present, so masking is a dashboard-display
    /// property, not the API withholding anything.
    #[test]
    fn a_masked_value_is_not_withheld() {
        let body = single_read("s3cret", "s3cret");
        let value = parse_secret_value(&body, "MONGO_CONNECTION")
            .unwrap()
            .expect("a masked secret is still readable");
        assert_eq!(value.expose_secret(), b"s3cret");
    }

    /// A missing secret is `Ok(None)`, and Doppler says so with HTTP 200 and a
    /// null value rather than a 404. An empty string is a stored value, not a
    /// missing one.
    #[test]
    fn a_missing_secret_is_none_and_an_empty_one_is_not() {
        let missing = serde_json::json!({
            "name": "NONEXISTENT_SECRET_XYZ",
            "value": {
                "raw": null, "computed": null, "note": null,
                "rawVisibility": null, "computedVisibility": null,
                "rawValueType": null, "computedValueType": null,
            },
            "success": true,
        })
        .to_string();
        assert!(
            parse_secret_value(&missing, "NONEXISTENT_SECRET_XYZ")
                .unwrap()
                .is_none()
        );

        let empty = single_read("", "");
        let value = parse_secret_value(&empty, "MONGO_CONNECTION")
            .unwrap()
            .expect("an empty string is a stored value");
        assert_eq!(value.expose_secret(), b"");
    }

    /// A secret Doppler refuses to serve is reported as the refusal it is, not
    /// dropped as if it were unset.
    ///
    /// A `restricted` secret read with a token tied to a user identity comes
    /// back HTTP 200, `success: true`, `computed: null` -- byte for byte an
    /// unset secret -- and only the visibility says otherwise. Reading it as
    /// unset makes `secretspec check` offer to set a production secret it was
    /// never allowed to see.
    #[test]
    fn a_withheld_value_is_refused_not_dropped() {
        let err = parse_secret_value(&restricted_read(), "MONGO_CONNECTION").unwrap_err();
        assert!(err.to_string().contains("withheld"), "{err}");
        assert!(err.to_string().contains("restricted"), "{err}");

        // ... and in a listing too, so a batch read agrees with a single read.
        let body = serde_json::json!({
            "secrets": {
                "MONGO_CONNECTION": {
                    "raw": null, "computed": null,
                    "rawVisibility": "restricted", "computedVisibility": "restricted",
                },
            },
            "success": true,
        })
        .to_string();
        let err = parse_config_secrets(&body, "prd").unwrap_err();
        assert!(err.to_string().contains("withheld"), "{err}");
    }

    /// An HTTP 200 that is not Doppler's answer is reported, not resolved to
    /// "the secret is not set".
    ///
    /// Indexing `["value"]["computed"]` through a body of another shape yields
    /// null, which is indistinguishable from an unset secret -- and a fallback
    /// chain treats that as an ordinary miss, serving the next provider's value
    /// with no warning at all.
    #[test]
    fn an_unrecognized_200_body_is_an_error() {
        for body in [
            r#"{"messages":["Invalid Auth"],"success":false}"#,
            r#"{"name":"MONGO_CONNECTION","value":"a plain string"}"#,
            r#"{}"#,
        ] {
            let err = parse_secret_value(body, "MONGO_CONNECTION")
                .unwrap_err()
                .to_string();
            assert!(err.contains("no `value` object"), "{body}: {err}");
        }

        // Doppler's own words are quoted when it sent any ...
        let err = parse_secret_value(r#"{"messages":["Invalid Auth"]}"#, "MONGO_CONNECTION")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid Auth"), "{err}");
    }

    /// The refusal for an unrecognized 200 body must never echo the body.
    ///
    /// A body that arrived with HTTP 200 is a *read* response, so an
    /// unrecognized one -- a renamed field, an intercepting proxy's envelope --
    /// can still carry the secret's plaintext. This error is printed and
    /// audited, so it names the shape and quotes only Doppler's own messages.
    #[test]
    fn an_unrecognized_200_body_is_never_echoed() {
        let renamed_field = r#"{"name":"MONGO_CONNECTION","secret":{"raw":"mongodb://leaked_pw_DO_NOT_ECHO@h/db","computed":"mongodb://leaked_pw_DO_NOT_ECHO@h/db"},"success":true}"#;
        let err = parse_secret_value(renamed_field, "MONGO_CONNECTION")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no `value` object"), "{err}");
        assert!(
            !err.contains("leaked_pw_DO_NOT_ECHO"),
            "a 200 body may hold the secret's plaintext and must not be echoed: {err}"
        );

        // A failed response is different: its body carries Doppler's diagnosis,
        // not a secret, and passing it through is what keeps an unrecognized
        // upstream error readable.
        assert_eq!(error_message("upstream timeout"), "upstream timeout");
    }

    /// A value Doppler returns as something other than a string is named as
    /// that, not misreported as withheld.
    ///
    /// Doppler carries a visibility even on a secret whose value is present, so
    /// falling through to the visibility branch would answer "Doppler withheld
    /// the value" for a secret that has one -- a diagnosis the user cannot act
    /// on. The error names the JSON type and never the value.
    #[test]
    fn a_non_string_value_is_named_rather_than_called_withheld() {
        let body = serde_json::json!({
            "name": "PORT",
            "value": {
                "raw": 5432,
                "computed": 5432,
                "rawVisibility": "masked",
                "computedVisibility": "masked",
            },
            "success": true,
        })
        .to_string();
        let err = parse_secret_value(&body, "PORT").unwrap_err().to_string();
        assert!(err.contains("a number"), "{err}");
        assert!(err.contains("PORT"), "{err}");
        assert!(!err.contains("withheld"), "{err}");
        assert!(
            !err.contains("5432"),
            "the refusal must not echo the value: {err}"
        );
    }

    /// Doppler takes no URI options, so a query is refused rather than dropped:
    /// `?config=prd` would silently leave the profile naming the config and
    /// serve another Doppler environment.
    #[test]
    fn a_uri_query_is_rejected() {
        let err = DopplerConfig::try_from(&ProviderUrl::new(
            Url::parse("doppler://myapp?config=prd").unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("query parameters"), "{err}");
    }

    /// A fragment is refused like a query: `doppler://myapp#prd` -- a typo of
    /// `/` as `#` -- would otherwise silently leave the profile naming the
    /// config, the identical silent substitution the query rejection exists
    /// to prevent.
    #[test]
    fn a_uri_fragment_is_rejected() {
        for spec in ["doppler://myapp#prd", "doppler://myapp/prd#dev"] {
            let err = DopplerConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap()))
                .expect_err("a fragment must be refused");
            assert!(err.to_string().contains("fragments"), "{spec}: {err}");
        }
    }

    /// The pre-check refuses exactly what `set` refuses, so a caller never
    /// prompts for a value it is going to discard.
    #[test]
    fn check_writable_refuses_what_set_would() {
        let p = provider("doppler://myapp");
        for (what, addr) in [
            ("a key Doppler cannot spell", ("dev", "lowercase_key")),
            (
                "a profile that cannot name a config",
                ("Production", "API_KEY"),
            ),
        ] {
            let addr = Address::convention("myapp", addr.0, addr.1);
            assert!(p.check_writable(addr).is_err(), "{what} was accepted");
        }

        // A ref naming no config, with none pinned.
        let bare = native("DATABASE_URL");
        assert!(p.check_writable(Address::Native(&bare)).is_err());

        // A name Doppler reserves: refused locally, so the value is never sent
        // for a request Doppler is certain to refuse.
        let err = p
            .check_writable(Address::convention("myapp", "dev", "DOPPLER_CONFIG"))
            .unwrap_err();
        assert!(
            err.to_string().contains("reserves the secret name"),
            "{err}"
        );

        // A writable address stays writable.
        assert!(
            p.check_writable(Address::convention("myapp", "dev", "API_KEY"))
                .is_ok()
        );
    }

    /// Deleting is a null write, so the write policy governs it too.
    ///
    /// Left at the coordinate-only default, a reserved name would clear
    /// preflight and then fail at Doppler partway through a multi-secret
    /// deletion -- exactly the half-finished `import --delete-source` that
    /// `check_deletable` exists to prevent.
    #[test]
    fn check_deletable_refuses_what_delete_would() {
        let p = provider("doppler://myapp/prd");
        for reserved in RESERVED_NAMES {
            let addr = native(reserved);
            let err = p
                .check_deletable(Address::Native(&addr))
                .expect_err("a reserved name must be refused before anything is removed");
            assert!(
                err.to_string().contains("reserves the secret name"),
                "{reserved}: {err}"
            );
        }

        // A deletable address stays deletable.
        let ok = native("DATABASE_URL");
        assert!(p.check_deletable(Address::Native(&ok)).is_ok());
    }

    /// The identity a destructive preflight compares carries the config, even
    /// when the address left it implicit.
    ///
    /// `import --delete-source` asks for `entry_coordinates` before removing a
    /// source entry. The default hands back a bare `ref` as written, so
    /// `DATABASE_URL` would name the same entry in every config of the project
    /// rather than the one `get`, `set` and `delete` reach.
    #[test]
    fn entry_coordinates_carry_the_resolved_config() {
        let pinned = provider("doppler://myapp/prd");

        let bare = native("DATABASE_URL");
        let coords = pinned.entry_coordinates(Address::Native(&bare)).unwrap();
        assert_eq!(coords.item, "prd/DATABASE_URL");

        // A ref that names its own config keeps it, rather than the pinned one.
        let qualified = native("stg/DATABASE_URL");
        let coords = pinned
            .entry_coordinates(Address::Native(&qualified))
            .unwrap();
        assert_eq!(coords.item, "stg/DATABASE_URL");

        // With nothing pinned, the profile supplies the config -- the same
        // default `locate` applies, so the two agree.
        let unpinned = provider("doppler://myapp");
        let coords = unpinned
            .entry_coordinates(Address::convention("myapp", "dev", "DATABASE_URL"))
            .unwrap();
        assert_eq!(coords.item, "dev/DATABASE_URL");
    }

    /// Doppler injects three names of its own into every config's listing.
    /// Passing them on would report secrets nobody declared.
    #[test]
    fn reserved_names_are_filtered_from_a_listing() {
        let body = serde_json::json!({
            "secrets": {
                "DOPPLER_PROJECT": { "raw": "", "computed": "myapp" },
                "DOPPLER_CONFIG": { "raw": "", "computed": "dev" },
                "DOPPLER_ENVIRONMENT": { "raw": "", "computed": "dev" },
                "MONGO_CONNECTION": { "raw": "mongodb://h/db", "computed": "mongodb://h/db" },
            },
            "success": true,
        })
        .to_string();

        let listed = parse_config_secrets(&body, "dev").unwrap();
        assert_eq!(listed.keys().collect::<Vec<_>>(), ["MONGO_CONNECTION"]);
        for reserved in RESERVED_NAMES {
            assert!(!listed.contains_key(reserved), "{reserved} survived");
        }
    }

    /// A listing entry of an unrecognized shape is an error, exactly as the
    /// single read reports one: indexing a non-object yields null, which is
    /// indistinguishable from unset, and a batch read must not resolve to
    /// "unset" what a single read refuses. The refusal names the shape, never
    /// the content -- a 200 body can hold plaintext.
    #[test]
    fn an_unrecognized_listing_entry_is_an_error() {
        let body = r#"{"secrets":{"API_KEY":"plaintext_DO_NOT_ECHO"},"success":true}"#;
        let err = parse_config_secrets(body, "prd").unwrap_err().to_string();
        assert!(err.contains("a string"), "{err}");
        assert!(err.contains("API_KEY"), "{err}");
        assert!(
            !err.contains("DO_NOT_ECHO"),
            "the entry's content must not be echoed: {err}"
        );
    }

    /// A single read of a reserved name is filtered too, so a batch read and a
    /// single read agree. Doppler refuses to *write* these names, so a value
    /// under one can never be SecretSpec's.
    ///
    /// Answered without asking: the provider holds no token and points at no
    /// endpoint, so a read that reached the network would fail rather than
    /// return `None`.
    #[test]
    fn a_reserved_name_reads_as_missing() {
        let p = provider("doppler://myapp/dev");
        for name in RESERVED_NAMES {
            assert!(
                p.get(Address::convention("unused", "dev", name))
                    .expect("a reserved name is answered locally")
                    .is_none(),
                "Doppler's own injected value must never be served as a secret: {name}"
            );
        }
    }

    /// A listing reads `computed`, so a reference resolves the same way in a
    /// batch read as in a single one.
    #[test]
    fn a_listing_reads_computed() {
        let body = serde_json::json!({
            "secrets": {
                "PLAIN_HOST": { "raw": "db.internal", "computed": "db.internal" },
                "DERIVED_URL": {
                    "raw": "postgres://${PLAIN_HOST}/app",
                    "computed": "postgres://db.internal/app",
                },
            },
            "success": true,
        })
        .to_string();

        let listed = parse_config_secrets(&body, "dev").unwrap();
        assert_eq!(
            listed["DERIVED_URL"].expose_secret(),
            b"postgres://db.internal/app"
        );
    }

    /// Doppler's error envelope becomes a message a human can act on, quoting
    /// Doppler's own text so a search for it reaches Doppler's documentation.
    #[test]
    fn doppler_error_messages_are_quoted_verbatim() {
        let envelope = r#"{"messages":["This token does not have access to requested config 'prod'"],"success":false}"#;
        assert_eq!(
            error_message(envelope),
            "This token does not have access to requested config 'prod'"
        );

        // Several messages are joined rather than one being picked.
        let two = r#"{"messages":["first thing","second thing"],"success":false}"#;
        assert_eq!(error_message(two), "first thing; second thing");

        // A body that is not the envelope is passed through, not replaced by a
        // summary that would hide it.
        assert_eq!(error_message("upstream timeout"), "upstream timeout");
    }

    /// The statuses a user actually hits are explained, and a pinned service
    /// token's refusal names the coordinates the provider addressed.
    #[test]
    fn http_errors_explain_the_status() {
        let pinned_elsewhere = r#"{"messages":["This token does not have access to requested config 'prd'"],"success":false}"#;

        let err = http_error(
            "myapp",
            StatusCode::BAD_REQUEST,
            pinned_elsewhere,
            "reading 'API_KEY'",
        );
        let err = err.to_string();
        assert!(
            err.contains("does not have access to requested config"),
            "{err}"
        );
        assert!(err.contains("dp.st."), "{err}");
        assert!(err.contains("myapp"), "{err}");

        let err = http_error(
            "myapp",
            StatusCode::UNAUTHORIZED,
            r#"{"messages":["Invalid Auth"]}"#,
            "reading",
        )
        .to_string();
        assert!(err.contains(DOPPLER_TOKEN_ENV), "{err}");

        let err = http_error(
            "myapp",
            StatusCode::NOT_FOUND,
            r#"{"messages":["Could not find requested config 'nope'"]}"#,
            "reading",
        )
        .to_string();
        assert!(err.contains("must already exist"), "{err}");
    }

    /// A 404 on a read means the *config* is absent -- Doppler answers a
    /// missing *secret* with 200 and a null value. For `get` that is a
    /// misconfiguration worth reporting rather than a profile of secrets
    /// quietly reading as unset; for `delete`'s probe it holds nothing to
    /// delete, because deleting is idempotent and cache invalidation runs
    /// over addresses that may never have been written.
    #[test]
    fn an_absent_config_is_an_error_for_get_and_nothing_for_delete() {
        let loc = location("myapp", "nope", "API_KEY");
        let body = r#"{"messages":["Could not find requested config 'nope'"],"success":false}"#;

        let err = interpret_read(&loc, StatusCode::NOT_FOUND, body, AbsentConfig::IsAnError)
            .expect_err("an absent config must be reported to a read");
        assert!(err.to_string().contains("must already exist"), "{err}");

        let probed = interpret_read(
            &loc,
            StatusCode::NOT_FOUND,
            body,
            AbsentConfig::HoldsNothing,
        )
        .expect("delete probes an absent config as empty");
        assert!(probed.is_none());

        // The leniency covers exactly the absent config, not error statuses
        // in general: a refusal is still a refusal to a delete probe.
        let refused = r#"{"messages":["This token does not have access to requested project 'myapp'"],"success":false}"#;
        let err = interpret_read(
            &loc,
            StatusCode::BAD_REQUEST,
            refused,
            AbsentConfig::HoldsNothing,
        )
        .expect_err("a 400 is an error whichever policy reads it");
        assert!(err.to_string().contains("myapp"), "{err}");
    }

    /// A 200 is parsed as the secret's value, and a failed listing names the
    /// config it was listing.
    #[test]
    fn interpretations_parse_200_and_report_the_rest() {
        let loc = location("myapp", "prd", "MONGO_CONNECTION");
        let value = interpret_read(
            &loc,
            StatusCode::OK,
            &single_read("v", "v"),
            AbsentConfig::IsAnError,
        )
        .unwrap()
        .expect("a stored secret");
        assert_eq!(value.expose_secret(), b"v");

        let denied = r#"{"messages":["Invalid Auth"],"success":false}"#;
        let err = interpret_listing(
            "myapp",
            "prd",
            StatusCode::UNAUTHORIZED,
            denied,
            parse_config_secrets,
        )
        .expect_err("a failed listing is an error");
        assert!(err.to_string().contains("listing config 'prd'"), "{err}");

        let err = interpret_listing(
            "myapp",
            "prd",
            StatusCode::UNAUTHORIZED,
            denied,
            parse_secret_names,
        )
        .expect_err("a failed names listing is an error");
        assert!(err.to_string().contains("listing config 'prd'"), "{err}");
    }

    /// A missing token is reported against both the credential and the
    /// environment variable, before any request is built.
    #[test]
    fn a_missing_token_names_both_sources() {
        if std::env::var(DOPPLER_TOKEN_ENV).is_ok() {
            return;
        }
        let err = provider("doppler://myapp/prd").token().unwrap_err();
        assert!(err.to_string().contains(DOPPLER_TOKEN_ENV), "{err}");
        assert!(err.to_string().contains("dp.sa."), "{err}");
    }

    /// A supplied credential is preferred over the environment, and trimmed, so
    /// `DOPPLER_TOKEN=$(cat token.txt)` with its trailing newline yields a
    /// header-safe value.
    #[test]
    fn a_supplied_credential_is_used_and_trimmed() {
        let mut p = provider("doppler://myapp/prd");
        let mut credentials = ProviderCredentials::new();
        credentials.insert(
            TOKEN.to_string(),
            SecretBytes::from_utf8(" dp.sa.from-credential\n"),
        );
        p.with_credentials(credentials);
        assert_eq!(p.token().unwrap().expose_secret(), b"dp.sa.from-credential");
    }

    /// Importing needs a config to read, and says so rather than guessing.
    #[test]
    fn reflect_reads_the_config_resolution_would() {
        use crate::provider::DiscoveryContext;

        // With no config pinned, discovery follows the profile -- the same rule
        // `convention_address` applies, so `init --from` finds the declarations
        // that resolving them would later read.
        assert_eq!(
            provider("doppler://myapp")
                .reflect_config(DiscoveryContext::new("payments", "production"))
                .unwrap(),
            "production"
        );

        // A pinned config wins, exactly as it does for a convention address.
        assert_eq!(
            provider("doppler://myapp/prd")
                .reflect_config(DiscoveryContext::new("payments", "production"))
                .unwrap(),
            "prd"
        );

        // A profile Doppler cannot spell as a config is refused, not guessed at.
        let err = provider("doppler://myapp")
            .reflect_config(DiscoveryContext::new("payments", "Production"))
            .unwrap_err();
        assert!(err.to_string().contains("lowercase letters"), "{err}");
    }

    /// Every request names its project and config: a params-free request is
    /// answered from wherever a pinned token points, which is the silent
    /// failure this provider exists to avoid. A read names them in its query;
    /// a write in its body.
    #[test]
    fn every_call_names_its_coordinates() {
        let loc = location("myapp", "prd", "API_KEY");

        assert_eq!(
            Call::Read(&loc).query(),
            [("project", "myapp"), ("config", "prd"), ("name", "API_KEY")]
        );
        assert_eq!(
            Call::List {
                project: "myapp",
                config: "prd",
                names: "API_KEY,DATABASE_URL",
            }
            .query(),
            [
                ("project", "myapp"),
                ("config", "prd"),
                ("include_managed_secrets", "false"),
                ("secrets", "API_KEY,DATABASE_URL"),
            ]
        );
        // An empty filter reads the whole config rather than sending an empty
        // `secrets=`.
        assert_eq!(
            Call::List {
                project: "myapp",
                config: "prd",
                names: "",
            }
            .query(),
            [
                ("project", "myapp"),
                ("config", "prd"),
                ("include_managed_secrets", "false"),
            ]
        );
        // Both listings ask Doppler to leave its own injected names out: the
        // parameter defaults to true, so a listing carries them otherwise.
        assert_eq!(
            Call::Names {
                project: "myapp",
                config: "prd",
            }
            .query(),
            [
                ("project", "myapp"),
                ("config", "prd"),
                ("include_managed_secrets", "false"),
            ]
        );

        let write = Call::Write(&loc, Some("v"));
        assert!(
            write.query().is_empty(),
            "a write's coordinates ride in its body"
        );
        let body = write.body().expect("a write has a body");
        assert_eq!(body["project"], "myapp");
        assert_eq!(body["config"], "prd");
        assert_eq!(body["secrets"]["API_KEY"], "v");

        // ... and a delete is a write of null, which is what Doppler's merge
        // endpoint deletes on.
        let body = Call::Write(&loc, None).body().expect("a delete has a body");
        assert_eq!(body["secrets"]["API_KEY"], serde_json::Value::Null);
    }

    /// Each call's method and endpoint, pinned so a wrong path is a unit
    /// failure rather than a live 404.
    #[test]
    fn each_call_names_its_endpoint() {
        let loc = location("myapp", "prd", "API_KEY");
        let cases = [
            (
                Call::Read(&loc),
                reqwest::Method::GET,
                "/configs/config/secret",
            ),
            (
                Call::List {
                    project: "myapp",
                    config: "prd",
                    names: "",
                },
                reqwest::Method::GET,
                "/configs/config/secrets",
            ),
            (
                Call::Names {
                    project: "myapp",
                    config: "prd",
                },
                reqwest::Method::GET,
                "/configs/config/secrets/names",
            ),
            (
                Call::Write(&loc, Some("v")),
                reqwest::Method::POST,
                "/configs/config/secrets",
            ),
        ];
        for (call, method, path) in &cases {
            assert_eq!(call.method(), *method, "{path}");
            assert_eq!(call.path(), *path);
        }
    }

    // ----------------------------------------------------------------------
    // Transport: what `dispatch` puts on the wire, against an in-process
    // stand-in for Doppler. Everything above `dispatch` is pure and tested
    // without a socket; these pin the one layer that is not.

    struct RecordedRequest {
        line: String,
        headers: HashMap<String, String>,
        body: String,
    }

    /// Answers `responses` in order, one connection each, recording what
    /// arrived. `header`, when given, is sent as one extra response header.
    fn response_server(
        responses: Vec<(&'static str, String, Option<(&'static str, String)>)>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<RecordedRequest>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut recorded = Vec::new();
            for (status, body, header) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut headers = HashMap::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.trim_end().split_once(':') {
                        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                    }
                }
                let content_length = headers
                    .get("content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut request_body = vec![0; content_length];
                reader.read_exact(&mut request_body).unwrap();
                recorded.push(RecordedRequest {
                    line: line.trim_end().to_string(),
                    headers,
                    body: String::from_utf8(request_body).unwrap(),
                });
                let header = header
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .unwrap_or_default();
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            recorded
        });
        (endpoint, server)
    }

    /// A provider aimed at the fixture instead of Doppler, holding a token.
    fn fixture_provider(spec: &str, endpoint: SocketAddr) -> DopplerProvider {
        let mut p = provider(spec);
        p.api_base = format!("http://{endpoint}");
        p.allow_insecure_loopback = true;
        let mut credentials = ProviderCredentials::new();
        credentials.insert(TOKEN.to_string(), SecretBytes::from_utf8("dp.sa.test"));
        p.with_credentials(credentials);
        p
    }

    /// A batch read names its project and config in the query, asks only for
    /// the declared names, and carries the token as a bearer header.
    #[test]
    fn a_list_names_its_coordinates_on_the_wire() {
        let (endpoint, server) = response_server(vec![(
            "200 OK",
            r#"{"secrets":{},"success":true}"#.to_string(),
            None,
        )]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);

        let requests = [
            ("API_KEY", Address::convention("unused", "prd", "API_KEY")),
            ("DB_URL", Address::convention("unused", "prd", "DB_URL")),
        ];
        let read = p.get_many(&requests).unwrap();
        assert!(read.is_empty());

        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 1);
        let request = &recorded[0];
        assert!(
            request.line.starts_with("GET /configs/config/secrets?"),
            "{}",
            request.line
        );
        assert!(request.line.contains("project=myapp"), "{}", request.line);
        assert!(request.line.contains("config=prd"), "{}", request.line);
        assert!(
            request.line.contains("secrets=API_KEY%2CDB_URL")
                || request.line.contains("secrets=DB_URL%2CAPI_KEY"),
            "{}",
            request.line
        );
        assert_eq!(request.headers["authorization"], "Bearer dp.sa.test");
    }

    /// A write carries its coordinates and the value in a JSON body, with
    /// nothing in the query.
    #[test]
    fn a_write_puts_the_value_in_the_body() {
        let (endpoint, server) =
            response_server(vec![("200 OK", r#"{"success":true}"#.to_string(), None)]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);

        p.set(
            Address::convention("unused", "prd", "API_KEY"),
            &SecretBytes::from_utf8("v1"),
        )
        .unwrap();

        let recorded = server.join().unwrap();
        let request = &recorded[0];
        assert_eq!(request.line, "POST /configs/config/secrets HTTP/1.1");
        assert_eq!(request.headers["authorization"], "Bearer dp.sa.test");
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["project"], "myapp");
        assert_eq!(body["config"], "prd");
        assert_eq!(body["secrets"]["API_KEY"], "v1");
    }

    /// A redirect is reported, never followed: the write body holds the
    /// plaintext, and the origin a response names is not Doppler's.
    #[test]
    fn a_redirect_is_not_followed() {
        let elsewhere = TcpListener::bind("127.0.0.1:0").unwrap();
        elsewhere.set_nonblocking(true).unwrap();
        let target = format!(
            "http://{}/configs/config/secrets",
            elsewhere.local_addr().unwrap()
        );
        let (endpoint, server) = response_server(vec![(
            "307 Temporary Redirect",
            String::new(),
            Some(("Location", target)),
        )]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);

        let err = p
            .set(
                Address::convention("unused", "prd", "API_KEY"),
                &SecretBytes::from_utf8("v1"),
            )
            .expect_err("a redirect must surface as an error");
        assert!(err.to_string().contains("HTTP 307"), "{err}");

        assert_eq!(server.join().unwrap().len(), 1);
        assert_eq!(
            elsewhere.accept().map(|_| ()).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the redirect target must never see the request"
        );
    }

    /// A failed write reports Doppler's own words and the status, so a pinned
    /// token's refusal is legible.
    #[test]
    fn a_failed_write_reports_dopplers_message() {
        let (endpoint, server) = response_server(vec![(
            "400 Bad Request",
            r#"{"messages":["This token does not have access to requested config 'prd'"],"success":false}"#.to_string(),
            None,
        )]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);

        let err = p
            .set(
                Address::convention("unused", "prd", "API_KEY"),
                &SecretBytes::from_utf8("v1"),
            )
            .expect_err("a 400 must be an error")
            .to_string();
        assert!(err.contains("(400)"), "{err}");
        assert!(
            err.contains("does not have access to requested config 'prd'"),
            "{err}"
        );
        assert!(err.contains("writing 'API_KEY'"), "{err}");
        server.join().unwrap();
    }

    /// A batch read maps each listed value back onto the request name that
    /// asked for it, shares one value between requests naming the same
    /// address, and omits a name the config does not hold.
    ///
    /// The mapping loop is what the whole `get_many` override exists for, and
    /// nothing else exercises it: a transposed `(name, key)` pair would ship
    /// green.
    #[test]
    fn a_batch_read_maps_values_back_onto_their_request_names() {
        let listing = serde_json::json!({
            "secrets": {
                "API_KEY": { "raw": "k", "computed": "k" },
                "DB_URL": { "raw": "u", "computed": "u" },
            },
            "success": true,
        })
        .to_string();
        let (endpoint, server) = response_server(vec![("200 OK", listing.to_string(), None)]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);

        let shared = NativeAddress {
            item: "prd/API_KEY".into(),
            ..Default::default()
        };
        let requests = [
            ("API_KEY", Address::convention("unused", "prd", "API_KEY")),
            ("DB_URL", Address::convention("unused", "prd", "DB_URL")),
            ("ABSENT", Address::convention("unused", "prd", "ABSENT")),
            // The same entry under a second declared name, as a `ref` sharing
            // one address: the dedup contract says both are served from one
            // fetch.
            ("ALIAS", Address::Native(&shared)),
        ];
        let read = p.get_many(&requests).unwrap();

        assert_eq!(read["API_KEY"].expose_secret(), b"k");
        assert_eq!(read["DB_URL"].expose_secret(), b"u");
        assert_eq!(read["ALIAS"].expose_secret(), b"k");
        assert!(!read.contains_key("ABSENT"), "an absent name is omitted");
        assert_eq!(read.len(), 3);

        // One request for the config, naming each wanted secret once.
        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 1);
        let line = &recorded[0].line;
        assert_eq!(line.matches("API_KEY").count(), 1, "{line}");
    }

    /// Deleting reads first so the `bool` tells a real invalidation from a
    /// no-op: an absent secret is one request and `false`, a stored one is a
    /// read followed by the null write and `true`.
    #[test]
    fn a_delete_probes_before_it_writes() {
        let absent = serde_json::json!({
            "name": "API_KEY",
            "value": { "raw": null, "computed": null,
                       "rawVisibility": null, "computedVisibility": null },
            "success": true,
        })
        .to_string();
        let (endpoint, server) = response_server(vec![("200 OK", absent.to_string(), None)]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);
        assert!(
            !p.delete(Address::convention("unused", "prd", "API_KEY"))
                .unwrap(),
            "nothing was there to delete"
        );
        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 1, "an absent secret is not written to");
        assert!(recorded[0].line.starts_with("GET /configs/config/secret?"));

        let (endpoint, server) = response_server(vec![
            ("200 OK", single_read("k", "k").to_string(), None),
            ("200 OK", r#"{"success":true}"#.to_string(), None),
        ]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);
        assert!(
            p.delete(Address::convention("unused", "prd", "API_KEY"))
                .unwrap(),
            "a stored secret was invalidated"
        );
        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[1].line, "POST /configs/config/secrets HTTP/1.1");
        let body: serde_json::Value = serde_json::from_str(&recorded[1].body).unwrap();
        assert_eq!(body["secrets"]["API_KEY"], serde_json::Value::Null);
    }

    /// A probe that fails for any reason but an absent config does not block
    /// the deletion.
    ///
    /// Doppler withholds a `restricted` value from a token tied to a user
    /// identity while still accepting a write of it, and
    /// [`Provider::check_deletable`] cannot foresee that without a round trip.
    /// Failing here would make preflight pass and the deletion abort partway
    /// through a multi-secret import.
    #[test]
    fn a_delete_survives_a_probe_it_cannot_read() {
        let (endpoint, server) = response_server(vec![
            ("200 OK", restricted_read().to_string(), None),
            ("200 OK", r#"{"success":true}"#.to_string(), None),
        ]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);
        assert!(
            p.delete(Address::convention("unused", "prd", "MONGO_CONNECTION"))
                .expect("an unreadable secret is still deletable"),
        );
        assert_eq!(server.join().unwrap().len(), 2);
    }

    /// A failure body that is not Doppler's envelope is quoted, but bounded: it
    /// came from something other than Doppler and lands in a message that is
    /// printed and persisted to the audit log.
    #[test]
    fn an_unrecognized_failure_body_is_bounded() {
        let page = format!("<html>{}</html>", "x".repeat(64 * 1024));
        let message = error_message(&page);
        assert!(
            message.len() < MAX_ERROR_BODY_BYTES + 64,
            "{} bytes",
            message.len()
        );
        assert!(message.starts_with("<html>xxx"), "{message}");
        assert!(message.ends_with("... (truncated)"), "{message}");

        // A body that fits is quoted whole, and Doppler's own envelope is
        // never truncated into.
        assert_eq!(error_message("upstream timeout"), "upstream timeout");
    }

    /// A raw value with nothing under `computed` is not Doppler's answer for
    /// an absent secret -- that one nulls every field -- so it is reported
    /// rather than read as a secret nobody set.
    ///
    /// Resolving it to "unset" would have a fallback chain serve the next
    /// provider's value with no warning, and `secretspec check` offer to
    /// overwrite a secret that exists.
    #[test]
    fn a_secret_object_missing_its_computed_value_is_an_error() {
        for value in [
            serde_json::json!({ "raw": "s3cret_DO_NOT_ECHO", "computed": null }),
            // The same shape with the field renamed away entirely.
            serde_json::json!({ "raw": "s3cret_DO_NOT_ECHO", "secretValue": "s3cret" }),
        ] {
            let body = serde_json::json!({ "value": value, "success": true }).to_string();
            let err = parse_secret_value(&body, "MONGO_CONNECTION")
                .expect_err("an unrecognized secret object must be reported")
                .to_string();
            assert!(err.contains("MONGO_CONNECTION"), "{err}");
            assert!(
                !err.contains("DO_NOT_ECHO"),
                "the value must not leak: {err}"
            );
        }
    }

    /// A filter too long for one URI is split, and every chunk's names are
    /// asked for exactly once.
    #[test]
    fn a_large_filter_is_split_across_requests() {
        let names: Vec<String> = (0..500)
            .map(|n| format!("SECRETSPEC_NAME_{n:04}"))
            .collect();
        let chunks = filter_chunks(&names);
        assert!(chunks.len() > 1, "500 names exceed one filter's budget");
        for chunk in &chunks {
            assert!(chunk.len() <= MAX_FILTER_BYTES, "{} bytes", chunk.len());
        }
        let rejoined: Vec<&str> = chunks.iter().flat_map(|c| c.split(',')).collect();
        assert_eq!(
            rejoined,
            names.iter().map(String::as_str).collect::<Vec<_>>()
        );

        // An empty filter stays one request, which reads the whole config.
        assert_eq!(filter_chunks(&[]), [""]);
    }

    /// Only a rate limit or a server error is retried, a suggested wait is
    /// honored up to the cap and refused beyond it, and attempts run out.
    #[test]
    fn retry_policy_follows_dopplers_rate_limit_contract() {
        let limited = StatusCode::TOO_MANY_REQUESTS;
        assert_eq!(
            retry_delay(limited, Some("2"), 1),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            retry_delay(limited, None, 1),
            Some(Duration::from_millis(250)),
            "no usable header falls back to a backoff"
        );
        assert_eq!(
            retry_delay(limited, Some("soon"), 2),
            Some(Duration::from_millis(500)),
            "an unparseable header is a missing one, and the backoff grows"
        );
        assert_eq!(
            retry_delay(limited, Some("60"), 1),
            None,
            "a wait past the cap is reported rather than sat out"
        );
        assert_eq!(
            retry_delay(limited, Some("0"), RETRY_ATTEMPTS),
            None,
            "attempts run out"
        );
        assert_eq!(
            retry_delay(StatusCode::SERVICE_UNAVAILABLE, None, 1),
            Some(Duration::from_millis(250))
        );
        for final_word in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::TEMPORARY_REDIRECT,
        ] {
            assert_eq!(retry_delay(final_word, Some("1"), 1), None, "{final_word}");
        }
    }

    /// A rate-limited read waits out Doppler's suggested `retry-after` and
    /// then asks again, so a single 429 does not fail a profile.
    #[test]
    fn a_rate_limited_read_is_retried_after_the_suggested_wait() {
        let (endpoint, server) = response_server(vec![
            (
                "429 Too Many Requests",
                r#"{"messages":["Too many requests"],"success":false}"#.to_string(),
                Some(("Retry-After", "1".to_string())),
            ),
            ("200 OK", single_read("k", "k").to_string(), None),
        ]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);

        let started = std::time::Instant::now();
        let value = p
            .get(Address::convention("unused", "prd", "API_KEY"))
            .unwrap()
            .expect("the retry read the value");
        assert_eq!(value.expose_secret(), b"k");
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "the suggested wait was honored: {:?}",
            started.elapsed()
        );

        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 2, "one retry");
        assert_eq!(recorded[0].line, recorded[1].line, "the same request again");
    }

    /// A panic elsewhere while the profile lock is held must not cost the
    /// profile: the guarded value is assigned in one step, so a poisoned lock
    /// holds exactly what an unpoisoned one would, and losing it would fail
    /// every bare `ref` with "No Doppler config".
    #[test]
    fn a_poisoned_profile_lock_keeps_the_profile() {
        let p = provider("doppler://myapp");
        p.set_profile("prd");
        let poisoning = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _held = p.profile.lock().unwrap();
                    panic!("poison the profile lock");
                })
                .join()
        });
        assert!(poisoning.is_err(), "the lock was poisoned");
        assert!(p.profile.lock().is_err(), "the lock is poisoned");

        assert_eq!(p.session_profile().as_deref(), Some("prd"));
        p.set_profile("stg");
        assert_eq!(
            p.session_profile().as_deref(),
            Some("stg"),
            "a poisoned lock still records a new profile"
        );
    }

    /// A server error that outlasts the attempts is reported in Doppler's own
    /// words, from the last answer.
    #[test]
    fn a_persistent_server_error_is_reported_after_the_last_attempt() {
        let outage = || {
            (
                "503 Service Unavailable",
                r#"{"messages":["Doppler is briefly unavailable"],"success":false}"#.to_string(),
                None,
            )
        };
        let (endpoint, server) = response_server(vec![outage(), outage(), outage()]);
        let p = fixture_provider("doppler://myapp/prd", endpoint);

        let err = p
            .set(
                Address::convention("unused", "prd", "API_KEY"),
                &SecretBytes::from_utf8("v1"),
            )
            .expect_err("three outages exhaust the attempts")
            .to_string();
        assert!(err.contains("HTTP 503"), "{err}");
        assert!(err.contains("Doppler is briefly unavailable"), "{err}");
        assert_eq!(
            server.join().unwrap().len(),
            RETRY_ATTEMPTS as usize,
            "every attempt was made"
        );
    }
}
