use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, percent_encode};
use url::Url;

/// Characters that are invalid in URI hosts but might appear in provider config
/// values like vault names (e.g., 1Password vault "Home Lab").
/// Structural URI delimiters (@, /, :, ?, #) are intentionally excluded so they
/// are preserved during encoding.
pub(crate) const URI_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b']')
    .add(b'|')
    .add(b'^')
    .add(b'\\');

/// Like [`URI_ENCODE_SET`] but also encodes `:`. Used for Windows absolute paths
/// (e.g. `C:\path`) where the drive-letter colon would otherwise be read as a
/// `host:port` separator and fail parsing with "invalid port number".
pub(super) const WINDOWS_PATH_ENCODE_SET: &AsciiSet = &URI_ENCODE_SET.add(b':');

/// Like [`URI_ENCODE_SET`] but also encodes the characters that are structurally
/// significant inside a URI query string. Query *values* (e.g. the `V` in
/// `?key=V`) are read back with `application/x-www-form-urlencoded` semantics via
/// [`ProviderUrl::query_pairs`], which treats `&` as a pair separator, `+` as a
/// space and `%` as an escape, while `#` ends the query at the URL level. Leaving
/// those unencoded (as plain [`URI_ENCODE_SET`] does) makes a value like
/// `/a&b` or `/a+b` decode to something different on the way back. Encoding them
/// makes [`ProviderUrl::encode_query`] a true inverse of that parsing, so query
/// values round-trip. Path and host components keep using [`URI_ENCODE_SET`].
const QUERY_ENCODE_SET: &AsciiSet = &URI_ENCODE_SET.add(b'%').add(b'#').add(b'&').add(b'+');

/// Detects a Windows-style absolute path such as `C:\path` or `C:/path`.
pub(super) fn is_windows_abs_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// A URL wrapper that automatically percent-decodes all accessors.
///
/// Providers receive `&ProviderUrl` instead of `&Url`, ensuring they always
/// get decoded values (e.g., `"Home Lab"` instead of `"Home%20Lab"`).
///
/// **Limitation:** Structural URI delimiters (`@`, `/`, `:`, `?`, `#`) are
/// never encoded, so they cannot appear literally in provider config values
/// like vault or folder names. For example, a vault named `"My@Vault"` would
/// be misinterpreted as a username/host separator.
pub(crate) struct ProviderUrl(Url);

impl ProviderUrl {
    pub fn new(url: Url) -> Self {
        Self(url)
    }

    pub(super) fn as_url(&self) -> &Url {
        &self.0
    }

    pub fn scheme(&self) -> &str {
        self.0.scheme()
    }

    pub fn host(&self) -> Option<String> {
        self.0
            .host_str()
            .map(|h| percent_decode_str(h).decode_utf8_lossy().into_owned())
    }

    pub fn username(&self) -> String {
        percent_decode_str(self.0.username())
            .decode_utf8_lossy()
            .into_owned()
    }

    pub fn password(&self) -> Option<String> {
        self.0
            .password()
            .map(|p| percent_decode_str(p).decode_utf8_lossy().into_owned())
    }

    pub fn path(&self) -> String {
        percent_decode_str(self.0.path())
            .decode_utf8_lossy()
            .into_owned()
    }

    #[cfg(any(
        feature = "aac",
        feature = "infisical",
        feature = "openbao",
        feature = "vault",
        test
    ))]
    pub fn port(&self) -> Option<u16> {
        self.0.port()
    }

    pub fn query_pairs(&self) -> url::form_urlencoded::Parse<'_> {
        self.0.query_pairs()
    }

    /// Returns the value of the first `key=value` query pair matching `key`,
    /// treating an empty value as absent. The owned `String` is the inverse of
    /// [`encode_query`](Self::encode_query).
    pub fn query_value(&self, key: &str) -> Option<String> {
        self.0
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
            .filter(|v| !v.is_empty())
    }

    /// Whether the provider URI contains a query component, including an
    /// explicitly empty one.
    pub(crate) fn has_query(&self) -> bool {
        self.0.query().is_some()
    }

    /// Percent-encode a value for use in a URI path or host component (e.g., in
    /// `uri()` methods).
    pub fn encode(value: &str) -> String {
        percent_encode(value.as_bytes(), URI_ENCODE_SET).to_string()
    }

    /// Percent-encode a value for use as a URI query-string value (the `V` in
    /// `?key=V`). Unlike [`encode`](Self::encode), this also escapes the
    /// characters that `application/x-www-form-urlencoded` parsing treats
    /// specially, so the value survives a round-trip through
    /// [`query_pairs`](Self::query_pairs).
    pub fn encode_query(value: &str) -> String {
        percent_encode(value.as_bytes(), QUERY_ENCODE_SET).to_string()
    }
}

impl std::fmt::Display for ProviderUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;
    use std::collections::HashMap;

    fn url(s: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(s).unwrap())
    }

    #[test]
    fn host_and_path_are_percent_decoded() {
        let u = url("keyring://Home%20Lab/My%20Path");
        assert_eq!(u.host().as_deref(), Some("Home Lab"));
        assert_eq!(u.path(), "/My Path");
    }

    #[test]
    fn username_and_password_are_percent_decoded() {
        let u = url("onepassword://work%40acct:tok%20en@Vault");
        assert_eq!(u.username(), "work@acct");
        assert_eq!(u.password().as_deref(), Some("tok en"));
        assert_eq!(u.host().as_deref(), Some("Vault"));
    }

    #[test]
    fn missing_password_and_port_are_none() {
        let u = url("keyring://host");
        assert_eq!(u.password(), None);
        assert_eq!(u.port(), None);
        assert_eq!(u.username(), "");
    }

    #[test]
    fn port_is_parsed_when_present() {
        assert_eq!(url("https://example.com:8200/").port(), Some(8200));
    }

    #[test]
    fn detects_windows_absolute_paths() {
        assert!(is_windows_abs_path(r"C:\Users\foo"));
        assert!(is_windows_abs_path("C:/Users/foo"));
        assert!(is_windows_abs_path(r"d:\x"));
        assert!(!is_windows_abs_path("/tmp/foo"));
        assert!(!is_windows_abs_path("relative/path"));
        assert!(!is_windows_abs_path("C:"));
        assert!(!is_windows_abs_path("vault"));
    }

    #[test]
    fn windows_dotenv_path_parses_instead_of_failing_on_port() {
        let provider = Box::<dyn Provider>::try_from(r"dotenv://C:\Users\foo\.env");
        assert!(
            provider.is_ok(),
            "Windows dotenv path should parse, got {:?}",
            provider.err()
        );
    }

    #[test]
    fn windows_file_path_uses_a_standard_file_url() {
        let provider = Box::<dyn Provider>::try_from(r"file://C:\Users\foo\secrets").unwrap();
        assert_eq!(provider.name(), "file");
        assert_eq!(provider.uri(), "file:///C:/Users/foo/secrets");
    }

    #[test]
    fn query_pairs_are_decoded() {
        let u = url("keyring://h/p?prefix=a%20b&kv=v2");
        let pairs: HashMap<String, String> = u
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(pairs.get("prefix").map(String::as_str), Some("a b"));
        assert_eq!(pairs.get("kv").map(String::as_str), Some("v2"));
    }

    #[test]
    fn encode_escapes_spaces_but_keeps_plain() {
        assert_eq!(ProviderUrl::encode("plain"), "plain");
        assert_eq!(ProviderUrl::encode("Home Lab"), "Home%20Lab");
    }

    #[test]
    fn windows_drive_paths_parse_as_provider_specs() {
        for spec in [
            r"dotenv://C:\Users\me\.env",
            r"dotenv://C:/Users/me/.env",
            r"dotenv:C:\Users\me\.env",
        ] {
            assert!(
                Box::<dyn Provider>::try_from(spec).is_ok(),
                "should parse: {}",
                spec
            );
        }
        assert!(Box::<dyn Provider>::try_from("dotenv:///tmp/.env").is_ok());
        assert!(Box::<dyn Provider>::try_from("dotenv://.env").is_ok());
    }

    #[test]
    fn encode_query_escapes_query_significant_chars() {
        assert_eq!(ProviderUrl::encode_query("/a/b"), "/a/b");
        assert_eq!(ProviderUrl::encode_query("a&b"), "a%26b");
        assert_eq!(ProviderUrl::encode_query("a+b"), "a%2Bb");
        assert_eq!(ProviderUrl::encode_query("a#b"), "a%23b");
        assert_eq!(ProviderUrl::encode_query("a%b"), "a%25b");
        assert_eq!(ProviderUrl::encode_query("a b"), "a%20b");

        let value = "/srv/a&b+c#d%e f";
        let encoded = ProviderUrl::encode_query(value);
        let u = url(&format!("keyring://?store_dir={encoded}"));
        let decoded = u
            .query_pairs()
            .find(|(k, _)| k == "store_dir")
            .map(|(_, v)| v.into_owned());
        assert_eq!(decoded.as_deref(), Some(value));
    }
}

/// Property tests for the URI encoding every provider's `uri()` runs through.
#[cfg(test)]
mod encoding_properties {
    use super::*;
    use proptest::prelude::*;

    fn query_value_of(uri: &str, key: &str) -> Option<String> {
        let url = ProviderUrl::new(Url::parse(uri).ok()?);
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    proptest! {
        #[test]
        fn encode_query_round_trips(value in ".*") {
            let uri = format!("keyring://?v={}", ProviderUrl::encode_query(&value));
            let decoded = query_value_of(&uri, "v");
            prop_assert_eq!(
                decoded.as_deref(),
                Some(value.as_str()),
                "value {:?} did not survive the round-trip through {:?}",
                value,
                uri,
            );
        }

        #[test]
        fn encode_query_is_deterministic(value in ".*") {
            prop_assert_eq!(
                ProviderUrl::encode_query(&value),
                ProviderUrl::encode_query(&value),
            );
        }

        #[test]
        fn encoded_values_are_query_safe(value in ".*") {
            let encoded = ProviderUrl::encode_query(&value);
            prop_assert!(
                !encoded.contains('&') && !encoded.contains('#') && !encoded.contains('+'),
                "encoded {encoded:?} still carries a query-structural character",
            );
        }
    }
}
