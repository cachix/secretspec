use crate::config::{Config, GlobalConfig};
use crate::{NamedResolution, Secrets};
use clap::Parser;
use miette::{IntoDiagnostic, Result, miette};
use percent_encoding::percent_decode_str;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use url::{Host, Url};

const MAX_ATTRIBUTE_LINE_BYTES: usize = 65_535;
const EMBEDDED_MANIFEST: &str = include_str!("git-credentials.toml");
const EMBEDDED_PASSWORD: &str = "PASSWORD";
const EMBEDDED_USERNAME: &str = "USERNAME";

pub(crate) struct EmbeddedGitCredentials {
    pub(crate) secrets: Secrets,
    pub(crate) password_secret: String,
    pub(crate) username_secret: String,
}

#[derive(Parser)]
#[command(
    name = "git-credential-secretspec",
    about = "Retrieve Git HTTP(S) or SMTP credentials through SecretSpec providers",
    version
)]
struct Args {
    #[arg(long, help = "Git URL this credential is allowed to authenticate")]
    url: Url,
    #[arg(long, help = "Git username this credential is allowed to authenticate")]
    username: Option<String>,
    #[arg(long, help = "SecretSpec key containing the Git username")]
    username_secret: Option<String>,
    #[arg(long, help = "SecretSpec key containing the Git password or token")]
    password_secret: String,
    #[arg(short = 'f', long, help = "Path to secretspec.toml")]
    file: Option<PathBuf>,
    #[arg(
        short = 'P',
        long,
        env = "SECRETSPEC_PROFILE",
        help = "SecretSpec profile to use"
    )]
    profile: Option<String>,
    #[arg(
        short,
        long,
        env = "SECRETSPEC_PROVIDER",
        help = "Override the SecretSpec provider"
    )]
    provider: Option<String>,
    #[arg(
        long,
        env = "SECRETSPEC_REASON",
        help = "Reason recorded for the secret access"
    )]
    reason: Option<String>,
    #[arg(help = "Git credential operation")]
    operation: String,
}

#[derive(Default)]
struct Request {
    protocol: Option<String>,
    host: Option<String>,
    path: Option<String>,
    username: Option<String>,
}

impl Request {
    fn read(mut input: impl BufRead) -> Result<Self> {
        let mut request = Self::default();
        let mut line = String::new();

        loop {
            line.clear();
            let read = input.read_line(&mut line).into_diagnostic()?;
            if read == 0 {
                break;
            }
            if read > MAX_ATTRIBUTE_LINE_BYTES {
                return Err(miette!("Git credential attribute exceeds 65535 bytes"));
            }
            if line.ends_with('\n') {
                line.pop();
                if line.ends_with('\r') {
                    line.pop();
                }
            }
            if line.is_empty() {
                break;
            }
            if line.contains('\0') {
                return Err(miette!("invalid Git credential attribute"));
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| miette!("invalid Git credential attribute"))?;
            match key {
                "protocol" => request.protocol = Some(value.to_string()),
                "host" => request.host = Some(value.to_string()),
                "path" => request.path = Some(value.to_string()),
                "username" => request.username = Some(value.to_string()),
                "url" => request.apply_url(value)?,
                _ => {}
            }
        }

        Ok(request)
    }

    /// Applies a `url=` attribute the way Git's own `credential_from_url`
    /// does: every field the URL covers is replaced, including the ones it
    /// leaves out. Keeping a username or path from an earlier attribute would
    /// answer a request the caller did not make.
    fn apply_url(&mut self, value: &str) -> Result<()> {
        let parsed = Url::parse(value).into_diagnostic()?;
        self.protocol = Some(parsed.scheme().to_string());
        self.host = parsed.host().map(|host| {
            let host = match host {
                Host::Ipv6(address) => format!("[{address}]"),
                host => host.to_string(),
            };
            match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            }
        });
        let username = percent_decode_str(parsed.username()).decode_utf8_lossy();
        self.username = (!username.is_empty()).then(|| username.into_owned());
        let path = percent_decode_str(parsed.path()).decode_utf8_lossy();
        let path = path.trim_start_matches('/');
        self.path = (!path.is_empty()).then(|| path.to_string());
        Ok(())
    }

    fn authority_url(&self) -> Option<Url> {
        let protocol = self.protocol.as_deref()?;
        let host = self.host.as_deref()?;
        let candidate = Url::parse(&format!("{protocol}://{host}/")).ok()?;
        (candidate.host().is_some()
            && candidate.username().is_empty()
            && candidate.password().is_none()
            && candidate.path() == "/"
            && candidate.query().is_none()
            && candidate.fragment().is_none())
        .then_some(candidate)
    }
}

pub(crate) fn validate_target(target: &Url) -> Result<()> {
    if !matches!(target.scheme(), "http" | "https" | "smtp") {
        return Err(miette!("Git credential URL must use HTTP, HTTPS, or SMTP"));
    }
    if target.host().is_none() {
        return Err(miette!("Git credential URL must include a host"));
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err(miette!("Git credential URL must not include credentials"));
    }
    if target.query().is_some() || target.fragment().is_some() {
        return Err(miette!(
            "Git credential URL must not include a query or fragment"
        ));
    }
    if target.scheme() == "smtp" && target.port().is_none() {
        return Err(miette!("SMTP credential URL must include an explicit port"));
    }
    if target.scheme() == "smtp" && !target.path().trim_matches('/').is_empty() {
        return Err(miette!("SMTP credential URL must not include a path"));
    }
    Ok(())
}

pub(crate) fn canonical_target(url: &Url) -> String {
    // The url crate lowercases hosts for special schemes only, so an `smtp`
    // target keeps whatever case was typed while Git's urlmatch always
    // lowercases. Without normalizing here, a mixed-case target registers a
    // helper that Git selects but that never recognizes the request it is
    // handed, and `login` would store under a second identity.
    let mut target = format!("{}://", url.scheme());
    if let Some(host) = url.host_str() {
        target.push_str(&host.to_ascii_lowercase());
    }
    if let Some(port) = url.port() {
        target.push_str(&format!(":{port}"));
    }
    let path = url.path().trim_end_matches('/');
    if !path.is_empty() {
        target.push_str(path);
    }
    target
}

fn hosts_match(target: &Url, candidate: &Url) -> bool {
    match (target.host_str(), candidate.host_str()) {
        (Some(target), Some(candidate)) => target.eq_ignore_ascii_case(candidate),
        (target, candidate) => target == candidate,
    }
}

fn context_username<'a>(target: &Url, username: Option<&'a str>) -> Result<Option<&'a str>> {
    if target.scheme() != "smtp" {
        return Ok(None);
    }
    let username = username.ok_or_else(|| miette!("SMTP credentials require a username"))?;
    if username.is_empty() || username.contains(['\n', '\r', '\0']) {
        return Err(miette!(
            "SMTP username cannot be empty or contain a newline or NUL byte"
        ));
    }
    Ok(Some(username))
}

fn embedded_identity(target: &Url, username: Option<&str>) -> Result<String> {
    let username = context_username(target, username)?;
    let target = canonical_target(target);
    let mut digest = Sha256::new();
    digest.update(target.as_bytes());
    if let Some(username) = username {
        digest.update([0]);
        digest.update(username.as_bytes());
    }
    Ok(data_encoding::HEXLOWER.encode(&digest.finalize()))
}

pub(crate) fn load_embedded_git_credentials(
    target: &Url,
    username: Option<&str>,
) -> Result<EmbeddedGitCredentials> {
    validate_target(target)?;
    let mut config: Config = toml::from_str(EMBEDDED_MANIFEST).into_diagnostic()?;
    let identity = embedded_identity(target, username)?;
    config.project.name = format!("git-credential-{identity}");
    // Some providers flatten convention addresses to the logical key and
    // ignore both project and profile, so the keys must carry the identity too.
    let password_secret = format!("{EMBEDDED_PASSWORD}_{identity}");
    let username_secret = format!("{EMBEDDED_USERNAME}_{identity}");
    let profile = config
        .profiles
        .get_mut("default")
        .ok_or_else(|| miette!("embedded Git credential manifest has no default profile"))?;
    let password = profile
        .secrets
        .remove(EMBEDDED_PASSWORD)
        .ok_or_else(|| miette!("embedded Git credential manifest has no password secret"))?;
    let username_config = profile
        .secrets
        .remove(EMBEDDED_USERNAME)
        .ok_or_else(|| miette!("embedded Git credential manifest has no username secret"))?;
    profile.secrets.insert(password_secret.clone(), password);
    profile
        .secrets
        .insert(username_secret.clone(), username_config);
    let config_path = GlobalConfig::path().into_diagnostic()?;
    let config_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| miette!("SecretSpec config path has no parent directory"))?;
    let mut secrets = Secrets::load_config(config, config_dir)?;
    secrets.set_profile("default");
    secrets.set_ignore_ambient_scope(true);
    Ok(EmbeddedGitCredentials {
        secrets,
        password_secret,
        username_secret,
    })
}

fn target_matches(target: &Url, username: Option<&str>, request: &Request) -> bool {
    let Some(candidate) = request.authority_url() else {
        return false;
    };
    if target.scheme() != candidate.scheme()
        || !hosts_match(target, &candidate)
        || target.port_or_known_default() != candidate.port_or_known_default()
    {
        return false;
    }
    match (target.scheme(), username, request.username.as_deref()) {
        ("smtp", expected, actual) if actual != expected => return false,
        (_, Some(expected), Some(actual)) if actual != expected => return false,
        _ => {}
    }

    let expected = percent_decode_str(target.path()).decode_utf8_lossy();
    let expected = expected.trim_matches('/');
    if expected.is_empty() {
        return true;
    }
    let actual = request
        .path
        .as_deref()
        .unwrap_or_default()
        .trim_matches('/');
    actual == expected
        || actual
            .strip_prefix(expected)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn validate_value(name: &str, attribute: &str, value: &SecretString) -> Result<()> {
    let value = value.expose_secret();
    if value.contains(['\n', '\r', '\0']) {
        return Err(miette!(
            "Secret '{name}' cannot be represented by Git's credential protocol"
        ));
    }
    if attribute.len() + value.len() + 2 > MAX_ATTRIBUTE_LINE_BYTES {
        return Err(miette!(
            "Secret '{name}' exceeds Git's credential protocol line limit"
        ));
    }
    Ok(())
}

fn load(args: &Args) -> Result<Secrets> {
    let mut secrets = match &args.file {
        Some(path) => Secrets::load_from(path)?,
        None => load_embedded_git_credentials(&args.url, args.username.as_deref())?.secrets,
    };
    if let Some(provider) = &args.provider {
        secrets.set_provider(provider);
    }
    if args.file.is_some()
        && let Some(profile) = &args.profile
    {
        secrets.set_profile(profile);
    }
    if let Some(reason) = &args.reason {
        secrets = secrets.with_reason(reason);
    }
    secrets.set_ignore_ambient_scope(true);
    Ok(secrets)
}

fn resolve(secrets: &Secrets, name: &str) -> Result<Option<SecretString>> {
    let Some(config) = secrets.resolve_secret_config(name, None) else {
        return Err(miette!(
            "Secret '{name}' is not declared in the selected SecretSpec profile"
        ));
    };
    if config.as_path == Some(true) {
        return Err(miette!(
            "Secret '{name}' uses as_path and cannot be returned as a Git credential"
        ));
    }
    match secrets.resolve_named(name)? {
        NamedResolution::Resolved(secret) => {
            let value = secret.value.ok_or_else(|| {
                miette!("Secret '{name}' uses as_path and cannot be returned as a Git credential")
            })?;
            Ok(Some(SecretString::new(value.into())))
        }
        NamedResolution::Missing { .. } => Ok(None),
        NamedResolution::Undeclared => Err(miette!(
            "Secret '{name}' is not declared in the selected SecretSpec profile"
        )),
    }
}

fn run(args: Args, input: impl BufRead, mut output: impl Write) -> Result<()> {
    if args.operation != "get" {
        return Ok(());
    }

    validate_target(&args.url)?;
    let request = Request::read(input)?;

    if !target_matches(&args.url, args.username.as_deref(), &request) {
        return Ok(());
    }

    let secrets = load(&args)?;
    let username = if args.username.is_none()
        && let Some(name) = &args.username_secret
    {
        match resolve(&secrets, name)? {
            Some(value) => Some((name, value)),
            None => {
                if args.file.is_some() {
                    return Ok(());
                }
                None
            }
        }
    } else {
        None
    };

    if let (Some(actual), Some((_, expected))) = (&request.username, &username)
        && actual != expected.expose_secret()
    {
        return Ok(());
    }

    let Some(password) = resolve(&secrets, &args.password_secret)? else {
        return Ok(());
    };

    validate_value(&args.password_secret, "password", &password)?;
    if let Some((name, value)) = &username {
        validate_value(name, "username", value)?;
    }

    if request.username.is_none()
        && let Some((_, username)) = username
    {
        writeln!(output, "username={}", username.expose_secret()).into_diagnostic()?;
    }
    write_password(&args.password_secret, &password, output)
}

fn write_password(name: &str, password: &SecretString, mut output: impl Write) -> Result<()> {
    validate_value(name, "password", password)?;
    writeln!(output, "password={}", password.expose_secret()).into_diagnostic()?;
    writeln!(output).into_diagnostic()?;
    Ok(())
}

pub fn main() -> Result<()> {
    run(
        Args::parse(),
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn manifest(contents: &str) -> (TempDir, PathBuf) {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("secretspec.toml");
        fs::write(&path, contents).unwrap();
        (directory, path)
    }

    fn args(path: PathBuf, operation: &str) -> Args {
        Args {
            url: Url::parse("https://github.com").unwrap(),
            username: None,
            username_secret: Some("GITHUB_USERNAME".to_string()),
            password_secret: "GITHUB_TOKEN".to_string(),
            file: Some(path),
            profile: None,
            provider: None,
            reason: None,
            operation: operation.to_string(),
        }
    }

    #[test]
    fn returns_declared_credentials_for_matching_url() {
        let (_directory, path) = manifest(
            r#"
[project]
name = "git-helper"
revision = "1.0"
require_reason = false

[profiles.default]
GITHUB_USERNAME = { description = "GitHub username", default = "vimjoyer", providers = ["null"] }
GITHUB_TOKEN = { description = "GitHub token", default = "token=value", providers = ["null"] }
"#,
        );
        let mut output = Vec::new();
        run(
            args(path, "get"),
            Cursor::new("protocol=https\nhost=github.com\n\n"),
            &mut output,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "username=vimjoyer\npassword=token=value\n\n"
        );
    }

    #[test]
    fn username_secret_rejects_a_different_http_request_username() {
        let (_directory, path) = manifest(
            r#"
[project]
name = "git-helper"
revision = "1.0"
require_reason = false

[profiles.default]
GITHUB_USERNAME = { description = "GitHub username", default = "alice", providers = ["null"] }
GITHUB_TOKEN = { description = "GitHub token", default = "alice-token", providers = ["null"] }
"#,
        );
        let mut output = Vec::new();
        run(
            args(path, "get"),
            Cursor::new("protocol=https\nhost=github.com\nusername=bob\n\n"),
            &mut output,
        )
        .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn mismatched_url_does_not_load_or_return_credentials() {
        let mut output = Vec::new();
        run(
            args(PathBuf::from("missing.toml"), "get"),
            Cursor::new("protocol=https\nhost=example.com\n\n"),
            &mut output,
        )
        .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn missing_stored_password_returns_nothing() {
        let (_directory, path) = manifest(
            r#"
[project]
name = "git-helper"
revision = "1.0"
require_reason = false

[profiles.default]
GITHUB_USERNAME = { description = "GitHub username", default = "vimjoyer", providers = ["null"] }
GITHUB_TOKEN = { description = "GitHub token", providers = ["null"] }
"#,
        );
        let mut output = Vec::new();
        run(
            args(path, "get"),
            Cursor::new("protocol=https\nhost=github.com\n\n"),
            &mut output,
        )
        .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn unsupported_operations_do_not_read_or_load() {
        for operation in ["store", "erase", "capability", "future-operation"] {
            let mut arguments = args(PathBuf::from("missing.toml"), operation);
            arguments.url = Url::parse("ssh://github.com").unwrap();
            let mut output = Vec::new();
            run(
                arguments,
                Cursor::new("not a credential attribute\n"),
                &mut output,
            )
            .unwrap();
            assert!(output.is_empty());
        }
    }

    #[test]
    fn configured_path_matches_only_its_path_segment() {
        let target = Url::parse("https://github.com/cachix").unwrap();
        let matching = Request {
            protocol: Some("https".to_string()),
            host: Some("github.com".to_string()),
            path: Some("cachix/secretspec".to_string()),
            username: None,
        };
        let unrelated = Request {
            protocol: Some("https".to_string()),
            host: Some("github.com".to_string()),
            path: Some("cachix-evil/secretspec".to_string()),
            username: None,
        };
        assert!(target_matches(&target, None, &matching));
        assert!(!target_matches(&target, None, &unrelated));
    }

    #[test]
    fn configured_path_matches_git_decoded_spaces_and_unicode() {
        let target = Url::parse("https://github.com/org%20name/r%C3%A9sum%C3%A9").unwrap();
        let matching = Request {
            protocol: Some("https".to_string()),
            host: Some("github.com".to_string()),
            path: Some("org name/résumé/repository".to_string()),
            username: None,
        };
        assert!(target_matches(&target, None, &matching));
    }

    #[test]
    fn different_protocol_or_similar_hostname_does_not_match() {
        let target = Url::parse("https://github.com").unwrap();
        for request in [
            Request {
                protocol: Some("http".to_string()),
                host: Some("github.com".to_string()),
                path: None,
                username: None,
            },
            Request {
                protocol: Some("https".to_string()),
                host: Some("github.com.example.com".to_string()),
                path: None,
                username: None,
            },
            Request {
                protocol: Some("https".to_string()),
                host: Some("example.com@github.com".to_string()),
                path: None,
                username: None,
            },
            Request {
                protocol: Some("https".to_string()),
                host: Some("github.com/path".to_string()),
                path: None,
                username: None,
            },
        ] {
            assert!(!target_matches(&target, None, &request));
        }
    }

    #[test]
    fn url_attribute_and_default_port_match() {
        let mut request = Request::default();
        request
            .apply_url("https://github.com:443/cachix/secretspec")
            .unwrap();
        assert!(target_matches(
            &Url::parse("https://github.com/cachix").unwrap(),
            None,
            &request
        ));
    }

    #[test]
    fn url_attribute_carries_userinfo_and_replaces_earlier_attributes() {
        let mut request = Request {
            protocol: Some("smtp".to_string()),
            host: Some("smtp.example.com:587".to_string()),
            path: Some("stale/path".to_string()),
            username: Some("stale@example.com".to_string()),
        };
        request
            .apply_url("https://alice%40example.com@github.com/cachix/secretspec")
            .unwrap();
        assert_eq!(request.protocol.as_deref(), Some("https"));
        assert_eq!(request.host.as_deref(), Some("github.com"));
        assert_eq!(request.path.as_deref(), Some("cachix/secretspec"));
        assert_eq!(request.username.as_deref(), Some("alice@example.com"));

        request.apply_url("https://github.com").unwrap();
        assert_eq!(request.path, None);
        assert_eq!(request.username, None);

        request
            .apply_url("https://github.com/org%20name/r%C3%A9sum%C3%A9")
            .unwrap();
        assert_eq!(request.path.as_deref(), Some("org name/résumé"));
    }

    #[test]
    fn http_matching_rejects_a_different_configured_username() {
        let target = Url::parse("https://github.com").unwrap();
        let request = Request {
            protocol: Some("https".to_string()),
            host: Some("github.com".to_string()),
            path: None,
            username: Some("bob".to_string()),
        };
        assert!(!target_matches(&target, Some("alice"), &request));
        assert!(target_matches(&target, Some("bob"), &request));
    }

    #[test]
    fn a_url_with_userinfo_selects_the_matching_smtp_account() {
        let target = Url::parse("smtp://smtp.example.com:587").unwrap();
        let mut request = Request::default();
        request
            .apply_url("smtp://user%40example.com@smtp.example.com:587")
            .unwrap();
        assert!(target_matches(&target, Some("user@example.com"), &request));
        assert!(!target_matches(
            &target,
            Some("other@example.com"),
            &request
        ));
    }

    #[test]
    fn embedded_storage_identity_uses_the_canonical_target() {
        let github = Url::parse("https://GITHUB.com:443/").unwrap();
        let canonical_github = Url::parse("https://github.com").unwrap();
        let path = Url::parse("https://github.com/cachix").unwrap();
        let insecure = Url::parse("http://github.com").unwrap();
        assert_eq!(
            embedded_identity(&github, None).unwrap(),
            embedded_identity(&canonical_github, None).unwrap()
        );
        assert_ne!(
            embedded_identity(&github, None).unwrap(),
            embedded_identity(&path, None).unwrap()
        );
        assert_ne!(
            embedded_identity(&github, None).unwrap(),
            embedded_identity(&insecure, None).unwrap()
        );
    }

    #[test]
    fn smtp_matching_requires_the_exact_server_port_and_username() {
        let target = Url::parse("smtp://smtp.example.com:587").unwrap();
        let request = Request {
            protocol: Some("smtp".to_string()),
            host: Some("smtp.example.com:587".to_string()),
            path: None,
            username: Some("user@example.com".to_string()),
        };
        assert!(target_matches(&target, Some("user@example.com"), &request));

        let mut mismatch = request;
        mismatch.username = Some("other@example.com".to_string());
        assert!(!target_matches(
            &target,
            Some("user@example.com"),
            &mismatch
        ));

        mismatch.username = Some("user@example.com".to_string());
        mismatch.host = Some("smtp.example.com:465".to_string());
        assert!(!target_matches(
            &target,
            Some("user@example.com"),
            &mismatch
        ));

        mismatch.protocol = Some("https".to_string());
        mismatch.host = Some("smtp.example.com:587".to_string());
        assert!(!target_matches(
            &target,
            Some("user@example.com"),
            &mismatch
        ));

        assert_ne!(
            embedded_identity(&target, Some("user@example.com")).unwrap(),
            embedded_identity(&target, Some("other@example.com")).unwrap()
        );
    }

    #[test]
    fn smtp_targets_are_matched_and_stored_case_insensitively() {
        let mixed = Url::parse("smtp://SMTP.Example.COM:2525").unwrap();
        let lower = Url::parse("smtp://smtp.example.com:2525").unwrap();
        assert_eq!(canonical_target(&mixed), "smtp://smtp.example.com:2525");
        assert_eq!(canonical_target(&mixed), canonical_target(&lower));
        assert_eq!(
            embedded_identity(&mixed, Some("user@example.com")).unwrap(),
            embedded_identity(&lower, Some("user@example.com")).unwrap()
        );

        // Git lowercases the host before it selects and calls a helper.
        let request = Request {
            protocol: Some("smtp".to_string()),
            host: Some("smtp.example.com:2525".to_string()),
            path: None,
            username: Some("user@example.com".to_string()),
        };
        assert!(target_matches(&mixed, Some("user@example.com"), &request));
    }

    #[test]
    fn canonical_target_keeps_ipv6_and_non_default_ports() {
        assert_eq!(
            canonical_target(&Url::parse("https://[::1]:8443/Org").unwrap()),
            "https://[::1]:8443/Org"
        );
        assert_eq!(
            canonical_target(&Url::parse("https://github.com:443").unwrap()),
            "https://github.com"
        );
    }

    #[test]
    fn smtp_targets_require_an_explicit_port() {
        let error = validate_target(&Url::parse("smtp://smtp.example.com").unwrap()).unwrap_err();
        assert!(error.to_string().contains("explicit port"));
        validate_target(&Url::parse("smtp://smtp.example.com:25").unwrap()).unwrap();
        validate_target(&Url::parse("https://github.com").unwrap()).unwrap();
    }

    #[test]
    fn rejects_values_that_git_cannot_represent() {
        for value in ["line\nfeed", "carriage\rreturn", "nul\0byte"] {
            let value = SecretString::new(value.to_string().into());
            assert!(validate_value("TOKEN", "password", &value).is_err());
        }

        let value = SecretString::new("x".repeat(MAX_ATTRIBUTE_LINE_BYTES).into());
        assert!(validate_value("TOKEN", "password", &value).is_err());
    }

    #[test]
    fn rejects_as_path_credentials() {
        let (_directory, path) = manifest(
            r#"
[project]
name = "git-helper"
revision = "1.0"
require_reason = false

[profiles.default]
GITHUB_USERNAME = { description = "GitHub username", default = "vimjoyer", providers = ["null"] }
GITHUB_TOKEN = { description = "GitHub token", default = "token", providers = ["null"], as_path = true }
"#,
        );
        let error = run(
            args(path, "get"),
            Cursor::new("protocol=https\nhost=github.com\n\n"),
            Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("uses as_path"));
    }
}
