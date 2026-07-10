use crate::provider::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::io;
use std::process::{Command, Stdio};

/// The resource field that carries a secret's value when a `ref` does not name
/// one explicitly. Passbolt resources model a login (name/username/uri/password
/// /description); the password is the secret material, so it is the default.
const DEFAULT_FIELD: &str = "password";

/// Resource fields a native `ref` may address via its `field` coordinate. These
/// are the standard Passbolt resource attributes; `password` is the secret, the
/// rest are metadata that a `ref` can still pin (e.g. reading a stored `uri`).
const KNOWN_FIELDS: &[&str] = &["password", "username", "uri", "description", "name"];

/// Environment variables that let secretspec supply the `passbolt` CLI's own
/// credentials, so `secretspec.toml` stays secret-free and no separate
/// `passbolt configure` step is needed. All are optional; when none are set the
/// provider falls back to whatever the CLI is already configured with (its
/// config file or native env vars).
///
/// The passphrase and inline key are *secrets*: they are forwarded to the child
/// through its environment (the names `go-passbolt-cli`'s viper reads), never on
/// the argv (which is world-visible via `ps`) and never in the provider URI.
const ENV_SERVER: &str = "SECRETSPEC_PASSBOLT_SERVER";
const ENV_PRIVATE_KEY_FILE: &str = "SECRETSPEC_PASSBOLT_PRIVATE_KEY_FILE";
const ENV_PRIVATE_KEY: &str = "SECRETSPEC_PASSBOLT_PRIVATE_KEY";
const ENV_PASSPHRASE: &str = "SECRETSPEC_PASSBOLT_PASSPHRASE";

/// One resource as emitted by `passbolt get/list resource --json`. Every column
/// is optional in the CLI output (fields are omitted when not requested or
/// empty), so all are `Option`. Only the subset secretspec needs is modeled.
#[derive(Debug, Deserialize)]
struct PassboltResource {
    id: Option<String>,
    name: Option<String>,
    username: Option<String>,
    uri: Option<String>,
    password: Option<String>,
    description: Option<String>,
}

impl PassboltResource {
    /// Extracts the named resource field, or `None` when the field is absent or
    /// empty. `field` is one of [`KNOWN_FIELDS`] (already validated upstream).
    fn field(&self, field: &str) -> Option<String> {
        let value = match field {
            "password" => &self.password,
            "username" => &self.username,
            "uri" => &self.uri,
            "description" => &self.description,
            "name" => &self.name,
            _ => &None,
        };
        value.clone().filter(|v| !v.is_empty())
    }
}

/// Resolved `passbolt` CLI credentials, kept separate from [`PassboltProvider::command`]
/// so the env → CLI mapping is unit-testable without mutating the process env.
///
/// Non-secret values (server address, key *file path*) go on the argv as flags,
/// which take reliable precedence over the CLI's config file. Secrets (the
/// passphrase and an inline key) are passed through the child's environment
/// under the names `go-passbolt-cli` reads, keeping them off the world-readable
/// argv.
struct CliAuth {
    server: Option<String>,
    key_file: Option<String>,
    key_inline: Option<String>,
    passphrase: Option<String>,
}

impl CliAuth {
    fn apply(&self, cmd: &mut Command) {
        if let Some(server) = &self.server {
            cmd.arg("--serverAddress").arg(server);
        }
        // A key *file* is a path (not itself secret) and takes precedence over
        // an inline key, matching go-passbolt-cli's own --userPrivateKeyFile
        // precedence.
        if let Some(key_file) = &self.key_file {
            cmd.arg("--userPrivateKeyFile").arg(key_file);
        } else if let Some(key) = &self.key_inline {
            cmd.env("USERPRIVATEKEY", key);
        }
        if let Some(passphrase) = &self.passphrase {
            cmd.env("USERPASSWORD", passphrase);
        }
    }
}

/// Reports whether `s` is a Passbolt resource id (a canonical UUID), so an
/// `item` coordinate can be routed straight to `get resource --id` instead of a
/// name lookup. Passbolt ids are lowercase UUIDs, but we accept any case.
fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, &b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => b.is_ascii_hexdigit(),
    })
}

/// Configuration for the Passbolt provider.
///
/// The Passbolt server address and the user's private key + passphrase are
/// *not* held here: they are the `passbolt` CLI's own configuration (written by
/// `passbolt configure`, or supplied via its env vars/flags), which the provider
/// inherits by shelling out. Only non-secret addressing lives in the URI.
#[derive(Debug, Clone, Default)]
pub struct PassboltConfig {
    /// Resource-name format string for convention secrets. Supports the
    /// `{project}`, `{profile}`, `{key}` placeholders. Defaults to
    /// `secretspec/{project}/{profile}/{key}` when absent.
    pub name_template: Option<String>,
    /// Optional folder id (`--folderParentID`) new convention resources are
    /// created under, and which name lookups are scoped to. From `?folder=`.
    pub folder_id: Option<String>,
    /// Optional Passbolt server address, passed as `--serverAddress`. When
    /// absent the CLI's configured server is used. From `?server=`. Not a
    /// secret (it is a URL), so it is safe to echo in [`Provider::uri`].
    pub server_address: Option<String>,
}

impl TryFrom<&ProviderUrl> for PassboltConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "passbolt" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for passbolt provider",
                url.scheme()
            )));
        }

        let mut config = Self::default();

        // host + path form the resource-name template, mirroring the pass
        // provider's folder_prefix (e.g. `passbolt://secretspec/{profile}/{key}`).
        if let Some(host) = url.host() {
            let path = url.path();
            config.name_template = Some(format!("{}{}", host, path));
        }

        config.folder_id = url.query_value("folder");
        config.server_address = url.query_value("server");

        Ok(config)
    }
}

/// Provider for [Passbolt](https://www.passbolt.com/), the self-hosted
/// open-source password manager, via the official `go-passbolt-cli` (`passbolt`).
///
/// Each convention secret maps to one Passbolt resource whose *name* encodes
/// `{project}/{profile}/{key}` and whose *password* field holds the value. This
/// suits the "a human enters an API key once via the Passbolt web UI, dev
/// machines read it at runtime" workflow: point a secret's [`ref`] at the
/// resource (by id or name) and the value is fetched with no secrets on disk.
///
/// # Authentication
///
/// The Passbolt private key and passphrase are the bootstrap secrets that
/// unlock every other secret, so they live neither in `secretspec.toml` nor in
/// the provider URI. Supply them one of two ways:
///
/// 1. **secretspec-owned env vars** (no separate CLI config step): set
///    `SECRETSPEC_PASSBOLT_PRIVATE_KEY_FILE` (or `SECRETSPEC_PASSBOLT_PRIVATE_KEY`
///    for an inline key) and `SECRETSPEC_PASSBOLT_PASSPHRASE`; the server address
///    comes from the URI's `?server=` or `SECRETSPEC_PASSBOLT_SERVER`. The
///    provider forwards these to the CLI itself — the passphrase and inline key
///    via the child's environment, never the argv.
/// 2. **the CLI's own configuration**: run `passbolt configure --serverAddress
///    https://... --userPrivateKeyFile key.asc --userPassword <passphrase>`
///    once. With none of the env vars above set, the provider inherits it.
///
/// Either way, no credentials appear in `secretspec.toml` or the provider URI.
///
/// # Storage
///
/// - Resource name: `secretspec/{project}/{profile}/{key}` by default,
///   customizable via the URI (`passbolt://<template>`).
/// - Secret value: the resource's `password` field. A `ref` may read a
///   different field (`username`, `uri`, `description`) via its `field`
///   coordinate.
///
/// [`ref`]: crate::config::NativeAddress
pub struct PassboltProvider {
    config: PassboltConfig,
    /// Path to the `passbolt` binary. Override with the
    /// `SECRETSPEC_PASSBOLT_CLI_PATH` environment variable.
    cli_binary_path: String,
}

crate::register_provider! {
    struct: PassboltProvider,
    config: PassboltConfig,
    name: "passbolt",
    description: "Passbolt self-hosted password manager via go-passbolt-cli",
    schemes: ["passbolt"],
    examples: [
        "passbolt://",
        "passbolt://secretspec/{project}/{profile}/{key}",
        "passbolt://?server=https://pass.example.com",
    ],
}

impl PassboltProvider {
    pub fn new(config: PassboltConfig) -> Self {
        let cli_binary_path =
            std::env::var("SECRETSPEC_PASSBOLT_CLI_PATH").unwrap_or_else(|_| "passbolt".to_string());
        Self {
            config,
            cli_binary_path,
        }
    }

    /// Renders the resource name for a convention secret from the configured
    /// (or default) name template.
    fn format_resource_name(&self, project: &str, profile: &str, key: &str) -> String {
        let template = self
            .config
            .name_template
            .as_deref()
            .unwrap_or("secretspec/{project}/{profile}/{key}");
        template
            .replace("{project}", project)
            .replace("{profile}", profile)
            .replace("{key}", key)
    }

    /// The Passbolt server address in effect: the URI's `?server=` (explicit in
    /// the provider spec) takes precedence over the ambient
    /// `SECRETSPEC_PASSBOLT_SERVER`. `None` leaves the CLI to use its own
    /// configured server.
    fn server_address(&self) -> Option<String> {
        self.config
            .server_address
            .clone()
            .or_else(|| std::env::var(ENV_SERVER).ok())
    }

    /// Resolves the CLI credentials from the URI and `SECRETSPEC_PASSBOLT_*`
    /// environment, reading process env once per invocation.
    fn cli_auth(&self) -> CliAuth {
        CliAuth {
            server: self.server_address(),
            key_file: std::env::var(ENV_PRIVATE_KEY_FILE).ok(),
            key_inline: std::env::var(ENV_PRIVATE_KEY).ok(),
            passphrase: std::env::var(ENV_PASSPHRASE).ok(),
        }
    }

    /// Builds a `passbolt` command with the resolved credentials applied, so
    /// every code path shells out consistently.
    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.cli_binary_path);
        self.cli_auth().apply(&mut cmd);
        cmd
    }

    /// Runs a `passbolt` invocation and returns its stdout, translating the two
    /// failure modes callers care about into helpful errors: a missing binary,
    /// and an unconfigured/unauthenticated CLI.
    fn run(&self, args: &[&str]) -> Result<String> {
        let output = match self
            .command()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(output) => output,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Passbolt CLI (passbolt) is not installed.\n\n\
                     Install go-passbolt-cli from https://github.com/passbolt/go-passbolt-cli, \
                     then configure it with 'passbolt configure --serverAddress https://... \
                     --userPrivateKeyFile key.asc --userPassword <passphrase>'."
                        .to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("is not defined") || stderr.contains("serverAddress") {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Passbolt CLI is not configured. Run 'passbolt configure --serverAddress \
                     https://... --userPrivateKeyFile key.asc --userPassword <passphrase>' \
                     (details: {})",
                    stderr.trim()
                )));
            }
            return Err(SecretSpecError::ProviderOperationFailed(stderr.to_string()));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))
    }

    /// Resolves a resource name to its id, scoped to the configured folder when
    /// set. Only metadata columns are requested, so no (expensive) secret
    /// decryption happens during the lookup. Returns the first match, or `None`
    /// when no resource carries that name.
    fn find_id_by_name(&self, name: &str) -> Result<Option<String>> {
        let mut args = vec![
            "list", "resource", "--json", "--column", "id", "--column", "name",
        ];
        if let Some(folder) = &self.config.folder_id {
            args.push("--folder");
            args.push(folder);
        }
        let output = self.run(&args)?;
        let resources: Vec<PassboltResource> = serde_json::from_str(&output)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))?;
        Ok(resources
            .into_iter()
            .find(|r| r.name.as_deref() == Some(name))
            .and_then(|r| r.id))
    }

    /// Resolves an `item` coordinate (a resource id or a resource name) to a
    /// concrete resource id, or `None` when a name matches nothing.
    fn resolve_id(&self, item: &str) -> Result<Option<String>> {
        if is_uuid(item) {
            Ok(Some(item.to_string()))
        } else {
            self.find_id_by_name(item)
        }
    }

    /// Fetches and decrypts a single resource by id, returning `None` when the
    /// resource no longer exists (mirroring how a missing convention secret
    /// reports absence).
    fn get_resource(&self, id: &str) -> Result<Option<PassboltResource>> {
        match self.run(&["get", "resource", "--id", id, "--json"]) {
            Ok(output) => serde_json::from_str::<PassboltResource>(&output)
                .map(Some)
                .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string())),
            Err(SecretSpecError::ProviderOperationFailed(msg)) if is_not_found(&msg) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The CLI flag that writes `field` on `create`/`update` (e.g. `password`
    /// -> `--password`). `field` is one of [`KNOWN_FIELDS`].
    fn field_flag(field: &str) -> String {
        format!("--{field}")
    }
}

/// Validates a `ref`'s `field` coordinate against the resource fields Passbolt
/// exposes ([`KNOWN_FIELDS`]), so a typo like `passwrd` fails loudly at
/// resolution instead of silently reading nothing. Returns the field on success.
fn validate_field(field: &str) -> Result<&str> {
    if KNOWN_FIELDS.contains(&field) {
        Ok(field)
    } else {
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "the passbolt provider has no `{field}` field; \
             ref `field` must be one of: {}",
            KNOWN_FIELDS.join(", ")
        )))
    }
}

/// Recognizes the CLI's "resource does not exist" failures so a missing secret
/// resolves to `Ok(None)` rather than an error. Passbolt surfaces this as an
/// HTTP 404 wrapped in the `getting resource:` context.
fn is_not_found(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("404")
        || lower.contains("not found")
        || lower.contains("does not exist")
        || lower.contains("could not find")
}

impl Provider for PassboltProvider {
    /// Convention secrets are named by the resource-name template,
    /// `secretspec/{project}/{profile}/{key}` by default, with the value in the
    /// `password` field (the default field, so it is left unset here).
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: self.format_resource_name(project, profile, key),
            ..Default::default()
        })
    }

    /// A `ref` may pin which resource `field` holds the value; the resource
    /// itself is named by `item` (an id or a name). Passbolt resources are not
    /// versioned and have no vault/section concept, so only `field` is honored.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        // Reconstructed from non-secret config only: the name template, folder
        // id, and server address. Credentials live in the CLI config, never in
        // the URI (enforced by `uri_never_echoes_a_userinfo_password`).
        let mut uri = match &self.config.name_template {
            Some(template) => format!("passbolt://{}", ProviderUrl::encode(template)),
            None => "passbolt".to_string(),
        };

        let mut query: Vec<String> = Vec::new();
        if let Some(folder) = &self.config.folder_id {
            query.push(format!("folder={}", ProviderUrl::encode_query(folder)));
        }
        if let Some(server) = &self.config.server_address {
            query.push(format!("server={}", ProviderUrl::encode_query(server)));
        }
        if !query.is_empty() {
            // A bare `passbolt` needs the `://` authority marker before a query.
            if !uri.contains("://") {
                uri.push_str("://");
            }
            uri.push('?');
            uri.push_str(&query.join("&"));
        }
        uri
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        let field = validate_field(coords.field.as_deref().unwrap_or(DEFAULT_FIELD))?;

        let Some(id) = self.resolve_id(&coords.item)? else {
            return Ok(None);
        };
        let Some(resource) = self.get_resource(&id)? else {
            return Ok(None);
        };
        Ok(resource
            .field(field)
            .map(|v| SecretString::new(v.into())))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let coords = self.resolve_coords(addr)?;
        let field = validate_field(coords.field.as_deref().unwrap_or(DEFAULT_FIELD))?;
        let flag = Self::field_flag(field);
        let secret = value.expose_secret();

        // Update the resource in place when it already exists (by id or by
        // resolved name); this is the path a human-provisioned resource takes.
        if let Some(id) = self.resolve_id(&coords.item)? {
            self.run(&["update", "resource", "--id", &id, &flag, secret])?;
            return Ok(());
        }

        // No such resource: create one. Only a name-addressed convention secret
        // reaches here — an id (`ref`) that resolves to nothing points at an
        // externally managed resource that must exist, so we refuse rather than
        // silently create a detached one.
        if is_uuid(&coords.item) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Passbolt resource '{}' does not exist; a ref must name an existing resource",
                coords.item
            )));
        }

        let mut args = vec!["create", "resource", "--name", &coords.item, &flag, secret];
        if let Some(folder) = &self.config.folder_id {
            args.push("--folderParentID");
            args.push(folder);
        }
        self.run(&args)?;
        Ok(())
    }
}

impl Default for PassboltProvider {
    fn default() -> Self {
        Self::new(PassboltConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn provider_url(s: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(s).unwrap())
    }

    fn config(s: &str) -> PassboltConfig {
        PassboltConfig::try_from(&provider_url(s)).unwrap()
    }

    #[test]
    fn is_uuid_recognizes_canonical_ids() {
        assert!(is_uuid("a9230ec4-5507-4870-b8b5-b3f500587e4c"));
        assert!(is_uuid("A9230EC4-5507-4870-B8B5-B3F500587E4C"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("secretspec/proj/default/KEY"));
        assert!(!is_uuid("a9230ec4-5507-4870-b8b5-b3f500587e4")); // too short
    }

    #[test]
    fn format_resource_name_default_and_custom() {
        let default = PassboltProvider::default();
        assert_eq!(
            default.format_resource_name("proj", "prod", "API_KEY"),
            "secretspec/proj/prod/API_KEY"
        );

        let custom = PassboltProvider::new(config("passbolt://vault/{profile}/{key}"));
        assert_eq!(
            custom.format_resource_name("proj", "prod", "API_KEY"),
            "vault/prod/API_KEY"
        );
    }

    #[test]
    fn try_from_parses_template_folder_and_server() {
        let c = config("passbolt://secretspec/{key}?folder=fid-123&server=https://pass.example.com");
        assert_eq!(c.name_template.as_deref(), Some("secretspec/{key}"));
        assert_eq!(c.folder_id.as_deref(), Some("fid-123"));
        assert_eq!(c.server_address.as_deref(), Some("https://pass.example.com"));
    }

    #[test]
    fn try_from_rejects_wrong_scheme() {
        let err = PassboltConfig::try_from(&provider_url("keyring://x")).unwrap_err();
        assert!(err.to_string().contains("Invalid scheme"));
    }

    #[test]
    fn uri_round_trips_default() {
        assert_eq!(PassboltProvider::default().uri(), "passbolt");
    }

    #[test]
    fn uri_round_trips_template_and_query() {
        for spec in [
            "passbolt://secretspec/{project}/{profile}/{key}",
            "passbolt://?folder=fid-123",
            "passbolt://?server=https://pass.example.com",
            "passbolt://vault/{key}?folder=fid-9&server=https://p.example.com",
        ] {
            let provider = PassboltProvider::new(config(spec));
            let uri = provider.uri();
            let reparsed = PassboltConfig::try_from(&provider_url(&uri))
                .unwrap_or_else(|e| panic!("uri {uri:?} failed to reparse: {e}"));
            let orig = config(spec);
            assert_eq!(reparsed.name_template, orig.name_template, "template {spec}");
            assert_eq!(reparsed.folder_id, orig.folder_id, "folder {spec}");
            assert_eq!(
                reparsed.server_address, orig.server_address,
                "server {spec}"
            );
        }
    }

    #[test]
    fn build_from_provider_registry() {
        let provider = Box::<dyn Provider>::try_from("passbolt").unwrap();
        assert_eq!(provider.name(), "passbolt");
        assert_eq!(provider.uri(), "passbolt");
    }

    #[test]
    fn resource_field_extracts_and_treats_empty_as_absent() {
        let r = PassboltResource {
            id: Some("id".into()),
            name: Some("n".into()),
            username: Some("user".into()),
            uri: None,
            password: Some("pw".into()),
            description: Some(String::new()),
        };
        assert_eq!(r.field("password").as_deref(), Some("pw"));
        assert_eq!(r.field("username").as_deref(), Some("user"));
        assert_eq!(r.field("uri"), None);
        assert_eq!(r.field("description"), None); // empty -> absent
    }

    /// A native address defaults to the `password` field and names the resource
    /// directly via `item`.
    #[test]
    fn convention_address_uses_default_field() {
        let p = PassboltProvider::default();
        let addr = p.convention_address("proj", "default", "KEY").unwrap();
        assert_eq!(addr.item, "secretspec/proj/default/KEY");
        assert_eq!(addr.field, None);
    }

    /// Passbolt resources have no vault concept; a `vault` coordinate is
    /// rejected while `field` is accepted.
    #[test]
    fn native_address_rejects_unsupported_coordinate() {
        let p = PassboltProvider::default();
        let ok = crate::config::NativeAddress {
            item: "My API Key".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        assert!(p.resolve_coords(Address::Native(&ok)).is_ok());

        let bad = crate::config::NativeAddress {
            item: "My API Key".into(),
            vault: Some("Personal".into()),
            ..Default::default()
        };
        let err = p.resolve_coords(Address::Native(&bad)).unwrap_err();
        assert!(err.to_string().contains("`vault`"), "{err}");
    }

    #[test]
    fn validate_field_accepts_known_and_rejects_unknown() {
        assert_eq!(validate_field("password").unwrap(), "password");
        assert_eq!(validate_field("uri").unwrap(), "uri");
        let err = validate_field("passwrd").unwrap_err();
        assert!(err.to_string().contains("no `passwrd` field"), "{err}");
    }

    /// Collects a Command's args and envs so `CliAuth::apply` can be asserted
    /// without touching the process environment.
    fn command_args_envs(auth: &CliAuth) -> (Vec<String>, Vec<(String, String)>) {
        let mut cmd = Command::new("passbolt");
        auth.apply(&mut cmd);
        let args = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let envs = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_string_lossy().into_owned(), v?.to_string_lossy().into_owned())))
            .collect();
        (args, envs)
    }

    #[test]
    fn cli_auth_puts_nonsecrets_on_argv_and_secrets_in_env() {
        let auth = CliAuth {
            server: Some("https://pass.example.com".into()),
            key_file: Some("/keys/ada.asc".into()),
            key_inline: None,
            passphrase: Some("s3cr3t".into()),
        };
        let (args, envs) = command_args_envs(&auth);

        // Server address and key-file path are non-secret -> reliable flags.
        assert!(args.windows(2).any(|w| w == ["--serverAddress", "https://pass.example.com"]));
        assert!(args.windows(2).any(|w| w == ["--userPrivateKeyFile", "/keys/ada.asc"]));

        // The passphrase must NOT appear on the argv (world-readable via `ps`);
        // it is passed to the child via the env name the CLI reads.
        assert!(!args.iter().any(|a| a.contains("s3cr3t")), "passphrase leaked to argv: {args:?}");
        assert!(envs.contains(&("USERPASSWORD".into(), "s3cr3t".into())));
    }

    #[test]
    fn cli_auth_inline_key_goes_to_env_and_yields_to_key_file() {
        // Inline key alone -> env USERPRIVATEKEY, never argv.
        let inline = CliAuth {
            server: None,
            key_file: None,
            key_inline: Some("-----BEGIN PGP PRIVATE KEY-----".into()),
            passphrase: None,
        };
        let (args, envs) = command_args_envs(&inline);
        assert!(args.is_empty(), "inline key must not reach argv: {args:?}");
        assert!(envs.iter().any(|(k, _)| k == "USERPRIVATEKEY"));

        // A key file takes precedence over an inline key (matches CLI behaviour).
        let both = CliAuth {
            key_file: Some("/keys/ada.asc".into()),
            key_inline: Some("inline".into()),
            ..inline
        };
        let (args, envs) = command_args_envs(&both);
        assert!(args.windows(2).any(|w| w == ["--userPrivateKeyFile", "/keys/ada.asc"]));
        assert!(!envs.iter().any(|(k, _)| k == "USERPRIVATEKEY"));
    }

    #[test]
    fn cli_auth_empty_adds_nothing() {
        let (args, envs) = command_args_envs(&CliAuth {
            server: None,
            key_file: None,
            key_inline: None,
            passphrase: None,
        });
        assert!(args.is_empty() && envs.is_empty());
    }

    /// The URI's `?server=` takes precedence over the ambient env var.
    #[test]
    fn server_address_prefers_uri_over_env() {
        let p = PassboltProvider::new(config("passbolt://?server=https://uri.example.com"));
        assert_eq!(
            p.server_address().as_deref(),
            Some("https://uri.example.com")
        );
    }

    #[test]
    fn is_not_found_matches_cli_errors() {
        assert!(is_not_found("getting resource: 404 Not Found"));
        assert!(is_not_found("The resource does not exist"));
        assert!(!is_not_found("some other failure"));
    }
}
