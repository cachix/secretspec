//! Provider that stores secrets in a single [age](https://age-encryption.org)
//! encrypted file.
//!
//! The file is an encrypted dotenv blob whose plaintext is `KEY=value` lines
//! encrypted to one or more age recipients. A read decrypts the whole blob with
//! the configured identity. A write decrypts it, updates one key, and
//! re-encrypts the whole blob to the current recipients.
//!
//! # URI format
//!
//! - `age://<path>` -- the encrypted blob file
//! - `?identity=<path>` -- identity file, one of the identity sources
//! - `?recipients-file=<path>` -- roster of recipient public keys; absent means
//!   solo mode (encrypt to your own identity)
//! - `?armor=false` -- write a binary blob instead of the default ASCII armor
//!
//! # Identity
//!
//! The private key is resolved from the `identity` provider credential, then
//! the `AGE_IDENTITY` environment variable, then `?identity=`.
//! X25519 and SSH identities are supported directly. Non-interactive plugin
//! keys also work when their `age-plugin-*` binary is on `PATH`, including the
//! ML-KEM-768 + X25519 `age1pq1...` recipient via `age-plugin-pq`.

use super::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env, flat_item};
use crate::config::{NativeAddress, Secret};
use crate::{Result, SecretSpecError};
use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::{Decryptor, Encryptor, Identity, IdentityFile, NoCallbacks, Recipient};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

/// Semantic credential name for the age identity
const IDENTITY: &str = "identity";
/// Environment variable fallback for the age identity material
const AGE_IDENTITY_ENV: &str = "AGE_IDENTITY";

fn provider_err(msg: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(msg.into())
}

/// An identity source after distinguishing multi-line SSH private keys from
/// age's one-identity-per-line file format.
enum ParsedIdentity {
    Age(IdentityFile<NoCallbacks>),
    Ssh(age::ssh::Identity),
}

impl ParsedIdentity {
    fn to_recipients(&self) -> Result<Vec<Box<dyn Recipient + Send>>> {
        match self {
            Self::Age(identity_file) => identity_file.to_recipients().map_err(|e| {
                provider_err(format!("Failed to derive recipient from identity: {}", e))
            }),
            Self::Ssh(identity) => age::ssh::Recipient::try_from(identity.clone())
                .map(|recipient| vec![Box::new(recipient) as Box<dyn Recipient + Send>])
                .map_err(|e| {
                    provider_err(format!(
                        "Failed to derive age recipient from SSH identity: {:?}",
                        e
                    ))
                }),
        }
    }

    fn into_identities(self) -> Result<Vec<Box<dyn Identity + Send + Sync>>> {
        match self {
            Self::Age(identity_file) => identity_file
                .into_identities()
                .map_err(|e| provider_err(format!("Failed to load age identities: {}", e))),
            Self::Ssh(identity) => Ok(vec![Box::new(identity.with_callbacks(NoCallbacks))]),
        }
    }
}

/// SSH private keys are multi-line files, while native and plugin age
/// identities are one-per-line. Try the SSH format first because
/// `IdentityFile` intentionally does not parse it.
fn parse_identity(data: &[u8], filename: Option<String>) -> std::io::Result<ParsedIdentity> {
    if let Ok(identity) = age::ssh::Identity::from_buffer(Cursor::new(data), filename) {
        return Ok(ParsedIdentity::Ssh(identity));
    }

    IdentityFile::from_buffer(Cursor::new(data)).map(ParsedIdentity::Age)
}

/// Configuration for the age provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeConfig {
    /// Path to the encrypted blob file
    pub path: PathBuf,
    /// Identity file path, used when no credential or env identity is set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_path: Option<PathBuf>,
    /// Roster of recipient public keys for team mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipients_file: Option<PathBuf>,
    /// Whether to write ASCII-armored output
    pub armor: bool,
}

impl Default for AgeConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("secrets.age"),
            identity_path: None,
            recipients_file: None,
            armor: true,
        }
    }
}

impl TryFrom<&ProviderUrl> for AgeConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "age" {
            return Err(provider_err(format!(
                "Invalid scheme '{}' for age provider",
                url.scheme()
            )));
        }

        // Accept both `age://path` (authority) and `age:///abs/path` forms
        let path_str = url.path();
        let path = if !path_str.is_empty() && path_str != "/" {
            match url.host() {
                Some(host) => format!("{}{}", host, path_str),
                None => path_str,
            }
        } else if let Some(host) = url.host() {
            host
        } else {
            "secrets.age".to_string()
        };

        Ok(Self {
            path: PathBuf::from(path),
            identity_path: url.query_value("identity").map(PathBuf::from),
            recipients_file: url.query_value("recipients-file").map(PathBuf::from),
            armor: url
                .query_value("armor")
                .map(|v| v != "false")
                .unwrap_or(true),
        })
    }
}

/// Provider that reads and writes an age-encrypted dotenv blob.
pub struct AgeProvider {
    config: AgeConfig,
    credentials: ProviderCredentials,
}

crate::register_provider! {
    struct: AgeProvider,
    config: AgeConfig,
    name: "age",
    description: "age-encrypted file",
    schemes: ["age"],
    examples: ["age://secrets.age", "age://secrets.age?recipients-file=secrets.age.recipients"],
    credential_names: ["identity"],
}

impl AgeProvider {
    pub fn new(config: AgeConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
        }
    }

    /// Parses the configured identity from credential, env, or path.
    fn identity(&self) -> Result<ParsedIdentity> {
        if let Some(material) = credential_or_env(&self.credentials, IDENTITY, AGE_IDENTITY_ENV) {
            return parse_identity(material.as_bytes(), None)
                .map_err(|e| provider_err(format!("Failed to parse age identity: {}", e)));
        }
        if let Some(path) = &self.config.identity_path {
            let data = std::fs::read(path).map_err(|e| {
                provider_err(format!(
                    "Failed to read age identity file {}: {}",
                    path.display(),
                    e
                ))
            })?;
            return parse_identity(&data, Some(path.display().to_string())).map_err(|e| {
                provider_err(format!(
                    "Failed to parse age identity file {}: {}",
                    path.display(),
                    e
                ))
            });
        }
        Err(provider_err(
            "No age identity configured. Set the `identity` credential, the \
             AGE_IDENTITY environment variable, or ?identity=<path> in the URI.",
        ))
    }

    /// Resolves recipients from the roster file, or the identity in solo mode
    fn recipients(&self) -> Result<Vec<Box<dyn Recipient + Send>>> {
        match &self.config.recipients_file {
            Some(path) => parse_recipients_file(path),
            None => self.identity()?.to_recipients(),
        }
    }

    /// Reads and decrypts the blob into a flat key/value map
    fn load(&self) -> Result<HashMap<String, String>> {
        if !self.config.path.exists() {
            return Ok(HashMap::new());
        }
        let ciphertext = std::fs::read(&self.config.path)?;
        let identities = self.identity()?.into_identities()?;

        let reader = ArmoredReader::new(&ciphertext[..]);
        let decryptor = Decryptor::new(reader)
            .map_err(|e| provider_err(format!("Failed to read age file: {}", e)))?;
        let mut plaintext = Vec::new();
        decryptor
            .decrypt(identities.iter().map(|i| i.as_ref() as &dyn Identity))
            .map_err(|e| provider_err(format!("Failed to decrypt age file: {}", e)))?
            .read_to_end(&mut plaintext)?;

        parse_dotenv(&plaintext)
    }

    /// Re-encrypts a full key/value map to the current recipients
    fn store(&self, vars: &HashMap<String, String>) -> Result<()> {
        let plaintext = super::dotenv::serialize_dotenv(vars);
        let recipients = self.recipients()?;
        let encryptor =
            Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn Recipient))
                .map_err(|e| provider_err(format!("No age recipients available: {}", e)))?;

        let mut out = Vec::new();
        let format = if self.config.armor {
            Format::AsciiArmor
        } else {
            Format::Binary
        };
        let armored = ArmoredWriter::wrap_output(&mut out, format)?;
        let mut writer = encryptor
            .wrap_output(armored)
            .map_err(|e| provider_err(format!("Failed to encrypt age file: {}", e)))?;
        writer.write_all(plaintext.as_bytes())?;
        writer
            .finish()
            .map_err(|e| provider_err(format!("Failed to finish age stream: {}", e)))?
            .finish()?;

        std::fs::write(&self.config.path, out)?;
        Ok(())
    }
}

/// Parses decrypted dotenv content into a flat map
fn parse_dotenv(plaintext: &[u8]) -> Result<HashMap<String, String>> {
    let mut vars = HashMap::new();
    for item in dotenvy::from_read_iter(plaintext) {
        let (key, value) =
            item.map_err(|e| provider_err(format!("Failed to parse decrypted content: {}", e)))?;
        vars.insert(key, value);
    }
    Ok(vars)
}

/// Reads a roster file into recipients, skipping comments and blank lines
fn parse_recipients_file(path: &Path) -> Result<Vec<Box<dyn Recipient + Send>>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        provider_err(format!(
            "Failed to read recipients file {}: {}",
            path.display(),
            e
        ))
    })?;

    let mut recipients: Vec<Box<dyn Recipient + Send>> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        recipients.push(parse_recipient(line)?);
    }

    if recipients.is_empty() {
        return Err(provider_err(format!(
            "Recipients file {} contains no recipients",
            path.display()
        )));
    }
    Ok(recipients)
}

/// Parses one recipient string in the same order as age's recipients-file
/// parser. Native tagged recipients must precede the generic plugin syntax
/// because `age1tag...` would otherwise be treated as `age-plugin-tag`.
fn parse_recipient(s: &str) -> Result<Box<dyn Recipient + Send>> {
    if let Ok(r) = s.parse::<age::x25519::Recipient>() {
        return Ok(Box::new(r));
    }
    if let Ok(r) = s.parse::<age::tag::Recipient>() {
        return Ok(Box::new(r));
    }
    if let Ok(r) = s.parse::<age::tagpq::Recipient>() {
        return Ok(Box::new(r));
    }
    if let Ok(r) = s.parse::<age::ssh::Recipient>() {
        return Ok(Box::new(r));
    }
    if let Ok(r) = s.parse::<age::plugin::Recipient>() {
        let plugin_name = r.plugin().to_string();
        let plugin = age::plugin::RecipientPluginV1::new(&plugin_name, &[r], &[], NoCallbacks)
            .map_err(|e| {
                provider_err(format!("age plugin '{}' unavailable: {:?}", plugin_name, e))
            })?;
        return Ok(Box::new(plugin));
    }
    Err(provider_err(format!("Unrecognized age recipient: {}", s)))
}

impl Provider for AgeProvider {
    /// Convention names map straight to the key inside the encrypted blob
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        key: &str,
    ) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: key.to_string(),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = format!("age:{}", self.config.path.display());
        let mut query = Vec::new();

        // Identity sources are deliberately omitted because they are private
        // configuration. Recipient rosters and output format are non-secret
        // and must survive audit/report URI reconstruction.
        if let Some(path) = &self.config.recipients_file {
            query.push(format!(
                "recipients-file={}",
                ProviderUrl::encode_query(&path.display().to_string())
            ));
        }
        if !self.config.armor {
            query.push("armor=false".to_string());
        }
        if !query.is_empty() {
            uri.push('?');
            uri.push_str(&query.join("&"));
        }

        uri
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    /// Resolves relative paths against the project root, like the dotenv provider
    fn with_base_dir(&mut self, base_dir: &Path) {
        if self.config.path.is_relative() {
            self.config.path = base_dir.join(&self.config.path);
        }
        if let Some(path) = &self.config.identity_path
            && path.is_relative()
        {
            self.config.identity_path = Some(base_dir.join(path));
        }
        if let Some(path) = &self.config.recipients_file
            && path.is_relative()
        {
            self.config.recipients_file = Some(base_dir.join(path));
        }
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let key = flat_item(self, addr)?;
        Ok(self
            .load()?
            .get(&*key)
            .map(|v| SecretString::new(v.clone().into())))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let key = flat_item(self, addr)?.into_owned();
        let mut vars = self.load()?;
        vars.insert(key, value.expose_secret().to_string());
        self.store(&vars)
    }

    /// Decrypts the blob once and serves every requested key from it
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        let vars = self.load()?;
        let mut out = HashMap::new();
        for (name, addr) in requests {
            let key = flat_item(self, *addr)?;
            if let Some(value) = vars.get(&*key) {
                out.insert(name.to_string(), SecretString::new(value.clone().into()));
            }
        }
        Ok(out)
    }

    fn reflect(&self) -> Result<HashMap<String, Secret>> {
        Ok(self
            .load()?
            .into_keys()
            .map(|key| {
                let secret = Secret {
                    description: Some(format!("{} secret", key)),
                    required: Some(true),
                    ..Default::default()
                };
                (key, secret)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    // Throwaway x25519 identity used only by these tests
    const TEST_IDENTITY: &str = concat!(
        "# public key: age1rcq2v5ckqn2r538m8qxz0xhx2am83zhxr60yfvmlsugkt6tygpcss829at\n",
        "AGE-SECRET-KEY-15SFU79V44S2N3G4HKMG578KN5VXWM4GNLZUWVLY2Z8ENUPUCNWXQPQ5X33\n",
    );
    const TEST_RECIPIENT: &str = "age1rcq2v5ckqn2r538m8qxz0xhx2am83zhxr60yfvmlsugkt6tygpcss829at";
    const TEST_SSH_IDENTITY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----";
    const TEST_SSH_RECIPIENT: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";
    const TEST_TAG_RECIPIENT: &str =
        "age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e";
    const TEST_TAGPQ_RECIPIENT: &str = concat!(
        "age1tagpq1m3e4wvp6hzcrn9exhy0ae3xfx2sjymp594k3tg7j4dpmj922we65vtnmrt2pyallax8669zqkr2pmfchp",
        "tr4n38kug2xmcmp3adk2lnjqu00x5kxz5pvhmrltvfh9wuq973pcx35cnq8syn9qd3tzpehgztl4xpzr3tpd67g8af9trnjpc05g",
        "h7wu536aq4qt2y8zhsm4tvrfpsfl36qs5fpzysnk3sp9w77qzeg49357xex40v4s2lvt620swyys7u8yxdcnu4rkkwxdmt55gsuc",
        "3h5c5swahnegjgqwc60hn085ec3sjztwm45l44y3j2at9t6v9zra4ek3kek6waecqm98yaxl37w0d2zra626nz63jdm5sg59w7ly",
        "ptw83zm6fntd8d0x03a9z6h9prfgpygzar6zrxjcrt4cdctk2mhf95s4a6v4zklfd49xhpsaeujm57thx2x3e3hwzc86ftfhmq5m",
        "kxxz3d6r8ws24xj4qfn73eyezg2wy094e3why592pghz27ruq3vkyegrv80eftnw9wqzwgvnwyseaus0yt84fylzrpzp6x2fguxu",
        "qjmgudr8xd33qm30evdpxd3jvjg8qh4q60kyq80jgff369k7nrepdc38grd2dava520excqp0ey0x39khx8ry03yffcatgv84fsx",
        "5j49djpapedsy693zute5xv5g2ewzrlj5se7akvkc4g4vmzhputpq8eyj9wz5dz6qtn7g3cfpd95nahw4ytspan0feyye04dcylv",
        "24ege7zkaj004gjwcxqxfqu2quawa83sx452jqjn8t48czp0xspwgnmvjyhttzzy6nhq8xzkdwnvsfefkwva6asrqc93zjn4rly5",
        "gnlv93xy3uzmr39szvjnf63426qzyeyvguc4vdcquwgsxgq236afcpqz866ny4tn7ckc0umefj242rt5vtvwqzzrvfev2mpvqcuf",
        "p9pqvefyv4ftyuhgausfzuaadsczeykmft5wv3frzgrcp9ztr93h478ke4t86spp2uhyjkj73mp9g92ddk2fpv7v3njzsqgwhq37",
        "89sqrgkskehn0zjscckhwftyq4vet7vrlx2hs5kd9cwnq6t0djffhh3zquh4j3p0yaj9z2rc9wykg0usqw7983rrgur9jg8rnnqy",
        "pwcz2lyclnnc705fc5g3an93ps60q6mxqp85u0ewtxdjlqcks84yduft0a0g6e7naew3v9u2d08knarvajn8q3gq9pgxde3s7nx9",
        "4lus48wwvw2xjm7k82tvylec2393jdsuvch2xpe77w8hpv9nvsxfsrs270njpmfvpmgyk2cffl9tjp3qqcc4dfkf5rme2dg0x7ew",
        "8g39www5smm705q5da4eqvnqwrkavtq6xje9ss38hnkglz4eddz8f5qruvqmq2ff9l22gwkv8h432rdkysy0grkul8e2fedvkyya",
        "pfxt760udcgu92m54wl9yavmj4ga3ph9r5n99cjrq6wj5v33x33fe5vkjvfwnnt40wuv2hyexc9f4ylyqv9ldqq9epd4yuv8vrsf",
        "x2qy2kqz08kqhnzspy6s0x8fa5c2xkg5y2q0rvz4vnk7rp0acg6eksc3t7cxnn8y7glkjsqja3p56uz6vvhcw55d3ysad0hvsqxp",
        "jnc7svenf2gc5xn5kyr0et2vvyruxlnpqcdpqh9pzplumy5yzjxftyzh9ujfw0jq7ee60zx2x23p0jzyh9dvmly8p9h9ysptlqu7",
        "kwnejd65dnr75a0np2fvke8xen38r57w6z3wz3mycjmmn267wwxndfh9jdps7uxtct2wwfgamkpa5ap8s96lhfjztpwcm6fguhph",
        "u38yunu2v4vz3syzrvgwtqpemkewzp766nyu6texxvjlaemnhyyqutkcy6a42vqfsz49rw5wr4gt70r4vdaasehqjg46fnyts4st",
        "hrxadfllha3avu49wsj2c4jx",
    );

    fn config_from(uri: &str) -> AgeConfig {
        let url = ProviderUrl::new(Url::parse(uri).unwrap());
        (&url).try_into().unwrap()
    }

    #[test]
    fn parses_uri_forms() {
        let c = config_from("age://secrets.age");
        assert_eq!(c.path.to_str().unwrap(), "secrets.age");
        assert!(c.identity_path.is_none());
        assert!(c.recipients_file.is_none());
        assert!(c.armor);

        let c = config_from("age:///abs/secrets.age");
        assert_eq!(c.path.to_str().unwrap(), "/abs/secrets.age");

        let c =
            config_from("age://dir/secrets.age?identity=k.txt&recipients-file=r.txt&armor=false");
        assert_eq!(c.path.to_str().unwrap(), "dir/secrets.age");
        assert_eq!(c.identity_path.unwrap().to_str().unwrap(), "k.txt");
        assert_eq!(c.recipients_file.unwrap().to_str().unwrap(), "r.txt");
        assert!(!c.armor);
    }

    #[test]
    fn base_dir_rebases_relative_paths() {
        let base = Path::new("/project/root");
        let mut provider = AgeProvider::new(AgeConfig {
            path: PathBuf::from("secrets.age"),
            identity_path: Some(PathBuf::from("key.txt")),
            recipients_file: Some(PathBuf::from("roster.recipients")),
            armor: true,
        });
        provider.with_base_dir(base);
        assert_eq!(provider.config.path, base.join("secrets.age"));
        assert_eq!(provider.config.identity_path.unwrap(), base.join("key.txt"));
        assert_eq!(
            provider.config.recipients_file.unwrap(),
            base.join("roster.recipients")
        );
    }

    #[test]
    fn parse_recipient_rejects_garbage() {
        assert!(parse_recipient("not-an-age-recipient").is_err());
    }

    #[test]
    fn parses_native_tagged_recipients_without_plugins() {
        for encoded in [TEST_TAG_RECIPIENT, TEST_TAGPQ_RECIPIENT] {
            let recipient = parse_recipient(encoded).unwrap();
            let encryptor =
                Encryptor::with_recipients(std::iter::once(recipient.as_ref() as &dyn Recipient))
                    .unwrap();
            let mut ciphertext = Vec::new();
            let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
            writer.write_all(b"tagged recipient").unwrap();
            writer.finish().unwrap();
            assert!(!ciphertext.is_empty());
        }
    }

    #[test]
    fn reported_uri_preserves_non_secret_options() {
        let provider = AgeProvider::new(AgeConfig {
            path: PathBuf::from("secrets.age"),
            identity_path: Some(PathBuf::from("/private/identity.txt")),
            recipients_file: Some(PathBuf::from("team &+ roster.txt")),
            armor: false,
        });

        let uri = provider.uri();
        assert_eq!(
            uri,
            "age:secrets.age?recipients-file=team%20%26%2B%20roster.txt&armor=false"
        );
        assert!(!uri.contains("identity"));

        let reparsed = config_from(&uri);
        assert_eq!(
            reparsed.recipients_file,
            Some(PathBuf::from("team &+ roster.txt"))
        );
        assert!(!reparsed.armor);
    }

    fn write_identity(dir: &Path) -> PathBuf {
        let key = dir.join("key.txt");
        std::fs::write(&key, TEST_IDENTITY).unwrap();
        key
    }

    #[test]
    fn solo_round_trip_preserves_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_identity(dir.path());
        let provider = AgeProvider::new(AgeConfig {
            path: dir.path().join("secrets.age"),
            identity_path: Some(key),
            recipients_file: None,
            armor: true,
        });

        let addr = |k| Address::convention("proj", "default", k);
        provider
            .set(
                addr("API_KEY"),
                &SecretString::new("sekret".to_string().into()),
            )
            .unwrap();

        let bytes = std::fs::read(&provider.config.path).unwrap();
        assert!(bytes.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));

        provider
            .set(addr("OTHER"), &SecretString::new("two".to_string().into()))
            .unwrap();

        assert_eq!(
            provider
                .get(addr("API_KEY"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "sekret"
        );
        assert_eq!(
            provider
                .get(addr("OTHER"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "two"
        );
        assert!(provider.get(addr("MISSING")).unwrap().is_none());
    }

    #[test]
    fn armor_false_writes_binary_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_identity(dir.path());
        let provider = AgeProvider::new(AgeConfig {
            path: dir.path().join("secrets.age"),
            identity_path: Some(key),
            recipients_file: None,
            armor: false,
        });
        let addr = Address::convention("proj", "default", "API_KEY");
        provider
            .set(addr, &SecretString::new("bin".to_string().into()))
            .unwrap();

        let bytes = std::fs::read(&provider.config.path).unwrap();
        assert!(!bytes.starts_with(b"-----BEGIN"));
        assert_eq!(provider.get(addr).unwrap().unwrap().expose_secret(), "bin");
    }

    #[test]
    fn team_recipients_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_identity(dir.path());
        let roster = dir.path().join("roster.recipients");
        std::fs::write(&roster, format!("# team\n{}\n", TEST_RECIPIENT)).unwrap();

        let provider = AgeProvider::new(AgeConfig {
            path: dir.path().join("team.age"),
            identity_path: Some(key),
            recipients_file: Some(roster),
            armor: true,
        });
        let addr = Address::convention("proj", "default", "API_KEY");
        provider
            .set(addr, &SecretString::new("teamsecret".to_string().into()))
            .unwrap();
        assert_eq!(
            provider.get(addr).unwrap().unwrap().expose_secret(),
            "teamsecret"
        );
    }

    #[test]
    fn ssh_identity_and_recipient_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let roster = dir.path().join("roster.recipients");
        std::fs::write(&roster, format!("{}\n", TEST_SSH_RECIPIENT)).unwrap();

        let mut provider = AgeProvider::new(AgeConfig {
            path: dir.path().join("ssh.age"),
            identity_path: None,
            recipients_file: Some(roster),
            armor: true,
        });
        let mut credentials = ProviderCredentials::new();
        credentials.insert(
            IDENTITY.to_string(),
            SecretString::new(TEST_SSH_IDENTITY.to_string().into()),
        );
        provider.with_credentials(credentials);

        let addr = Address::convention("proj", "default", "API_KEY");
        provider
            .set(addr, &SecretString::new("ssh-secret".to_string().into()))
            .unwrap();

        assert_eq!(
            provider.get(addr).unwrap().unwrap().expose_secret(),
            "ssh-secret"
        );
    }
}
