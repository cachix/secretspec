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
//! Recipient parsing and identity resolution both go through age's plugin
//! system, so plugin keys such as the ML-KEM/X25519 (X-Wing) `age1pq1...`
//! recipients work when their `age-plugin-*` binary is on `PATH`.

use super::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env, flat_item};
use crate::config::{NativeAddress, Secret};
use crate::{Result, SecretSpecError};
use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::{Decryptor, Encryptor, Identity, IdentityFile, NoCallbacks, Recipient};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Semantic credential name for the age identity
const IDENTITY: &str = "identity";
/// Environment variable fallback for the age identity material
const AGE_IDENTITY_ENV: &str = "AGE_IDENTITY";

fn provider_err(msg: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(msg.into())
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

    /// Parses the configured identity file from credential, env, or path
    fn identity_file(&self) -> Result<IdentityFile<NoCallbacks>> {
        if let Some(material) = credential_or_env(&self.credentials, IDENTITY, AGE_IDENTITY_ENV) {
            return IdentityFile::from_buffer(std::io::Cursor::new(material.into_bytes()))
                .map(|f| f.with_callbacks(NoCallbacks))
                .map_err(|e| provider_err(format!("Failed to parse age identity: {}", e)));
        }
        if let Some(path) = &self.config.identity_path {
            return IdentityFile::from_file(path.display().to_string())
                .map(|f| f.with_callbacks(NoCallbacks))
                .map_err(|e| {
                    provider_err(format!(
                        "Failed to read age identity file {}: {}",
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
            None => self.identity_file()?.to_recipients().map_err(|e| {
                provider_err(format!("Failed to derive recipient from identity: {}", e))
            }),
        }
    }

    /// Reads and decrypts the blob into a flat key/value map
    fn load(&self) -> Result<HashMap<String, String>> {
        if !self.config.path.exists() {
            return Ok(HashMap::new());
        }
        let ciphertext = std::fs::read(&self.config.path)?;
        let identities = self
            .identity_file()?
            .into_identities()
            .map_err(|e| provider_err(format!("Failed to load age identities: {}", e)))?;

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

/// Parses one recipient string as x25519, ssh, or a plugin recipient
fn parse_recipient(s: &str) -> Result<Box<dyn Recipient + Send>> {
    if let Ok(r) = s.parse::<age::x25519::Recipient>() {
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
        format!("age:{}", self.config.path.display())
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
}
