use crate::{
    Result, SecretSpecError,
    provider::{
        ProviderUrl,
        sops::{
            SopsFormat,
            SopsMode::{self},
            fields::{PATHBUF_FIELDS, STRING_FIELDS},
            pattern::SopsPathPattern,
        },
    },
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SopsConfig {
    // Set by Provider::with_base_dir
    pub base_dir: Option<std::path::PathBuf>,

    pub format: SopsFormat,
    pub mode: SopsMode,

    // SOPS settings
    pub sops_config: Option<PathBuf>,
    pub sops_decryption_order: Option<String>,
    pub sops_editor: Option<String>,
    pub sops_enable_local_keyservice: Option<String>,
    pub sops_keyservice: Option<String>,

    // Age configuration
    pub age_key_file: Option<PathBuf>,
    pub age_key_cmd: Option<String>,
    pub age_recipients: Option<String>,
    pub age_ssh_private_key_file: Option<PathBuf>,
    pub age_ssh_private_key_cmd: Option<String>,

    // AWS KMS configuration
    pub aws_access_key_id: Option<String>,
    pub aws_profile: Option<String>,
    pub aws_region: Option<String>,
    pub kms_arn: Option<String>,

    // Azure configuration
    pub azure_client_id: Option<String>,
    pub azure_tenant_id: Option<String>,
    pub azure_keyvault_urls: Option<String>,

    // GCP configuration
    pub gcp_kms_client_type: Option<String>,
    pub gcp_kms_endpoint: Option<String>,
    pub gcp_kms_ids: Option<String>,
    pub gcp_kms_universe_domain: Option<String>,

    // PGP configuration
    pub pgp_fp: Option<String>,

    // GPG configuration
    pub gpg_exec: Option<String>,

    // HashiCorp Vault/OpenBao configuration
    pub hc_vault_addr: Option<String>,
    pub hc_vault_allowlist: Option<String>,

    // Huawei Cloud KMS
    pub huawei_sdk_project_id: Option<String>,
    pub huawei_kms_ids: Option<String>,
}

impl Default for SopsConfig {
    fn default() -> Self {
        Self {
            age_key_cmd: None,
            age_key_file: None,
            age_recipients: None,
            age_ssh_private_key_cmd: None,
            age_ssh_private_key_file: None,
            aws_access_key_id: None,
            aws_profile: None,
            aws_region: None,
            azure_client_id: None,
            azure_keyvault_urls: None,
            azure_tenant_id: None,
            base_dir: None,
            format: SopsFormat::default(),
            gcp_kms_client_type: None,
            gcp_kms_endpoint: None,
            gcp_kms_ids: None,
            gcp_kms_universe_domain: None,
            gpg_exec: None,
            hc_vault_addr: None,
            hc_vault_allowlist: None,
            huawei_kms_ids: None,
            huawei_sdk_project_id: None,
            kms_arn: None,
            mode: SopsMode::Uninitialized,
            pgp_fp: None,
            sops_config: None,
            sops_decryption_order: None,
            sops_editor: None,
            sops_enable_local_keyservice: None,
            sops_keyservice: None,
        }
    }
}

fn split_template_path(path: &str) -> (PathBuf, String) {
    match path.find('{') {
        None => (PathBuf::from(path), String::new()),
        Some(idx) => {
            let prefix = &path[..idx];
            match prefix.rfind(['/', '\\']) {
                Some(separator) => (
                    PathBuf::from(&path[..separator]),
                    path[separator + 1..].to_string(),
                ),
                None => (PathBuf::new(), path.to_string()),
            }
        }
    }
}

fn infer_format(path: &str) -> Result<SopsFormat> {
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Cannot infer the SOPS format from '{path}'. Add a supported extension \
                 (.yaml, .yml, .json, .env, .dotenv, or .ini) or set ?format=."
            ))
        })?;

    SopsFormat::from_str(extension)
}

impl TryFrom<&ProviderUrl> for SopsConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "sops" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for SOPS provider",
                url.scheme()
            )));
        }

        let mut target_path = PathBuf::new();

        if let Some(host) = url.host()
            && host != "localhost"
            && !host.is_empty()
        {
            target_path.push(host);
        }

        let url_path = url.path();

        if !url_path.is_empty() && url_path != "/" {
            let path_part = if target_path.as_os_str().is_empty() {
                url_path.as_str()
            } else {
                url_path.trim_start_matches('/')
            };

            if !path_part.is_empty() {
                target_path.push(path_part);
            }
        }

        if target_path.as_os_str().is_empty() {
            target_path = PathBuf::from("secrets.enc.yaml");
        }

        let raw_path = target_path.to_string_lossy().to_string();

        let mut config = SopsConfig::default();

        let mut explicit_format: Option<SopsFormat> = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "format" => {
                    explicit_format = Some(SopsFormat::from_str(value.as_ref()).map_err(|e| {
                        SecretSpecError::ProviderOperationFailed(format!(
                            "Invalid format parameter: {}",
                            e
                        ))
                    })?);
                }
                other => {
                    if let Err(e) = config.apply_query_parameter(other, value.as_ref()) {
                        return Err(e);
                    }
                }
            }
        }

        let (dir_path, pattern) = split_template_path(&raw_path);

        let format = match explicit_format {
            Some(format) => format,
            None => infer_format(&raw_path)?,
        };

        // SOPS does not accept `--input-type ini`. An INI override can only be
        // honored when the file itself has an INI extension and SOPS can infer
        // the store from that extension.
        if explicit_format == Some(SopsFormat::Ini) && infer_format(&raw_path)? != SopsFormat::Ini {
            return Err(SecretSpecError::ProviderOperationFailed(
                "SOPS cannot override a non-INI filename with ?format=ini; use a .ini filename"
                    .to_string(),
            ));
        }

        let mode = if pattern.is_empty() {
            SopsMode::SingleFile(PathBuf::from(raw_path))
        } else {
            SopsMode::Directory {
                path: dir_path,
                pattern: SopsPathPattern::try_from(pattern)?,
                format,
            }
        };

        Ok(SopsConfig {
            format,
            mode,
            ..config
        })
    }
}

impl SopsConfig {
    pub fn apply_env(&self, cmd: &mut std::process::Command) {
        for spec in STRING_FIELDS {
            if let Some(v) = (spec.field)(self) {
                cmd.env(spec.env_key, v);
            }
        }

        for spec in PATHBUF_FIELDS {
            if let Some(v) = (spec.field)(self) {
                cmd.env(spec.env_key, self.rebase_path(v.to_path_buf()));
            }
        }

        if self.sops_config.is_none()
            && let Some(path) = self.discover_sops_config()
        {
            cmd.env("SOPS_CONFIG", path);
        }
    }

    pub fn apply_query_parameter(&mut self, key: &str, value: &str) -> Result<()> {
        for spec in STRING_FIELDS {
            if spec.url_key == key {
                *(spec.field_mut)(self) = Some(String::from(value));

                return Ok(());
            }
        }

        for spec in PATHBUF_FIELDS {
            if spec.url_key == key {
                *(spec.field_mut)(self) = Some(PathBuf::from(value));

                return Ok(());
            }
        }

        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Invalid query parameter: {}",
            key
        )))
    }

    pub fn with_base_dir(&mut self, base_dir: &std::path::Path) {
        self.base_dir = Some(base_dir.to_owned());
    }

    pub fn rebase_path(&self, path: std::path::PathBuf) -> std::path::PathBuf {
        if let Some(base) = &self.base_dir {
            if path.is_relative() {
                return base.join(path);
            }
        }

        return path;
    }

    fn discover_sops_config(&self) -> Option<PathBuf> {
        self.base_dir.as_deref().and_then(|base_dir| {
            base_dir
                .ancestors()
                .map(|directory| directory.join(".sops.yaml"))
                .find(|candidate| candidate.is_file())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provider;
    use std::fs;
    use url::Url;

    #[test]
    fn test_sops_config_try_from_succeeds_for_known_query_parameters() {
        let mut url_query_parameter_keys: Vec<&str> =
            STRING_FIELDS.iter().map(|f| f.url_key).collect();

        url_query_parameter_keys.extend(PATHBUF_FIELDS.iter().map(|f| f.url_key).into_iter());

        url_query_parameter_keys.iter().for_each(|key| {
        let url: Url = Url::parse(format!("sops://src/provider/sops/test_fixtures/single_file/some-project-name.enc.json?{}=foo", key).as_str()).unwrap();

        let provider_result: std::result::Result<Box<dyn Provider>, _> = (&url).try_into();

        match provider_result {
            Err(e) => {
                assert!(false, "{}", e.to_string());
            }
            Ok(_) => ()
        }
    });
    }

    #[test]
    fn test_sops_config_try_from_errors_on_unknown_query_parameter() {
        let url = Url::parse("sops://src/provider/sops/test_fixtures/single_file/some-project-name.enc.json?invalid_parameter=foo").unwrap();

        let provider_result: std::result::Result<Box<dyn Provider>, _> = (&url).try_into();

        match provider_result {
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    "Provider operation failed: Invalid query parameter: invalid_parameter"
                );
            }
            _ => {
                assert!(false)
            }
        }
    }

    #[test]
    fn unknown_extension_returns_an_error_instead_of_panicking() {
        for spec in [
            "sops://secrets.enc",
            "sops://secrets/{project}/{profile}.enc",
        ] {
            let url = Url::parse(spec).unwrap();
            let result: std::result::Result<Box<dyn Provider>, _> = (&url).try_into();
            let error = result.err().expect("unknown extension should fail");
            assert!(
                error.to_string().contains("Supported formats"),
                "unexpected error for {spec}: {error}"
            );
        }
    }

    #[test]
    fn explicit_dotenv_format_allows_an_enc_extension() {
        let url = Url::parse("sops://secrets/{project}/.env.{profile}.enc?format=dotenv").unwrap();
        let provider: std::result::Result<Box<dyn Provider>, _> = (&url).try_into();
        assert!(provider.is_ok());
    }

    #[test]
    fn explicit_ini_format_requires_an_ini_extension() {
        let url = Url::parse("sops://secrets.enc?format=ini").unwrap();
        let result: std::result::Result<Box<dyn Provider>, _> = (&url).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn template_literal_prefix_stays_in_the_pattern() {
        let url =
            Url::parse("sops://secrets-{project}/{profile}.enc.json").expect("valid SOPS URL");
        let provider_url = ProviderUrl::new(url);
        let config = SopsConfig::try_from(&provider_url).expect("valid SOPS config");

        match config.mode {
            SopsMode::Directory { path, pattern, .. } => {
                assert!(path.as_os_str().is_empty());
                assert_eq!(
                    pattern.render("myapp", "production"),
                    PathBuf::from("secrets-myapp/production.enc.json")
                );
            }
            mode => panic!("expected directory mode, got {mode:?}"),
        }
    }

    #[test]
    fn project_sops_config_is_discovered_from_the_manifest_directory() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("services/api");
        fs::create_dir_all(&nested).unwrap();
        let expected = root.path().join(".sops.yaml");
        fs::write(&expected, "creation_rules: []\n").unwrap();

        let mut config = SopsConfig::default();
        config.with_base_dir(&nested);

        assert_eq!(config.discover_sops_config(), Some(expected));
    }
}
