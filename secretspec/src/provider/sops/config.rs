use crate::{
    Result, SecretSpecError,
    provider::{
        ProviderUrl,
        sops::{
            SopsFormat, SopsMode,
            fields::{PATHBUF_FIELDS, STRING_FIELDS},
        },
    },
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

struct EnvString(String);

impl From<&PathBuf> for EnvString {
    fn from(p: &PathBuf) -> Self {
        EnvString(p.to_string_lossy().into_owned())
    }
}

impl From<&String> for EnvString {
    fn from(s: &String) -> Self {
        EnvString(s.clone())
    }
}

impl AsRef<OsStr> for EnvString {
    fn as_ref(&self) -> &OsStr {
        OsStr::new(&self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SopsConfig {
    pub mode: SopsMode,
    pub format: Option<SopsFormat>,

    // Age configuration
    pub age_key_file: Option<PathBuf>,
    pub age_key: Option<String>,
    pub age_key_cmd: Option<String>,
    pub age_recipients: Option<String>,
    pub age_ssh_private_key_file: Option<PathBuf>,
    pub age_ssh_private_key_cmd: Option<String>,

    // AWS KMS configuration
    pub kms_arn: Option<String>,
    pub aws_profile: Option<String>,
    pub aws_access_key_id: Option<String>,
    pub aws_secret_access_key: Option<String>,
    pub aws_secret_key: Option<String>, // alias
    pub aws_region: Option<String>,

    // Azure configuration
    pub azure_client_id: Option<String>,
    pub azure_client_secret: Option<String>,
    pub azure_tenant_id: Option<String>,
    pub azure_keyvault_urls: Option<String>,

    // GCP KMS configuration
    pub gcp_kms: Option<String>,
    pub gcp_kms_client_type: Option<String>,
    pub gcp_kms_endpoint: Option<String>,
    pub gcp_kms_ids: Option<String>,
    pub gcp_kms_universe_domain: Option<String>,

    // PGP configuration
    pub pgp_fp: Option<String>,
    pub gpg_exec: Option<String>,

    // HashiCorp Vault configuration
    pub hc_vault_addr: Option<String>,
    pub hc_vault_token: Option<String>,
    pub hc_vault_allowlist: Option<String>,

    // Huawei Cloud KMS
    pub huawei_sdk_ak: Option<String>,
    pub huawei_sdk_sk: Option<String>,
    pub huawei_sdk_project_id: Option<String>,
    pub huawei_kms_ids: Option<String>,

    // Generic SOPS settings
    pub sops_config: Option<String>,
    pub sops_decryption_order: Option<String>,
    pub sops_editor: Option<String>,
    pub sops_enable_local_keyservice: Option<String>,
    pub sops_keyservice: Option<String>,

    // AES_GCM
    pub aes_gcm: Option<String>,

    // ENCRYPT_DECRYPT toggle
    pub encrypt_decrypt: Option<String>,

    // Google OAuth token
    pub google_oauth_access_token: Option<String>,
}

impl Default for SopsConfig {
    fn default() -> Self {
        Self {
            aes_gcm: None,
            age_key_cmd: None,
            age_key_file: None,
            age_key: None,
            age_recipients: None,
            age_ssh_private_key_cmd: None,
            age_ssh_private_key_file: None,
            aws_access_key_id: None,
            aws_profile: None,
            aws_region: None,
            aws_secret_access_key: None,
            aws_secret_key: None,
            azure_client_id: None,
            azure_client_secret: None,
            azure_keyvault_urls: None,
            azure_tenant_id: None,
            encrypt_decrypt: None,
            format: None,
            gcp_kms_client_type: None,
            gcp_kms_endpoint: None,
            gcp_kms_ids: None,
            gcp_kms_universe_domain: None,
            gcp_kms: None,
            google_oauth_access_token: None,
            gpg_exec: None,
            hc_vault_addr: None,
            hc_vault_allowlist: None,
            hc_vault_token: None,
            huawei_kms_ids: None,
            huawei_sdk_ak: None,
            huawei_sdk_project_id: None,
            huawei_sdk_sk: None,
            kms_arn: None,
            mode: SopsMode::SingleFile(PathBuf::from(".enc.yaml")),
            pgp_fp: None,
            sops_config: None,
            sops_decryption_order: None,
            sops_editor: None,
            sops_enable_local_keyservice: None,
            sops_keyservice: None,
        }
    }
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

        let mut config = SopsConfig::default();

        // Build path from host and path
        let mut target_path = PathBuf::new();

        if let Some(host) = url.host()
            && host != "localhost"
            && !host.is_empty()
        {
            target_path.push(host);
        }

        let url_path = url.path();

        if !url_path.is_empty() && url_path != "/" {
            let path_part = url_path.trim_start_matches('/');

            if !path_part.is_empty() {
                target_path.push(path_part);
            }
        }

        // If no path specified, use default
        if target_path.as_os_str().is_empty() {
            target_path = PathBuf::from(".enc.yaml");
        }

        // Parse query parameters first to get pattern and format
        let pattern: Option<String> = None;
        let default_format = SopsFormat::Yaml;

        for (key, value) in url.query_pairs() {
            match config.apply_url_field(key.as_ref(), value.as_ref()) {
                Ok(_) => (),
                Err(e) => return Err(e),
            };
        }

        // Determine mode based on path and pattern
        config.mode = if let Some(pattern_str) = pattern {
            // Explicit directory mode with custom pattern
            SopsMode::Directory {
                path: target_path,
                pattern: pattern_str,
                default_format,
            }
        } else if target_path.is_dir()
            || (!target_path.exists() && !Self::looks_like_file(&target_path))
        {
            // Auto-detect directory mode
            let auto_pattern = Self::build_default_pattern(&default_format);
            SopsMode::Directory {
                path: target_path,
                pattern: auto_pattern,
                default_format,
            }
        } else {
            // Single file mode
            SopsMode::SingleFile(target_path)
        };

        Ok(config)
    }
}

impl SopsConfig {
    pub fn apply_env(&self, cmd: &mut std::process::Command) {
        for spec in STRING_FIELDS {
            if let Some(v) = (spec.field)(self) {
                cmd.env(spec.env_key, EnvString::from(v));
            }
        }

        for spec in PATHBUF_FIELDS {
            if let Some(v) = (spec.field)(self) {
                cmd.env(spec.env_key, EnvString::from(v));
            }
        }
    }

    pub fn apply_url_field(&mut self, key: &str, value: &str) -> Result<()> {
        if key == "format" {
            let fmt = SopsFormat::from_str(value).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!("Invalid format parameter: {}", e))
            })?;

            self.format = Some(fmt.clone());

            return Ok(());
        }

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

        Ok(())
    }

    fn looks_like_file(path: &Path) -> bool {
        path.extension().is_some()
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.contains('.'))
                .unwrap_or(false)
    }

    fn build_default_pattern(format: &SopsFormat) -> String {
        // Default to hierarchical structure
        let extensions = format.extensions();
        format!("{{project}}/{{profile}}.enc.{}", extensions[0])
    }
}
