use std::path::PathBuf;

pub struct FieldSpec<T> {
    pub env_key: &'static str,
    pub field: fn(&super::SopsConfig) -> &Option<T>,
    pub field_mut: fn(&mut super::SopsConfig) -> &mut Option<T>,
    pub url_key: &'static str,
}

pub static STRING_FIELDS: &[FieldSpec<String>] = &[
    FieldSpec {
        field: |c| &c.age_key,
        field_mut: |c| &mut c.age_key,
        url_key: "age_key",
        env_key: "SOPS_AGE_KEY",
    },
    FieldSpec {
        field: |c| &c.age_key_cmd,
        field_mut: |c| &mut c.age_key_cmd,
        url_key: "age_key_cmd",
        env_key: "SOPS_AGE_KEY_CMD",
    },
    FieldSpec {
        field: |c| &c.age_recipients,
        field_mut: |c| &mut c.age_recipients,
        url_key: "age_recipients",
        env_key: "SOPS_AGE_RECIPIENTS",
    },
    FieldSpec {
        field: |c| &c.age_ssh_private_key_cmd,
        field_mut: |c| &mut c.age_ssh_private_key_cmd,
        url_key: "age_ssh_private_key_cmd",
        env_key: "SOPS_AGE_SSH_PRIVATE_KEY_CMD",
    },
    FieldSpec {
        field: |c| &c.kms_arn,
        field_mut: |c| &mut c.kms_arn,
        url_key: "kms_arn",
        env_key: "SOPS_KMS_ARN",
    },
    FieldSpec {
        field: |c| &c.aws_profile,
        field_mut: |c| &mut c.aws_profile,
        url_key: "aws_profile",
        env_key: "AWS_PROFILE",
    },
    FieldSpec {
        field: |c| &c.aws_access_key_id,
        field_mut: |c| &mut c.aws_access_key_id,
        url_key: "aws_access_key_id",
        env_key: "AWS_ACCESS_KEY_ID",
    },
    FieldSpec {
        field: |c| &c.aws_secret_access_key,
        field_mut: |c| &mut c.aws_secret_access_key,
        url_key: "aws_secret_access_key",
        env_key: "AWS_SECRET_ACCESS_KEY",
    },
    FieldSpec {
        field: |c| &c.aws_secret_key,
        field_mut: |c| &mut c.aws_secret_key,
        url_key: "aws_secret_key",
        env_key: "AWS_SECRET_KEY",
    },
    FieldSpec {
        field: |c| &c.aws_region,
        field_mut: |c| &mut c.aws_region,
        url_key: "aws_region",
        env_key: "AWS_REGION",
    },
    FieldSpec {
        field: |c| &c.azure_client_id,
        field_mut: |c| &mut c.azure_client_id,
        url_key: "azure_client_id",
        env_key: "AZURE_CLIENT_ID",
    },
    FieldSpec {
        field: |c| &c.azure_client_secret,
        field_mut: |c| &mut c.azure_client_secret,
        url_key: "azure_client_secret",
        env_key: "AZURE_CLIENT_SECRET",
    },
    FieldSpec {
        field: |c| &c.azure_tenant_id,
        field_mut: |c| &mut c.azure_tenant_id,
        url_key: "azure_tenant_id",
        env_key: "AZURE_TENANT_ID",
    },
    FieldSpec {
        field: |c| &c.azure_keyvault_urls,
        field_mut: |c| &mut c.azure_keyvault_urls,
        url_key: "azure_keyvault_urls",
        env_key: "SOPS_AZURE_KEYVAULT_URLS",
    },
    FieldSpec {
        field: |c| &c.gcp_kms,
        field_mut: |c| &mut c.gcp_kms,
        url_key: "gcp_kms",
        env_key: "SOPS_GCP_KMS",
    },
    FieldSpec {
        field: |c| &c.gcp_kms_client_type,
        field_mut: |c| &mut c.gcp_kms_client_type,
        url_key: "gcp_kms_client_type",
        env_key: "SOPS_GCP_KMS_CLIENT_TYPE",
    },
    FieldSpec {
        field: |c| &c.gcp_kms_endpoint,
        field_mut: |c| &mut c.gcp_kms_endpoint,
        url_key: "gcp_kms_endpoint",
        env_key: "SOPS_GCP_KMS_ENDPOINT",
    },
    FieldSpec {
        field: |c| &c.gcp_kms_ids,
        field_mut: |c| &mut c.gcp_kms_ids,
        url_key: "gcp_kms_ids",
        env_key: "SOPS_GCP_KMS_IDS",
    },
    FieldSpec {
        field: |c| &c.gcp_kms_universe_domain,
        field_mut: |c| &mut c.gcp_kms_universe_domain,
        url_key: "gcp_kms_universe_domain",
        env_key: "SOPS_GCP_KMS_UNIVERSE_DOMAIN",
    },
    FieldSpec {
        field: |c| &c.pgp_fp,
        field_mut: |c| &mut c.pgp_fp,
        url_key: "pgp_fp",
        env_key: "SOPS_PGP_FP",
    },
    FieldSpec {
        field: |c| &c.gpg_exec,
        field_mut: |c| &mut c.gpg_exec,
        url_key: "gpg_exec",
        env_key: "SOPS_GPG_EXEC",
    },
    FieldSpec {
        field: |c| &c.hc_vault_addr,
        field_mut: |c| &mut c.hc_vault_addr,
        url_key: "hc_vault_addr",
        env_key: "VAULT_ADDR",
    },
    FieldSpec {
        field: |c| &c.hc_vault_token,
        field_mut: |c| &mut c.hc_vault_token,
        url_key: "hc_vault_token",
        env_key: "VAULT_TOKEN",
    },
    FieldSpec {
        field: |c| &c.hc_vault_allowlist,
        field_mut: |c| &mut c.hc_vault_allowlist,
        url_key: "hc_vault_allowlist",
        env_key: "SOPS_HC_VAULT_ALLOWLIST",
    },
    FieldSpec {
        field: |c| &c.huawei_sdk_ak,
        field_mut: |c| &mut c.huawei_sdk_ak,
        url_key: "huawei_sdk_ak",
        env_key: "HUAWEICLOUD_SDK_AK",
    },
    FieldSpec {
        field: |c| &c.huawei_sdk_sk,
        field_mut: |c| &mut c.huawei_sdk_sk,
        url_key: "huawei_sdk_sk",
        env_key: "HUAWEICLOUD_SDK_SK",
    },
    FieldSpec {
        field: |c| &c.huawei_sdk_project_id,
        field_mut: |c| &mut c.huawei_sdk_project_id,
        url_key: "huawei_sdk_project_id",
        env_key: "HUAWEICLOUD_SDK_PROJECT_ID",
    },
    FieldSpec {
        field: |c| &c.huawei_kms_ids,
        field_mut: |c| &mut c.huawei_kms_ids,
        url_key: "huawei_kms_ids",
        env_key: "SOPS_HUAWEICLOUD_KMS_IDS",
    },
    FieldSpec {
        field: |c| &c.sops_config,
        field_mut: |c| &mut c.sops_config,
        url_key: "sops_config",
        env_key: "SOPS_CONFIG",
    },
    FieldSpec {
        field: |c| &c.sops_decryption_order,
        field_mut: |c| &mut c.sops_decryption_order,
        url_key: "sops_decryption_order",
        env_key: "SOPS_DECRYPTION_ORDER",
    },
    FieldSpec {
        field: |c| &c.sops_editor,
        field_mut: |c| &mut c.sops_editor,
        url_key: "sops_editor",
        env_key: "SOPS_EDITOR",
    },
    FieldSpec {
        field: |c| &c.sops_enable_local_keyservice,
        field_mut: |c| &mut c.sops_enable_local_keyservice,
        url_key: "sops_enable_local_keyservice",
        env_key: "SOPS_ENABLE_LOCAL_KEYSERVICE",
    },
    FieldSpec {
        field: |c| &c.sops_keyservice,
        field_mut: |c| &mut c.sops_keyservice,
        url_key: "sops_keyservice",
        env_key: "SOPS_KEYSERVICE",
    },
    FieldSpec {
        field: |c| &c.aes_gcm,
        field_mut: |c| &mut c.aes_gcm,
        url_key: "aes_gcm",
        env_key: "AES_GCM",
    },
    FieldSpec {
        field: |c| &c.encrypt_decrypt,
        field_mut: |c| &mut c.encrypt_decrypt,
        url_key: "encrypt_decrypt",
        env_key: "ENCRYPT_DECRYPT",
    },
    FieldSpec {
        field: |c| &c.google_oauth_access_token,
        field_mut: |c| &mut c.google_oauth_access_token,
        url_key: "google_oauth_access_token",
        env_key: "GOOGLE_OAUTH_ACCESS_TOKEN",
    },
];

pub static PATHBUF_FIELDS: &[FieldSpec<PathBuf>] = &[
    FieldSpec {
        field: |c| &c.age_key_file,
        field_mut: |c| &mut c.age_key_file,
        url_key: "age_key_file",
        env_key: "SOPS_AGE_KEY_FILE",
    },
    FieldSpec {
        field: |c| &c.age_ssh_private_key_file,
        field_mut: |c| &mut c.age_ssh_private_key_file,
        url_key: "age_ssh_private_key_file",
        env_key: "SOPS_AGE_SSH_PRIVATE_KEY_FILE",
    },
];
