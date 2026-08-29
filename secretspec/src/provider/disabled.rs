//! Registry entries for providers omitted by Cargo feature selection.
//!
//! The implementation modules cannot be compiled without their optional
//! dependencies, but their identity remains part of SecretSpec's provider
//! registry so using one produces an actionable feature error.

#[cfg(not(feature = "aac"))]
crate::register_disabled_provider! {
    feature: "aac", name: "aac", description: "Azure App Configuration (0.20+)",
    schemes: ["aac"],
    examples: ["aac://payments-production", "aac://shared?label=production&prefix=payments:", "aac://shared?tag=app=payments&tag=stage=production"],
    credential_names: ["tenant_id", "client_id", "client_secret", "connection_string"],
    deletes: true,
}

#[cfg(not(feature = "age"))]
crate::register_disabled_provider! {
    feature: "age", name: "age", description: "age-encrypted file",
    schemes: ["age"], examples: ["age://secrets.age", "age://secrets.age?recipients-file=secrets.age.recipients"],
    credential_names: ["identity"], deletes: true,
}

#[cfg(not(feature = "akv"))]
crate::register_disabled_provider! {
    feature: "akv", name: "akv", description: "Azure Key Vault",
    schemes: ["akv"], examples: ["akv://myvault", "akv://myvault?auth=managed_identity", "akv://myvault?suffix=vault.azure.cn"],
    credential_names: ["tenant_id", "client_id", "client_secret"],
}

#[cfg(not(feature = "awsps"))]
crate::register_disabled_provider! {
    feature: "awsps", name: "awsps", description: "AWS Systems Manager Parameter Store (0.18+)",
    schemes: ["awsps"], examples: ["awsps://us-east-1", "awsps://production@us-east-1", "awsps://us-east-1?prefix=/myteam", "awsps://us-east-1?template=/{profile}/{project}/{key}", "awsps://us-east-1?kms_key_id=alias/my-key&tier=advanced"],
}

#[cfg(not(feature = "awssm"))]
crate::register_disabled_provider! {
    feature: "awssm", name: "awssm", description: "AWS Secrets Manager",
    schemes: ["awssm"], examples: ["awssm://us-east-1", "awssm://production@us-east-1", "awssm://us-east-1?prefix=myteam", "awssm://prod@us-east-1?kms_key_id=alias/my-key&tag.team=platform"],
}

#[cfg(not(feature = "bw"))]
crate::register_disabled_provider! {
    feature: "bw", name: "bw", description: "Bitwarden Password Manager",
    schemes: ["bw"], examples: ["bw://", "bw://collection-id", "bw://org@collection"],
}

#[cfg(not(feature = "bws"))]
crate::register_disabled_provider! {
    feature: "bws", name: "bws", description: "Bitwarden Secrets Manager via official bws CLI",
    schemes: ["bws"], examples: ["bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"],
    credential_names: ["access_token"],
}

#[cfg(not(feature = "cloudflare"))]
crate::register_disabled_provider! {
    feature: "cloudflare", name: "cloudflare", description: "Cloudflare Secrets Store, write-only (0.20+)",
    schemes: ["cloudflare"], examples: ["cloudflare://STORE_ID?account_id=ACCOUNT_ID", "cloudflare://STORE_ID?account_id=ACCOUNT_ID&auth=wrangler"],
    credential_names: ["api_token"], reads: false, deletes: true,
}

#[cfg(not(feature = "ejson"))]
crate::register_disabled_provider! {
    feature: "ejson", name: "ejson", description: "EJSON encrypted files (0.20+)",
    schemes: ["ejson"], examples: ["ejson:config/secrets.production.ejson"],
    credential_names: ["private_key"],
}

#[cfg(not(feature = "gcsm"))]
crate::register_disabled_provider! {
    feature: "gcsm", name: "gcsm", description: "Google Cloud Secret Manager",
    schemes: ["gcsm"], examples: ["gcsm://my-gcp-project"],
}

#[cfg(not(feature = "infisical"))]
crate::register_disabled_provider! {
    feature: "infisical", name: "infisical", description: "Infisical secret management",
    schemes: ["infisical"], examples: ["infisical://app.infisical.com/{project-id}"],
    credential_names: ["client_id", "client_secret", "token"],
}

#[cfg(not(feature = "kdbx"))]
crate::register_disabled_provider! {
    feature: "kdbx", name: "kdbx", description: "KeePass KDBX databases (0.17+)",
    schemes: ["kdbx"], examples: ["kdbx:./secrets.kdbx", "kdbx:./secrets.kdbx?keyfile=./secrets.key"],
    credential_names: ["password"],
}

#[cfg(not(feature = "keeper"))]
crate::register_disabled_provider! {
    feature: "keeper", name: "keeper", description: "Keeper Secrets Manager (0.18+) via official Rust SDK",
    schemes: ["keeper"], examples: ["keeper://SHARED_FOLDER_UID"],
    credential_names: ["config", "token"], deletes: true,
}

#[cfg(not(feature = "keyring"))]
crate::register_disabled_provider! {
    feature: "keyring", name: "keyring", description: "Uses system keychain (Recommended)",
    schemes: ["keyring"], examples: ["keyring://", "keyring://secretspec/shared/{profile}/{key}"],
    deletes: true,
}

#[cfg(not(feature = "kubernetes"))]
crate::register_disabled_provider! {
    feature: "kubernetes", name: "kubernetes", description: "Kubernetes (0.20+)",
    schemes: ["k8s+configmap", "k8s+secret"], examples: ["k8s+secret://db-config", "k8s+configmap://db-config@default"],
    deletes: true,
}

#[cfg(not(feature = "openbao"))]
crate::register_disabled_provider! {
    feature: "openbao", name: "openbao", description: "OpenBao secret management (0.17+)",
    schemes: ["openbao"], examples: ["openbao://bao.example.com:8200/secret"],
    credential_names: ["role_id", "secret_id", "token"], deletes: true,
}

#[cfg(not(feature = "scaleway"))]
crate::register_disabled_provider! {
    feature: "scaleway", name: "scaleway", description: "Scaleway Secret Manager",
    schemes: ["scaleway"], examples: ["scaleway://fr-par", "scaleway://nl-ams?project_id=PROJECT_UUID", "scaleway://fr-par?project_id=PROJECT_UUID&path=/myteam"],
    credential_names: ["secret_key"],
}

#[cfg(not(feature = "sops"))]
crate::register_disabled_provider! {
    feature: "sops", name: "sops", description: "SOPS encrypted files (0.17+)",
    schemes: ["sops"], examples: ["sops://secrets.enc.yaml", "sops://secrets-dir/{project}/{profile}.enc.json", "sops://secrets-dir/{project}/.env.{profile}.enc?format=dotenv"],
    credential_names: ["age_key", "aws_secret_access_key", "azure_client_secret", "hc_vault_token", "huawei_sdk_ak", "huawei_sdk_sk", "google_oauth_access_token"],
}

#[cfg(not(feature = "vault"))]
crate::register_disabled_provider! {
    feature: "vault", name: "vault", description: "HashiCorp Vault secret management",
    schemes: ["vault"], examples: ["vault://vault.example.com:8200/secret"],
    credential_names: ["role_id", "secret_id", "token"], deletes: true,
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(not(feature = "keyring"))]
    fn disabled_provider_is_known_and_reports_its_feature() {
        assert!(super::super::spec_names_known_provider("keyring://").unwrap());
        let error = match Box::<dyn super::super::Provider>::try_from("keyring://") {
            Ok(_) => panic!("disabled provider unexpectedly constructed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            crate::SecretSpecError::ProviderFeatureDisabled {
                ref provider,
                feature: "keyring"
            } if provider == "keyring"
        ));
    }
}
