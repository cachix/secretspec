//! Metadata for providers whose implementations are controlled by Cargo features.
//!
//! Both the real provider registration and its disabled fallback point at these
//! values, keeping discovery and error metadata identical in every build.

use super::{ProviderInfo, ProviderMetadata};

macro_rules! metadata {
    (
        $name:ident,
        name: $provider_name:expr,
        description: $description:expr,
        schemes: [$($scheme:expr),* $(,)?],
        examples: [$($example:expr),* $(,)?]
        $(, credential_names: [$($credential_name:expr),* $(,)?])?
        $(, reads: $reads:literal)?
        $(, deletes: $deletes:literal)? $(,)?
    ) => {
        pub(crate) static $name: ProviderMetadata = ProviderMetadata {
            info: ProviderInfo {
                name: $provider_name,
                description: $description,
                examples: &[$($example,)*],
            },
            schemes: &[$($scheme,)*],
            credential_names: &[$($($credential_name,)*)?],
            reads: crate::provider::declared_read_capability(&[$($reads,)?]),
            deletes: crate::provider::declared_flag(&[$($deletes,)?]),
        };
    };
}

metadata! {
    AAC,
    name: "aac",
    description: "Azure App Configuration (0.20+)",
    schemes: ["aac"],
    examples: [
        "aac://payments-production",
        "aac://shared?label=production&prefix=payments:",
        "aac://shared?tag=app=payments&tag=stage=production",
    ],
    credential_names: ["tenant_id", "client_id", "client_secret", "connection_string"],
    deletes: true,
}

metadata! {
    AGE,
    name: "age",
    description: "age-encrypted file",
    schemes: ["age"],
    examples: ["age://secrets.age", "age://secrets.age?recipients-file=secrets.age.recipients"],
    credential_names: ["identity"],
    deletes: true,
}

metadata! {
    AKV,
    name: "akv",
    description: "Azure Key Vault",
    schemes: ["akv"],
    examples: ["akv://myvault", "akv://myvault?auth=managed_identity", "akv://myvault?suffix=vault.azure.cn"],
    credential_names: ["tenant_id", "client_id", "client_secret"],
}

metadata! {
    AWSPS,
    name: "awsps",
    description: "AWS Systems Manager Parameter Store (0.18+)",
    schemes: ["awsps"],
    examples: [
        "awsps://us-east-1",
        "awsps://production@us-east-1",
        "awsps://us-east-1?prefix=/myteam",
        "awsps://us-east-1?template=/{profile}/{project}/{key}",
        "awsps://us-east-1?kms_key_id=alias/my-key&tier=advanced",
    ],
}

metadata! {
    AWSSM,
    name: "awssm",
    description: "AWS Secrets Manager",
    schemes: ["awssm"],
    examples: ["awssm://us-east-1", "awssm://production@us-east-1", "awssm://us-east-1?prefix=myteam", "awssm://prod@us-east-1?kms_key_id=alias/my-key&tag.team=platform"],
}

metadata! {
    BW,
    name: "bw",
    description: "Bitwarden Password Manager",
    schemes: ["bw"],
    examples: ["bw://", "bw://collection-id", "bw://org@collection"],
}

metadata! {
    BWS,
    name: "bws",
    description: "Bitwarden Secrets Manager via official bws CLI",
    schemes: ["bws"],
    examples: ["bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"],
    credential_names: ["access_token"],
}

metadata! {
    CLOUDFLARE,
    name: "cloudflare",
    description: "Cloudflare Secrets Store, write-only (0.20+)",
    schemes: ["cloudflare"],
    examples: ["cloudflare://STORE_ID?account_id=ACCOUNT_ID", "cloudflare://STORE_ID?account_id=ACCOUNT_ID&auth=wrangler"],
    credential_names: ["api_token"],
    reads: false,
    deletes: true,
}

metadata! {
    EJSON,
    name: "ejson",
    description: "EJSON encrypted files (0.20+)",
    schemes: ["ejson"],
    examples: ["ejson:config/secrets.production.ejson"],
    credential_names: ["private_key"],
}

metadata! {
    GCSM,
    name: "gcsm",
    description: "Google Cloud Secret Manager",
    schemes: ["gcsm"],
    examples: ["gcsm://my-gcp-project"],
}

metadata! {
    INFISICAL,
    name: "infisical",
    description: "Infisical secret management",
    schemes: ["infisical"],
    examples: ["infisical://app.infisical.com/{project-id}"],
    credential_names: ["client_id", "client_secret", "token"],
}

metadata! {
    KDBX,
    name: "kdbx",
    description: "KeePass KDBX databases (0.17+)",
    schemes: ["kdbx"],
    examples: ["kdbx:./secrets.kdbx", "kdbx:./secrets.kdbx?keyfile=./secrets.key"],
    credential_names: ["password"],
}

metadata! {
    KEEPER,
    name: "keeper",
    description: "Keeper Secrets Manager (0.18+) via official Rust SDK",
    schemes: ["keeper"],
    examples: ["keeper://SHARED_FOLDER_UID"],
    credential_names: ["config", "token"],
    deletes: true,
}

metadata! {
    KEYRING,
    name: "keyring",
    description: "Uses system keychain (Recommended)",
    schemes: ["keyring"],
    examples: ["keyring://", "keyring://secretspec/shared/{profile}/{key}"],
    deletes: true,
}

metadata! {
    KUBERNETES,
    name: "kubernetes",
    description: "Kubernetes (0.20+)",
    schemes: ["k8s+configmap", "k8s+secret"],
    examples: ["k8s+secret://db-config", "k8s+configmap://db-config@default"],
    deletes: true,
}

metadata! {
    OPENBAO,
    name: "openbao",
    description: "OpenBao secret management (0.17+)",
    schemes: ["openbao"],
    examples: ["openbao://bao.example.com:8200/secret"],
    credential_names: ["role_id", "secret_id", "token"],
    deletes: true,
}

metadata! {
    SCALEWAY,
    name: "scaleway",
    description: "Scaleway Secret Manager",
    schemes: ["scaleway"],
    examples: ["scaleway://fr-par", "scaleway://nl-ams?project_id=PROJECT_UUID", "scaleway://fr-par?project_id=PROJECT_UUID&path=/myteam"],
    credential_names: ["secret_key"],
}

metadata! {
    SOPS,
    name: "sops",
    description: "SOPS encrypted files (0.17+)",
    schemes: ["sops"],
    examples: [
        "sops://secrets.enc.yaml",
        "sops://secrets-dir/{project}/{profile}.enc.json",
        "sops://secrets-dir/{project}/.env.{profile}.enc?format=dotenv",
    ],
    credential_names: ["age_key", "aws_secret_access_key", "azure_client_secret", "hc_vault_token", "huawei_sdk_ak", "huawei_sdk_sk", "google_oauth_access_token"],
}

metadata! {
    VAULT,
    name: "vault",
    description: "HashiCorp Vault secret management",
    schemes: ["vault"],
    examples: ["vault://vault.example.com:8200/secret"],
    credential_names: ["role_id", "secret_id", "token"],
    deletes: true,
}
