//! Registry entries for providers omitted by Cargo feature selection.
//!
//! The implementation modules cannot be compiled without their optional
//! dependencies, but their identity remains part of SecretSpec's provider
//! registry so using one produces an actionable feature error.

use super::catalog;

macro_rules! disabled {
    ($feature:literal, $metadata:ident) => {
        crate::register_disabled_provider! {
            feature: $feature,
            metadata: &catalog::$metadata,
        }
    };
}

#[cfg(not(feature = "aac"))]
disabled!("aac", AAC);
#[cfg(not(feature = "age"))]
disabled!("age", AGE);
#[cfg(not(feature = "akv"))]
disabled!("akv", AKV);
#[cfg(not(feature = "awsps"))]
disabled!("awsps", AWSPS);
#[cfg(not(feature = "awssm"))]
disabled!("awssm", AWSSM);
#[cfg(not(feature = "bw"))]
disabled!("bw", BW);
#[cfg(not(feature = "bws"))]
disabled!("bws", BWS);
#[cfg(not(feature = "cloudflare"))]
disabled!("cloudflare", CLOUDFLARE);
#[cfg(not(feature = "ejson"))]
disabled!("ejson", EJSON);
#[cfg(not(feature = "gcsm"))]
disabled!("gcsm", GCSM);
#[cfg(not(feature = "infisical"))]
disabled!("infisical", INFISICAL);
#[cfg(not(feature = "kdbx"))]
disabled!("kdbx", KDBX);
#[cfg(not(feature = "keeper"))]
disabled!("keeper", KEEPER);
#[cfg(not(feature = "keyring"))]
disabled!("keyring", KEYRING);
#[cfg(not(feature = "kubernetes"))]
disabled!("kubernetes", KUBERNETES);
#[cfg(not(feature = "openbao"))]
disabled!("openbao", OPENBAO);
#[cfg(not(feature = "scaleway"))]
disabled!("scaleway", SCALEWAY);
#[cfg(not(feature = "sops"))]
disabled!("sops", SOPS);
#[cfg(not(feature = "vault"))]
disabled!("vault", VAULT);

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
