#[cfg(test)]
mod test_provider_not_found {
    use secretspec::provider::Provider;
    use std::convert::TryFrom;

    #[test]
    fn test_keyring_provider_when_feature_disabled() {
        // This test checks what error we get when trying to use keyring provider
        // when the keyring feature is disabled
        
        #[cfg(not(feature = "keyring"))]
        {
            match Box::<dyn Provider>::try_from("keyring") {
                Ok(_) => panic!("Should not create keyring provider when feature is disabled"),
                Err(e) => {
                    println!("Error when keyring feature disabled: {}", e);
                    // Check if it's ProviderNotFound
                    match e {
                        secretspec::SecretSpecError::ProviderNotFound(name) => {
                            assert_eq!(name, "keyring");
                        }
                        _ => panic!("Expected ProviderNotFound, got: {:?}", e),
                    }
                }
            }
        }
        
        #[cfg(feature = "keyring")]
        {
            // When feature is enabled, keyring should work
            match Box::<dyn Provider>::try_from("keyring") {
                Ok(provider) => assert_eq!(provider.name(), "keyring"),
                Err(e) => panic!("Should create keyring provider when feature is enabled: {}", e),
            }
        }
    }
    
    #[test] 
    fn test_truly_unknown_provider() {
        // Test a provider that really doesn't exist
        match Box::<dyn Provider>::try_from("nonexistent_provider") {
            Ok(_) => panic!("Should not create nonexistent provider"),
            Err(e) => {
                println!("Error for nonexistent provider: {}", e);
                match e {
                    secretspec::SecretSpecError::ProviderNotFound(name) => {
                        assert_eq!(name, "nonexistent_provider");
                    }
                    _ => panic!("Expected ProviderNotFound, got: {:?}", e),
                }
            }
        }
    }
}