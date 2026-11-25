use secretspec::{ProviderInfo, providers};
use std::collections::HashSet;

#[test]
fn lists_builtin_providers_through_public_api() {
    let listed: Vec<ProviderInfo> = providers();
    let names: HashSet<_> = listed.iter().map(|provider| provider.name).collect();

    assert_eq!(names.len(), listed.len(), "provider names must be unique");
    for name in ["dotenv", "env", "keyring", "onepassword"] {
        assert!(names.contains(name), "missing built-in provider {name}");
    }
    assert!(
        listed
            .iter()
            .all(|provider| !provider.description.is_empty())
    );
    assert!(
        listed
            .iter()
            .any(|provider| provider.name == "dotenv" && !provider.examples.is_empty())
    );
}
