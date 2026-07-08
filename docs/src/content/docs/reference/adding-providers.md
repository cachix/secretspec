---
title: Adding a New Provider
description: Step-by-step guide for implementing custom provider backends
---

## Provider Trait

All providers must implement the `Provider` trait. Every operation names its
secret with an `Address`: either the store's own coordinates (a secret's
`ref`) or SecretSpec's `{project}/{profile}/{key}` naming convention, which
your provider compiles into its native coordinates via `convention_address`:

```rust
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn uri(&self) -> String;

    /// Compile SecretSpec's naming convention into the store's native
    /// coordinates. The single owner of the provider's convention layout.
    fn convention_address(&self, project: &str, profile: &str, key: &str)
        -> Result<NativeAddress>;

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>>;
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()>;

    /// Optional, defaults to empty. The `ref` coordinates your store can
    /// honor beyond `item`; every other coordinate is rejected for you.
    fn supported_coords(&self) -> &'static [&'static str] { &[] }

    /// Optional, defaults to writable. Read-only providers reject every
    /// address; providers whose refs name externally managed secrets reject
    /// native addresses only. State the reason: it is what the user sees.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> { Ok(()) }

    /// Optional batch read. The default resolves each request's address and
    /// fetches every unique address once, concurrently; override it when the
    /// store has a real bulk surface (one listing, a batch API).
    fn get_many(&self, requests: &[(&str, Address<'_>)])
        -> Result<HashMap<String, SecretString>> { /* default */ }
}
```

Inside `get`/`set`, call `self.resolve_coords(addr)` to obtain the native
coordinates for any address. It rejects any coordinate outside
`supported_coords` (e.g. a `field` on a flat key/value store), so a `ref`
written for another store fails loudly instead of resolving something else —
you declare the set, you never write the check. Have `set` call
`self.check_writable(addr)?` first, so the pre-check and the write agree on
one refusal message.

## Implementation Steps

1. **Create provider module** in `src/provider/mybackend.rs`
2. **Define config struct** with `Serialize`, `Deserialize`, `Default`, and `TryFrom<&Url>`
3. **Implement provider struct** and use the `register_provider!` macro for automatic registration
4. **Implement Provider trait** for your provider struct
5. **Export from mod.rs**: Add `pub mod mybackend;`

## Example Implementation

```rust
use super::Provider;
use crate::{Result, SecretSpecError};
use url::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyBackendConfig {
    pub endpoint: Option<String>,
}

impl Default for MyBackendConfig {
    fn default() -> Self {
        Self { endpoint: None }
    }
}

impl TryFrom<&Url> for MyBackendConfig {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "mybackend" {
            return Err(SecretSpecError::ProviderOperationFailed(
                format!("Invalid scheme '{}' for mybackend provider", url.scheme())
            ));
        }
        
        // Parse URL into configuration
        Ok(Self {
            endpoint: url.host_str().map(|s| s.to_string()),
        })
    }
}

pub struct MyBackendProvider {
    config: MyBackendConfig,
}

crate::register_provider! {
    struct: MyBackendProvider,
    config: MyBackendConfig,
    name: "mybackend",
    description: "My custom backend provider",
    schemes: ["mybackend"],
    examples: ["mybackend://api.example.com", "mybackend://localhost:8080"],
}

impl MyBackendProvider {
    pub fn new(config: MyBackendConfig) -> Self {
        Self { config }
    }
}

impl Provider for MyBackendProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "mybackend".to_string()
    }

    fn convention_address(&self, project: &str, profile: &str, key: &str)
        -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: format!("secretspec/{}/{}/{}", project, profile, key),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        // Reject coordinates the store cannot honor, then read coords.item
        Ok(None)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let coords = self.resolve_coords(addr)?;
        // Write value at coords.item
        Ok(())
    }
}
```
