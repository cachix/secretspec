---
title: Adding a New Provider
description: Step-by-step guide for implementing custom provider backends
---

## Provider Trait

All providers must implement the `Provider` trait:

```rust
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<String>>;
    fn set(&self, project: &str, key: &str, value: &str, profile: &str) -> Result<()>;
    fn allows_set(&self) -> bool { true }  // Optional, defaults to true
}
```

## Implementation Steps

1. **Create provider module** in `src/provider/mybackend.rs`
2. **Define config struct** with `Serialize`, `Deserialize`, `Default`, and `TryFrom<&Url>`
3. **Implement provider struct** and use the `register_provider!` macro for automatic registration
4. **Implement Provider trait** for your provider struct
5. **Export from mod.rs**: Add `pub mod mybackend;`

## Example Implementation

```rust
use super::Provider;
use crate::{Result, MonosecretError};
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
    type Error = MonosecretError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "mybackend" {
            return Err(MonosecretError::ProviderOperationFailed(
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

    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<String>> {
        // Implementation
        Ok(None)
    }

    fn set(&self, project: &str, key: &str, value: &str, profile: &str) -> Result<()> {
        // Implementation
        Ok(())
    }
}
```
