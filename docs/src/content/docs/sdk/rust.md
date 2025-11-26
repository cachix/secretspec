---
title: Rust SDK
description: Type-safe Rust integration for SecretSpec
---

SecretSpec provides a Rust library with type-safe access to secrets through a derive macro that generates strongly-typed structs from your `secretspec.toml` file at compile time.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
secretspec = { version = "0.2.0" }
secretspec-derive = { version = "0.2.0" }
```

Basic example:

```rust
// Generate typed structs from secretspec.toml
secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load secrets using the builder pattern
    let secretspec = SecretSpec::builder()
        .with_provider("keyring")  // Can use provider name or URI like "dotenv:/path/to/.env"
        .with_profile("development")  // Can use string or Profile enum
        .load()?;  // All conversions and errors are handled here

    // Access secrets (field names are lowercased)
    println!("Database: {}", secretspec.secrets.database_url);  // DATABASE_URL → database_url

    // Optional secrets are Option<String>
    if let Some(redis) = &secretspec.secrets.redis_url {
        println!("Redis: {}", redis);
    }

    // Access profile and provider information
    println!("Using profile: {}", secretspec.profile);
    println!("Using provider: {}", secretspec.provider);

    // From backwards compatibility, you can tell it to set environment variables
    secretspec.secrets.set_as_env_vars();

    Ok(())
}
```

## Loading with Profile-Specific Types

The `load_profile()` method on the builder provides profile-specific types for your secrets:

```rust
secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load secrets with profile-specific types
    let secrets = Secrets::builder()
        .with_provider("keyring")
        .with_profile(Profile::Production)
        .load_profile()?;

    // Access profile and provider information
    println!("Loaded profile: {}", secrets.profile);
    println!("Using provider: {}", secrets.provider);

    // Access secrets through profile-specific enum
    match secrets.secrets {
        SecretsProfile::Production { database_url, api_key, .. } => {
            // In production: these are String (required)
            println!("Database: {}", database_url);
            println!("API Key: {}", api_key);
        }
        SecretsProfile::Development { database_url, api_key, .. } => {
            // In development: these might be Option<String> if they have defaults
            if let Some(db) = database_url {
                println!("Database: {}", db);
            }
        }
        _ => {}
    }

    Ok(())
}
```

## Secrets as File Paths

Secrets with `as_path = true` are generated as `PathBuf` instead of `String`:

```toml
# secretspec.toml
[profiles.default]
TLS_CERT = { description = "TLS certificate", as_path = true }
TLS_KEY = { description = "TLS private key", as_path = true, required = false }
```

```rust
secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let validated = Secrets::builder().check()?;

    // Required as_path secrets are PathBuf
    let cert_path: &std::path::PathBuf = &validated.secrets.tls_cert;

    // Optional as_path secrets are Option<PathBuf>
    if let Some(key_path) = &validated.secrets.tls_key {
        println!("Key at: {}", key_path.display());
    }

    // Temporary files are cleaned up when `validated` is dropped
    // To persist files beyond the struct's lifetime:
    let paths = validated.keep_temp_files()?;

    Ok(())
}
```
