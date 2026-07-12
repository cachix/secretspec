---
title: Rust SDK
description: Type-safe Rust integration for Monosecret
---

Monosecret provides a Rust library with type-safe access to secrets through a derive macro that generates strongly-typed structs from your `monosecret.toml` file at compile time.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
monosecret = { version = "0.1" }
monosecret_derive = { version = "0.1" }
```

Basic example:

```rust
// Generate typed structs from monosecret.toml
monosecret_derive::declare_secrets!("monosecret.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Load secrets using the builder pattern
	let monosecret = Monosecret::builder()
		.with_provider("keyring") // Can use provider name or URI like "dotenv:/path/to/.env"
		.with_profile("development") // Can use string or Profile enum
		.load()?; // All conversions and errors are handled here

	// Access secrets (field names are lowercased)
	println!("Database: {}", monosecret.secrets.database_url); // DATABASE_URL → database_url

	// Optional secrets are Option<String>
	if let Some(redis) = &monosecret.secrets.redis_url {
		println!("Redis: {}", redis);
	}

	// Access profile and provider information
	println!("Using profile: {}", monosecret.profile);
	println!("Using provider: {}", monosecret.provider);

	// From backwards compatibility, you can tell it to set environment variables
	monosecret.secrets.set_as_env_vars();

	Ok(())
}
```

## Loading with Profile-Specific Types

The `load_profile()` method on the builder provides profile-specific types for your secrets:

```rust
monosecret_derive::declare_secrets!("monosecret.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Load secrets with profile-specific types
	let secrets = Monosecret::builder()
		.with_provider("keyring")
		.with_profile(Profile::Production)
		.load_profile()?;

	// Access profile and provider information
	println!("Loaded profile: {}", secrets.profile);
	println!("Using provider: {}", secrets.provider);

	// Access secrets through profile-specific enum
	match secrets.secrets {
		MonosecretProfile::Production {
			database_url,
			api_key,
			..
		} => {
			// In production: these are String (required)
			println!("Database: {}", database_url);
			println!("API Key: {}", api_key);
		}
		MonosecretProfile::Development {
			database_url,
			api_key,
			..
		} => {
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
# monosecret.toml
[profiles.default]
TLS_CERT = { description = "TLS certificate", as_path = true }
TLS_KEY = { description = "TLS private key", as_path = true, required = false }
```

```rust
monosecret_derive::declare_secrets!("monosecret.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let resolved = Monosecret::builder().load()?;

	// Required as_path secrets are PathBuf
	let cert_path: &std::path::PathBuf = &resolved.secrets.tls_cert;
	println!("Certificate at: {}", cert_path.display());

	// Optional as_path secrets are Option<PathBuf>
	if let Some(key_path) = &resolved.secrets.tls_key {
		println!("Key at: {}", key_path.display());
	}

	Ok(())
}
```
