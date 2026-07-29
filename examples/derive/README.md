# SecretSpec Code Generation Example

This example demonstrates how to use SecretSpec's proc macro to create strongly-typed secret structs.

## How it works

1. The `secretspec_derive::declare_secrets!()` macro generates Rust structs from `secretspec.toml` at compile time
2. The generated types include:
   - `SecretSpec` struct with union types (safe for any profile)
   - `SecretSpecProfile` enum with profile-specific field types
   - `Profile` enum with all profiles from your TOML
   - Methods for loading from different providers and profiles

## Running the example

```bash
# From this directory
cargo run

# Or from the workspace root
cargo run -p secretspec-derive-example
```

## Generated Code

The proc macro generates types like this:

```rust
// Union type struct (safe for any profile)
pub struct SecretSpec {
    pub database_url: String,
    pub api_key: String,
    pub redis_url: String,
    pub session_secret: String,
}

// Profile-specific enum
pub enum SecretSpecProfile {
    Default {
        database_url: String,
        api_key: String,
        redis_url: String,
        session_secret: String,
    },
    Development {
        database_url: String,          // Guaranteed by its development default
        api_key: String,               // Guaranteed by its development default
        redis_url: String,             // Guaranteed by its development default
        session_secret: String,        // Development-only default
    },
    Production {
        database_url: String,
        api_key: String,
        redis_url: String,
        session_secret: String,
    }
}

impl SecretSpec {
    pub fn load(provider: Provider) -> Result<Self, SecretSpecError> { ... }
    pub fn load_profile(provider: Provider, profile: Profile) -> Result<SecretSpecProfile, SecretSpecError> { ... }
    pub fn set_as_env_vars(&self) { ... }
}
```
