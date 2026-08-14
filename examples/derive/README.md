# Monosecret Code Generation Example

This example demonstrates how to use Monosecret's proc macro to create strongly-typed secret structs.

## How it works

1. The `monosecret_derive::declare_secrets!()` macro generates Rust structs from `monosecret.toml` at compile time
2. The generated types include:
   - `Monosecret` struct with union types (safe for any profile)
   - `MonosecretProfile` enum with profile-specific field types
   - `Profile` enum with all profiles from your TOML
   - Methods for loading from different providers and profiles

## Running the example

```bash
# From this directory
cargo run

# Or from the workspace root
cargo run -p monosecret_derive-example --bin derive
```

## Generated Code

The proc macro generates types like this:

```rust
// Union type struct (safe for any profile)
pub struct Monosecret {
    pub database_url: String,
    pub api_key: String,
    pub redis_url: String,
    pub session_secret: String,
}

// Profile-specific enum
pub enum MonosecretProfile {
    Development {
        database_url: Option<String>,
        api_key: Option<String>,
        redis_url: Option<String>,
        session_secret: Option<String>,
    },
    Production {
        database_url: String,
        api_key: String,
        redis_url: String,
        session_secret: String,
    }
}

impl Monosecret {
    pub fn builder() -> MonosecretBuilder { ... }
    pub fn set_as_env_vars(&self) { ... }
}

impl MonosecretBuilder {
    pub fn load(self) -> Result<Resolved<Monosecret>, MonosecretError> { ... }
    pub fn load_profile(self) -> Result<Resolved<MonosecretProfile>, MonosecretError> { ... }
}
```
