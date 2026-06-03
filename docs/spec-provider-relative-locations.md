# Spec: Provider-Relative Secret Locations & Structured Provider Refs

## Summary

Allow secrets to be stored at provider-relative locations (e.g. a specific field
within a single 1Password item) and let providers declare dependencies on other
secrets for auth/bootstrap. Introduce structured provider references while
preserving full backward compatibility with the existing string-only alias model.

---

## 1. Structured Provider Configs (`[providers]`)

### 1.1 Motivation

Currently `Config.providers` is `Option<HashMap<String, String>>` — an alias
always resolves to a URI string. We need provider entries that can optionally
carry a `[providers.<name>.requires]` table so that auth tokens can be defined
as normal secrets and resolved by the dependency graph before the provider is
used.

### 1.2 New Types

```rust
/// A single entry in `[providers]`.
///
/// Deserialized from TOML via `#[serde(untagged)]` for backward compat:
/// - A bare string is treated as `ProviderConfig::Alias(uri)`.
/// - A table is `ProviderConfig::Structured { uri, requires }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderConfig {
    /// Legacy alias: `keyring = "keyring://"`
    Alias(String),
    /// Structured provider: `op-dotfiles = { uri = "…", requires = { … } }`
    Structured(ProviderConfigStructured),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfigStructured {
    /// The provider URI (required).
    pub uri: String,
    /// Required secrets (resolved before the provider is used).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub requires: HashMap<String, ProviderRequirement>,
}

/// A single dependency declaration under `[providers.<name>.requires]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRequirement {
    /// The Monosecret secret name that provides the value (e.g. `OP_SERVICE_ACCOUNT_TOKEN`).
    pub secret: String,
}
```

### 1.3 Config Change

```diff
- pub providers: Option<HashMap<String, String>>,
+ pub providers: Option<HashMap<String, ProviderConfig>>,
```

Backward compat:

- `providers = "keyring://"` → `ProviderConfig::Alias("keyring://")` via untagged deserialization.
- Both `ProviderConfig::Alias` and `ProviderConfig::Structured` provide a `uri()` accessor.

### 1.4 TOML Example

```toml
[providers]
keyring = "keyring://"
env = "env://"

[providers.op-dotfiles]
uri = "onepassword://Development"
requires = { service_token = { secret = "OP_SERVICE_ACCOUNT_TOKEN" } }
```

---

## 2. Provider References in Per-Secret `providers`

### 2.1 Motivation

Currently `Secret.providers` is `Option<Vec<String>>` — each entry is an alias
name. We need entries that can also carry a provider-relative `path` and `key`
so that a single provider "root" (e.g. a 1Password vault/item) can serve many
secrets at different paths within it.

### 2.2 Model

```
provider root (URI → resolves to a provider instance)
    + path (e.g. ["GitHub"] → section/folder within the store)
        + key  (e.g. "token" → field within that section)
```

- `key` defaults to the Monosecret secret name.
- `path` is `Option<Vec<String>>` — absent means "use provider root directly".

### 2.3 New Types

```rust
/// A single entry in a secret's `providers` list.
///
/// Deserialized via `#[serde(untagged)]`:
/// - A bare string `"env"` → `ProviderRef::Alias("env")` (backward compat).
/// - A table `{ provider = "op-dotfiles", path = ["GitHub"], key = "token" }`
///   → `ProviderRef::Detail { … }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderRef {
    /// Simple alias reference (backward compat).
    Alias(String),
    /// Detailed provider reference with relative location.
    Detail(ProviderRefDetail),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRefDetail {
    /// The provider alias name (resolved against `[providers]`).
    pub provider: String,
    /// Optional path segments within the provider's store (e.g. section, folder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    /// Optional key within that path. Defaults to the Monosecret secret name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}
```

### 2.4 Secret Config Change

```diff
- pub providers: Option<Vec<String>>,
+ pub providers: Option<Vec<ProviderRef>>,
```

### 2.5 TOML Example

```toml
[profiles.default]
# Simple alias — backward compat.
DATABASE_URL = { description = "Dev DB", providers = ["env"] }

# Detailed provider ref with path/key.
GITHUB_TOKEN = {
  description = "GitHub personal access token",
  providers = [
    { provider = "op-dotfiles", path = ["GitHub"], key = "token" }
  ]
}

# Multiple fallbacks can mix aliases and details.
API_KEY = {
  description = "External API key",
  providers = ["keyring", { provider = "op-dotfiles", path = ["APIs"] }]
}
```

---

## 3. Provider Dependency Resolution

### 3.1 Algorithm

1. Collect all provider alias → `ProviderConfig` mappings from `config.providers`
   and `global_config.defaults.providers` (project wins on conflict, same as today).
2. Build a dependency graph: for each provider entry with `requires`, the
   dependency is the secret named in `requires.<name>.secret`.
3. **Topological sort** — check for cycles. Cyclic dependencies are a config
   validation error.
4. **Bootstrap order**: providers with no dependencies are instantiated first.
   Then dependencies are resolved by looking up their required secrets as
   normal monosecret secrets (using the already-instantiated bootstrap
   providers). Once a required secret is available, the dependent provider
   can be instantiated (e.g. with its `OP_SERVICE_ACCOUNT_TOKEN`).

### 3.2 Cycle Detection

```rust
enum ProviderConfigError {
    CycleDetected(Vec<String>),  // the cycle path
}
```

---

## 4. Request-Aware Secret Lookup

### 4.1 New Struct

```rust
/// Carries location hints for provider-relative lookups.
#[derive(Debug, Clone, Default)]
pub struct SecretRequest {
    /// Path segments within the provider (e.g. ["GitHub"]).
    pub path: Option<Vec<String>>,
    /// Key at that path (defaults to secret name).
    pub key: Option<String>,
}
```

### 4.2 Provider Trait — Default Method Addition (No Breaking Change)

Add a **defaulted** method to `Provider` that receives the request:

```rust
pub trait Provider: Send + Sync {
    // … existing methods unchanged …

    /// Look up a single secret with an optional provider-relative location.
    ///
    /// Default implementation delegates to `get(project, key, profile)` ignoring
    /// the `request`. Providers that support path/key navigation override this.
    fn get_with_request(
        &self,
        project: &str,
        key: &str,
        profile: &str,
        request: &SecretRequest,
    ) -> Result<Option<SecretString>> {
        let _ = request; // backward compat: ignore
        self.get(project, key, profile)
    }
}
```

This avoids breaking any existing provider implementations. The 1Password
provider will override `get_with_request` to navigate to the correct
section/field.

---

## 5. Implementation Plan

### Phase 1: Config Types (serde-only)

1. Add `ProviderConfig`, `ProviderConfigStructured`, `ProviderRequirement` to
   `config.rs`.
2. Add `ProviderRef`, `ProviderRefDetail` to `config.rs`.
3. Change `Config.providers` to `Option<HashMap<String, ProviderConfig>>`.
4. Change `Secret.providers` to `Option<Vec<ProviderRef>>`.
5. Add `SecretRequest` to `config.rs`.
6. Add `uri()` helper on `ProviderConfig`.
7. Update `resolve_secret_config` in `secrets.rs` to handle `ProviderRef`
   merging.
8. Update `resolve_provider_aliases` and `resolve_read_provider_uris` to
   work with `ProviderRef`.

### Phase 2: Provider Dependency Graph

1. Add `ProviderDependencyResolver` in a new module or within `secrets.rs`.
2. Topological sort with cycle detection.
3. Resolve required secrets before instantiating dependent providers.

### Phase 3: Request-Aware Lookup

1. Add `SecretRequest` type.
2. Add default `get_with_request` on `Provider` trait.
3. Pass `SecretRequest` through the lookup pipeline in `Secrets`.
4. Override `get_with_request` in `OnePasswordProvider`.

### Phase 4: 1Password Section/Field Lookup

1. Update `OnePasswordProvider::get_with_request` to use `request.path`
   as section name and `request.key` as field label.
2. Fetch the shared project item once, then extract multiple fields from it
   (batch-friendly).

### Phase 5: Tests

1. Backward-compat tests: string aliases in `[providers]` and `Secret.providers`.
2. Mixed ProviderRef tests: strings and tables in the same list.
3. Structured provider tests with `requires`.
4. Cycle detection tests.
5. Integration tests for 1Password section/field lookup (if `op` available).
6. All existing tests must continue to pass.

### Phase 6: Docs & Changelog

1. Update `docs/src/content/docs/reference/configuration.md`.
2. Update `CHANGELOG.md`.
3. Update provider docs if needed.

---

## 6. Backward Compatibility Guarantees

| Existing feature             | Status                          |
| ---------------------------- | ------------------------------- |
| `[providers]` string aliases | Untouched, supported            |
| `Secret.providers` strings   | Untouched, supported            |
| `ProfileDefaults.providers`  | Unchanged (`Vec<String>` stays) |
| `GlobalDefaults.providers`   | Unchanged (aliases only)        |
| Provider trait               | No signature changes            |
| All existing tests           | Must pass without edits         |
