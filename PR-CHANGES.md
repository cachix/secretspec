# PR: Provider-Relative Secret Locations, Structured Configs & 1Password Environments

**Branch:** `feat/provider-secret-locations`  
**Commits:** 3  
**Files changed:** 12 files / +2,006 lines / −83 lines

---

## Overview

This PR addresses two long-standing pain points:

1. **1Password item sprawl** — currently every secret creates a separate 1Password item (`secretspec/{project}/{profile}/{KEY}`). A project with 20 secrets creates 20 items.
2. **Ambient provider auth** — providers that need auth tokens (like 1Password service accounts) currently rely on environment variables that may or may not be set.

Two new features solve these:

- **Provider-relative secret locations** — many secrets can live inside one provider "root" (e.g. one 1Password item per project/profile, with sections for services and fields for keys)
- **Provider dependency declarations** — providers can declare auth requirements in the config, making dependencies explicit
- **1Password Environments provider** — new `onepassword+env://` scheme for the beta Environments feature

All changes are purely additive at the TOML level — every existing `secretspec.toml` parses identically.

---

## Files Changed

### Core Types (`secretspec/src/config.rs`)

| Type | Purpose |
|------|---------|
| `ProviderConfig` | `[providers]` entry: bare string or structured `{ uri, depends_on }` |
| `ProviderConfigStructured` | Table with `uri` + optional `depends_on` array |
| `ProviderDependency` | Dependency: `{ secret = "SECRET_NAME" }` with optional `as = "ENV_VAR"` (defaults to `secret`) |
| `ProviderRef` | Per-secret provider ref: bare string or detailed `{ provider, path, key }` |
| `ProviderRefDetail` | Location info: `provider` + optional `path` + optional `key` |
| `SecretRequest` | Runtime hints: `path` (section) + `key` (field), defaults to secret name |

All use `#[serde(untagged)]` — backward compatible. String → `Alias`, table → `Structured`/`Detail`.

### Lookup Pipeline (`secretspec/src/secrets.rs`)

- `resolve_provider_ref_uris` returns `Vec<(uri, SecretRequest)>` — carries location hints through resolution
- `get_secret_from_providers` uses `get_with_request` for request-aware lookups
- `resolve_provider_requirements` resolves `[[providers.<name>.depends_on]]` secrets
- Full fallback chain support for structured refs

### Provider Trait (`secretspec/src/provider/mod.rs`)

- `get_with_request(&self, project, key, profile, &SecretRequest)` — default method, delegates to `get()`
- Delegated through `Arc<Provider>` and `PreflightGuard`

### 1Password Item Provider (`secretspec/src/provider/onepassword.rs`)

- `get_with_request` override: section/field navigation within a shared project item
- `OnePasswordSection` struct for parsing 1Password CLI section data
- `strip_op_session_env` made `pub(crate)` for reuse

### 1Password Environments Provider (`secretspec/src/provider/onepassword_env.rs`) — NEW

- `onepassword+env://` scheme: desktop app auth
- `onepassword+env+token://` scheme: service account token auth
- Uses `op environment read <id>` — single call fetches all variables
- **Cached** — the full environment is fetched once and cached for the provider lifetime;
  subsequent `get()`/`get_batch()` calls use the in-memory cache
- Read-only (variables managed in 1Password desktop app)
- ~220 lines — significantly simpler than the item-based provider

### Tests (`secretspec/src/tests.rs`)

38 new tests across 3 categories:
- ProviderRef/ProviderConfig serde roundtrip (8)
- SecretRequest construction and serde (4)
- Provider requirement resolution (4)
- get_with_request default delegation (1)
- Backward compatibility (1)
- OnePassword section deserialization (2)
- OnePasswordEnv config parsing (6)
- OnePasswordEnv provider impl (5)
- Various edge cases (7)

250 total, 0 failures.

### Docs

- `CHANGELOG.md` — rewritten with Motivation section + full breakdown
- `docs/reference/configuration.md` — "Provider References" + "Structured Provider Configs" sections

---

## Configuration Examples

### 1. Basic provider-relative lookup (1Password sections/fields)

Store all secrets in one 1Password item, organized by section:

```toml
[project]
name = "myapp"
revision = "1.0"

[providers]
op-dev = "onepassword://Development"

[profiles.default]
GITHUB_TOKEN = {
  description = "GitHub personal access token",
  providers = [{ provider = "op-dev", path = ["GitHub"], key = "token" }]
}
GITHUB_USER  = {
  description = "GitHub username",
  providers = [{ provider = "op-dev", path = ["GitHub"], key = "user" }]
}
DATABASE_URL = {
  description = "Database connection string",
  providers = [{ provider = "op-dev", path = ["Database"], key = "url" }]
}
AWS_ACCESS_KEY_ID = {
  description = "AWS access key",
  providers = [{ provider = "op-dev", path = ["AWS"], key = "access_key" }]
}
AWS_SECRET_ACCESS_KEY = {
  description = "AWS secret key",
  providers = [{ provider = "op-dev", path = ["AWS"], key = "secret_key" }]
}
```

**Result:** One 1Password item `secretspec/myapp/default` with sections "GitHub", "Database", "AWS", each containing their respective fields.

### 2. Mixed aliases and detailed refs in fallback chains

Use simple aliases as fallbacks when detailed lookups fail:

```toml
[providers]
op-prod = "onepassword://Production"
keyring = "keyring://"

[profiles.production]
API_KEY = {
  description = "External API key",
  providers = [
    { provider = "op-prod", path = ["APIs"], key = "stripe" },
    "keyring"  # fallback to local keyring if not in 1Password
  ]
}
```

### 3. Mapping a 1Password item path

Given the 1Password reference `op://Development/dotfiles/GitHub/GITHUB_TOKEN`:

| Component | Value |
|-----------|-------|
| Vault | `Development` |
| Item | `dotfiles` |
| Section | `GitHub` |
| Field | `GITHUB_TOKEN` |

There are several ways to represent this in `secretspec.toml`:

**A) Provider alias targets the item, key defaults to secret name:**

```toml
[project]
name = "myapp"
revision = "1.0"

[providers]
dotfiles = "onepassword://Development/dotfiles"

[profiles.default]
GITHUB_TOKEN = {
  description = "GitHub personal access token",
  providers = [{ provider = "dotfiles", path = ["GitHub"] }]
  # key defaults to "GITHUB_TOKEN" (the secret name)
}
```

**B) Explicit key for clarity when field names differ:**

```toml
[profiles.default]
GITHUB_TOKEN = {
  description = "GitHub personal access token",
  providers = [{
    provider = "dotfiles",
    path = ["GitHub"],
    key = "GITHUB_TOKEN"  # explicit — matches the 1Password field
  }]
}
DOCKER_PASSWORD = {
  description = "Docker Hub password",
  providers = [{
    provider = "dotfiles",
    path = ["Docker"],
    key = "password"  # SecretSpec name differs from 1Password field
  }]
}
```

**C) Vault-level alias, item in path for multiple items:**

```toml
[providers]
op-dev = "onepassword://Development"

[profiles.default]
GITHUB_TOKEN = {
  description = "GitHub token from dotfiles item",
  providers = [{
    provider = "op-dev",
    path = ["dotfiles", "GitHub"],
    key = "token"
  }]
}
SSH_KEY = {
  description = "SSH key from servers item",
  providers = [{
    provider = "op-dev",
    path = ["servers", "SSH"],
    key = "private_key"
  }]
}
```

### 4. Provider dependencies for 1Password service accounts

Declare that a provider depends on a service account token, which itself is a SecretSpec secret:

```toml
[project]
name = "myapp"
revision = "1.0"

[providers]
keyring = "keyring://"

[providers.op-prod]
uri = "onepassword://Production"
[[providers.op-prod.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"

[profiles.default]
# The service account token itself — stored in the local keyring
OP_SERVICE_ACCOUNT_TOKEN = {
  description = "1Password service account token for Production vault",
  required = true,
  providers = ["keyring"]
}

[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["op-prod"] }
API_KEY      = { description = "Prod API key", providers = ["op-prod"] }
```

The `depends_on` entries accept an optional `as` field to rename the injected
environment variable. When `as` is omitted, it defaults to the secret name:

```toml
[[providers.op-prod.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"
as = "OP_TOKEN"  # exports as OP_TOKEN instead of OP_SERVICE_ACCOUNT_TOKEN
```

The `OP_SERVICE_ACCOUNT_TOKEN` secret is resolved first (from keyring), then the `op-prod` provider can authenticate.

### 5. Profile-specific provider aliases (dev vs. prod vaults)

Different profiles point at different 1Password vaults:

```toml
[providers]
op-dev  = "onepassword://Development"
op-prod = "onepassword://Production"

[profiles.default]
DATABASE_URL = { description = "Dev DB", providers = ["op-dev"] }

[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["op-prod"] }
```

### 6. Cross-project shared config with inheritance

A team-wide `secretspec.toml` defines provider aliases, inherited by individual projects:

```toml
# team-shared/secretspec.toml
[providers]
op-core  = "onepassword://Core"
op-prod  = "onepassword://Production"
keyring  = "keyring://"
env      = "env://"

# myapp/secretspec.toml
[project]
name = "myapp"
revision = "1.0"
extends = ["../team-shared"]

[profiles.default]
DATABASE_URL = { description = "Dev DB", providers = ["op-core", "keyring"] }
```

### 7. 1Password Environments provider (beta)

Use the new `onepassword+env://` scheme for the beta Environments feature:

```toml
[providers]
# Desktop app auth
dev-env  = "onepassword+env://work@blgexucrwfr2dtsxe2q4uu7dp4"

# Service account token in URL
ci-env   = "onepassword+env+token://ops_abc123def456@xyz789"

[profiles.default]
DATABASE_URL = { description = "Dev DB", providers = ["dev-env"] }

[profiles.ci]
DATABASE_URL = { description = "CI DB", providers = ["ci-env"] }
API_KEY      = { description = "CI API key", providers = ["ci-env"] }
```

> **Note:** 1Password Environments are read-only via `op environment read`.
> You cannot set or update environment variables from SecretSpec because
> 1Password does not currently support editing environments through the CLI.
> Variables must be managed directly in the 1Password app.

### 8. Mixed item-based and environment-based providers

Use item-based for secrets that need complex structure, environments for simple key-value:

```toml
[providers]
op-items = "onepassword://Development"
env-vars = "onepassword+env://blgexucrwfr2dtsxe2q4uu7dp4"

[profiles.default]
# Complex secrets stored with sections in items
GITHUB_TOKEN = { description = "GitHub token",
  providers = [{ provider = "op-items", path = ["GitHub"], key = "token" }] }

# Simple env vars from environments
PORT        = { description = "Server port", providers = ["env-vars"] }
LOG_LEVEL   = { description = "Log level", providers = ["env-vars"] }
NODE_ENV    = { description = "Node env", providers = ["env-vars", "env"] }
```

### 9. Self-documenting secret with path-only (key defaults to secret name)

When `key` is omitted, it defaults to the SecretSpec secret name:

```toml
[profiles.default]
# key defaults to "GOOGLE_APPLICATION_CREDENTIALS"
GOOGLE_APPLICATION_CREDENTIALS = {
  description = "GCP service account JSON",
  providers = [{ provider = "op-prod", path = ["Google"] }]
}
```

### 10. Multiple requirements on one provider

A provider can declare multiple dependencies:

```toml
[providers.op-multi]
uri = "onepassword://Team"
[[providers.op-multi.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"
secret = "SOME_API_KEY"

[profiles.default]
OP_SERVICE_ACCOUNT_TOKEN = { description = "OP token", providers = ["keyring"] }
SOME_API_KEY = { description = "API key for auth", providers = ["env"] }
```

### 11. Full CI setup with environments + token

Automated CI using environments with service account tokens stored in keyring:

```toml
[project]
name = "ci-pipeline"
revision = "1.0"

[providers]
keyring = "keyring://"
env     = "env://"

[providers.ci-env]
uri = "onepassword+env+token://abc123def456"
[[providers.ci-env.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"

[profiles.default]
OP_SERVICE_ACCOUNT_TOKEN = {
  description = "1Password CI service account token",
  required = true,
  providers = ["keyring", "env"]
}
DEPLOY_KEY    = { description = "Deploy key", providers = ["ci-env"] }
SLACK_WEBHOOK = { description = "Slack webhook URL", providers = ["ci-env"] }
NPM_TOKEN     = { description = "NPM publish token", providers = ["ci-env"] }
```

---

## Rust SDK Examples

### Constructing ProviderRefs programmatically

```rust
use secretspec::{ProviderRef, ProviderRefDetail, Secret, SecretRequest};

// Simple alias (backward compat)
let alias = ProviderRef::from("keyring");

// Detailed ref with path and key
let detail = ProviderRef::Detail(ProviderRefDetail {
    provider: "op-dev".into(),
    path: Some(vec!["GitHub".into()]),
    key: Some("token".into()),
});

// Secret with mixed providers
let secret = Secret {
    description: "API key".into(),
    required: true,
    providers: Some(vec![detail, alias]),
    ..Default::default()
};

// Create a SecretRequest from a ProviderRef
let request = SecretRequest::from_provider_ref(&detail);
assert_eq!(request.path, Some(vec!["GitHub".into()]));
assert_eq!(request.key, Some("token".into()));
```

### Using Secrets::resolve_provider_requirements

```rust
let secrets = Secrets::load()?;
let requirements = secrets.resolve_provider_requirements("op-prod", "production")?;
// requirements is HashMap<String, SecretString>
// e.g. {"service_token": SecretString("ops_...")}
```

### Using Secrets::load_from with explicit path

```rust
let secrets = Secrets::load_from(Path::new("/path/to/secretspec.toml"))?;
secrets.check(true)?;
```

---

## Backward Compatibility

| Layer | Status |
|-------|--------|
| TOML files | ✅ Bare strings parse as `Alias` — identical behavior |
| Provider trait | ✅ `get_with_request` is defaulted — no changes required |
| Profile-level `providers` | ✅ Still `Vec<String>` — unchanged |
| Global `[defaults.providers]` | ✅ Still `HashMap<String, String>` — unchanged |
| Public API | ✅ New types are additive — nothing removed or renamed |
| Rust struct construction | ⚠️ `Secret { providers: vec!["keyring".into()] }` → `vec![ProviderRef::from("keyring")]` |
