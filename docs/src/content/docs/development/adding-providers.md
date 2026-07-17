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

## Documentation and Release Visibility

The documentation site is built from `main`, so it can describe code that has
not reached the latest SecretSpec release yet. A new provider must not appear
to be available in the currently released binary before it is published.

### Provider page structure

Provider pages should be predictable to scan. Keep the shared sections in the
following relative order, inserting provider-specific topics where readers need
them:

1. A one-sentence description and, for an unreleased provider, the version
   compatibility notice.
2. **At a glance**: the provider name, URI, read/write behavior, best use case,
   authentication, optional build feature or availability, and default storage
   layout.
3. **Quick start**: the shortest useful `set`, `get`, and `run` workflow.
   Assume the reader completes the following setup section first; keep this
   example focused on the successful path.
4. **Setup**: prerequisites, authentication methods, and required permissions.
5. **Configuration**: **URI format**, copyable **URI examples**, and a
   **Project configuration** example showing a checked-in alias used by a
   secret.
6. **Storage model**: the exact provider-native name or path SecretSpec creates,
   including how projects and profiles stay isolated.
7. **Use existing secrets**: how `ref` maps to provider-native coordinates and
   whether referenced secrets are writable.
8. **CI/CD**, when machine authentication or deployment setup differs from
   local use.
9. **Advanced configuration** for optional provider-specific behavior.
10. **Troubleshooting and limitations** or **Security considerations**, when
    there are important operational constraints.

Keep the at-a-glance table compact; explain edge cases in the relevant section
instead of expanding the table. Start with this shape:

```md
## At a glance

| | |
| --- | --- |
| Provider | `mybackend` |
| URI | `mybackend://HOST[/path]` |
| Access | Read and write |
| Best for | The main workload or audience this provider serves |
| Authentication | The identity or credential users need |
| Build feature | `mybackend` |
| Default storage | `secretspec/{project}/{profile}/{key}` |
```

Use sentence case for section headings. If a standard section does not apply,
omit it rather than adding an empty placeholder. Keep command sequences in
**Quick start** and list bare provider specifications in **URI examples** so
the two sections do not repeat one another.

When adding a provider for an upcoming release:

1. Add a version notice near the top of the provider page:

   ```md
   :::note[Version compatibility]
   The MyBackend provider is an upcoming SecretSpec 0.16 feature and is not
   available in SecretSpec 0.15.
   :::
   ```

2. Mark the provider as `(0.16+)` anywhere it appears in a provider list,
   table, selector example, sidebar, landing page, README, or generated
   documentation description.
3. If the provider changes authentication or configuration syntax, show the
   latest released version's working form first, then label the upcoming form
   explicitly. Include a practical fallback such as the environment variable
   used by the released version.
4. Add the provider under the existing `Unreleased` section in `CHANGELOG.md`.

Update every provider location; names otherwise drift out of sync:

1. `docs/src/content/docs/providers/<provider>.md`
2. `docs/astro.config.ts` — sidebar and `starlightLlmsTxt` provider summary
3. `docs/src/content/docs/concepts/providers.md` — available providers table
4. `docs/src/content/docs/reference/providers.md` — provider details and
   security considerations
5. `docs/src/pages/index.astro` — `providerMetadata` and any provider selector
   examples
6. `docs/src/content/docs/quick-start.mdx` — provider selector example
7. `README.md` — provider lists and provider selector example

When the release is published, replace temporary wording such as “upcoming”
and “not available in 0.15” with durable wording such as “Available since
SecretSpec 0.16.” The `(0.16+)` labels may remain where knowing the minimum
version is useful.

Apply the same rule to unreleased CLI commands and configuration fields:
place a version notice beside the command or field, not only on a separate
concept page. Readers often arrive directly from search results.

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
