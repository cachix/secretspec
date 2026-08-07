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

    /// Optional, defaults to writable. Reject only the addresses the provider
    /// cannot safely write: for example every address on a read-only provider,
    /// or version-pinned and ARN refs on an otherwise writable provider. State
    /// the reason: it is what the user sees.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> { Ok(()) }

    /// SecretSpec 0.19+: optional, defaults to Persist. Return Ephemeral only
    /// when generated values should be returned for one resolution without
    /// calling `set`; ordinary writes remain governed by `check_writable`.
    fn generated_value_persistence(&self) -> GeneratedValuePersistence {
        GeneratedValuePersistence::Persist
    }

    /// SecretSpec 0.19+: optional pre-write description. The default renders
    /// native coordinates; file-backed providers should include the resolved
    /// file/container and selector. Never include credentials.
    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        /* default */
    }

    /// Optional batch read. The default resolves each request's address and
    /// fetches every unique address once, concurrently; override it when the
    /// store has a real bulk surface (one listing, a batch API).
    fn get_many(&self, requests: &[(&str, Address<'_>)])
        -> Result<HashMap<String, SecretString>> { /* default */ }

    /// SecretSpec 0.18+: optional discovery hook used to build secret
    /// declarations from a provider. Return definitions only; never put values
    /// in descriptions or other manifest fields. Flat stores can ignore the
    /// context; hierarchical stores use it to bound discovery.
    fn reflect(&self, context: DiscoveryContext<'_>)
        -> Result<HashMap<String, Secret>> { /* unsupported */ }
}
```

Inside `get`/`set`, call `self.resolve_coords(addr)` to obtain the native
coordinates for any address. It rejects any coordinate outside
`supported_coords` (e.g. a `field` on a flat key/value store), so a `ref`
written for another store fails loudly instead of resolving something else —
you declare the set, you never write the check. Have `set` call
`self.check_writable(addr)?` first, so the pre-check and the write agree on
one refusal message.

SecretSpec 0.19+ also exposes `generated_value_persistence`. Leave its default
of `Persist` for storage providers. `Ephemeral` is an explicit generation-only
capability: after a healthy read miss, SecretSpec returns the generated logical
value for the current materializing resolution without calling `set` or
refreshing a cache. It does not make ordinary writes succeed and must be a pure,
I/O-free capability check.

In SecretSpec 0.19+, override `describe_write_target` when the provider URI and
native coordinates do not identify the physical destination clearly. The
`secretspec set` and interactive `secretspec check` commands print this
description before they read or prompt for a value; SDK and library writes do
not print it. The method must be pure with respect to the backing store:
resolving and formatting a path is fine, but it must not create the file or
directory. Keep the description credential-free, just like `uri()`.

### Convention templates

When a provider lets users replace its complete convention layout, call that
option `template` and support the `{project}`, `{profile}`, and `{key}`
placeholders. Reserve `prefix` for an option that only prepends literal text to
an otherwise fixed convention. For example, a hierarchical provider might use:

```text
mybackend://account?template=/{profile}/{project}/{key}
```

Render the template only in `convention_address`, then validate the resulting
native name before any provider I/O. This keeps `get`, `set`, batch reads,
generation, and imports in the same address space. Document when a template
omits a placeholder intentionally; in particular, omitting `{key}` can make
several declarations target the same stored value.

### Discovery and `init --from`

SecretSpec 0.18+ passes a `DiscoveryContext` to the `reflect(context)`
discovery hook. During `secretspec init --from PROVIDER`, the CLI constructs
the provider, calls that hook, and turns the returned map into declarations in
a new manifest. Flat stores such as dotenv and age ignore the context;
hierarchical stores use it to bound discovery. A reflected `Secret` describes
the discovered key; do not copy its value into the description, default, or
any other committed field.

`secretspec import PROVIDER` is different: it does **not** call
`reflect(context)` or enumerate the source. It iterates the secrets
already declared in the active and default profiles and copies their values
into the configured destination. Implement the reflection hook for manifest
discovery, not to change import semantics. SecretSpec 0.18+ accepts any
provider that implements the hook as an `init --from` source. Use `--project`
and `--profile` when the provider's convention needs context other than the
current directory name and the `default` profile.

For a hierarchical store, reflection must have a bounded namespace and a
reversible mapping from native names to SecretSpec keys. A configured template
such as `/{profile}/{project}/{key}` provides both: render it with
`DiscoveryContext`, list the prefix before `{key}`, reject nested or otherwise
ambiguous results, and return the remaining key names. Do not list an entire
account or vault as a fallback.

The reflection hook returns declarations, not values, so it is also not a
runtime namespace-injection API. A Chamber-style “export everything under this
path” feature would need a separate value-bearing contract or an intentional
extension of the provider trait.

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
   The MyBackend provider is added in SecretSpec 0.16.
   :::
   ```

2. Mark the provider as `(0.16+)` anywhere it appears in a provider list,
   table, selector example, sidebar, landing page, README, or generated
   documentation description.
3. If the provider changes authentication or configuration syntax, label the
   new form explicitly with its target version.
4. Add the provider under the existing `Unreleased` section in `CHANGELOG.md`.

Update every provider location; names otherwise drift out of sync:

1. `docs/src/content/docs/providers/<provider>.md` (or `.mdx` when it renders
   the provider credential catalog)
2. `docs/astro.config.ts` — sidebar and `starlightLlmsTxt` provider summary
3. `docs/src/content/docs/concepts/providers.mdx` — available providers table
4. `docs/src/content/docs/reference/providers.md` — provider details and
   security considerations
5. `docs/src/pages/index.astro` — `providerMetadata` and any provider selector
   examples
6. `docs/src/content/docs/quick-start.mdx` — provider selector example
7. `README.md` — provider lists and provider selector example

If the provider accepts injected provider credentials, also update
`docs/src/data/provider-credentials.json`. Record every semantic credential
name in the Rust registration's order, its ordered environment fallbacks, its
minimum SecretSpec version, and the implementation files where those fallbacks
are defined. Use an `.mdx` provider page with exactly one
`## Provider credentials` section and render the shared component there:

```mdx
import ProviderCredentials from '../../../components/ProviderCredentials.astro';

## Provider credentials

<ProviderCredentials provider="mybackend" />
```

The catalog also renders the complete
[provider credentials reference](/reference/provider-credentials/), and every
provider-specific component links back to it.

Run `npm --prefix docs run check:provider-credentials`. It rejects missing or
stale catalog entries, environment fallbacks without implementation backlinks,
and credential-aware provider pages that do not render their catalog entry.

Use durable wording such as “Added in SecretSpec 0.16.” The `(0.16+)` labels
may remain where knowing the minimum version is useful.

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
