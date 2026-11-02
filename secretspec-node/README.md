# secretspec (Node.js SDK)

Node.js / TypeScript bindings for [SecretSpec](https://secretspec.dev/), a
declarative secrets manager. A thin wrapper over a napi-rs native addon
(`secretspec.node`) that statically embeds the Rust resolver, so the SDK inherits
every provider with no JS-side logic and nothing to load at runtime. Resolution
happens in the Rust core.

```js
const { SecretSpec } = require('secretspec');

const resolved = SecretSpec.builder()
  .withProvider('keyring://')
  .withProfile('production')
  .withReason('boot web app')
  .load();

console.log(resolved.provider, resolved.profile);
const db = resolved.secrets.DATABASE_URL;
console.log(db.get());   // the value, or the file path for as_path secrets
resolved.setAsEnv();     // export everything into process.env
```

A missing required secret throws `MissingRequiredError`; any other failure
throws `SecretSpecError` (with a stable `.kind`). TypeScript declarations ship
in `index.d.ts`.

## Scopes (0.17+)

Use `.withScope('api')` to resolve only a named `[scopes.api]` subset. Both
`resolved.scope` and `report.scope` return the selected scope:

```js
const resolved = SecretSpec.builder().withScope('api').load();
```

## Cleanup

In SecretSpec **0.22+**, `as_path` delivery uses memory-backed leases on Linux
and macOS. Install the matching `secretspec` executable beside the application
or on PATH to host the helper. `SECRETSPEC_BIN` can select its location (0.22+). Cleanup releases the complete result, including
hidden file dependencies, through the native lease API. Other platforms,
including Windows, and storage failures return an error without a disk fallback.
Older runtimes retain their existing temporary-file behavior.

Linux helpers require a sufficient `RLIMIT_MEMLOCK` for page-rounded live file
sizes (0.22+). See [file delivery limits](https://secretspec.dev/reference/configuration/#as_path-option).


`as_path` paths remain valid after resolution until cleanup or process exit. Call
`resolved.dispose()` (or `using resolved = builder.load()`) when done so the
secret files do not accumulate in the temp dir.

## Value-free report

`report()` (and `reportAsync()`) returns the inventory/preflight view: per-secret
status and provenance, never a value. Unlike `load()`, it does not throw when a
required secret is missing — it appears as a `SecretReport` with status
`"missing_required"`.

```js
const report = SecretSpec.builder().withProfile('production').report();
for (const s of report.secrets) console.log(s.name, s.status, s.required);
```

## Native addon

The resolver is compiled into the napi-rs addon (`secretspec.node`), so there is
no separate library to locate and no `SECRETSPEC_FFI_LIB` to set. Prebuilt
per-platform addons are published as npm packages (no install-time native build);
from a source checkout the addon is built by `scripts/build-addon.sh`.
