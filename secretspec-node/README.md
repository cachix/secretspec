# secretspec (Node.js SDK)

Node.js / TypeScript bindings for [SecretSpec](https://secretspec.dev/), a
declarative secrets manager. A thin client over the `secretspec-ffi` C ABI,
loaded at runtime via [koffi](https://koffi.dev/) (dlopen). Resolution happens
in the Rust core, so the SDK inherits every provider with no JS-side logic.

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

## Cleanup

`as_path` secrets are materialized to temp files that outlive the call. Call
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

## Library discovery

The native library is found via the `SECRETSPEC_FFI_LIB` environment variable,
or a Cargo `target` directory found by searching up from the working directory.
