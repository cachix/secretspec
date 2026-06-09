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

## Library discovery

The native library is found via the `SECRETSPEC_FFI_LIB` environment variable,
or a Cargo `target` directory found by searching up from the working directory.
