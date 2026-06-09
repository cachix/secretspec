---
title: Node.js SDK
description: Resolve SecretSpec secrets from Node.js and TypeScript
---

The Node.js / TypeScript SDK (`secretspec`) is a thin wrapper over a
[napi-rs](https://napi.rs/) native addon that embeds the resolver. Resolution
happens in the Rust core, so the SDK inherits every provider with no JS-side
logic, and `npm install` needs no native build. TypeScript declarations ship in
`index.d.ts`.

## Quick start

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
throws `SecretSpecError` (with a stable `.kind`).

## Typed access (codegen)

Generate typed interfaces with `secretspec schema` plus
[quicktype](https://quicktype.io), then convert `resolved.fieldsJson()`:

```bash
secretspec schema | quicktype -s schema --lang typescript -o secrets_gen.ts
```

```ts
import { Convert } from './secrets_gen'; // typed, generated

const typed = Convert.toSecretSpec(resolved.fieldsJson());
console.log(typed.DATABASE_URL);
```
