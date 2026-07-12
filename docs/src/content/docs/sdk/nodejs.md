---
title: Node.js SDK
description: Resolve Monosecret secrets from Node.js and TypeScript
---

`@monosecret/client` is the sole canonical Node.js package. Its existing `MonosecretClient` subprocess API remains available, and an additive napi-rs API embeds the Rust resolver behind lazily loaded `@monosecret/client-<platform>` optional dependencies.

## Install

```sh
pnpm add @monosecret/client
```

Add `@monosecret/cli` when using `MonosecretClient`.

## Embedded resolver

```ts
import { Monosecret } from "@monosecret/client";

const resolved = await Monosecret.builder()
  .withProvider("keyring://")
  .withProfile("production")
  .withReason("boot web app")
  .loadAsync();

try {
  console.log(resolved.provider, resolved.profile);
  console.log(resolved.secrets.DATABASE_URL?.get());
} finally {
  resolved.dispose();
}
```

Use the asynchronous methods for provider I/O. A missing required secret throws `MissingRequiredError`; any other failure throws `MonosecretError` with a stable `.kind`.

## Existing CLI client

```ts
import { MonosecretClient } from "@monosecret/client";

const client = new MonosecretClient();
const value = await client.get("DATABASE_URL", { profile: "production" });
```

Importing and using `MonosecretClient` does not load the native addon.
