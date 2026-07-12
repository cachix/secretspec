# @monosecret/client

The canonical Node.js and TypeScript client for [Monosecret](https://github.com/ifiokjr/monosecret). It preserves the existing typed CLI client and also provides an additive, embedded native resolver backed by napi-rs.

## Install

```sh
pnpm add @monosecret/client
```

Install `@monosecret/cli` as well when using the subprocess API:

```sh
pnpm add @monosecret/client @monosecret/cli
```

## Existing CLI API

```ts
import { MonosecretClient } from "@monosecret/client";

const client = new MonosecretClient();
const databaseUrl = await client.get("DATABASE_URL", {
  profile: "development",
});
await client.check({ noPrompt: true });
```

By default, `MonosecretClient` runs `monosecret` from `PATH`. Pass `executable`, `workingDirectory`, or `environment` to customize the child process. Importing this API does not load the native addon.

## Embedded native API

```ts
import { Monosecret } from "@monosecret/client";

const resolved = await Monosecret.builder()
  .withPath("monosecret.toml")
  .withProfile("development")
  .loadAsync();

try {
  console.log(resolved.fields());
} finally {
  resolved.dispose();
}
```

Use `loadAsync()` and `reportAsync()` for network-backed providers. Their synchronous counterparts are useful for short local resolution but block the Node.js event loop. Native loading is lazy and resolves the matching optional `@monosecret/client-<platform>` package only when this API is called.

Publication of the native platform packages—and therefore publication of this
updated canonical package manifest—is deferred. Native development remains
available from a source checkout with `pnpm run build:native`.
