# @monosecret/client

TypeScript client for [Monosecret](https://github.com/ifiokjr/monosecret), implemented as a small typed wrapper around the `monosecret` CLI.

## Install

```sh
pnpm add @monosecret/client @monosecret/cli
```

## Usage

```ts
import { MonosecretClient } from '@monosecret/client';

const monosecret = new MonosecretClient();

const databaseUrl = await monosecret.get('DATABASE_URL', {
  profile: 'development',
});

await monosecret.check({ noPrompt: true });

const environment = await monosecret.loadEnvironment({
  include: ['DATABASE_URL', 'API_KEY'],
});
```

By default the client runs `monosecret` from `PATH`. Pass `executable`, `workingDirectory`, or `environment` to customize the child process.
