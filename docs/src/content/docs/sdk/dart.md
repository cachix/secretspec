---
title: Dart SDK
description: Runtime and generated Dart access to Monosecret secrets
---

Monosecret provides a Dart SDK with two layers: a **runtime client** that shells out to the `monosecret` CLI, and a **build_runner generator** that produces typed Dart classes from your `monosecret.toml` at compile time.

## How it works

1. **`monosecret_builder`** reads `monosecret.toml` at build time and generates typed enums and structs. The generated code contains **no secret values** — only the shape of your configuration.
2. **`monosecret`** (runtime) wraps the `monosecret` CLI. At runtime, `AppSecrets.load()` calls `monosecret env --shell dotenv` to resolve actual values from your providers.
3. The `monosecret` CLI must be installed and on `PATH` wherever `AppSecrets.load()` runs (local dev, CI, or production).

## Quick start

### 1. Install packages

```sh
dart pub add monosecret
dart pub add --dev build_runner monosecret_builder
```

### 2. Create `monosecret.toml`

```toml
[project]
name = "my-app"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string", required = true }
API_TOKEN = { description = "API authentication token", required = true }

[profiles.development]
DATABASE_URL = { default = "postgresql://localhost/dev" }
```

### 3. Set secret values

```sh
monosecret set DATABASE_URL --provider dotenv:.env.local
monosecret set API_TOKEN --provider dotenv:.env.local
monosecret check --provider dotenv:.env.local --no-prompt
```

### 4. Create `lib/app_secrets.dart`

```dart
@MonosecretConfig(className: 'AppSecrets')
library app_secrets;

import 'package:monosecret/monosecret.dart';

part 'app_secrets.g.dart';
```

### 5. Run code generation

```sh
dart run build_runner build --delete-conflicting-outputs
```

### 6. Use the generated SDK

```dart
import 'app_secrets.dart';

Future<void> main() async {
  final secrets = await AppSecrets.load(
    profile: AppProfile.development,
    provider: 'dotenv:.env.local',
  );

  print(secrets.databaseUrl);

  // Or fetch a single secret at runtime:
  final token = await MonosecretClient().getAppSecret(AppSecret.apiToken);
  print(token);
}
```

## Runtime client

The `MonosecretClient` class wraps the `monosecret` CLI for ad-hoc access without code generation:

```dart
import 'package:monosecret/monosecret.dart';

final client = MonosecretClient();

// Get a single secret value.
final databaseUrl = await client.get('DATABASE_URL', profile: 'development');

// Resolve all secrets for the active profile as a Map.
final environment = await client.exportEnvironment(
  include: ['DATABASE_URL', 'API_TOKEN'],
);

// Run a check (useful in CI).
await client.check(provider: 'dotenv:.env.local', noPrompt: true);
```

- `exportEnvironment` uses `monosecret env --shell dotenv` and returns only resolved Monosecret secrets.
- `loadEnvironment` uses `monosecret run -- env` (includes parent process env vars; prefer `exportEnvironment`).

## CI/CD usage

```sh
# Verify all required secrets are present in CI.
monosecret check --provider env --profile ci --no-prompt

# Run tests with secrets injected as environment variables.
monosecret run --provider env --profile ci -- dart test
```

In a GitHub Actions workflow:

```yaml
- name: Check secrets
  run: monosecret check --provider env --profile ci --no-prompt

- name: Run tests
  run: monosecret run --provider env --profile ci -- dart test
```

## Design principles

- **Generated code is secret-value-free.** The build_runner output contains only configuration metadata (secret names, profiles, types). Actual values are resolved at runtime through the CLI and your configured providers.
- **Runtime requires the `monosecret` CLI.** `AppSecrets.load()` and `MonosecretClient` shell out to `monosecret`, so the CLI must be installed and on `PATH` in every environment that runs your Dart application.
- **The builder reads `monosecret.toml` directly.** No intermediate `monosecret manifest` file is needed — `monosecret_builder` parses the TOML at build time via the `MonosecretConfig(path: ...)` annotation.
