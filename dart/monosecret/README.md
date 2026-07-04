# monosecret Dart SDK

Dart SDK for invoking Monosecret and loading secrets into Dart applications.

## Overview

The SDK has two layers:

- **`monosecret`** — runtime client that wraps the `monosecret` CLI for ad-hoc secret access and environment loading.
- **`monosecret_builder`** — build_runner generator that produces typed Dart classes from `monosecret.toml` at compile time.

Generated code contains **no secret values**. All values are resolved at runtime through the CLI and your configured providers.

## Installation

```sh
dart pub add monosecret
dart pub add --dev build_runner monosecret_builder
```

## End-to-end setup

### 1. Create `monosecret.toml`

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

### 2. Set secret values

```sh
monosecret set DATABASE_URL --provider dotenv:.env.local
monosecret set API_TOKEN --provider dotenv:.env.local
monosecret check --provider dotenv:.env.local --no-prompt
```

### 3. Create `lib/app_secrets.dart`

```dart
@MonosecretConfig(className: 'AppSecrets')
library app_secrets;

import 'package:monosecret/monosecret.dart';

part 'app_secrets.g.dart';
```

### 4. Run code generation

```sh
dart run build_runner build --delete-conflicting-outputs
```

### 5. Use the generated SDK

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

```dart
import 'package:monosecret/monosecret.dart';

final client = MonosecretClient();

// Get a single secret value.
final databaseUrl = await client.get('DATABASE_URL', profile: 'development');

// Resolve all secrets for the active profile as a Map.
final environment = await client.exportEnvironment(include: ['DATABASE_URL']);

// Run a check (useful in CI).
await client.check(provider: 'dotenv:.env.local', noPrompt: true);
```

`exportEnvironment` uses `monosecret env --shell dotenv` and returns only resolved Monosecret secrets. `loadEnvironment` remains available for the older `monosecret run -- env` behavior.

## CI/CD

```sh
monosecret check --provider env --profile ci --no-prompt
monosecret run --provider env --profile ci -- dart test
```

The `monosecret` CLI must be on `PATH` wherever `AppSecrets.load()` runs.

## Learn more

- [Dart SDK documentation](https://ifiokjr.github.io/monosecret/sdk/dart/)
- [Configuration reference](https://ifiokjr.github.io/monosecret/reference/configuration/)
- [Provider reference](https://ifiokjr.github.io/monosecret/reference/providers/)
