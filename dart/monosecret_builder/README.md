# monosecret_builder

Build runner generator for typed Dart access to `monosecret.toml` manifests.

## What it does

`monosecret_builder` reads your `monosecret.toml` at build time and generates:

- A typed secrets class (e.g. `AppSecrets`) with fields matching your secret names
- A `Profile` enum for profile-specific loading
- Extension methods on `MonosecretClient` for single-secret access

Generated code contains **no secret values** — only configuration metadata. Values are resolved at runtime through the `monosecret` CLI.

## Quick start

```dart
@MonosecretConfig(className: 'AppSecrets')
library app_secrets;

import 'package:monosecret/monosecret.dart';

part 'app_secrets.g.dart';
```

Run:

```sh
dart run build_runner build --delete-conflicting-outputs
```

## Learn more

- [Dart SDK documentation](https://ifiokjr.github.io/monosecret/sdk/dart/) — full end-to-end setup guide
- [Configuration reference](https://ifiokjr.github.io/monosecret/reference/configuration/)
