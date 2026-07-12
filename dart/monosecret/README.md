# monosecret Dart SDK

Native Dart SDK for resolving Monosecret secrets in server applications without installing the `monosecret` CLI.

## Requirements

- Dart 3.10 or later
- Linux with glibc, macOS, or Windows
- x64 or ARM64

The package uses a Dart build hook to download the matching `monosecret_ffi` release library. The hook verifies its SHA-256 sidecar before registering it as a bundled Dart code asset. Android, iOS, Dart web, and Linux musl are not supported.

## Installation

```sh
dart pub add monosecret
```

For generated typed accessors:

```sh
dart pub add --dev build_runner monosecret_builder
```

## Resolve secrets

```dart
import 'package:monosecret/monosecret.dart';

Future<void> main() async {
  final resolved = await Monosecret.builder()
      .withPath('monosecret.toml')
      .withProfile('production')
      .withProvider('env://')
      .withReason('Start the API server')
      .load();

  try {
    print(resolved.secrets['DATABASE_URL']?.usable);
  } finally {
    await resolved.close();
  }
}
```

`Resolved.close()` removes temporary files created for `as_path` secrets. Secret values are copied into Dart-managed strings and cannot be reliably zeroized; prefer reports, `no_values`, or `as_path` where appropriate.

## Value-free reports

```dart
final report = await Monosecret.builder()
    .withProfile('production')
    .withReason('Deployment preflight')
    .report();

for (final secret in report.secrets) {
  print('${secret.name}: ${secret.status}');
}
```

Reports describe resolution status and provenance without copying secret values across the native boundary.

## Filtering

```dart
final resolved = await Monosecret.builder()
    .withInclude(['DATABASE_URL'])
    .withGroups(['backend'])
    .withReason('Start backend workers')
    .load();
```

Includes and groups are combined as a union and applied before required-secret validation.

## Convenience client

```dart
const client = MonosecretClient();

final token = await client.get(
  'API_TOKEN',
  profile: 'production',
  reason: 'Authenticate an upstream request',
);

final environment = await client.exportEnvironment(
  groups: ['backend'],
  reason: 'Configure the server process',
);
```

Use `resolve()` instead of `get()` or `exportEnvironment()` when consuming `as_path` secrets so their lifetime can be closed explicitly.

## Typed generated access

Create a library:

```dart
@MonosecretConfig(className: 'AppSecrets')
library app_secrets;

import 'package:monosecret/monosecret.dart';

part 'app_secrets.g.dart';
```

Generate it:

```sh
dart run build_runner build --delete-conflicting-outputs
```

Generated code contains configuration shape only. Values are always resolved at runtime by the bundled native resolver.

## Native artifact integrity

Published package versions download an identically versioned GitHub release asset. The release pipeline builds and attests each C ABI library before publishing the Dart package. The build hook rejects missing assets, unsupported platforms, non-successful downloads, malformed checksum sidecars, and SHA-256 mismatches.

Repository development uses `hooks.user_defines.monosecret.native_library_directory` to select a locally built `target/debug` library instead of downloading a release.

## Learn more

- [Dart SDK documentation](https://ifiokjr.github.io/monosecret/sdk/dart/)
- [Configuration reference](https://ifiokjr.github.io/monosecret/reference/configuration/)
- [Provider reference](https://ifiokjr.github.io/monosecret/reference/providers/)
