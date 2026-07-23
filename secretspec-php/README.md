# SecretSpec PHP SDK

A thin PHP client over the same Rust resolver every [SecretSpec](https://secretspec.dev)
SDK uses. Resolution — providers, fallback chains, profiles, generation,
`as_path` — happens in the core, so the SDK inherits every provider with no
PHP-side logic.

It reaches the resolver through one of two native backends over an identical JSON
contract, preferring the first that is available:

1. **The `secretspec` PHP extension** (built with
   [ext-php-rs](https://github.com/davidcole1340/ext-php-rs), crate
   `secretspec-php-native`) embeds the resolver like `ext-redis` does — no
   `ffi.enable`, works under PHP-FPM. Recommended for Laravel/Symfony.
2. **`ext-ffi`** dlopens the `secretspec-ffi` shared library at runtime. Nothing
   to compile; ideal for CLI and local development.

## Install

```bash
composer require cachix/secretspec
```

Then enable one backend: install the `secretspec-php-native` extension (a prebuilt
`.so` from the [releases](https://github.com/cachix/secretspec/releases), or built
from source), or enable FFI (`extension=ffi`, `ffi.enable=true`) and run
`vendor/bin/secretspec-install-lib` to fetch the native library. See the
[PHP SDK docs](https://secretspec.dev/sdk/php) for details, plus Laravel and
Symfony integration.

## Usage

```php
<?php

use Secretspec\SecretSpec;

$resolved = SecretSpec::builder()
    ->withProvider('keyring://')
    ->withProfile('production')
    ->withReason('boot web app')
    ->load();

echo $resolved->secrets['DATABASE_URL']->get();  // value, or file path for as_path
$resolved->setAsEnv();                            // export into getenv()/$_ENV/$_SERVER
```

A missing required secret throws `Secretspec\MissingRequiredException`; any other
failure throws `Secretspec\SecretSpecException` (with a stable `->kind`).

## Scopes (0.17+)

Use `withScope('api')` to resolve only a named `[scopes.api]` subset. Both
`$resolved->scope` and `$report->scope` return the selected scope:

```php
$resolved = SecretSpec::builder()->withScope('api')->load();
```

## Development

The SDK talks to the resolver built from this repository. The Composer manifest
lives at the repo root (so Packagist reads it from the monorepo); `vendor-dir`
points back here, so tests still run from `secretspec-php/`. From a `devenv shell`:

```bash
composer install                 # run at the repo root; installs to secretspec-php/vendor

# Backend 1: ext-ffi fallback. Build the cdylib; it is discovered via the
# nearest Cargo target/ dir (or set SECRETSPEC_FFI_LIB).
cargo build -p secretspec-ffi
( cd secretspec-php && ./vendor/bin/phpunit )

# Backend 2: the native extension. Build and load it.
bash secretspec-php/scripts/build-ext.sh
( cd secretspec-php && php -d extension="$PWD/lib/secretspec.so" ./vendor/bin/phpunit )
```

`tests/ConformanceTest.php` runs the shared cross-language conformance fixtures
in `../conformance/fixtures`.
