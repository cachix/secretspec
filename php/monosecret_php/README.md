# Monosecret PHP SDK

A thin PHP client over the same Rust resolver every [Monosecret](https://ifiokjr.github.io/monosecret)
SDK uses. Resolution — providers, fallback chains, profiles, generation,
`as_path` — happens in the core, so the SDK inherits every provider with no
PHP-side logic.

It reaches the resolver through one of two native backends over an identical JSON
contract, preferring the first that is available:

1. **The `monosecret` PHP extension** (built with
   [ext-php-rs](https://github.com/davidcole1340/ext-php-rs), crate
   `monosecret-php-native`) embeds the resolver like `ext-redis` does — no
   `ffi.enable`, works under PHP-FPM. Recommended for Laravel/Symfony.
2. **`ext-ffi`** dlopens the `libmonosecret_ffi` shared library at runtime. Nothing
   to compile; ideal for CLI and local development.

## Install (planned for Monosecret 0.2+)

Composer and native artifact publication are deferred. The following command
shows the intended workflow after release; contributors should use this source
checkout and the local test instructions below.

```bash
composer require ifiokjr/monosecret
```

Then enable one backend: install the `monosecret-php-native` extension (a prebuilt
`.so` from the [releases](https://github.com/ifiokjr/monosecret/releases), or built
from source), or enable FFI (`extension=ffi`, `ffi.enable=true`) and run
`vendor/bin/monosecret-install-lib` to fetch the native library. See the
[PHP SDK docs](https://ifiokjr.github.io/monosecret/sdk/php) for details, plus Laravel and
Symfony integration.

## Usage

```php
<?php

use Monosecret\Monosecret;

$resolved = Monosecret::builder()
    ->withProvider('keyring://')
    ->withProfile('production')
    ->withReason('boot web app')
    ->load();

echo $resolved->secrets['DATABASE_URL']->get();  // value, or file path for as_path
$resolved->setAsEnv();                            // export into getenv()/$_ENV/$_SERVER
```

A missing required secret throws `Monosecret\MissingRequiredException`; any other
failure throws `Monosecret\MonosecretException` (with a stable `->kind`).

## Scopes (schema v2)

Use `withScope('api')` to resolve only a named `[scopes.api]` subset. Both
`$resolved->scope` and `$report->scope` return the selected scope:

```php
$resolved = Monosecret::builder()->withScope('api')->load();
```

## Development

The SDK talks to the resolver built from this repository. The Composer manifest
lives at the repo root (so Packagist reads it from the monorepo); `vendor-dir`
points back here, so tests still run from `php/monosecret_php/`. From a `devenv shell`:

```bash
composer install                 # run at the repo root; installs to php/monosecret_php/vendor

# Backend 1: ext-ffi fallback. Build the cdylib; it is discovered via the
# nearest Cargo target/ dir (or set MONOSECRET_FFI_LIB).
cargo build -p monosecret_ffi
( cd php/monosecret_php && ./vendor/bin/phpunit )

# Backend 2: the native extension. Build and load it.
bash php/monosecret_php/scripts/build-ext.sh
( cd php/monosecret_php && php -d extension="$PWD/lib/monosecret.so" ./vendor/bin/phpunit )
```

`tests/ConformanceTest.php` runs the shared cross-language conformance fixtures
in `../../conformance/fixtures`.
