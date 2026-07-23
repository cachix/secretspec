---
title: PHP SDK
description: Resolve SecretSpec secrets from PHP, Laravel, and Symfony
---

The PHP SDK (`cachix/secretspec`) is a thin client over the same Rust resolver
every other SecretSpec SDK uses, so it inherits every provider, chain, profile,
and generator with no PHP-side logic. It reaches the resolver through one of two
native backends over an identical JSON contract:

- **The `secretspec` PHP extension** (built with
  [ext-php-rs](https://github.com/davidcole1340/ext-php-rs)) embeds the resolver
  the way `pdo` or `redis` do. It needs no `ffi.enable` and works under PHP-FPM
  and the web SAPI out of the box — the recommended path for Laravel and Symfony.
- **`ext-ffi`** dlopens the `secretspec-ffi` shared library at runtime. Nothing
  to compile, ideal for CLI tools and local development; requires the FFI
  extension enabled.

The SDK prefers the extension whenever it is loaded and transparently falls back
to `ext-ffi`, so your application code is the same either way.

## Install

```bash
composer require cachix/secretspec
```

That installs the pure-PHP client. Then provide the native resolver with **one**
of the backends below.

### Option A — the PHP extension (recommended for web / FPM)

The `secretspec-php-native` extension embeds the resolver, so it works under
PHP-FPM with no `ffi.enable` and nothing to locate at runtime — the same
operational model as `ext-redis` or `ext-imagick` (the binary is provisioned at
the image/host level, not by Composer). Install it one of three ways:

- **Prebuilt binary** — download the `secretspec-php-native-<php>-nts-<target>`
  shared object for your PHP version and platform from the
  [GitHub release](https://github.com/cachix/secretspec/releases), then enable
  it in `php.ini`:

  ```ini
  extension=/path/to/secretspec-php-native.so
  ```

  In an official PHP Docker image, drop it into the extension dir and
  `docker-php-ext-enable secretspec-php-native`.

- **Build from source** (needs the Rust toolchain, `php-config`, and libclang):

  ```bash
  cargo build --release -p secretspec-php-native
  # then point extension= at target/release/libsecretspec_php_native.so
  ```

Once loaded, `php -m` lists `secretspec-php-native` and the SDK uses it
automatically.

### Option B — ext-ffi (quick start / CLI)

The FFI backend dlopens the `secretspec-ffi` library at runtime. Enable the
bundled FFI extension — in CLI it is on by default; for the web SAPI set:

```ini
extension=ffi
ffi.enable=true
```

Then fetch the native library for your platform (a one-time step; Composer does
not run it automatically):

```bash
vendor/bin/secretspec-install-lib
```

That downloads the right `secretspec-ffi` library from the matching GitHub
release into the package. Alternatively, point `SECRETSPEC_FFI_LIB` at a library
you built or placed yourself. The SDK looks at `SECRETSPEC_FFI_LIB` first, then
the downloaded copy, then a local Cargo `target/` directory.

## Quick start

```php
<?php

use Secretspec\SecretSpec;

$resolved = SecretSpec::builder()
    ->withProvider('keyring://')
    ->withProfile('production')
    ->withReason('boot web app')
    ->load();

echo $resolved->provider, ' ', $resolved->profile, PHP_EOL;

$db = $resolved->secrets['DATABASE_URL'];
echo $db->get();        // the value, or the file path for as_path secrets

$resolved->setAsEnv();  // export everything into getenv()/$_ENV/$_SERVER
```

A missing required secret throws `Secretspec\MissingRequiredException` (with a
`->missing` list); any other failure throws `Secretspec\SecretSpecException`
(with a stable `->kind`).

There is also a one-shot form using named arguments:

```php
$resolved = SecretSpec::resolve(provider: 'keyring://', reason: 'boot');
```

## Scopes (0.17+)

Use `withScope('api')` to resolve only a named `[scopes.api]` subset. The
selected name is available as `$resolved->scope` and `$report->scope`:

```php
$resolved = SecretSpec::builder()->withScope('api')->load();
```

## Laravel

Resolve your secrets early and export them so Laravel's `env()` and config see
them. A service provider is a natural home:

```php
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Secretspec\SecretSpec;

class SecretSpecServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        SecretSpec::builder()
            ->withProfile(app()->environment())   // "production", "local", ...
            ->withReason('laravel boot')
            ->load()
            ->setAsEnv();
    }
}
```

Register it first in `bootstrap/providers.php` so the secrets are present before
other providers read configuration. Because `setAsEnv()` also populates `$_ENV`
and `$_SERVER`, the `env()` helper and any `config/*.php` that calls `env(...)`
resolve normally.

> If you run `php artisan config:cache`, configuration is frozen at cache time
> and `env()` is not read per request. Either resolve before caching, or bind the
> `Resolved` into the container and read secrets from it directly where you need
> them.

## Symfony

Export the secrets in the front controller and `bin/console`, before the kernel
boots, so `%env(DATABASE_URL)%` in your config resolves:

```php
// public/index.php (and bin/console)
use Secretspec\SecretSpec;

require_once dirname(__DIR__).'/vendor/autoload.php';

SecretSpec::builder()
    ->withProfile($_SERVER['APP_ENV'] ?? 'dev')
    ->withReason('symfony boot')
    ->load()
    ->setAsEnv();
```

`setAsEnv()` sets `$_ENV`, `$_SERVER`, and `putenv()`, all three of which
Symfony's env-var processors read, so no bundle or extra configuration is needed.

## Plain PHP

Point the builder at a specific manifest and provider and read the values back:

```php
use Secretspec\SecretSpec;

$resolved = SecretSpec::builder()
    ->withPath(__DIR__.'/secretspec.toml')
    ->withProvider('dotenv://.env.production')
    ->withReason('cron job')
    ->load();

foreach ($resolved->secrets as $name => $secret) {
    // $secret->get() is the value, or a readable file path for as_path secrets.
    printf("%s=%s\n", $name, $secret->get());
}
```

## Typed access (codegen)

Generate a typed class with `secretspec schema` plus
[quicktype](https://quicktype.io), then build it from `$resolved->fields()`:

```bash
secretspec schema | quicktype -s schema --top-level SecretSpec --lang php -o SecretSpecTyped.php
```

```php
// $resolved->fields() is a [SECRET_NAME => value] map; quicktype's `from`
// wants an object, so cast it.
$typed = SecretSpec::from((object) $resolved->fields());
echo $typed->getDatabaseURL();
```

## Files (`as_path`)

Secrets declared `as_path` are materialized to a temporary file and come back as
a readable path; `$secret->get()` returns the path. The SDK persists the file
(mode 0400) so the path stays valid after `load()` returns — you own its
lifetime. Call `$resolved->close()` when done to remove those temp files:

```php
$resolved = SecretSpec::builder()->withReason('tls')->load();
try {
    $certPath = $resolved->secrets['TLS_CERT']->get();
    // ... use the file ...
} finally {
    $resolved->close();
}
```

## Native backends

The SDK chooses a backend automatically: if the `secretspec-php-native` extension
is loaded it is used directly (no `ffi.enable`, no library to locate); otherwise
the SDK dlopens the `secretspec-ffi` library via `ext-ffi`, looking first at
`SECRETSPEC_FFI_LIB`, then the copy `vendor/bin/secretspec-install-lib` places in
the package, then a local Cargo `target/` directory. Both backends call the
identical Rust `resolve_json`, so the result is the same — a cross-language
conformance suite asserts it.
