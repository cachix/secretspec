<?php

/**
 * Fetch the platform `secretspec-ffi` shared library into the package's lib/
 * directory, so the `ext-ffi` backend works after a plain `composer require`
 * with no `SECRETSPEC_FFI_LIB` to set.
 *
 * Run it once after install via the `vendor/bin/secretspec-install-lib` command
 * (Composer does not run a dependency's install scripts in the consumer project,
 * so this is an explicit step rather than a post-install hook — which also keeps
 * a secrets tool from silently downloading a binary during `composer install`).
 * It is deliberately FAIL-SOFT: any problem (offline, an unsupported platform, a
 * missing release asset) prints a note and exits 0, because
 *
 *   - the native `secretspec-php-native` extension, when installed, makes this
 *     download unnecessary; and
 *   - if neither backend ends up available, the SDK raises a clear runtime error
 *     with remediation, which is friendlier than breaking `composer install`.
 *
 * The library is downloaded from the GitHub release matching the installed
 * package version and verified against its published `.sha256` sidecar.
 */

declare(strict_types=1);

// Locate the Composer autoloader (needed for Composer\InstalledVersions) across
// both a dev checkout and an installed-under-vendor layout. Composer's bin proxy
// exposes $_composer_autoload_path; the fallbacks cover direct invocation.
foreach ([
    $GLOBALS['_composer_autoload_path'] ?? null,
    dirname(__DIR__) . '/vendor/autoload.php',       // dev: secretspec-php/vendor
    dirname(__DIR__, 4) . '/autoload.php',            // installed: <vendor>/cachix/secretspec/secretspec-php
] as $autoload) {
    if (is_string($autoload) && is_file($autoload)) {
        require_once $autoload;
        break;
    }
}

/** Print a note and exit successfully — never fail the install over this. */
function note(string $message): never
{
    fwrite(STDERR, "[secretspec] {$message}\n");
    exit(0);
}

// Skip when the native extension is present: it embeds the resolver, so the
// ext-ffi cdylib is not needed.
if (function_exists('secretspec_native_resolve')) {
    note('native extension detected; skipping ext-ffi library download.');
}

// Respect an explicit override.
$override = getenv('SECRETSPEC_FFI_LIB');
if (is_string($override) && $override !== '') {
    note('SECRETSPEC_FFI_LIB is set; skipping download.');
}

// Map the running platform to the release target triple; the library file name
// comes from Native so the download target and the loader agree on one name.
$target = secretspec_target();
if ($target === null) {
    note('no prebuilt secretspec-ffi library for this platform; set '
        . 'SECRETSPEC_FFI_LIB or install the secretspec extension.');
}
if (!class_exists(\Secretspec\Native::class)) {
    note('the Secretspec classes are not autoloadable; run `composer install` first.');
}
$libName = \Secretspec\Native::libraryFileName();

$libDir = dirname(__DIR__) . '/lib';
$dest = $libDir . '/' . $libName;
if (is_file($dest)) {
    note("library already present at {$dest}.");
}

$version = secretspec_installed_version();
if ($version === null) {
    note('could not determine the installed package version (dev checkout?); '
        . 'build the cdylib with `cargo build -p secretspec-ffi` instead.');
}

$asset = "secretspec-ffi-{$target}." . pathinfo($libName, PATHINFO_EXTENSION);
$base = "https://github.com/cachix/secretspec/releases/download/v{$version}";
$url = "{$base}/{$asset}";

$bytes = secretspec_fetch($url);
if ($bytes === null) {
    note("could not download {$url}; set SECRETSPEC_FFI_LIB or install the extension.");
}

// Verify the sha256 sidecar when the release publishes one.
$sum = secretspec_fetch("{$url}.sha256");
if (is_string($sum)) {
    $expected = strtolower(trim(explode(' ', trim($sum))[0]));
    $actual = hash('sha256', $bytes);
    if ($expected !== '' && !hash_equals($expected, $actual)) {
        note("checksum mismatch for {$asset} (expected {$expected}, got {$actual}); not installing.");
    }
}

if (!is_dir($libDir) && !@mkdir($libDir, 0o755, true) && !is_dir($libDir)) {
    note("could not create {$libDir}.");
}
if (@file_put_contents($dest, $bytes) === false) {
    note("could not write {$dest}.");
}
@chmod($dest, 0o644);

fwrite(STDERR, "[secretspec] installed {$dest} ({$target}).\n");
exit(0);

/**
 * The release target triple for the running platform, or null if no prebuilt
 * secretspec-ffi library is published for it.
 */
function secretspec_target(): ?string
{
    $machine = strtolower(php_uname('m'));
    $isArm = in_array($machine, ['arm64', 'aarch64'], true);
    $isX64 = in_array($machine, ['x86_64', 'amd64'], true);

    switch (PHP_OS_FAMILY) {
        case 'Linux':
            if ($isX64) {
                return 'x86_64-unknown-linux-gnu';
            }
            if ($isArm) {
                return 'aarch64-unknown-linux-gnu';
            }
            break;
        case 'Darwin':
            if ($isArm) {
                return 'aarch64-apple-darwin';
            }
            break;
        case 'Windows':
            if ($isX64) {
                return 'x86_64-pc-windows-msvc';
            }
            break;
    }

    return null;
}

/** The installed version of this package, or null in a dev/path checkout. */
function secretspec_installed_version(): ?string
{
    if (!class_exists(\Composer\InstalledVersions::class)) {
        return null;
    }
    try {
        $version = \Composer\InstalledVersions::getPrettyVersion('cachix/secretspec');
    } catch (\OutOfBoundsException) {
        return null;
    }
    if ($version === null) {
        return null;
    }
    // A tagged install reports "1.2.3"; dev branches report "dev-*", which has no
    // matching release asset.
    $version = ltrim($version, 'v');

    return preg_match('/^\d+\.\d+\.\d+/', $version) === 1 ? $version : null;
}

/** GET a URL, returning the body or null on any failure. */
function secretspec_fetch(string $url): ?string
{
    // PHP's HTTP stream wrapper reads its options from the 'http' key for both
    // http:// and https:// URLs, so a single entry covers both.
    $context = stream_context_create([
        'http' => ['method' => 'GET', 'follow_location' => 1, 'timeout' => 30,
            'header' => 'User-Agent: secretspec-php-installer'],
    ]);
    $body = @file_get_contents($url, false, $context);

    return $body === false ? null : $body;
}
