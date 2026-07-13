<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * The bridge to the native resolver, over the same versioned JSON envelope every
 * other SDK uses. There is no wide native surface to bind and no per-provider PHP
 * logic — the SDK inherits every provider from the core.
 *
 * Two backends resolve the JSON, tried in this order:
 *
 *  1. The `secretspec-php-native` PHP extension (built with ext-php-rs), which
 *     embeds the resolver and exposes `secretspec_native_resolve()`. This is the
 *     production path: it needs no `ffi.enable` and works under FPM/web like any
 *     other PHP extension. Preferred whenever it is loaded.
 *  2. A runtime `ext-ffi` fallback that dlopens the `secretspec-ffi` cdylib and
 *     calls the three C entry points from `secretspec-ffi/include/secretspec.h`.
 *     Zero-config for CLI and local dev; requires the FFI extension.
 *
 * Both call `secretspec::resolve_json` and return the identical envelope.
 *
 * @internal
 */
final class Native
{
    /**
     * C declarations for the three-function ABI. Kept in lock-step with
     * `secretspec-ffi/include/secretspec.h`.
     */
    private const CDEF = <<<'C'
        char *secretspec_resolve(const char *request_json);
        void secretspec_free(char *ptr);
        const char *secretspec_abi_version(void);
        C;

    private static ?\FFI $ffi = null;

    private function __construct()
    {
    }

    /**
     * Resolve a JSON request and return the JSON response envelope string.
     *
     * @throws SecretSpecException if no backend is available or the call fails.
     */
    public static function resolve(string $requestJson): string
    {
        // Prefer the embedded extension; it is faster and needs no ffi.enable.
        if (\function_exists('secretspec_native_resolve')) {
            return \secretspec_native_resolve($requestJson);
        }

        return self::resolveViaFfi($requestJson);
    }

    /** The ABI version reported by the active backend. */
    public static function abiVersion(): string
    {
        if (\function_exists('secretspec_native_abi_version')) {
            return \secretspec_native_abi_version();
        }

        // PHP's FFI auto-materializes a `const char *` return into a PHP string,
        // whereas the non-const `char *` from resolve() stays an FFI\CData; accept
        // either so we do not depend on that conversion detail.
        $ret = self::ffi()->secretspec_abi_version();

        return \is_string($ret) ? $ret : \FFI::string($ret);
    }

    /**
     * The FFI fallback: dlopen the cdylib and call the C ABI. The returned C
     * allocation is copied into a PHP string and freed before we return, so no
     * native memory outlives the call.
     */
    private static function resolveViaFfi(string $requestJson): string
    {
        $ffi = self::ffi();
        $ptr = $ffi->secretspec_resolve($requestJson);
        // secretspec_resolve returns null only on catastrophic allocation failure.
        if ($ptr === null || \FFI::isNull($ptr)) {
            throw new SecretSpecException('ffi', 'secretspec_resolve returned null');
        }

        try {
            // \FFI::string copies the NUL-terminated bytes into a PHP string here,
            // before the finally frees the C pointer.
            return \FFI::string($ptr);
        } finally {
            $ffi->secretspec_free($ptr);
        }
    }

    /** Lazily dlopen the shared library and bind the ABI once per process. */
    private static function ffi(): \FFI
    {
        if (self::$ffi === null) {
            if (!\extension_loaded('ffi')) {
                throw new SecretSpecException(
                    'load',
                    'the PHP FFI extension is required; enable ext-ffi (and set ffi.enable) '
                    . 'to use the SecretSpec SDK',
                );
            }
            self::$ffi = \FFI::cdef(self::CDEF, self::locateLibrary());
        }

        return self::$ffi;
    }

    /**
     * Find `libsecretspec_ffi`: the `SECRETSPEC_FFI_LIB` override first, then a
     * copy bundled in the package's `lib/` directory (the installed layout), then
     * the nearest Cargo `target/` directory (a source checkout).
     *
     * @throws SecretSpecException if no library can be found.
     */
    private static function locateLibrary(): string
    {
        $env = \getenv('SECRETSPEC_FFI_LIB');
        if (\is_string($env) && $env !== '') {
            return $env;
        }

        $names = self::libraryNames();

        // A copy bundled alongside the package (distribution layout).
        foreach ($names as $name) {
            $bundled = \dirname(__DIR__) . \DIRECTORY_SEPARATOR . 'lib' . \DIRECTORY_SEPARATOR . $name;
            if (\is_file($bundled)) {
                return $bundled;
            }
        }

        // Walk up from the package looking for a Cargo target dir; pick the most
        // recently built library so a stale release build does not shadow the
        // debug build a developer just produced.
        $dir = __DIR__;
        while (true) {
            $best = null;
            $bestMtime = -1;
            foreach (['release', 'debug'] as $profile) {
                foreach ($names as $name) {
                    $candidate = $dir . \DIRECTORY_SEPARATOR . 'target'
                        . \DIRECTORY_SEPARATOR . $profile . \DIRECTORY_SEPARATOR . $name;
                    if (\is_file($candidate)) {
                        $mtime = \filemtime($candidate);
                        if ($mtime !== false && $mtime > $bestMtime) {
                            $best = $candidate;
                            $bestMtime = $mtime;
                        }
                    }
                }
            }
            if ($best !== null) {
                return $best;
            }
            $parent = \dirname($dir);
            if ($parent === $dir) {
                break;
            }
            $dir = $parent;
        }

        throw new SecretSpecException(
            'load',
            'could not locate the secretspec-ffi library; set SECRETSPEC_FFI_LIB to its path',
        );
    }

    /** @return list<string> platform-specific shared-library file names. */
    private static function libraryNames(): array
    {
        return match (\PHP_OS_FAMILY) {
            'Darwin' => ['libsecretspec_ffi.dylib'],
            'Windows' => ['secretspec_ffi.dll'],
            default => ['libsecretspec_ffi.so'],
        };
    }
}
