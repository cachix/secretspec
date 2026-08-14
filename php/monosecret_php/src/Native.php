<?php

declare(strict_types=1);

namespace Monosecret;

/**
 * The bridge to the native resolver, over the same versioned JSON envelope every
 * other SDK uses. There is no wide native surface to bind and no per-provider PHP
 * logic — the SDK inherits every provider from the core.
 *
 * Two backends resolve the JSON, tried in this order:
 *
 *  1. The `monosecret-php-native` PHP extension (built with ext-php-rs), which
 *     embeds the resolver and exposes `monosecret_native_resolve()`. This is the
 *     production path: it needs no `ffi.enable` and works under FPM/web like any
 *     other PHP extension. Preferred whenever it is loaded.
 *  2. A runtime `ext-ffi` fallback that dlopens the `libmonosecret_ffi` cdylib and
 *     calls the three C entry points from `crates/monosecret_ffi/include/monosecret.h`.
 *     Zero-config for CLI and local dev; requires the FFI extension.
 *
 * Both call `monosecret::resolve_json` and return the identical envelope.
 *
 * @internal
 */
final class Native
{
    /**
     * C declarations for the three-function ABI. Kept in lock-step with
     * `crates/monosecret_ffi/include/monosecret.h`.
     */
    private const CDEF = <<<'C'
        char *monosecret_resolve(const char *request_json);
        void monosecret_free(char *ptr);
        const char *monosecret_abi_version(void);
        C;

    private static ?\FFI $ffi = null;

    private function __construct()
    {
    }

    /**
     * Resolve a JSON request and return the JSON response envelope string.
     *
     * @throws MonosecretException if no backend is available or the call fails.
     */
    public static function resolve(string $requestJson): string
    {
        // Prefer the embedded extension; it is faster and needs no ffi.enable.
        if (\function_exists('monosecret_native_resolve')) {
            return \monosecret_native_resolve($requestJson);
        }

        return self::resolveViaFfi($requestJson);
    }

    /** The ABI version reported by the active backend. */
    public static function abiVersion(): string
    {
        if (\function_exists('monosecret_native_abi_version')) {
            return \monosecret_native_abi_version();
        }

        // PHP's FFI auto-materializes a `const char *` return into a PHP string,
        // whereas the non-const `char *` from resolve() stays an FFI\CData; accept
        // either so we do not depend on that conversion detail.
        $ret = self::ffi()->monosecret_abi_version();

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
        $ptr = $ffi->monosecret_resolve($requestJson);
        // monosecret_resolve returns null only on catastrophic allocation failure.
        if ($ptr === null || \FFI::isNull($ptr)) {
            throw new MonosecretException('ffi', 'monosecret_resolve returned null');
        }

        try {
            // \FFI::string copies the NUL-terminated bytes into a PHP string here,
            // before the finally frees the C pointer.
            return \FFI::string($ptr);
        } finally {
            $ffi->monosecret_free($ptr);
        }
    }

    /** Lazily dlopen the shared library and bind the ABI once per process. */
    private static function ffi(): \FFI
    {
        if (self::$ffi === null) {
            if (!\extension_loaded('ffi')) {
                throw new MonosecretException(
                    'load',
                    'the PHP FFI extension is required; enable ext-ffi (and set ffi.enable) '
                    . 'to use the Monosecret SDK',
                );
            }
            self::$ffi = \FFI::cdef(self::CDEF, self::locateLibrary());
        }

        return self::$ffi;
    }

    /**
     * Find `libmonosecret_ffi`: the `MONOSECRET_FFI_LIB` override first, then a
     * copy bundled in the package's `lib/` directory (the installed layout), then
     * the nearest Cargo `target/` directory (a source checkout).
     *
     * @throws MonosecretException if no library can be found.
     */
    private static function locateLibrary(): string
    {
        $env = \getenv('MONOSECRET_FFI_LIB');
        if (\is_string($env) && $env !== '') {
            return $env;
        }

        $name = self::libraryFileName();

        // A copy bundled alongside the package (distribution layout).
        $bundled = \dirname(__DIR__) . \DIRECTORY_SEPARATOR . 'lib' . \DIRECTORY_SEPARATOR . $name;
        if (\is_file($bundled)) {
            return $bundled;
        }

        // Walk up from the package looking for a Cargo target dir; pick the most
        // recently built library so a stale release build does not shadow the
        // debug build a developer just produced.
        $dir = __DIR__;
        while (true) {
            $best = null;
            $bestMtime = -1;
            foreach (['release', 'debug'] as $profile) {
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
            if ($best !== null) {
                return $best;
            }
            $parent = \dirname($dir);
            if ($parent === $dir) {
                break;
            }
            $dir = $parent;
        }

        throw new MonosecretException(
            'load',
            'could not locate the libmonosecret_ffi library; set MONOSECRET_FFI_LIB to its path',
        );
    }

    /**
     * The platform-specific `libmonosecret_ffi` file name the loader looks for.
     * Shared with the `monosecret-install-lib` script so the downloaded copy and
     * the loader agree on one name.
     */
    public static function libraryFileName(): string
    {
        return match (\PHP_OS_FAMILY) {
            'Darwin' => 'libmonosecret_ffi.dylib',
            'Windows' => 'monosecret_ffi.dll',
            default => 'libmonosecret_ffi.so',
        };
    }
}
