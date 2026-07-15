<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * Entry point for the SecretSpec PHP SDK, mirroring the Rust derive crate's
 * `SecretSpec::builder()`.
 *
 * The SDK is a thin client over the `secretspec-ffi` C ABI (loaded via PHP's
 * FFI extension): resolution — providers, fallback chains, profiles, generation,
 * `as_path` materialization — happens entirely in the Rust core, so every
 * provider works with no PHP-side logic.
 *
 * ```php
 * use Secretspec\SecretSpec;
 *
 * $resolved = SecretSpec::builder()
 *     ->withProvider('keyring://')
 *     ->withProfile('production')
 *     ->withReason('boot web app')
 *     ->load();
 *
 * echo $resolved->secrets['DATABASE_URL']->get();
 * $resolved->setAsEnv();
 * ```
 */
final class SecretSpec
{
    /** Start a fluent {@see Builder}. */
    public static function builder(): Builder
    {
        return new Builder();
    }

    /**
     * Convenience one-shot resolve. Equivalent to building and calling
     * {@see Builder::load()}.
     *
     * @throws MissingRequiredException if a required secret is missing
     * @throws SecretSpecException      for any other failure
     */
    public static function resolve(
        ?string $path = null,
        ?string $provider = null,
        ?string $profile = null,
        ?string $reason = null,
    ): Resolved {
        return self::configured($path, $provider, $profile, $reason)->load();
    }

    /**
     * Convenience one-shot value-free {@see Report}. Equivalent to building and
     * calling {@see Builder::report()}.
     *
     * @throws SecretSpecException for a transport failure
     */
    public static function report(
        ?string $path = null,
        ?string $provider = null,
        ?string $profile = null,
        ?string $reason = null,
    ): Report {
        return self::configured($path, $provider, $profile, $reason)->report();
    }

    /** Build a {@see Builder} from the shared one-shot options. */
    private static function configured(
        ?string $path,
        ?string $provider,
        ?string $profile,
        ?string $reason,
    ): Builder {
        return self::builder()
            ->withPath($path)
            ->withProvider($provider)
            ->withProfile($profile)
            ->withReason($reason);
    }

    /** The ABI version reported by the loaded native library. */
    public static function abiVersion(): string
    {
        return Native::abiVersion();
    }
}
