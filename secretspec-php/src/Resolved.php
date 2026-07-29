<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * A successful resolution, mirroring the Rust `Resolved` wrapper: the provider
 * and profile that answered, plus the resolved secrets keyed by declared name.
 */
final class Resolved
{
    /**
     * @param array<string, ResolvedSecret> $secrets         resolved secrets by declared name
     * @param list<string>                   $missingOptional optional secrets that were not found
     * @param string|null                    $scope           selected manifest scope (0.17+)
     */
    public function __construct(
        public readonly string $provider,
        public readonly string $profile,
        public readonly array $secrets,
        public readonly array $missingOptional = [],
        public readonly ?string $scope = null,
    ) {
    }

    /**
     * Export each resolved secret into the environment by its declared name,
     * setting it for `getenv()` (via `putenv`) as well as `$_ENV` / `$_SERVER`
     * so framework `env()` helpers see it too. Secrets with no usable value
     * (e.g. under `withNoValues`) are skipped rather than exported as empty.
     */
    public function setAsEnv(): void
    {
        foreach ($this->secrets as $name => $secret) {
            $value = $secret->get();
            if ($value !== null) {
                \putenv("{$name}={$value}");
                $_ENV[$name] = $value;
                $_SERVER[$name] = $value;
            }
        }
    }

    /**
     * Flat `{SECRET_NAME: value}` map (the file path for `as_path`). A secret
     * with no usable value (e.g. under `withNoValues`) maps to `null`, matching
     * the null the other SDKs emit.
     *
     * This is the input for a quicktype-generated deserializer: feed it to the
     * generated type's `from` method to get a typed object. See `secretspec schema`.
     *
     * @return array<string, ?string>
     */
    public function fields(): array
    {
        $out = [];
        foreach ($this->secrets as $name => $secret) {
            $out[$name] = $secret->get();
        }

        return $out;
    }

    /**
     * Remove the temp files backing any `as_path` secrets in this result. The
     * resolver persists those files (mode 0400) so their paths stay valid after
     * resolve returns; the caller owns their lifetime. Call `close()` when done
     * so secret files do not accumulate in the temp dir. A file already gone is
     * not an error.
     */
    public function close(): void
    {
        foreach ($this->secrets as $secret) {
            if ($secret->asPath && $secret->path !== null && \is_file($secret->path)) {
                @\unlink($secret->path);
            }
        }
    }
}
