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
        private readonly ?string $fileLeaseId = null,
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
     * Revoke this result's secret files, including hidden dependencies (0.22+).
     * Call close() after the final consumer. Repeated calls are harmless.
     * Older runtimes use filesystem cleanup.
     */
    public function close(): void
    {
        if ($this->fileLeaseId !== null) {
            $payload = \json_encode(['request_version' => 1, 'operation' => 'release_files',
                'source' => ['lease_id' => $this->fileLeaseId]], \JSON_THROW_ON_ERROR);
            $envelope = \json_decode(Native::call($payload), true, 512, \JSON_THROW_ON_ERROR);
            if (empty($envelope['ok'])) {
                $error = $envelope['error'] ?? [];
                throw new SecretSpecException($error['kind'] ?? 'unknown', $error['message'] ?? '');
            }
            return;
        }
        foreach ($this->secrets as $secret) {
            if ($secret->asPath && $secret->path !== null && \is_file($secret->path)) {
                @\unlink($secret->path);
            }
        }
    }
}
