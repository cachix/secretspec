<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * Fluent builder for a resolution, mirroring the Rust derive crate's builder.
 * Accumulates an optional path, provider, profile, and access reason, then
 * `load()`s the values or `report()`s the value-free inventory.
 */
final class Builder
{
    /**
     * Response wire-format version this SDK understands. Tracks secretspec-ffi's
     * RESOLVE_SCHEMA_VERSION; a mismatch means the loaded library is incompatible.
     */
    private const RESOLVE_SCHEMA_VERSION = 1;

    /**
     * Wire-format version of the value-free report. Tracks secretspec's
     * RESOLUTION_REPORT_SCHEMA_VERSION.
     */
    private const REPORT_SCHEMA_VERSION = 1;

    /** @var array<string, mixed> */
    private array $request = [];

    /** Path to a `secretspec.toml`; omit to walk up from the working directory. */
    public function withPath(?string $path): self
    {
        if ($path !== null) {
            $this->request['path'] = $path;
        }

        return $this;
    }

    /** Provider address, e.g. `keyring://` or `dotenv://.env.production`. */
    public function withProvider(?string $provider): self
    {
        if ($provider !== null) {
            $this->request['provider'] = $provider;
        }

        return $this;
    }

    /** Profile to resolve, e.g. `production`. */
    public function withProfile(?string $profile): self
    {
        if ($profile !== null) {
            $this->request['profile'] = $profile;
        }

        return $this;
    }

    /** Human-readable reason for the access, surfaced to reason-policy providers. */
    public function withReason(?string $reason): self
    {
        if ($reason !== null) {
            $this->request['reason'] = $reason;
        }

        return $this;
    }

    /** Omit secret values, returning only structure and provenance. */
    public function withNoValues(bool $noValues = true): self
    {
        $this->request['no_values'] = $noValues;

        return $this;
    }

    /**
     * Resolve the secrets.
     *
     * @throws MissingRequiredException if a required secret is missing
     * @throws SecretSpecException      for any other failure
     */
    public function load(): Resolved
    {
        $response = $this->checkedResponse($this->request, 'resolve', self::RESOLVE_SCHEMA_VERSION);

        $missing = $response['missing_required'] ?? [];
        if (!empty($missing)) {
            throw new MissingRequiredException($missing);
        }

        $secrets = [];
        foreach ($response['secrets'] ?? [] as $name => $entry) {
            $secrets[$name] = new ResolvedSecret(
                $entry['value'] ?? null,
                $entry['path'] ?? null,
                $entry['as_path'] ?? false,
                $entry['source'] ?? '',
                $entry['source_provider'] ?? null,
            );
        }

        return new Resolved(
            $response['provider'],
            $response['profile'],
            $secrets,
            $response['missing_optional'] ?? [],
        );
    }

    /**
     * Resolve a value-free {@see Report} (the inventory/preflight view, the same
     * one the CLI exposes as `check --json`). Unlike {@see load()}, never throws
     * {@see MissingRequiredException}: a missing required secret appears as a
     * {@see SecretReport} with status `missing_required`.
     *
     * @throws SecretSpecException for a transport failure
     */
    public function report(): Report
    {
        $request = $this->request;
        $request['mode'] = 'report';
        $response = $this->checkedResponse($request, 'report', self::REPORT_SCHEMA_VERSION);

        $secrets = [];
        foreach ($response['secrets'] ?? [] as $s) {
            $secrets[] = new SecretReport(
                $s['name'],
                $s['status'],
                $s['required'],
                $s['source_provider'] ?? null,
                $s['default_applied'],
                $s['generated'],
                $s['as_path'],
            );
        }

        return new Report($response['provider'], $response['profile'], $secrets);
    }

    /**
     * Resolve a JSON request payload and return the validated `response` object,
     * or throw. `$kind` is `resolve` or `report`; it selects the schema version
     * to enforce and labels the version-mismatch message.
     *
     * @param array<string, mixed> $request
     *
     * @return array<string, mixed>
     */
    private function checkedResponse(array $request, string $kind, int $expectedVersion): array
    {
        // An empty request must serialize as a JSON object `{}`, not an array
        // `[]`; cast to object so the resolver parses it either way.
        $payload = \json_encode((object) $request, \JSON_THROW_ON_ERROR);
        $envelope = \json_decode(Native::resolve($payload), true, 512, \JSON_THROW_ON_ERROR);

        if (empty($envelope['ok'])) {
            $err = $envelope['error'] ?? [];
            throw new SecretSpecException($err['kind'] ?? 'unknown', $err['message'] ?? '');
        }

        $response = $envelope['response'] ?? null;
        if ($response === null) {
            throw new SecretSpecException('ffi', 'secretspec_resolve reported ok with no response');
        }

        $version = $response['schema_version'] ?? null;
        if ($version !== $expectedVersion) {
            throw new SecretSpecException(
                'version',
                "unsupported {$kind} schema version " . \var_export($version, true)
                . " (expected {$expectedVersion}); the secretspec-ffi library and this SDK "
                . 'are out of sync',
            );
        }

        return $response;
    }
}
