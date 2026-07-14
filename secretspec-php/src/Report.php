<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * A value-free resolution snapshot (the inventory/preflight view the CLI
 * exposes as `check --json`). Unlike {@see Resolved}, a missing required secret
 * is a `missing_required` status here, not an error, so a report describes a
 * profile even when its secrets are not all available.
 */
final class Report
{
    /** @param list<SecretReport> $secrets one entry per declared secret */
    public function __construct(
        public readonly string $provider,
        public readonly string $profile,
        public readonly array $secrets,
    ) {
    }
}
