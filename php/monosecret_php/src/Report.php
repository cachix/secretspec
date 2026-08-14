<?php

declare(strict_types=1);

namespace Monosecret;

/**
 * A value-free resolution snapshot (the inventory/preflight view the CLI
 * exposes as `check --json`). Unlike {@see Resolved}, a missing required secret
 * is a `missing_required` status here, not an error, so a report describes a
 * profile even when its secrets are not all available.
 */
final class Report
{
    /**
     * @param list<SecretReport>       $secrets              one entry per declared secret
     * @param string|null              $scope                selected manifest scope (schema v2)
     * @param list<ConstraintViolation> $constraintViolations failed cross-secret constraints
     */
    public function __construct(
        public readonly string $provider,
        public readonly string $profile,
        public readonly array $secrets,
        public readonly ?string $scope = null,
        public readonly array $constraintViolations = [],
    ) {
    }
}
