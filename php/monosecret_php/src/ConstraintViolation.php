<?php

declare(strict_types=1);

namespace Monosecret;

/** A failed cross-secret presence constraint in a resolution report. */
final class ConstraintViolation
{
    /**
     * @param list<string> $secrets
     * @param list<string> $present
     */
    public function __construct(
        public readonly ConstraintViolationKind $kind,
        public readonly string $group,
        public readonly array $secrets,
        public readonly array $present,
    ) {
    }
}
