<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * One or more required secrets were not found anywhere. Distinct from a
 * transport failure ({@see SecretSpecException}) so callers can treat "a secret
 * is not set" differently from "resolution itself broke".
 */
final class MissingRequiredException extends SecretSpecException
{
    /** @param list<string> $missing the names of the required secrets that are absent */
    public function __construct(public readonly array $missing)
    {
        parent::__construct(
            'missing_required',
            'missing required secret(s): ' . \implode(', ', $missing),
        );
    }
}
