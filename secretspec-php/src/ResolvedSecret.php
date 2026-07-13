<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * One resolved secret. Exactly one of {@see $value} / {@see $path} is set:
 * {@see $path} when the secret is materialized to a temp file (`as_path`),
 * {@see $value} otherwise.
 */
final class ResolvedSecret
{
    public function __construct(
        public readonly ?string $value,
        public readonly ?string $path,
        public readonly bool $asPath,
        public readonly string $source,
        public readonly ?string $sourceProvider,
    ) {
    }

    /** The usable string: the file path for `as_path` secrets, else the value. */
    public function get(): ?string
    {
        return $this->asPath ? $this->path : $this->value;
    }
}
