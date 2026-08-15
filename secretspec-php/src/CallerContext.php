<?php

declare(strict_types=1);

namespace Secretspec;

/** Caller-asserted software-integration context (SecretSpec 0.20+). */
final class CallerContext
{
    public function __construct(
        public readonly string $name,
        public readonly ?string $version = null,
        public readonly ?string $operation = null,
        public readonly ?string $resource = null,
    ) {
    }

    /** @return array<string, string> */
    public function toArray(): array
    {
        return array_filter(
            [
                'name' => $this->name,
                'version' => $this->version,
                'operation' => $this->operation,
                'resource' => $this->resource,
            ],
            static fn (?string $value): bool => $value !== null,
        );
    }
}
