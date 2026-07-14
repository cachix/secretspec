<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * A resolution call failed: a bad manifest, a provider error, a reason-policy
 * rejection, or the native library failing to load. The stable {@see $kind}
 * distinguishes the failure class the same way it does in the other SDKs.
 */
class SecretSpecException extends \RuntimeException
{
    public function __construct(
        public readonly string $kind,
        string $message,
    ) {
        parent::__construct("{$message} (kind: {$kind})");
    }
}
