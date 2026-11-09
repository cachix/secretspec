<?php

declare(strict_types=1);

namespace Secretspec;

/**
 * One resolved secret. Exactly one of {@see $value} / {@see $path} is set:
 * {@see $path} when the secret is delivered as a temporary or leased file (`as_path`),
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
        private readonly ?string $fileLeaseId = null,
    ) {
    }

    /** The usable string: the file path for `as_path` secrets, else the value. */
    public function get(): ?string
    {
        return $this->asPath ? $this->path : $this->value;
    }

    /**
     * Open an independent, seekable read stream for a file secret (0.22+).
     * Native reads bypass PHP's canonicalization of Linux memfd paths. The
     * contents are copied into PHP memory, never a temporary file. Close the
     * stream with fclose(); closing the result does not erase an open stream.
     *
     * @return resource
     */
    public function open()
    {
        if (!$this->asPath || $this->path === null) {
            throw new SecretSpecException('representation', 'secret has no file value');
        }
        return Native::openFile($this->path, $this->fileLeaseId);
    }
}
