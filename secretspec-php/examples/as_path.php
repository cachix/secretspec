<?php

$resolved = SecretSpec::builder()->withReason('tls')->load();
try {
    // PHP stream access (0.22+), including Linux memfd paths.
    $stream = $resolved->secrets['TLS_CERT']->open();
    try {
        $certificate = stream_get_contents($stream);
        // ... use the certificate bytes ...
    } finally {
        fclose($stream);
    }
    // get() still returns the original path for external programs.
} finally {
    $resolved->close();
}
