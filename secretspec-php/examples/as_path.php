<?php

$resolved = SecretSpec::builder()->withReason('tls')->load();
try {
    $certPath = $resolved->secrets['TLS_CERT']->get();
    // ... use the file ...
} finally {
    $resolved->close();
}
