<?php

use Monosecret\Monosecret;

$resolved = Monosecret::builder()
    ->withProvider('keyring://')
    ->withProfile('production')
    ->withReason('boot web app')
    ->load();

echo $resolved->provider, ' ', $resolved->profile, PHP_EOL;

$db = $resolved->secrets['DATABASE_URL'];
echo $db->get();        // the value, or the file path for as_path secrets

$resolved->setAsEnv();  // export everything into getenv()/$_ENV/$_SERVER
