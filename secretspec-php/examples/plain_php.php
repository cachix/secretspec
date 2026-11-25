<?php

use Secretspec\SecretSpec;

$resolved = SecretSpec::builder()
    ->withPath(__DIR__.'/secretspec.toml')
    ->withProvider('dotenv://.env.production')
    ->withReason('cron job')
    ->load();

foreach ($resolved->secrets as $name => $secret) {
    // $secret->get() is the value, or a readable file path for as_path secrets.
    printf("%s=%s\n", $name, $secret->get());
}
