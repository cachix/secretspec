<?php

use Monosecret\Monosecret;

$resolved = Monosecret::builder()
    ->withPath(__DIR__.'/monosecret.toml')
    ->withProvider('dotenv://.env.production')
    ->withReason('cron job')
    ->load();

foreach ($resolved->secrets as $name => $secret) {
    // $secret->get() is the value, or a readable file path for as_path secrets.
    printf("%s=%s\n", $name, $secret->get());
}
