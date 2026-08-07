<?php

// public/index.php (and bin/console)
use Secretspec\SecretSpec;

require_once dirname(__DIR__).'/vendor/autoload.php';

SecretSpec::builder()
    ->withProfile($_SERVER['APP_ENV'] ?? 'dev')
    ->withReason('symfony boot')
    ->load()
    ->setAsEnv();
