<?php

// public/index.php (and bin/console)
use Monosecret\Monosecret;

require_once dirname(__DIR__).'/vendor/autoload.php';

Monosecret::builder()
    ->withProfile($_SERVER['APP_ENV'] ?? 'dev')
    ->withReason('symfony boot')
    ->load()
    ->setAsEnv();
