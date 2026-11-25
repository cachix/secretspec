<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Secretspec\SecretSpec;

class SecretSpecServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        SecretSpec::builder()
            ->withProfile(app()->environment())   // "production", "local", ...
            ->withReason('laravel boot')
            ->load()
            ->setAsEnv();
    }
}
