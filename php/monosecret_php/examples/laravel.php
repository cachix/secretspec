<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Monosecret\Monosecret;

class MonosecretServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        Monosecret::builder()
            ->withProfile(app()->environment())   // "production", "local", ...
            ->withReason('laravel boot')
            ->load()
            ->setAsEnv();
    }
}
