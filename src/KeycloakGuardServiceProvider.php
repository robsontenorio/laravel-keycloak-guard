<?php

namespace KeycloakGuard;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class KeycloakGuardServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->publishes([
        __DIR__ . '/../config/keycloak.php' => app()->configPath('keycloak.php'),
        ], 'config');

        $this->mergeConfigFrom(__DIR__ . '/../config/keycloak.php', 'keycloak');
    }

    public function register(): void
    {
        Auth::extend('keycloak', function ($app, $name, array $config) {
            return new KeycloakGuard(Auth::createUserProvider($config['provider']), $app->request);
        });
    }
}
