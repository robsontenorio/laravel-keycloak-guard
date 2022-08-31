<?php

namespace KeycloakGuard;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;

class KeycloakGuardServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([__DIR__.'/../config/keycloak.php' => config_path('keycloak.php')], 'config');
        $this->mergeConfigFrom(__DIR__.'/../config/keycloak.php', 'keycloak');
    }

     public function register()
     {
         Auth::extend('keycloak', function ($app, $name, array $config) {
             return new KeycloakGuard(Auth::createUserProvider($config['provider']), $app->request);
         });
     }
}
