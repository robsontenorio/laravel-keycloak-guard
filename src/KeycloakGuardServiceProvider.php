<?php
namespace KeycloakGuard;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Auth;

class KeycloakGuardServiceProvider extends ServiceProvider
{
  public function boot()
  {
      $path = 'keycloak.php';

      $this->publishes([
          __DIR__ . '/../config/keycloak.php' => app()->basePath() . '/config' . ($path ? '/' . $path : $path),
      ], 'config');

    $this->mergeConfigFrom(__DIR__ . '/../config/keycloak.php', 'keycloak');
  }

  public function register()
  {
    Auth::extend('keycloak', function ($app, $name, array $config) {
      return new KeycloakGuard(Auth::createUserProvider($config['provider']), $app->request);
    });
  }
}