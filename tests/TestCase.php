<?php
namespace KeycloakGuard\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Database\Schema\Blueprint;
use Orchestra\Testbench\TestCase as Orchestra;
use KeycloakGuard\KeycloakGuardServiceProvider;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Route;
use KeycloakGuard\Tests\Models\User;
use Illuminate\Auth\Middleware\Authenticate;

class TestCase extends Orchestra
{
  protected function setUp() : void
  {
    parent::setUp();    
    
    // Laravel default configs

    config(['auth.providers.users.model' => User::class]);
    config(['auth.defaults.guard' => 'api']);
    config(['auth.guards.api.driver' => 'keycloak']);

    // Prepare private/public keys and a default JWT token, with a simple payload

    $this->privateKey = openssl_pkey_new(array(
      'digest_alg' => 'sha256',
      'private_key_bits' => 1024,
      'private_key_type' => OPENSSL_KEYTYPE_RSA
    ));

    $this->publicKey = openssl_pkey_get_details($this->privateKey)['key'];

    $this->payload = [
      'preferred_username' => 'johndoe',
      'resource_access' => ['myapp-backend' => []]
    ];

    $this->token = JWT::encode($this->payload, $this->privateKey, 'RS256');

    // Set Keycloak Guard default configs

    config(['keycloak.realm_public_key' => $this->plainPublicKey($this->publicKey)]);
    config(['keycloak.user_provider_credential' => 'username']);
    config(['keycloak.token_principal_attribute' => 'preferred_username']);
    config(['keycloak.append_decoded_token' => false]);
    config(['keycloak.allowed_resources' => 'myapp-backend']);

    // bootstrap 

    $this->setUpDatabase($this->app);
    $this->withFactories(__DIR__ . '/Factories');

    // Default user, same as jwt token

    $this->user = factory(User::class)->create([
      'username' => 'johndoe'
    ]);
  }

  protected function setUpDatabase(Application $app)
  {
    $app['db']->connection()->getSchemaBuilder()->create('users', function (Blueprint $table) {
      $table->increments('id');
      $table->string('username');
      $table->timestamps();
    });
  }

  protected function getPackageProviders($app)
  {
    Route::get('/foo/secret', 'KeycloakGuard\Tests\Controllers\FooController@secret')->middleware(Authenticate::class);
    Route::get('/foo/public', 'KeycloakGuard\Tests\Controllers\FooController@public');

    return [KeycloakGuardServiceProvider::class];
  }

  // Just extract a string  from the public key, as required by config file

  protected function plainPublicKey($key)
  {
    $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $key);
    $string = trim(str_replace('-----END PUBLIC KEY-----', '', $string));
    $string = str_replace('\n', '', $string);

    return $string;
  }

  // Build a diferent token with custom payload

  protected function buildCustomToken(array $payload)
  {
    $payload = array_replace($this->payload, $payload);

    $this->token = JWT::encode($payload, $this->privateKey, 'RS256');
  }

  // Setup default token, for the default user

  protected function withToken()
  {
    $this->withHeaders(['Authorization' => 'Bearer ' . $this->token]);

    return $this;
  }
}