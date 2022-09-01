<?php

namespace KeycloakGuard\Tests;

use Firebase\JWT\JWT;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use KeycloakGuard\KeycloakGuardServiceProvider;
use KeycloakGuard\Tests\Factories\UserFactory;
use KeycloakGuard\Tests\Models\User;
use OpenSSLAsymmetricKey;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    private OpenSSLAsymmetricKey $privateKey;
    private string $publicKey;
    private array $payload;
    private string $token;

    protected function setUp(): void
    {
        // Prepare credentials
        $this->prepareCredentials();

        parent::setUp();

        // bootstrap
        $this->setUpDatabase($this->app);

        // Default user, same as jwt token
        $this->user = UserFactory::new()->create([
            'username' => 'johndoe'
        ]);
    }

    protected function prepareCredentials()
    {
        // Prepare private/public keys and a default JWT token, with a simple payload
        $this->privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);

        $this->publicKey = openssl_pkey_get_details($this->privateKey)['key'];

        $this->payload = [
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []]
        ];

        $this->token = JWT::encode($this->payload, $this->privateKey, 'RS256');
    }

    // Default configs to make it running
    protected function defineEnvironment($app)
    {
        $app['config']->set('auth.defaults.guard', 'api');
        $app['config']->set('auth.guards.api.driver', 'keycloak');
        $app['config']->set('auth.guards.api.provider', 'users');
        $app['config']->set('auth.providers.users.model', User::class);

        $app['config']->set('keycloak.realm_public_key', $this->plainPublicKey());
        $app['config']->set('keycloak.user_provider_credential', 'username');
        $app['config']->set('keycloak.token_principal_attribute', 'preferred_username');
        $app['config']->set('keycloak.append_decoded_token', false);
        $app['config']->set('keycloak.allowed_resources', 'myapp-backend');
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
        Route::any('/foo/secret', 'KeycloakGuard\Tests\Controllers\FooController@secret')->middleware(Authenticate::class);
        Route::any('/foo/public', 'KeycloakGuard\Tests\Controllers\FooController@public');

        return [KeycloakGuardServiceProvider::class];
    }

    // Just extract a string  from the public key, as required by config file
    protected function plainPublicKey(): string
    {
        $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $this->publicKey);
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
     public function withKeycloakToken()
     {
         $this->withToken($this->token);

         return $this;
     }
}
