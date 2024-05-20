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
use KeycloakGuard\Token;
use OpenSSLAsymmetricKey;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    public OpenSSLAsymmetricKey $privateKey;
    public string $publicKey;
    public array $defaultPayload;
    public string $token;

    protected function setUp(): void
    {
        // Prepare credentials
        $this->prepareCredentials();

        parent::setUp();
        $this->withoutExceptionHandling();

        // bootstrap
        $this->setUpDatabase($this->app);

        // Default user, same as jwt token
        $this->user = UserFactory::new()->create([
            'username' => 'johndoe'
        ]);
    }

    protected function prepareCredentials(string $encryptionAlgorithm = 'RS256', ?array $openSSLConfig = null)
    {
        // Prepare private/public keys and a default JWT token, with a simple payload
        if (!$openSSLConfig) {
            $openSSLConfig = [
                'digest_alg' => 'sha256',
                'private_key_bits' => 1024,
                'private_key_type' => OPENSSL_KEYTYPE_RSA
            ];
        }

        $this->privateKey = openssl_pkey_new($openSSLConfig);

        $this->publicKey = openssl_pkey_get_details($this->privateKey)['key'];

        $this->defaultPayload = [
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []]
        ];

        $this->token = JWT::encode($this->defaultPayload, $this->privateKey, $encryptionAlgorithm);
    }

    // Default configs to make it running
    protected function defineEnvironment($app)
    {
        $app['config']->set('auth.defaults.guard', 'api');
        $app['config']->set('auth.providers.users.model', User::class);

        $app['config']->set('auth.guards.api', [
            'driver' => 'keycloak',
            'provider' => 'users'
        ]);

        $app['config']->set('keycloak', [
            'realm_public_key' => Token::plainPublicKey($this->publicKey),
            'user_provider_credential' => 'username',
            'token_principal_attribute' => 'preferred_username',
            'append_decoded_token' => false,
            'allowed_resources' => 'myapp-backend',
            'ignore_resources_validation' => false,
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
        Route::any('/foo/secret', 'KeycloakGuard\Tests\Controllers\FooController@secret')->middleware(Authenticate::class);
        Route::any('/foo/public', 'KeycloakGuard\Tests\Controllers\FooController@public');

        return [KeycloakGuardServiceProvider::class];
    }

    // Build a different token with custom payload
    protected function buildCustomToken(array $payload, string $encryptionAlgorithm = 'RS256')
    {
        $payload = array_replace($this->defaultPayload, $payload);

        $this->token = JWT::encode($payload, $this->privateKey, $encryptionAlgorithm);
    }

    // Setup default token, for the default user
    public function withKeycloakToken()
    {
        $this->withToken($this->token);

        return $this;
    }
}
