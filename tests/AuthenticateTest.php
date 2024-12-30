<?php

namespace KeycloakGuard\Tests;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Auth;
use KeycloakGuard\ActingAsKeycloakUser;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;
use KeycloakGuard\Exceptions\TokenException;
use KeycloakGuard\Exceptions\UserNotFoundException;
use KeycloakGuard\KeycloakGuard;
use KeycloakGuard\Tests\Extensions\CustomUserProvider;
use KeycloakGuard\Tests\Factories\UserFactory;
use KeycloakGuard\Tests\Models\User;
use KeycloakGuard\Token;

class AuthenticateTest extends TestCase
{
    use ActingAsKeycloakUser;

    protected function setUp(): void
    {
        parent::setUp();
    }

    public function test_authenticates_the_user_when_requesting_a_private_endpoint_with_token()
    {
        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);

        $this->withKeycloakToken()->json('POST', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);

        $this->withKeycloakToken()->json('PUT', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);

        $this->withKeycloakToken()->json('PATCH', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);

        $this->withKeycloakToken()->json('DELETE', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    public function test_authenticates_the_user_when_requesting_an_public_endpoint_with_token()
    {
        $this->withKeycloakToken()->json('GET', '/foo/public');

        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    public function test_forbiden_when_request_a_protected_endpoint_without_token()
    {
        $this->expectException(AuthenticationException::class);
        $this->json('GET', '/foo/secret');
    }

    public function test_laravel_default_interface_for_authenticated_users()
    {
        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertEquals(Auth::hasUser(), true);
        $this->assertEquals(Auth::guest(), false);
        $this->assertEquals(Auth::id(), $this->user->id);
    }

    public function test_laravel_default_interface_for_unathenticated_users()
    {
        $this->json('GET', '/foo/public');

        $this->assertEquals(Auth::hasUser(), false);
        $this->assertEquals(Auth::guest(), true);
        $this->assertEquals(Auth::id(), null);
    }

    public function test_throws_a_exception_when_user_is_not_found()
    {
        $this->expectException(UserNotFoundException::class);

        $this->buildCustomToken([
            'preferred_username' => 'mary'
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    public function test_appends_token_to_the_user()
    {
        config(['keycloak.append_decoded_token' => true]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertNotNull(Auth::user()->token);
        $this->assertEquals(json_decode(Auth::token()), Auth::user()->token);
    }

    public function test_does_not_appends_token_to_the_user()
    {
        config(['keycloak.append_decoded_token' => false]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertNull(Auth::user()->token);
    }

    public function test_does_not_load_user_from_database()
    {
        config(['keycloak.load_user_from_database' => false]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertCount(0, Auth::user()->getAttributes());
    }

    public function test_does_not_load_user_from_database_but_appends_decoded_token()
    {
        config(['keycloak.load_user_from_database' => false]);
        config(['keycloak.append_decoded_token' => true]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertArrayHasKey('token', Auth::user()->toArray());
    }

    public function test_throws_a_exception_when_resource_access_is_not_allowed_by_api()
    {
        $this->expectException(ResourceAccessNotAllowedException::class);

        $this->buildCustomToken([
            'resource_access' => ['some_resouce_not_allowed' => []]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    public function test_ignores_resources_validation()
    {
        config(['keycloak.ignore_resources_validation' => true]);

        $this->buildCustomToken([
            'resource_access' => ['some_resouce_not_allowed' => []]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertEquals(Auth::id(), $this->user->id);
    }

    public function test_check_user_has_role_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2'
                    ]
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2'
                    ]
                ]
            ]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasRole('myapp-backend', 'myapp-backend-role1'));
    }

    public function test_check_user_no_has_role_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2'
                    ]
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2'
                    ]
                ]
            ]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasRole('myapp-backend', 'myapp-backend-role3'));
    }

    public function test_prevent_cross_roles_resources()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2'
                    ]
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2'
                    ]
                ]
            ]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasRole('myapp-backend', 'myapp-frontend-role1'));
    }

    public function test_check_user_has_any_role_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2'
                    ]
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2'
                    ]
                ]
            ]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasAnyRole('myapp-backend', ['myapp-backend-role1', 'myapp-backend-role3']));
    }

    public function test_check_user_no_has_any_role_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2'
                    ]
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2'
                    ]
                ]
            ]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasAnyRole('myapp-backend', ['myapp-backend-role3', 'myapp-backend-role4']));
    }

    public function test_prevent_cross_roles_resources_with_any_role()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2'
                    ]
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2'
                    ]
                ]
            ]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasAnyRole('myapp-backend', ['myapp-frontend-role1', 'myapp-frontend-role2']));
    }

    public function test_check_user_has_scope()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasScope('scope-a'));
    }

    public function test_check_user_no_has_scope()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasScope('scope-d'));
    }

    public function test_check_user_has_any_scope()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasAnyScope(['scope-a', 'scope-c']));
    }

    public function test_check_user_no_has_any_scope()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasAnyScope(['scope-f', 'scope-k']));
    }

    public function test_check_user_scopes()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $expectedValues = ["scope-a", "scope-b", "scope-c"];
        foreach ($expectedValues as $value) {
            $this->assertContains($value, Auth::scopes());
        }
        $this->assertCount(count($expectedValues), Auth::scopes());
    }

    public function test_check_user_no_scopes()
    {
        $this->buildCustomToken([
            'scope' => null,
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertCount(0, Auth::scopes());
    }

    public function test_custom_user_retrieve_method()
    {
        config(['keycloak.user_provider_custom_retrieve_method' => 'custom_retrieve']);

        Auth::extend('keycloak', function ($app, $name, array $config) {
            return new KeycloakGuard(new CustomUserProvider(new BcryptHasher(), User::class), $app->request);
        });

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::user()->customRetrieve);
    }

    public function test_throws_a_exception_with_invalid_iat()
    {
        $this->expectException(TokenException::class);

        $this->buildCustomToken([
            'iat' => time() + 30,   // time ahead in the future
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    public function test_works_with_leeway()
    {
        // Allows up to 60 seconds ahead in the  future
        config(['keycloak.leeway' => 60]);

        $this->buildCustomToken([
            'iat' => time() + 30, // time ahead in the future
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    public function test_authenticates_with_custom_input_key()
    {
        config(['keycloak.input_key' => "api_token"]);

        $this->json('GET', '/foo/secret?api_token='.$this->token);

        $this->assertEquals(Auth::id(), $this->user->id);

        $this->json('POST', '/foo/secret', ['api_token' => $this->token]);
    }

    public function test_authentication_prefers_bearer_token_over_with_custom_input_key()
    {
        config(['keycloak.input_key' => "api_token"]);

        $this->withKeycloakToken()->json('GET', '/foo/secret?api_token=some-junk');

        $this->assertEquals(Auth::id(), $this->user->id);

        $this->json('POST', '/foo/secret', ['api_token' => $this->token]);
    }

    public function test_authenticates_with_custom_input_key_cookie()
    {
        config(['keycloak.input_key' => "api_token"]);

        $this->withKeycloakCookie('api_token')->json('GET', '/foo/secret');

        $this->assertEquals(Auth::id(), $this->user->id);
    }

    public function test_acting_as_keycloak_user_trait()
    {
        $this->actingAsKeycloakUser($this->user)->json('GET', '/foo/secret');

        $this->assertEquals($this->user->username, Auth::user()->username);
        $token = Token::decode(request()->bearerToken(), config('keycloak.realm_public_key'), config('keycloak.leeway'), config('keycloak.token_encryption_algorithm'));
        $this->assertNotNull($token->iat);
        $this->assertNotNull($token->exp);
        $this->assertNotNull($token->iss);
        $this->assertNotNull($token->azp);
        $this->assertNotNull($token->aud);
    }

    public function test_acting_as_keycloak_user_trait_with_username()
    {
        $this->actingAsKeycloakUser($this->user->username)->json('GET', '/foo/secret');

        $this->assertEquals($this->user->username, Auth::user()->username);
        $token = Token::decode(request()->bearerToken(), config('keycloak.realm_public_key'), config('keycloak.leeway'), config('keycloak.token_encryption_algorithm'));
        $this->assertNotNull($token->iat);
        $this->assertNotNull($token->exp);
    }

    /**
     * @dataProvider scopeProvider
     *
     * @return void
     */
    public function test_acting_as_keycloak_user_trait_with_custom_payload(string $scope)
    {
        UserFactory::new()->create([
            'username' => 'test_username',
        ]);
        $payload = [
            'sub' => 'test_sub',
            'aud' => 'test_aud',
            'preferred_username' => 'test_username',
            'iat' => 12345,
            'exp' => 9999999999999,
        ];

        $arg = [];

        if ($scope === 'class') {
            $this->jwtPayload = $payload;
        } else {
            $this->jwtPayload['sub'] = 'should_be_overwritten';
            $arg = $payload;
        }

        $this->actingAsKeycloakUser(payload: $arg)->json('GET', '/foo/secret');

        $this->assertEquals('test_username', Auth::user()->username);
        $token = Token::decode(request()->bearerToken(), config('keycloak.realm_public_key'), config('keycloak.leeway'), config('keycloak.token_encryption_algorithm'));
        $this->assertEquals(12345, $token->iat);
        $this->assertEquals(9999999999999, $token->exp);
        $this->assertEquals('test_sub', $token->sub);
        $this->assertEquals('test_aud', $token->aud);
        $this->assertTrue(config('keycloak.load_user_from_database'));
    }

    public function test_acting_as_keycloak_user_trait_without_user()
    {
        $this->actingAsKeycloakUser()->json('GET', '/foo/secret');

        $this->assertTrue(Auth::hasUser());

        $this->assertFalse(Auth::guest());
    }

    public function test_it_decodes_token_with_the_configured_encryption_algorithm()
    {
        $this->prepareCredentials('ES256', [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1'
        ]);

        config([
            'keycloak.token_encryption_algorithm' => 'ES256',
            'keycloak.realm_public_key' => Token::plainPublicKey($this->publicKey)
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    public function scopeProvider(): array
    {
        return [
            ['local'],
            ['class'],
        ];
    }
}
