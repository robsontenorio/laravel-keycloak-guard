<?php

namespace KeycloakGuard\Tests;

use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Auth;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;
use KeycloakGuard\Exceptions\UserNotFoundException;
use KeycloakGuard\KeycloakGuard;
use KeycloakGuard\Tests\Extensions\CustomUserProvider;
use KeycloakGuard\Tests\Models\User;

class AuthenticateTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    /** @test */
    public function it_authenticates_the_user_when_request_any_endpoint_with_token()
    {
        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertEquals($this->user->username, Auth::user()->username);

        $response = $this->json('GET', '/foo/public');

        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    /** @test */
    public function it_forbiden_when_request_a_protected_endpoint_without_token()
    {
        $response = $this->json('GET', '/foo/secret');

        $response->assertStatus(401);
    }

    /** @test */
    public function it_throws_a_exception_when_user_is_not_found()
    {
        $this->expectException(UserNotFoundException::class);
        $this->withoutExceptionHandling();

        $this->buildCustomToken([
            'preferred_username' => 'mary'
        ]);

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    /** @test */
    public function it_throws_a_exception_when_resource_access_is_not_allowed_by_api()
    {
        $this->expectException(ResourceAccessNotAllowedException::class);
        $this->withoutExceptionHandling();

        $this->buildCustomToken([
            'resource_access' => ['some_resouce_not_allowed' => []]
        ]);

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    /** @test */
    public function it_appends_token_to_the_user()
    {
        config(['keycloak.append_decoded_token' => true]);

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertNotNull(Auth::user()->token);
    }

    /** @test */
    public function it_does_not_appends_token_to_the_user()
    {
        config(['keycloak.append_decoded_token' => false]);       

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertNull(Auth::user()->token);
    }

    /** @test */
    public function it_does_not_load_user_from_database()
    {
        config(['keycloak.load_user_from_database' => false]);

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertCount(0, Auth::user()->getAttributes());
    }

    /** @test */
    public function it_does_not_load_user_from_database_but_appends_decoded_token()
    {
        config(['keycloak.load_user_from_database' => false]);
        config(['keycloak.append_decoded_token' => true]);

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertArrayHasKey('token', Auth::user()->toArray());
    }

    /** @test */
    public function it_check_user_has_role_in_resource()
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

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasRole('myapp-backend', 'myapp-backend-role1'));
    }

    /** @test */
    public function it_check_user_no_has_role_in_resource()
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

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasRole('myapp-backend', 'myapp-backend-role3'));
    }

    /** @test */
    public function it_prevent_cross_roles_resources()
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

        $response = $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasRole('myapp-backend', 'myapp-frontend-role1'));
    }

      /** @test */
      public function custom_user_retrieve_method()
      {
          config(['keycloak.user_provider_custom_retrieve_method' => 'custom_retrieve']);

          Auth::extend('keycloak', function ($app, $name, array $config) {
              return new KeycloakGuard(new CustomUserProvider(new BcryptHasher(), User::class), $app->request);
          });

          $response = $this->withKeycloakToken()->json('GET', '/foo/secret');
          $this->assertTrue(Auth::user()->customRetrieve);
      }
}
