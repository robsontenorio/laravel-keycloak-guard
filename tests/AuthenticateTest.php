<?php
namespace KeycloakGuard\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use KeycloakGuard\KeycloakGuard;
use KeycloakGuard\Tests\Models\User;
use KeycloakGuard\KeycloakGuardServiceProvider;
use KeycloakGuard\Tests\Controllers\FooController;
use Illuminate\Routing\Router;
use Illuminate\Events\Dispatcher;
use KeycloakGuard\Exceptions\UserNotFoundException;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;

class AuthenticateTest extends TestCase
{

  protected function setUp() : void
  {
    parent::setUp();
  }

  /** @test */
  public function it_authenticates_the_user_when_request_any_endpoint_with_token()
  {
    $response = $this->withToken()->json('GET', '/foo/secret');

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

    $response = $this->withToken()->json('GET', '/foo/secret');
  }

  /** @test */
  public function it_throws_a_exception_when_resource_access_is_not_allowed_by_api()
  {
    $this->expectException(ResourceAccessNotAllowedException::class);
    $this->withoutExceptionHandling();

    $this->buildCustomToken([
      'resource_access' => ['some_resouce_not_allowed' => []]
    ]);

    $response = $this->withToken()->json('GET', '/foo/secret');
  }

  /** @test */
  public function it_appends_token_to_the_user()
  {
    config(['keycloak.append_decoded_token' => true]);

    $response = $this->withToken()->json('GET', '/foo/secret');

    $this->assertNotNull(Auth::user()->token);
  }

  /** @test */
  public function it_does_not_appends_token_to_the_user()
  {
    config(['keycloak.append_decoded_token' => false]);

    $response = $this->withToken()->json('GET', '/foo/secret');

    $this->assertNull(Auth::user()->token);
  }

  /** @test */
  public function it_does_not_load_user_from_database()
  {
    config(['keycloak.load_user_from_database' => false]);

    $response = $this->withToken()->json('GET', '/foo/secret');

    $this->assertEquals(count(Auth::user()->getAttributes()), 0);
  }

  /** @test */
  public function it_does_not_load_user_from_database_but_appends_decoded_token()
  {
    config(['keycloak.load_user_from_database' => false]);
    config(['keycloak.append_decoded_token' => true]);

    $response = $this->withToken()->json('GET', '/foo/secret');

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

    $response = $this->withToken()->json('GET', '/foo/secret');
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

    $response = $this->withToken()->json('GET', '/foo/secret');
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

    $response = $this->withToken()->json('GET', '/foo/secret');
    $this->assertFalse(Auth::hasRole('myapp-backend', 'myapp-frontend-role1'));
  }


}
