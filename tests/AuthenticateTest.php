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

  protected function setUp()
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
}