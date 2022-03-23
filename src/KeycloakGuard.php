<?php
namespace KeycloakGuard;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use KeycloakGuard\Exceptions\TokenException;
use KeycloakGuard\Exceptions\UserNotFoundException;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;

class KeycloakGuard implements Guard
{
  private $config;
  private $user;
  private $provider;
  private $decodedToken;

  public function __construct(UserProvider $provider, Request $request)
  {
    $this->config = config('keycloak');
    $this->user = null;
    $this->provider = $provider;
    $this->decodedToken = null;
    $this->request = $request;

    $this->authenticate();
  }

  /**
   * Decode token, validate and authenticate user
   *
   * @return mixed
   */

  private function authenticate()
  {
    try {
      $this->decodedToken = Token::decode($this->request->bearerToken(), $this->config['realm_public_key']);
    } catch (\Exception $e) {
      throw new TokenException($e->getMessage());
    }

    if ($this->decodedToken) {
      $this->validate([
        $this->config['user_provider_credential'] => $this->decodedToken->{$this->config['token_principal_attribute']}
      ]);
    }
  }


  /**
   * Determine if the current user is authenticated.
   *
   * @return bool
   */
  public function check()
  {
    return !is_null($this->user());
  }

  /**
   * Determine if the guard has a user instance.
   *
   * @return bool
   */
  public function hasUser()
  {
    return !is_null($this->user());
  }

  /**
   * Determine if the current user is a guest.
   *
   * @return bool
   */
  public function guest()
  {
    return !$this->check();
  }

  /**
   * Get the currently authenticated user.
   *
   * @return \Illuminate\Contracts\Auth\Authenticatable|null
   */
  public function user()
  {
    if (is_null($this->user)) {
      return null;
    }

    if ($this->config['append_decoded_token']) {
      $this->user->token = $this->decodedToken;
    }

    return $this->user;
  }

  /**
   * Get the ID for the currently authenticated user.
   *
   * @return int|null
   */
  public function id()
  {
    if ($user = $this->user()) {
      return $this->user()->id;
    }
  }

  /**
   * Validate a user's credentials.
   *
   * @param  array  $credentials
   * @return bool
   */
  public function validate(array $credentials = [])
  {
    if (!$this->decodedToken) {
      return false;
    }

    $this->validateResources();

    if ($this->config['load_user_from_database']) {
      $methodOnProvider = $this->config['user_provider_custom_retrieve_method'] ?? null;
      if ($methodOnProvider) {
        $user = $this->provider->{$methodOnProvider}($this->decodedToken, $credentials);
      } else {
        $user = $this->provider->retrieveByCredentials($credentials);
      }      

      if (!$user) {
        throw new UserNotFoundException("User not found. Credentials: " . json_encode($credentials));
      }
    } else {
      $class = $this->provider->getModel();
      $user = new $class();
    }

    $this->setUser($user);

    return true;
  }

  /**
   * Set the current user.
   *
   * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
   * @return void
   */
  public function setUser(Authenticatable $user)
  {
    $this->user = $user;
  }

  /**
   * Validate if authenticated user has a valid resource
   *
   * @return void
   */
  private function validateResources()
  {
    $token_resource_access = array_keys((array)($this->decodedToken->resource_access ?? []));
    $allowed_resources = explode(',', $this->config['allowed_resources']);

    if (count(array_intersect($token_resource_access, $allowed_resources)) == 0) {
      throw new ResourceAccessNotAllowedException("The decoded JWT token has not a valid `resource_access` allowed by API. Allowed resources by API: " . $this->config['allowed_resources']);
    }
  }

  /**
   * Returns full decoded JWT token from athenticated user
   *
   * @return mixed|null
   */
  public function token()
  {
    return json_encode($this->decodedToken);
  }

  /**
   * Check if authenticated user has a especific role into resource
   * @param string $resource
   * @param string $role
   * @return bool
   */
  public function hasRole($resource, $role)
  {
    $token_resource_access = (array)$this->decodedToken->resource_access;
    if (array_key_exists($resource, $token_resource_access)) {
      $token_resource_values = (array)$token_resource_access[$resource];

      if (array_key_exists('roles', $token_resource_values) &&
        in_array($role, $token_resource_values['roles'])) {
        return true;
      }
    }
    return false;
  }
}
