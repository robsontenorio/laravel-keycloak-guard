<?php
namespace KeycloakGuard;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use KeycloakGuard\Exceptions\TokenException;
use KeycloakGuard\Exceptions\UserNotFoundException;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;
use Log;

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

    Log::info("Will authenticate...");

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
      Log::info(var_export($this->decodedToken, true));

    } catch (\Exception $e) {
      Log::info("Error, could not decode token: " . $e->getMessage());
      throw new TokenException($e->getMessage());
    }

    if ($this->decodedToken) {
      Log::info("Token could be decoded. Now validate");
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

    Log::info("Try to validate resources...");
    $this->validateResources();
    Log::info("Resources validated");

    if ($this->config['load_user_from_database']) {
      $user = $this->provider->retrieveByCredentials($credentials);

      if (!$user) {
        throw new UserNotFoundException("User not found. Credentials: " . json_encode($credentials));
      }
    } else {
      Log::info("No user table, use generic model");
      $class = $this->provider->getModel();
      $user = new $class();
    }

    $this->setUser($user);
    Log::info("Following user was set:");
    Log::info(print_r($user, true));


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
    $token_role_property = $this->config['token_role_property'];
    $allowed_resources = explode(',', $this->config['allowed_resources']);
    Log::info("Allowed resource:");
    Log::info(var_export($allowed_resources, true));
    $bpRoles = (array)$this->decodedToken->{$token_role_property};
    Log::info("BP-Roles:");
    Log::info(var_export($bpRoles, true));
    $roles = array_shift($bpRoles);
    Log::info("Roles:");
    Log::info(var_export($roles, true));

    if (is_array($roles)) {
      $token_resource_access = array_keys($roles ?? []);
    } else {
      throw new ResourceAccessNotAllowedException("The decoded JWT token has not a valid roles");
    }
    // $token_resource_access = array_keys((array)($this->decodedToken->{$token_role_property} ?? []));

    if (count(array_intersect($roles, $allowed_resources)) == 0) {
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
