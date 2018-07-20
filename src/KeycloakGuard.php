<?php
namespace KeycloakGuard;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;

class KeycloakGuard implements Guard
{

  public function __construct(UserProvider $provider, Request $request)
  {
    $this->key = config('keycloak.realm_public_key');
    $this->userProviderCredential = config('keycloak.user_provider_credential');
    $this->tokenPrincipalAttribute = config('keycloak.token_principal_attribute');
    $this->decodeUserDetails = config('keycloak.decode_user_details');

    $token = $request->bearerToken();
    $publicKey = $this->buildPublicKey($this->key);
    $this->decodedToken = $token ? JWT::decode($token, $publicKey, ['RS256']) : null;

    $this->provider = $provider;
    $this->user = null;
  }

  private function buildPublicKey($key)
  {
    return <<<EOD
-----BEGIN PUBLIC KEY-----
{$key}
-----END PUBLIC KEY-----
EOD;
  }

  /**
   * Determine if the current user is authenticated.
   *
   * @return bool
   */
  public function check()
  {
    return !is_null($this->user);
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
    $user = null;


    if ($this->decodedToken) {
      $user = $this->provider->retrieveByCredentials([
        $this->userProviderCredential => $this->decodedToken->{$this->tokenPrincipalAttribute}
      ]);

      if ($this->decodeUserDetails) {
        $user->details = $this->decodedToken;
      }

      $this->setUser($user);
    }

    return $user;
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

    return $this;
  }
}
