<?php
namespace KeycloakGuard;

use Illuminate\Contracts\Auth\Authenticatable;

class KeyCloakUser
{
    private $user = null;

  /**
   * Get the currently authenticated user.
   *
   * @return \Illuminate\Contracts\Auth\Authenticatable|null
   */
  public function get()
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
    if ($user = $this->user) {
      return $this->user->id;
    }
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
}