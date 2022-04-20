<?php
namespace KeycloakGuard;

use Illuminate\Contracts\Auth\Authenticatable;

class KeyCloakUser
{
    private $user = null;
    private $decodedToken = null;
    private $config;

    public function __construct()
    {
        $this->config = config('keycloak');
    }

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
        if (!empty($this->user)) {
            return $this->user->id;
        }
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(Authenticatable $user, $decodedToken)
    {
        $this->user = $user;
        $this->decodedToken = $decodedToken;
    }

    /**
     * return roles
     * @return array|mixed
     */
    public function roles()
    {
        $token_resource_access = (array)$this->decodedToken->resource_access;

        if(empty($token_resource_access['account']->roles)) {
            return [];
        }

        return $token_resource_access['account']->roles;
    }

    /**
     * return scopes
     * @return array|mixed
     */
    public function scopes()
    {
        $token_resource_access = (array)$this->decodedToken;
        if (array_key_exists('scope', $token_resource_access)) {
            return $token_resource_access['scope'];
        }

        return [];
    }

    /**
     * Check if authenticated user has a especific role into resource
     * @param string $resource
     * @param string $role
     * @return bool
     */
    public function hasRole(string $resource, string $role)
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