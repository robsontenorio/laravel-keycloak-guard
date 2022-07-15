<?php

namespace KeycloakGuard;

use App\Models\User;
use Illuminate\Support\Arr;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;
use KeycloakGuard\Exceptions\TokenException;

class KeycloakGuard implements Guard
{
    private $config;
    private $user;
    private $keyCloakUser;
    private $provider;
    private $decodedToken;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->config = config('keycloak');
        $this->user = null;
        $this->keyCloakUser = new KeyCloakUser();
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
            // set key and server
            $pubKey = !empty($this->config['realm_public_key']) ? $this->config['realm_public_key'] : '';
            $server = !empty($this->config['realm_address']) ? $this->config['realm_address'] : '';

            $this->decodedToken = Token::decode($this->request->bearerToken(), $pubKey, $server);
        } catch (\Exception $e) {
            abort(401, "[Keycloak Guard] ".$e->getMessage());
        }

        if ($this->decodedToken) {
            $this->validate([
                $this->config['user_provider_credential'] => $this->decodedToken->{$this->config['token_principal_attribute']}
            ]);
        }
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (!$this->decodedToken) {
            return false;
        }

        if ($this->validateResources() === false && $this->validateScopes() === false) {
            throw new ResourceAccessNotAllowedException("The decoded JWT token has no a valid access allowed by API. Allowed resources by API: " . $this->config['allowed_resources']);
        }

        if ($this->config['load_user_from_database']) {
            $methodOnProvider = $this->config['user_provider_custom_retrieve_method'] ?? null;
            if ($methodOnProvider) {
                $user = $this->provider->{$methodOnProvider}($this->decodedToken, $credentials);
            } else {
                $user = $this->provider->retrieveByCredentials($credentials);
            }

            if (!$user) {
                $user = $this->saveUser();
            }
        } else {
            $class = $this->provider->getModel();
            $user = new $class();
        }

        $this->keyCloakUser->setUser($user, $this->decodedToken);

        return true;
    }

    /**
     * Validate if authenticated user has a valid resource
     */
    private function validateResources(): bool
    {
        $token_resource_access = array_keys((array)($this->decodedToken->resource_access ?? []));
        $allowed_resources = explode(',', $this->config['allowed_resources']);

        return count(array_intersect($token_resource_access, $allowed_resources)) > 0;
    }

    /**
     * Validate if authenticated user has a valid resource
     */
    private function validateScopes(): bool
    {
        $token_scopes = explode(' ', $this->decodedToken->scope);
        $allowed_resources = explode(',', $this->config['allowed_resources']);

        return count(array_intersect($token_scopes, $allowed_resources)) > 0;
    }

    private function saveUser()
    {
        if (!empty($this->decodedToken->preferred_username)) {
            return User::create([
                'email' => $this->decodedToken->preferred_username,
                'name' => $this->decodedToken->name ?? '',
            ]);
        }
    }

    /**
     * Set the current user.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->keyCloakUser->setUser($user, $this->decodedToken);
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @return bool
     */
    public function hasUser()
    {
        return !is_null($this->keyCloakUser->get());
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
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return !is_null($this->keyCloakUser->get());
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
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id()
    {
        return $this->keyCloakUser->id();
    }

    public function user()
    {
        return $this->keyCloakUser->get();
    }

    public function getSubject(): ?string
    {
        return $this->decodedToken->sub ?? null;
    }

    public function getScopes(): array
    {
        if (empty($this->decodedToken->scope)) {
            return [];
        }
        return explode(" ", $this->decodedToken->scope);
    }

    public function getRoles(): array
    {
        if (empty($this->decodedToken->role)) {
            return [];
        }

        return $this->decodedToken->role;
    }

    public function getResourceAccess(): array
    {
        if (empty($this->decodedToken->resource_access)) {
            return [];
        }

        return get_object_vars($this->decodedToken->resource_access);
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->getScopes(), true);
    }

    public function hasRole(string $path, string $role): bool
    {
        return (Arr::get($this->getRoles(), $path) == $role);
    }
}