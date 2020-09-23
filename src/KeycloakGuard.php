<?php

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
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

        $this->authenticate($request);
    }

    /**
     * Decode token, validate and authenticate user
     *
     * @return mixed
     */

    private function authenticate(Request $req)
    {
        $publicKey = $this->config['realm_public_key'];

        try {
            $autorealm_configured = $this->config['autorealm_cookie'];
            if ($autorealm_configured != null) {
                // Check validation
                if (!is_array($autorealm_configured) ||
                    sizeof($autorealm_configured) != 2 ||
                    !is_string($autorealm_configured[0]) ||
                    !is_string($autorealm_configured[1])
                ) {
                    $msg = 'AutoRealm Cookie is not correctly configured in keycloak.php file';
                    Log::error($msg);
                    throw new TokenException($msg);
                }

                // Extract cookie value from Request
                $realm_cookie = $req->cookie($autorealm_configured[0]);
                if ($realm_cookie != null) {
                    $indicated_realm = null;
                    if (is_array($realm_cookie)) {
                        $indicated_realm = $realm_cookie[0];
                    } else {
                        $indicated_realm = $realm_cookie;
                    }

                    Log::debug("AutoRealm Cookie: $indicated_realm");

                    // Obtain signing keys from cache or server
                    $realm_keys = Cache::remember("keycloak-$indicated_realm-keys", 300, function() use ($autorealm_configured, $indicated_realm) {
                        $cert_url = "{$autorealm_configured[1]}/auth/realms/$indicated_realm/protocol/openid-connect/certs";
                        Log::notice("Retrieving realm [$indicated_realm] keys from $cert_url");
                        $response = Http::get($cert_url);
                        if ($response->successful()) {
                            if (isset($response['keys']) && is_array($response['keys'])) {
                                $keys_collection = [];
                                foreach ($response['keys'] as $key) {
                                    $cert = Token::buildPublicCert($key['x5c'][0]);
                                    $pkey = openssl_pkey_get_public($cert);
                                    if (is_bool($pkey) && $pkey == false) {
                                        Log::error("Error converting key wiht kid {$key['kid']} into a public key");
                                        Log::error(openssl_error_string());
                                        continue;
                                    }
                                    $details = openssl_pkey_get_details($pkey);
                                    $keys_collection[$key['kid']] = $details['key'];
                                }

                                return $keys_collection;
                            }
                        } else {
                            $msg = 'Error downloading certificates from IdMS';
                            Log::error($msg);
                            throw new TokenException($msg);
                        }
                    });

                    $this->decodedToken = JWT::decode($this->request->bearerToken(), $realm_keys, ['RS256']);
                } else {
                    $msg = 'AutoRealm Cookie configured, but did not found it';
                    Log::error($msg);
                    throw new TokenException($msg);
                }
            } else {
                $this->decodedToken = Token::decode($this->request->bearerToken(), $this->config['realm_public_key']);
            }



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
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = [], $recursive = false)
    {
        if (!$this->decodedToken) {
            return false;
        }

        $this->validateResources();

        if ($this->config['load_user_from_database']) {
            $user = $this->provider->retrieveByCredentials($credentials);

            if (!$user) {
                if ($this->config['user_auto_register'] && !$recursive) {
                    Log::debug("User of AT does not exists, calling User Auto Registration closure");
                    $this->config['user_auto_register']($this->decodedToken);

                    return $this->validate($credentials, true);
                } else {
                    throw new UserNotFoundException("User not found. Credentials: " . json_encode($credentials));
                }
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
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;

        return $this;
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
