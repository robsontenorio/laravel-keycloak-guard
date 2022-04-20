<?php
namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Http;
use KeycloakGuard\Exceptions\TokenException;

class Token
{
    /**
     * Decode a JWT token
     *
     * @param string|null $token
     * @param string $publicKey
     * @param string $keyCloakServer
     * @return mixed|null
     */
    public static function decode(string $token = null, string $publicKey = '', string $keyCloakServer = '')
    {
        if (!empty($publicKey)) {
            $publicKey = self::buildPublicKey($publicKey);
        }

        if (!empty($keyCloakServer)) {
            $publicKey = self::getPublicFromKeyCloak($keyCloakServer);
        }

        if (empty($publicKey)) {
            throw new TokenException("No pub key found.");
        }

        return $token ? JWT::decode($token, new Key($publicKey, 'RS256')) : null;
    }

    /**
     * Build a valid public key from a string
     *
     * @param  string  $key
     * @return mixed
     */
    private static function buildPublicKey(string $key)
    {
        return "-----BEGIN PUBLIC KEY-----\n" . wordwrap($key, 64, "\n", true) . "\n-----END PUBLIC KEY-----";
    }

    /**
     * @param string $keyCloakServer
     * @return mixed
     */
    private static function getPublicFromKeyCloak(string $keyCloakServer)
    {
        $response = Http::get($keyCloakServer);
        if (!$response->successful()) {
            throw new TokenException("Cant get public key from keycloak server.");
        }

        return $response->json()['public_key'];
    }
}
