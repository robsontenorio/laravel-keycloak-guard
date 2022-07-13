<?php
namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;
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
        return $token ? JWT::decode(
            $token,
            new Key(self::loadPublicKey($publicKey, $keyCloakServer), 'RS256')
        ) : null;
    }

    /**
     * @param string $publicKey
     * @param string $keyCloakServer
     * @return string
     */
    private static function loadPublicKey(string $publicKey = '', string $keyCloakServer = ''): string
    {
        return match (true) {
            strlen($keyCloakServer) > 0 => self::buildPublicKey(self::getPublicFromKeyCloak($keyCloakServer)),
            strlen($publicKey) > 0 => self::buildPublicKey($publicKey),
            default => throw new TokenException('No public key found.'),
        };
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
        $key = Cache::get('keycloak_key');
        if(isset($key)) {
            return $key;
        }

        $response = Http::get($keyCloakServer);
        if (!$response->successful()) {
            throw new TokenException("Cant get public key from keycloak server.");
        }

        Cache::put('keycloak_key', $response->json()['public_key'], now()->addHours(config('keycloak')['key_cache_time']));
        return $response->json()['public_key'];
    }
}
