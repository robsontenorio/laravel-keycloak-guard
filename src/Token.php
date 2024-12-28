<?php

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Token
{
    /**
     * Decode a JWT token
     *
     * @param  string  $token
     * @param  string  $publicKey
     * @return mixed|null
     */
    public static function decode(?string $token, string $publicKey, int $leeway = 0, string $algorithm = 'RS256')
    {
        JWT::$leeway = $leeway;
        $publicKey = self::buildPublicKey($publicKey);

        return $token ? JWT::decode($token, new Key($publicKey, $algorithm)) : null;
    }

    /**
     * Build a valid public key from a string
     *
     * @param  string  $key
     * @return mixed
     */
    private static function buildPublicKey(string $key)
    {
        return "-----BEGIN PUBLIC KEY-----\n".wordwrap($key, 64, "\n", true)."\n-----END PUBLIC KEY-----";
    }

    /**
     * Get the plain public key from a string
     *
     * @param  string  $key
     * @return string
     */
    public static function plainPublicKey(string $key): string
    {
        $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $key);
        $string = trim(str_replace('-----END PUBLIC KEY-----', '', $string));
        $string = str_replace('\n', '', $string);

        return $string;
    }
}
