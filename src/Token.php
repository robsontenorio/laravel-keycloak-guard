<?php

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

class Token
{
    /**
     * Decode a JWT token
     */
    public static function decode(?string $token, string $publicKey, int $leeway = 0, string $algorithm = 'RS256'): ?stdClass
    {
        JWT::$leeway = $leeway;
        $publicKey = self::buildPublicKey($publicKey);

        return $token ? JWT::decode($token, new Key($publicKey, $algorithm)) : null;
    }

    /**
     * Build a valid public key from a string
     */
    private static function buildPublicKey(string $key): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".wordwrap($key, 64, "\n", true)."\n-----END PUBLIC KEY-----";
    }

    /**
     * Get the plain public key from a string
     */
    public static function plainPublicKey(string $key): string
    {
        $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $key);
        $string = trim(str_replace('-----END PUBLIC KEY-----', '', $string));
        $string = str_replace('\n', '', $string);

        return $string;
    }
}
