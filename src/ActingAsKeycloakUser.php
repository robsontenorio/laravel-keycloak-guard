<?php

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Config;

trait ActingAsKeycloakUser
{
    public function actingAsKeycloakUser($user = null)
    {
        if (!$user) {
            Config::set('keycloak.load_user_from_database', false);
        }

        $token = $this->generateKeycloakToken($user);

        $this->withHeader('Authorization', 'Bearer '.$token);

        return $this;
    }

    public function generateKeycloakToken($user = null)
    {
        $privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);

        $publicKey = openssl_pkey_get_details($privateKey)['key'];

        $publicKey = Token::plainPublicKey($publicKey);

        Config::set('keycloak.realm_public_key', $publicKey);

        $payload = [
            'preferred_username' => $user->username ?? config('keycloak.preferred_username'),
            'resource_access' => [config('keycloak.allowed_resources') => []]
        ];

        $token = JWT::encode($payload, $privateKey, 'RS256');

        return $token;
    }
}
