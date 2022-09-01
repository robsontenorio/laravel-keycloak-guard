<?php

namespace KeycloakGuard\Exceptions;

class KeycloakGuardException extends \UnexpectedValueException
{
    public function __construct(string $message)
    {
        $this->message = "[Keycloak Guard] {$message}";
    }
}
