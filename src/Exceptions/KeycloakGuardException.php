<?php

namespace KeycloakGuard\Exceptions;

use UnexpectedValueException;

class KeycloakGuardException extends UnexpectedValueException
{
    public function __construct(string $message)
    {
        $this->message = "[Keycloak Guard] {$message}";
    }
}
