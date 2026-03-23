<?php

namespace KeycloakGuard\Exceptions;

use UnexpectedValueException;

class KeycloakGuardException extends UnexpectedValueException
{
    public function __construct(string $message)
    {
        parent::__construct("[Keycloak Guard] {$message}");
    }
}
