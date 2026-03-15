<?php

namespace KeycloakGuard\Exceptions;

class KeycloakGuardException extends \UnexpectedValueException
{
    public function __construct(string $message)
    {
        parent::__construct("[Keycloak Guard] {$message}");
    }
}
