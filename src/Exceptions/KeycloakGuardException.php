<?php
namespace KeycloakGuard\Exceptions;

class KeycloakGuardException extends \UnexpectedValueException
{
  public function __construct(string $message)
  {
    $this->message = "[Keycloack Guard] {$message}";
  }
}