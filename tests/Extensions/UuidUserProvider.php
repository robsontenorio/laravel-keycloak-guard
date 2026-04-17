<?php

namespace KeycloakGuard\Tests\Extensions;

use Illuminate\Auth\EloquentUserProvider;
use KeycloakGuard\Tests\Models\UuidUser;

class UuidUserProvider extends EloquentUserProvider
{
    public function custom_retrieve(object $token, array $credentials)
    {
        $user = new UuidUser();
        $user->customRetrieve = true;

        return $user;
    }
}
