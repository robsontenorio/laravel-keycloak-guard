<?php

namespace KeycloakGuard\Tests\Extensions;

use Illuminate\Auth\EloquentUserProvider;

class CustomUserProvider extends EloquentUserProvider
{
    public function custom_retrieve(object $token, array $credentials)
    {
        $model = parent::retrieveByCredentials($credentials);
        $model->customRetrieve = true;

        return $model;
    }
}
