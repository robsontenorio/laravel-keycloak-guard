<?php

namespace KeycloakGuard\Tests\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use KeycloakGuard\Tests\Factories\UserFactory;

class User extends Authenticatable
{
    use HasFactory;

    /** Create a new factory instance for the model. */
    protected static function newFactory(): UserFactory
    {
        return UserFactory::new();
    }
}
