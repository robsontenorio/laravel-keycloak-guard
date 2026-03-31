<?php

namespace KeycloakGuard\Tests\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User as Authenticatable;

class UuidUser extends Authenticatable {
    use HasUuids;

    protected $table = "uuid_users";

    protected $keyType = 'string';

    public $incrementing = false;
}
