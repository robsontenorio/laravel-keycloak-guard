<?php

namespace KeycloakGuard\Tests\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use KeycloakGuard\Tests\Models\User;

class UserFactory extends Factory
{
    protected $model = User::class;

    public function definition()
    {
        return [
            'username' => $this->faker->userName,
        ];
    }
}
