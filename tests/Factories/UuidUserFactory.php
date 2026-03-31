<?php

namespace KeycloakGuard\Tests\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use KeycloakGuard\Tests\Models\UuidUser;

class UuidUserFactory extends Factory
{
    protected $model = UuidUser::class;

    public function definition(): array
    {
        return [
            'id' => $this->faker->uuid(),
            'username' => $this->faker->userName(),
        ];
    }
}