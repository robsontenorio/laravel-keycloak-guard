<?php

namespace KeycloakGuard\Tests\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use KeycloakGuard\Tests\Models\User;

class UserFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var string
     */
    protected $model = User::class;


    /**
     * Define the model's default state.
     *
     * @return array
     */
    public function definition()
    {
        return [
            'username' => $this->faker->userName,
        ];
    }
}
