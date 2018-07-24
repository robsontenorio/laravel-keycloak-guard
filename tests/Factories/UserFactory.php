<?php
use Faker\Generator as Faker;
use KeycloakGuard\Tests\Models\User;

$factory->define(User::class, function (Faker $faker) {
  return [
    'username' => $faker->userName
  ];
});