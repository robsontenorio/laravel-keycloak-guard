<p align="center">
  <img src="bird.png">  
</p>
<p align="center">
&nbsp;
        <img src="https://img.shields.io/packagist/v/robsontenorio/laravel-keycloak-guard.svg" />
        <img src="https://img.shields.io/packagist/dt/robsontenorio/laravel-keycloak-guard.svg" />

</p>

# Simple Keycloak Guard for Laravel

This package helps you authenticate users on a Laravel API based on JWT tokens generated from  **Keycloak Server**.


# Requirements

✔️ I`m building an API with Laravel. 

✔️ I will not use Laravel Passport, because Keycloak Server will do the job.

✔️ The frontend is a separated project.

✔️ The frontend users authenticate **directly on Keycloak Server** to obtain a JWT token. This process have nothing to do with the Laravel API.

✔️ The frontend keep the JWT token.

✔️ The frontend make requests to the backend with that token.



# How does it work


1. The frontend user authenticates on Keycloak Server and obtains a JWT token.

1. In another moment, the frontend user makes a request to some endpoint on a Laravel API, with that token.

1. The Laravel API (through Simple Keycloak Guard) validates the user based on that token.
   - is this a trustable token?
   - Is this a valid token?
   - Is this a expired token?
   - Find the user on database and authenticate it.
   - Process the request

# Install

Require the package

```
composer require robsontenorio/laravel-keycloak-guard
```

Publish the config file

```
php artisan vendor:publish  --provider="KeycloakGuard\KeycloakGuardServiceProvider" 

```

# Configuration

## Keycloack guard config

Note that `config/keycloak.php` support `.env` files.
```php
<?php 

return [  
  'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),
  'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', null),
  'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', null),
  'decode_user_details' => env('KEYCLOAK_DECODE_USER_DETAILS', true)
];

```

**realm_public_key**

The Keycloack Server realm public key (RSA256 format).

**user_provider_credential**


The field from `users` table that contains the user unique identifier (eg.  `username`, `email`, `nickname`). 

**token_principal_attribute**

The property from JWT token that contains the user identifier. 
This will be confronted against  `user_provider_credential` attribute.

**decode_user_details**

Appends to the authenticated user the full decoded JWT token. Useful if you need to kwnow roles, groups and another user info holded by JWT token.

## Laravel auth config

Changes on `config/auth.php`
```php
'defaults' => [
        'guard' => 'api', # <-- For sure, i`m building an API
        'passwords' => 'users',
    ],

    'guards' => [
        'api' => [
            'driver' => 'keycloak', # <-- Set the API guard to "keycloack"
            'provider' => 'users',
        ],
    ],
```