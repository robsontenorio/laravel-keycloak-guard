<p align="center">
  <img src="bird.png">  
</p>
<p align="center">
&nbsp;
        <img src="https://img.shields.io/packagist/v/robsontenorio/laravel-keycloak-guard.svg" />
        <img src="https://img.shields.io/packagist/dt/robsontenorio/laravel-keycloak-guard.svg" />

</p>

# Simple Keycloak Guard for Laravel / Lumen

This package helps you authenticate users on a Laravel API based on JWT tokens generated from  **Keycloak Server**.


# Requirements

✔️ I`m building an API with Laravel.

✔️ I will not use Laravel Passport for authentication, because Keycloak Server will do the job.

✔️ The frontend is a separated project.

✔️ The frontend users authenticate **directly on Keycloak Server** to obtain a JWT token. This process have nothing to do with the Laravel API.

✔️ The frontend keep the JWT token from Keycloak Server.

✔️ The frontend make requests to the Laravel API, with that token.


💔 If your app does not match requirements, probably you are looking for https://socialiteproviders.com/Keycloak or https://github.com/Vizir/laravel-keycloak-web-guard

# The flow

<p align="center">
  <img src="flow.png">  
</p>


1. The frontend user authenticates on Keycloak Server

1. The frontend user obtains a JWT token.

1. In another moment, the frontend user makes a request to some protected endpoint on a Laravel API, with that token.

1. The Laravel API (through `Keycloak Guard`) handle it.
   - Verify token signature.
   - Verify token structure.
   - Verify token expiration time.
   - Verify if my API allows `resource access` from token.

1. If everything is ok, find the user on database and authenticate it on my API.

1. Optionally, the user can be created / updated in the API users database.

1. Return response

# Install

### Laravel / Lumen

Require the package

```
composer require robsontenorio/laravel-keycloak-guard
```

### Lumen only

Register the provider in your boostrap app file ```bootstrap/app.php```

Add the following line in the "Register Service Providers"  section at the bottom of the file. 

```php
$app->register(\KeycloakGuard\KeycloakGuardServiceProvider::class);
```
For facades, uncomment ```$app->withFacades();``` in your boostrap app file ```bootstrap/app.php```

# Configuration

## Keycloak Guard

The Keycloak Guard configuration can be handled from Laravel `.env` file. ⚠️ Be sure all strings **are trimmed.**


Optionally you can publish the config file.

```
php artisan vendor:publish  --provider="KeycloakGuard\KeycloakGuardServiceProvider"
```


```php
<?php

return [  
  'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),

  'load_user_from_database' => env('KEYCLOAK_LOAD_USER_FROM_DATABASE', true),
    
  'user_provider_custom_retrieve_method' => null,

  'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', 'username'),

  'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', 'preferred_username'),

  'append_decoded_token' => env('KEYCLOAK_APPEND_DECODED_TOKEN', false),

  'allowed_resources' => env('KEYCLOAK_ALLOWED_RESOURCES', null)
];

```

✔️  **realm_public_key**

*Required.*

The Keycloak Server realm public key (string).

> How to get realm public key? Click on "Realm Settings" > "Keys" > "Algorithm RS256" Line > "Public Key" Button  


✔️ **load_user_from_database**

*Required. Default is `true`.*

If you do not have an `users` table you must disable this.

It fetchs user from database and fill values into authenticated user object. If enabled, it will work together with `user_provider_credential` and `token_principal_attribute`.

✔️ **user_provider_custom_retrieve_method**

*Default is `null`.*

If you have an `users` table and want it to be updated (creating or updating users) based on the token, you can inform a custom method on a custom UserProvider, that will be called instead `retrieveByCredentials` and will receive the complete decoded token as parameter, not just the credentials (as default).  
This will allow you to customize the way you want to interact with your database, before matching and delivering the authenticated user object, having all the information contained in the (valid) access token available. To read more about custom UserProviders, please check [Laravel's documentation about](https://laravel.com/docs/8.x/authentication#adding-custom-user-providers).

If using this feature, obviously, values defined for `user_provider_credential` and `token_principal_attribute` will be ignored.

✔️ **user_provider_credential**

*Required. Default is `username`.*


The field from "users" table that contains the user unique identifier (eg.  username, email, nickname). This will be confronted against  `token_principal_attribute` attribute, while authenticating.

✔️ **token_principal_attribute**

*Required. Default is `preferred_username`.*

The property from JWT token that contains the user identifier.
This will be confronted against  `user_provider_credential` attribute, while authenticating.

✔️ **append_decoded_token**

*Default is `false`.*

Appends to the authenticated user the full decoded JWT token (`$user->token`). Useful if you need to know roles, groups and other user info holded by JWT token. Even choosing `false`, you can also get it using `Auth::token()`, see API section.

✔️ **allowed_resources**

*Required*

Usually you API should handle one *resource_access*. But, if you handle multiples, just use a comma separated list of allowed resources accepted by API. This attribute will be confronted against `resource_access` attribute from JWT token, while authenticating.

## Laravel Auth

Changes on `config/auth.php`
```php
...
'defaults' => [
        'guard' => 'api', # <-- For sure, i`m building an API
        'passwords' => 'users',
    ],
    
    ....
    
    'guards' => [
        'api' => [
            'driver' => 'keycloak', # <-- Set the API guard driver to "keycloak"
            'provider' => 'users',
        ],
    ],
```

## Laravel Routes
Just protect some endpoints on `routes/api.php` and you are done!

```php
// public endpoints
Route::get('/hello', function () {
    return ':)';
});

// protected endpoints
Route::group(['middleware' => 'auth:api'], function () {
    Route::get('/protected-endpoint', 'SecretController@index');
    // more endpoints ...
});
```


## Lumen Routes
Just protect some endpoints on `routes/web.php` and you are done!

```php
// public endpoints
$router->get('/hello', function () {
    return ':)';
});

// protected endpoints
$router->group(['middleware' => 'auth'], function () {
    $router->get('/protected-endpoint', 'SecretController@index');
    // more endpoints ...
});
```

# API

Simple Keycloak Guard implements `Illuminate\Contracts\Auth\Guard`. So, all Laravel default methods will be available. Ex: `Auth::user()` returns the authenticated user.

### Default methods:

- check()
- guest()
- user()
- id()
- validate()
- setUser()


### Keycloak Guard methods:

- token()

Ex: `Auth::token()` returns full decoded JWT token from authenticated user

- hasRole('some-resource', 'some-role'):  Check if the authenticated user has especific role into a resource.

Ex:
Whit this payload:

```
'resource_access' => [
  'myapp-backend' => [
      'roles' => [
        'myapp-backend-role1',
        'myapp-backend-role2'
      ]
  ],
  'myapp-frontend' => [
    'roles' => [
      'myapp-frontend-role1',
      'myapp-frontend-role2'
    ]
  ]
]
```
```
Auth::hasRole('myapp-backend', 'myapp-backend-role1') // true
Auth::hasRole('myapp-frontend', 'myapp-frontend-role1') // true
Auth::hasRole('myapp-backend', 'myapp-frontend-role1') // false
```

# Contact

Twitter [@robsontenorio](https://twitter.com/robsontenorio)
