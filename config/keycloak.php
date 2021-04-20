<?php 

return [
  'realm1' => [
    'realm_public_key' => env('KEYCLOAK_REALM1_PUBLIC_KEY', null),
    'load_user_from_database' => env('KEYCLOAK_LOAD_USER_FROM_DATABASE', true),
    'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', 'username'),
    'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', 'username'),
    'append_decoded_token' => env('KEYCLOAK_APPEND_DECODED_TOKEN', false),
    'allowed_resources' => env('KEYCLOAK_ALLOWED_RESOURCES', null)
  ],
  'realm2' => [
    'realm_public_key' => env('KEYCLOAK_REALM2_PUBLIC_KEY', null),
    'load_user_from_database' => env('KEYCLOAK_LOAD_USER_FROM_DATABASE', true),
    'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', 'username'),
    'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', 'username'),
    'append_decoded_token' => env('KEYCLOAK_APPEND_DECODED_TOKEN', false),
    'allowed_resources' => env('KEYCLOAK_ALLOWED_RESOURCES', null)
  ],
  'realm3' => [
    'realm_public_key' => env('KEYCLOAK_REALM3_PUBLIC_KEY', null),
    'load_user_from_database' => env('KEYCLOAK_LOAD_USER_FROM_DATABASE', true),
    'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', 'username'),
    'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', 'username'),
    'append_decoded_token' => env('KEYCLOAK_APPEND_DECODED_TOKEN', false),
    'allowed_resources' => env('KEYCLOAK_ALLOWED_RESOURCES', null)
  ],
  'realm4' => [
    'realm_public_key' => env('KEYCLOAK_REALM4_PUBLIC_KEY', null),
    'load_user_from_database' => env('KEYCLOAK_LOAD_USER_FROM_DATABASE', true),
    'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', 'username'),
    'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', 'username'),
    'append_decoded_token' => env('KEYCLOAK_APPEND_DECODED_TOKEN', false),
    'allowed_resources' => env('KEYCLOAK_ALLOWED_RESOURCES', null)
  ]
];
