<?php 

return [
  'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),
  'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', null),
  'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', null),
  'decode_user_details' => env('KEYCLOAK_DECODE_USER_DETAILS', true)
];
