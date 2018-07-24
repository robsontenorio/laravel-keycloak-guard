<?php

namespace KeycloakGuard\Tests\Controllers;

use Illuminate\Routing\Controller as BaseController;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Request;

class FooController extends BaseController
{
  use AuthorizesRequests;

  public function secret(Request $request)
  {
    return 'protected';
  }

  public function public(Request $request)
  {
    return 'public';
  }
}
