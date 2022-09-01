<?php

namespace KeycloakGuard\Tests\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

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
