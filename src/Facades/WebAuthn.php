<?php

namespace Faiare\LaravelWebAuthn\Facades;

use Illuminate\Support\Facades\Facade;

class WebAuthn extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'webauthn';
    }
}
