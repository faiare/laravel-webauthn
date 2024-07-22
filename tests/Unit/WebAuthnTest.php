<?php

namespace Faiare\LaravelWebAuthn\Tests\Unit;

use Faiare\LaravelWebAuthn\Facades\WebAuthn;
use Faiare\LaravelWebAuthn\Tests\TestCase;
use Faiare\LaravelWebAuthn\WebAuthnHelper;

class WebAuthnTest extends TestCase
{

    public function test_the_facade_instance()
    {
        $this->assertInstanceOf(
            WebAuthnHelper::class,
            WebAuthn::getFacadeRoot()
        );
    }
}
