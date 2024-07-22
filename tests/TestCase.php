<?php

namespace Faiare\LaravelWebAuthn\Tests;

use Faiare\LaravelWebAuthn\WebAuthnServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

class TestCase extends OrchestraTestCase
{

    protected function getPackageProviders($app): array
    {
        return [
            WebAuthnServiceProvider::class,
        ];
    }

    public function setUp(): void
    {
        parent::setUp();

        config()->set('webauthn.appId', 'localhost');
    }
}
