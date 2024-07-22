<?php

namespace Faiare\LaravelWebAuthn\Tests\Unit;

use Faiare\LaravelWebAuthn\Entities\PrepareChallengeForRegistration;
use Faiare\LaravelWebAuthn\Entities\RegisterPublicKey;
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

    public function test_prepare_challenge_for_registration()
    {
        $result = WebAuthn::prepareChallengeForRegistration(
            username: 'test',
            userid: 'test',
            crossPlatform: true
        );

        $this->assertInstanceOf(PrepareChallengeForRegistration::class, $result);

        $this->assertArrayHasKey('publicKey', $result->jsonSerialize());
        $this->assertArrayHasKey('b64challenge', $result->jsonSerialize());
    }

    public function test_register()
    {
        // TODO: Implement test_register() method.
    }
}
