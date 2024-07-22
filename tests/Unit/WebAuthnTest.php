<?php

namespace Faiare\LaravelWebAuthn\Tests\Unit;

use Faiare\LaravelWebAuthn\Construct\WebAuthn;
use PHPUnit\Framework\TestCase;

class WebAuthnTest extends TestCase
{
    private WebAuthn $webAuthn;

    protected function setUp(): void
    {
        parent::setUp();
        $this->webAuthn = $this->createMock(WebAuthn::class);
    }

    public function testCancel()
    {
        $this->webAuthn->expects($this->once())
            ->method('cancel')
            ->willReturn('cancelled');

        $result = $this->webAuthn->cancel();
        $this->assertEquals('cancelled', $result);
    }

    public function testRegister()
    {
        $info = 'registration_info';
        $expectedResult = (object)['status' => 'registered'];

        $this->webAuthn->expects($this->once())
            ->method('register')
            ->with($info)
            ->willReturn($expectedResult);

        $result = $this->webAuthn->register($info);
        $this->assertEquals($expectedResult, $result);
    }

    public function testPrepareForLogin()
    {
        $expectedResult = (object)['challenge' => 'login_challenge'];

        $this->webAuthn->expects($this->once())
            ->method('prepareForLogin')
            ->willReturn($expectedResult);

        $result = $this->webAuthn->prepareForLogin();
        $this->assertEquals($expectedResult, $result);
    }

    public function testPrepareChallengeForRegistration()
    {
        $username = 'testuser';
        $userid = 'user123';
        $crossPlatform = true;
        $expectedResult = ['challenge' => 'registration_challenge'];

        $this->webAuthn->expects($this->once())
            ->method('prepareChallengeForRegistration')
            ->with($username, $userid, $crossPlatform)
            ->willReturn($expectedResult);

        $result = $this->webAuthn->prepareChallengeForRegistration($username, $userid, $crossPlatform);
        $this->assertEquals($expectedResult, $result);
    }

    public function testAuthenticate()
    {
        $info = 'authentication_info';
        $userWebAuthn = 'user_webauthn_data';

        $this->webAuthn->expects($this->once())
            ->method('authenticate')
            ->with($info, $userWebAuthn)
            ->willReturn(true);

        $result = $this->webAuthn->authenticate($info, $userWebAuthn);
        $this->assertTrue($result);
    }
}
