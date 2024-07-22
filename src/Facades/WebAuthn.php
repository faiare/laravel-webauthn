<?php

namespace Faiare\LaravelWebAuthn\Facades;

use Faiare\LaravelWebAuthn\Entities\PrepareChallengeForRegistration;
use Faiare\LaravelWebAuthn\Entities\PrepareAuthenticatePublicKey;
use Faiare\LaravelWebAuthn\Entities\RegisterPublicKey;
use Illuminate\Support\Facades\Facade;

/**
 * @method static RegisterPublicKey register(string $info)
 * @method static PrepareAuthenticatePublicKey prepareForAuthenticate()
 * @method static PrepareChallengeForRegistration prepareChallengeForRegistration(string $username, string $userid, bool $crossPlatform)
 * @method static bool authenticate(string $info, mixed $userwebauthn)
 * @method static string parseWebAuthnId(string $info)
 *
 * @see \Faiare\LaravelWebAuthn\Construct\WebAuthn
 */
class WebAuthn extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'webauthn';
    }
}
