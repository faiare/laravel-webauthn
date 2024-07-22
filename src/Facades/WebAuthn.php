<?php

namespace Faiare\LaravelWebAuthn\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string cancel()
 * @method static object register(string $info)
 * @method static object prepareForLogin()
 * @method static array prepareChallengeForRegistration(string $username, string $userid, bool $crossPlatform)
 * @method static bool authenticate(string $info, mixed $userwebauthn)
 * @method static string arrayToString(array $a)
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
    protected static function getFacadeAccessor()
    {
        return 'webauthn';
    }
}
