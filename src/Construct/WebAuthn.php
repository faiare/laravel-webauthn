<?php

namespace Faiare\LaravelWebAuthn\Construct;

use Faiare\LaravelWebAuthn\Entities\PrepareChallengeForRegistration;
use Faiare\LaravelWebAuthn\Entities\PrepareLoginPublicKey;
use Faiare\LaravelWebAuthn\Entities\RegisterPublicKey;

interface WebAuthn
{
    public function __construct(string $appid);

    public function prepareChallengeForRegistration(
        string $username, string $userid, bool $crossPlatform
    ): PrepareChallengeForRegistration;

    public function register(string $info): RegisterPublicKey;

    public function prepareForAuthenticate(): PrepareLoginPublicKey;

    public function authenticate(string $info, mixed $userwebauthn): bool;

    public function parseWebAuthnId(string $info): string;
}
