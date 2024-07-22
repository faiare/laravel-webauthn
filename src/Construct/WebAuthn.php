<?php

namespace Faiare\LaravelWebAuthn\Construct;

interface WebAuthn
{
    public function __construct(string $appid);

    public function cancel(): string;

    public function register(string $info): object;

    public function prepareForLogin(): object;

    public function prepareChallengeForRegistration(string $username, string $userid, bool $crossPlatform): array;

    public function authenticate(string $info, mixed $userwebauthn): bool;

    public static function arrayToString(array $a): string;
}
