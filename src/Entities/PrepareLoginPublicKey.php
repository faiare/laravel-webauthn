<?php

namespace Faiare\LaravelWebAuthn\Entities;

readonly class PrepareLoginPublicKey
{
    public function __construct(
        public array  $challenge,
        public int    $timeout,
        public string $userVerification,
        public object $extensions,
        public string $rpId
    )
    {
    }
}