<?php

namespace Faiare\LaravelWebAuthn\Entities;

use JsonSerializable;

readonly class PrepareAuthenticatePublicKey implements JsonSerializable
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

    public function jsonSerialize(): mixed
    {
        return [
            'challenge' => $this->challenge,
            'timeout' => $this->timeout,
            'userVerification' => $this->userVerification,
            'extensions' => $this->extensions,
            'rpId' => $this->rpId,
        ];
    }
}
