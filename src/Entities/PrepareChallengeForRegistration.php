<?php

namespace Faiare\LaravelWebAuthn\Entities;

use JsonSerializable;

readonly class PrepareChallengeForRegistration implements JsonSerializable
{
    public function __construct(
        public object $publicKey,
        public string $b64challenge,
    )
    {
    }

    public function jsonSerialize(): array
    {
        return [
            'publicKey' => $this->publicKey,
            'b64challenge' => $this->b64challenge,
        ];
    }
}
