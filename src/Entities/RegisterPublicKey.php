<?php

namespace Faiare\LaravelWebAuthn\Entities;

readonly class RegisterPublicKey
{
    public function __construct(
        public string $key,
        public string $id
    )
    {

    }
}
