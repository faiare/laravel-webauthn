<?php

namespace Faiare\LaravelWebAuthn\Entities;

readonly class Extensions
{
    public function __construct(public ?bool $exts = null, public ?string $txAuthSimple = null)
    {
    }
}
