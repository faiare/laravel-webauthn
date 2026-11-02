<?php

namespace Faiare\LaravelWebAuthn\Cbor;

/**
 * A decoded CBOR byte string (major type 2), kept distinct from text strings.
 *
 * @internal
 */
final readonly class ByteString
{
    public function __construct(public string $bytes)
    {
    }
}
