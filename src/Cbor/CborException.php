<?php

namespace Faiare\LaravelWebAuthn\Cbor;

use RuntimeException;

/**
 * Thrown when CBOR input is malformed or uses a feature this decoder does not support.
 *
 * @internal
 */
final class CborException extends RuntimeException
{
}
