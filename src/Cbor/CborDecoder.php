<?php

namespace Faiare\LaravelWebAuthn\Cbor;

/**
 * Minimal CBOR (RFC 8949) decoder covering what WebAuthn needs: the attestationObject and COSE keys.
 *
 * Supported: unsigned/negative integers, byte strings, UTF-8 text strings, arrays, maps with integer or
 * text keys, false/true/null. Everything else (indefinite lengths, tags, floats, other simple values) is
 * rejected, as CTAP2 canonical encoding never produces them.
 *
 * Output mapping: integers -> int, byte strings -> ByteString, text strings -> string,
 * arrays -> list, maps -> array.
 *
 * @internal
 */
final class CborDecoder
{
    private const MAX_DEPTH = 16;

    private int $offset = 0;

    private readonly int $length;

    private function __construct(private readonly string $data)
    {
        $this->length = strlen($data);
    }

    /**
     * Decode exactly one data item; trailing bytes are an error.
     *
     * @throws CborException
     */
    public static function decode(string $data): mixed
    {
        $decoder = new self($data);
        $value = $decoder->readItem(1);
        if ($decoder->offset !== $decoder->length) {
            throw new CborException('CBOR: unexpected trailing data');
        }

        return $value;
    }

    /**
     * Decode the first data item and ignore anything after it.
     *
     * @param int|null $consumed set to the number of bytes the item occupied
     *
     * @throws CborException
     */
    public static function decodeFirst(string $data, ?int &$consumed = null): mixed
    {
        $decoder = new self($data);
        $value = $decoder->readItem(1);
        $consumed = $decoder->offset;

        return $value;
    }

    private function readItem(int $depth): mixed
    {
        $initial = ord($this->read(1));
        $major = $initial >> 5;
        $info = $initial & 0x1f;

        if ($major === 7) {
            return match ($info) {
                20 => false,
                21 => true,
                22 => null,
                default => throw new CborException('CBOR: unsupported simple value or float'),
            };
        }

        $argument = $this->readArgument($info);

        switch ($major) {
            case 0:
                return $argument;
            case 1:
                return -1 - $argument;
            case 2:
                return new ByteString($this->read($argument));
            case 3:
                $text = $this->read($argument);
                if (preg_match('//u', $text) !== 1) {
                    throw new CborException('CBOR: text string is not valid UTF-8');
                }

                return $text;
            case 4:
                $this->assertDepth($depth);
                // every item takes at least one byte, so a count beyond the remaining input cannot be valid
                $this->assertRemaining($argument);
                $list = [];
                for ($i = 0; $i < $argument; $i++) {
                    $list[] = $this->readItem($depth + 1);
                }

                return $list;
            case 5:
                $this->assertDepth($depth);
                // a map entry takes at least two bytes (key and value)
                if ($argument > intdiv($this->length - $this->offset, 2)) {
                    throw new CborException('CBOR: unexpected end of data');
                }
                $map = [];
                for ($i = 0; $i < $argument; $i++) {
                    $key = $this->readItem($depth + 1);
                    if (!is_int($key) && !is_string($key)) {
                        throw new CborException('CBOR: map key must be an integer or text string');
                    }
                    if (array_key_exists($key, $map)) {
                        throw new CborException('CBOR: duplicate map key');
                    }
                    $map[$key] = $this->readItem($depth + 1);
                }

                return $map;
            default: // 6: tags
                throw new CborException('CBOR: tags are not supported');
        }
    }

    private function assertDepth(int $depth): void
    {
        if ($depth > self::MAX_DEPTH) {
            throw new CborException('CBOR: nesting too deep');
        }
    }

    private function readArgument(int $info): int
    {
        if ($info < 24) {
            return $info;
        }

        $value = match ($info) {
            24 => ord($this->read(1)),
            25 => unpack('n', $this->read(2))[1],
            26 => unpack('N', $this->read(4))[1],
            27 => unpack('J', $this->read(8))[1],
            31 => throw new CborException('CBOR: indefinite lengths are not supported'),
            default => throw new CborException('CBOR: reserved additional information value'),
        };

        // 'J' yields a negative PHP int when the top bit is set, i.e. the value exceeds PHP_INT_MAX
        if ($value < 0) {
            throw new CborException('CBOR: integer out of range');
        }

        return $value;
    }

    private function read(int $length): string
    {
        $this->assertRemaining($length);
        $bytes = substr($this->data, $this->offset, $length);
        $this->offset += $length;

        return $bytes;
    }

    private function assertRemaining(int $length): void
    {
        if ($length > $this->length - $this->offset) {
            throw new CborException('CBOR: unexpected end of data');
        }
    }
}
