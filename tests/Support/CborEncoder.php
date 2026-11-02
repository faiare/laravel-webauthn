<?php

namespace Faiare\LaravelWebAuthn\Tests\Support;

use Faiare\LaravelWebAuthn\Cbor\ByteString;
use InvalidArgumentException;

/**
 * Minimal CBOR encoder for tests only.
 * Supports int, string (text), ByteString, bool, null, non-empty lists (array) and other arrays (map).
 */
final class CborEncoder
{
    public static function encode(mixed $value): string
    {
        if (is_int($value)) {
            return $value >= 0 ? self::head(0, $value) : self::head(1, ~$value);
        }
        if (is_string($value)) {
            return self::head(3, strlen($value)) . $value;
        }
        if ($value instanceof ByteString) {
            return self::head(2, strlen($value->bytes)) . $value->bytes;
        }
        if ($value === true) {
            return "\xf5";
        }
        if ($value === false) {
            return "\xf4";
        }
        if ($value === null) {
            return "\xf6";
        }
        if (is_array($value)) {
            if ($value !== [] && array_is_list($value)) {
                $out = self::head(4, count($value));
                foreach ($value as $item) {
                    $out .= self::encode($item);
                }

                return $out;
            }
            $out = self::head(5, count($value));
            foreach ($value as $k => $v) {
                $out .= self::encode($k) . self::encode($v);
            }

            return $out;
        }

        throw new InvalidArgumentException('Unsupported value type: ' . get_debug_type($value));
    }

    private static function head(int $major, int $n): string
    {
        $m = $major << 5;
        if ($n < 24) {
            return chr($m | $n);
        }
        if ($n <= 0xff) {
            return chr($m | 24) . chr($n);
        }
        if ($n <= 0xffff) {
            return chr($m | 25) . pack('n', $n);
        }
        if ($n <= 0xffffffff) {
            return chr($m | 26) . pack('N', $n);
        }

        return chr($m | 27) . pack('J', $n);
    }
}
