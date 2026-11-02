<?php

namespace Faiare\LaravelWebAuthn\Tests\Unit;

use Faiare\LaravelWebAuthn\Cbor\ByteString;
use Faiare\LaravelWebAuthn\Cbor\CborDecoder;
use Faiare\LaravelWebAuthn\Cbor\CborException;
use Faiare\LaravelWebAuthn\Tests\Support\CborEncoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class CborDecoderTest extends TestCase
{
    // ------------------------------------------------------------ valid items

    public static function validVectors(): array
    {
        return [
            'uint 0' => ['00', 0],
            'uint 1' => ['01', 1],
            'uint 10' => ['0a', 10],
            'uint 23' => ['17', 23],
            'uint 24' => ['1818', 24],
            'uint 25' => ['1819', 25],
            'uint 100' => ['1864', 100],
            'uint 255' => ['18ff', 255],
            'uint 1000' => ['1903e8', 1000],
            'uint 65535' => ['19ffff', 65535],
            'uint 1000000' => ['1a000f4240', 1000000],
            'uint 4294967295' => ['1affffffff', 4294967295],
            'uint 1000000000000' => ['1b000000e8d4a51000', 1000000000000],
            'uint PHP_INT_MAX' => ['1b7fffffffffffffff', PHP_INT_MAX],
            'nint -1' => ['20', -1],
            'nint -10' => ['29', -10],
            'nint -24' => ['37', -24],
            'nint -25' => ['3818', -25],
            'nint -100' => ['3863', -100],
            'nint -1000' => ['3903e7', -1000],
            'nint -7 (ES256)' => ['26', -7],
            'nint -257 (RS256)' => ['390100', -257],
            'nint PHP_INT_MIN' => ['3b7fffffffffffffff', PHP_INT_MIN],
            'empty bstr' => ['40', new ByteString('')],
            'bstr 4 bytes' => ['4401020304', new ByteString("\x01\x02\x03\x04")],
            'bstr 1-byte length' => ['5801ff', new ByteString("\xff")],
            'bstr 2-byte length' => ['590001ab', new ByteString("\xab")],
            'bstr 4-byte length' => ['5a00000001ab', new ByteString("\xab")],
            'bstr 8-byte length' => ['5b0000000000000001ab', new ByteString("\xab")],
            'empty tstr' => ['60', ''],
            'tstr a' => ['6161', 'a'],
            'tstr IETF' => ['6449455446', 'IETF'],
            'tstr quote-backslash' => ['62225c', "\"\\"],
            'tstr u-umlaut' => ['62c3bc', "\u{00fc}"],
            'tstr water' => ['63e6b0b4', "\u{6c34}"],
            'tstr emoji' => ['64f0908591', "\u{10151}"],
            'tstr 1-byte length' => ['780161', 'a'],
            'false' => ['f4', false],
            'true' => ['f5', true],
            'null' => ['f6', null],
            'empty array' => ['80', []],
            'array [1,2,3]' => ['83010203', [1, 2, 3]],
            'nested array' => ['8301820203820405', [1, [2, 3], [4, 5]]],
            'array 1-byte count' => ['9801' . '00', [0]],
            'empty map' => ['a0', []],
            'map {1:2,3:4}' => ['a201020304', [1 => 2, 3 => 4]],
            'map text keys' => ['a26161016162820203', ['a' => 1, 'b' => [2, 3]]],
            'array with map' => ['826161a161626163', ['a', ['b' => 'c']]],
            'map negative keys' => ['a22001' . '2102', [-1 => 1, -2 => 2]],
            'array of bools/null' => ['83f4f5f6', [false, true, null]],
        ];
    }

    #[DataProvider('validVectors')]
    public function test_decode_valid_vector(string $hex, mixed $expected): void
    {
        $actual = CborDecoder::decode(hex2bin($hex));

        if (is_object($expected)) {
            $this->assertEquals($expected, $actual);
        } else {
            $this->assertSame($expected, $actual);
        }
    }

    public function test_byte_string_is_wrapped_and_text_string_is_plain_string(): void
    {
        $this->assertInstanceOf(ByteString::class, CborDecoder::decode("\x41a"));
        $this->assertSame('a', CborDecoder::decode("\x61a"));
        $this->assertSame("\x00\xff", CborDecoder::decode("\x42\x00\xff")->bytes);
    }

    public function test_map_with_array_value_keeps_int_keys_as_int(): void
    {
        $result = CborDecoder::decode(hex2bin('a201020304'));

        $this->assertSame([1, 3], array_keys($result));
    }

    public function test_array_is_returned_as_list(): void
    {
        $result = CborDecoder::decode(hex2bin('83010203'));

        $this->assertTrue(array_is_list($result));
    }

    public function test_text_string_with_embedded_nul_is_valid(): void
    {
        $this->assertSame("a\0b", CborDecoder::decode("\x63a\0b"));
    }

    // -------------------------------------------------------------- COSE key

    public function test_decodes_realistic_cose_es256_key(): void
    {
        $x = random_bytes(32);
        $y = random_bytes(32);
        $cbor = CborEncoder::encode([
            1 => 2,
            3 => -7,
            -1 => 1,
            -2 => new ByteString($x),
            -3 => new ByteString($y),
        ]);

        $key = CborDecoder::decode($cbor);

        $this->assertSame(2, $key[1]);
        $this->assertSame(-7, $key[3]);
        $this->assertSame(1, $key[-1]);
        $this->assertInstanceOf(ByteString::class, $key[-2]);
        $this->assertSame($x, $key[-2]->bytes);
        $this->assertSame($y, $key[-3]->bytes);
        $this->assertCount(5, $key);
    }

    public function test_decodes_attestation_object_shape(): void
    {
        $authData = random_bytes(60);
        $cbor = CborEncoder::encode([
            'fmt' => 'none',
            'attStmt' => [],
            'authData' => new ByteString($authData),
        ]);

        $ao = CborDecoder::decode($cbor);

        $this->assertSame('none', $ao['fmt']);
        $this->assertSame([], $ao['attStmt']);
        $this->assertSame($authData, $ao['authData']->bytes);
    }

    // ------------------------------------------------------------ round trips

    public static function roundTripValues(): array
    {
        return [
            'zero' => [0],
            'small' => [23],
            '1-byte' => [24],
            '1-byte max' => [255],
            '2-byte' => [256],
            '2-byte max' => [65535],
            '4-byte' => [65536],
            '4-byte max' => [4294967295],
            '8-byte' => [4294967296],
            'int max' => [PHP_INT_MAX],
            'neg small' => [-1],
            'neg 24' => [-24],
            'neg 25' => [-25],
            'neg 256' => [-256],
            'neg 257' => [-257],
            'neg 4-byte' => [-4294967296],
            'neg 8-byte' => [-4294967297],
            'int min' => [PHP_INT_MIN],
            'empty string' => [''],
            'string' => ['hello'],
            'long string (2-byte len)' => [str_repeat('x', 300)],
            'long string (4-byte len)' => [str_repeat('y', 70000)],
            'unicode' => ["\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}"],
            'true' => [true],
            'false' => [false],
            'null' => [null],
            'bytes' => [new ByteString("\x00\x01\xfe\xff")],
            'empty bytes' => [new ByteString('')],
            'long bytes' => [new ByteString(str_repeat("\xaa", 300))],
            'list' => [[1, 'a', true, null, new ByteString('z')]],
            'long list (1-byte count)' => [range(0, 99)],
            'long list (2-byte count)' => [range(0, 299)],
            'empty array' => [[]],
            'int-key map' => [[1 => 2, 3 => -7, -1 => 1]],
            'text-key map' => [['a' => 1, 'b' => [1, 2], 'c' => ['d' => null]]],
            'nested' => [[[1, [2, [3, []]]], ['k' => [new ByteString('v')]]]],
        ];
    }

    #[DataProvider('roundTripValues')]
    public function test_round_trip_through_test_encoder(mixed $value): void
    {
        $decoded = CborDecoder::decode(CborEncoder::encode($value));

        $this->assertEquals($value, $decoded);
    }

    // ------------------------------------------------------------ decodeFirst

    public function test_decode_first_ignores_trailing_bytes_and_reports_consumed(): void
    {
        $item = CborEncoder::encode([1 => 2, 3 => -7]);

        $result = CborDecoder::decodeFirst($item . "\xa1\x01\x02garbage", $consumed);

        $this->assertSame([1 => 2, 3 => -7], $result);
        $this->assertSame(strlen($item), $consumed);
    }

    public function test_decode_first_without_trailing_bytes_consumes_everything(): void
    {
        $item = hex2bin('83010203');

        $result = CborDecoder::decodeFirst($item, $consumed);

        $this->assertSame([1, 2, 3], $result);
        $this->assertSame(4, $consumed);
    }

    public function test_decode_first_works_without_consumed_argument(): void
    {
        $this->assertSame(1, CborDecoder::decodeFirst("\x01\x02"));
    }

    public static function decodeFirstConsumedVectors(): array
    {
        return [
            'tiny uint' => ['00', 1],
            '1-byte uint' => ['1818', 2],
            '2-byte uint' => ['1903e8', 3],
            '4-byte uint' => ['1a000f4240', 5],
            '8-byte uint' => ['1b000000e8d4a51000', 9],
            'bstr' => ['4401020304', 5],
            'tstr' => ['6449455446', 5],
            'array' => ['83010203', 4],
            'map' => ['a201020304', 5],
            'simple' => ['f5', 1],
        ];
    }

    #[DataProvider('decodeFirstConsumedVectors')]
    public function test_decode_first_consumed_count(string $hex, int $expected): void
    {
        CborDecoder::decodeFirst(hex2bin($hex) . "\x00\x00\x00", $consumed);

        $this->assertSame($expected, $consumed);
    }

    public function test_decode_first_trailing_garbage_that_is_invalid_cbor_is_not_inspected(): void
    {
        $this->assertSame(5, CborDecoder::decodeFirst("\x05\xff\xff\xc0", $consumed));
        $this->assertSame(1, $consumed);
    }

    public function test_decode_first_still_throws_on_malformed_first_item(): void
    {
        $this->expectException(CborException::class);
        CborDecoder::decodeFirst("\x44\x01\x02");
    }

    // ----------------------------------------------------------------- errors

    public static function malformedVectors(): array
    {
        return [
            'empty input' => [''],

            // truncated
            'truncated 1-byte argument' => ['18'],
            'truncated 2-byte argument' => ['19ff'],
            'truncated 4-byte argument' => ['1affffff'],
            'truncated 8-byte argument' => ['1b00000000000000'],
            'truncated negative argument' => ['38'],
            'truncated bstr length' => ['58'],
            'bstr shorter than length' => ['440102'],
            'bstr shorter (3 of 4)' => ['44010203'],
            'tstr shorter than length' => ['6449'],
            'tstr 1-byte len, no data' => ['7805'],
            'array missing items' => ['830102'],
            'array no items' => ['81'],
            'array 1-byte count truncated' => ['98'],
            'map missing second pair' => ['a2010203'],
            'map no items' => ['a1'],
            'map key without value' => ['a101'],
            'nested truncated' => ['8281'],

            // indefinite lengths
            'indefinite bstr' => ['5f4101ff'],
            'indefinite tstr' => ['7f6161ff'],
            'indefinite array' => ['9f0102ff'],
            'indefinite map' => ['bf01 02ff'],
            'lone break' => ['ff'],
            'indefinite uint (0x1f)' => ['1f'],
            'indefinite nint (0x3f)' => ['3f'],

            // reserved additional info
            'reserved ai 28 uint' => ['1c'],
            'reserved ai 29 uint' => ['1d'],
            'reserved ai 30 uint' => ['1e'],
            'reserved ai 28 nint' => ['3c'],
            'reserved ai 30 bstr' => ['5e'],
            'reserved ai 29 tstr' => ['7d'],
            'reserved ai 28 array' => ['9c'],
            'reserved ai 30 map' => ['be'],

            // tags
            'tag 0' => ['c074323031332d30332d32315432303a30343a30305a'],
            'tag 1' => ['c11a514b67b0'],
            'tag 24' => ['d818456449455446'],
            'tag 55799' => ['d9d9f700'],
            'tag inside array' => ['81c000'],

            // floats and other simple values
            'float16' => ['f93c00'],
            'float32' => ['fa47c35000'],
            'float64' => ['fb3ff199999999999a'],
            'undefined' => ['f7'],
            'simple 0' => ['e0'],
            'simple 16' => ['f0'],
            'simple 1-byte' => ['f820'],
            'simple 1-byte false-like' => ['f814'],
            'float inside array' => ['81f93c00'],

            // integers that do not fit PHP int
            'uint 2^63' => ['1b8000000000000000'],
            'uint 2^64-1' => ['1bffffffffffffffff'],
            'nint -1-2^63' => ['3b8000000000000000'],
            'nint -2^64' => ['3bffffffffffffffff'],

            // lengths and counts larger than the input
            'bstr huge 8-byte length' => ['5bffffffffffffffff'],
            'bstr int-max length' => ['5b7fffffffffffffff'],
            'bstr 4-byte huge length' => ['5affffffff00'],
            'bstr length 2^32' => ['5b000000010000000000'],
            'tstr huge 8-byte length' => ['7bffffffffffffffff'],
            'tstr int-max length' => ['7b7fffffffffffffff6161'],
            'array huge 8-byte count' => ['9bffffffffffffffff'],
            'array int-max count' => ['9b7fffffffffffffff00'],
            'array 4-byte huge count' => ['9affffffff00'],
            'array count 2^32' => ['9b000000010000000000'],
            'map huge 8-byte count' => ['bbffffffffffffffff'],
            'map int-max count' => ['bb7fffffffffffffff0102'],
            'map 4-byte huge count' => ['baffffffff0102'],
            'nested huge count' => ['819bffffffffffffffff'],

            // invalid UTF-8
            'tstr lone continuation' => ['6180'],
            'tstr truncated sequence' => ['62c3' . '28'],
            'tstr overlong' => ['62c080'],
            'tstr surrogate' => ['63eda080'],
            'tstr 0xff' => ['61ff'],
            'tstr beyond U+10FFFF' => ['64f4908080'],

            // invalid map keys
            'map key bstr' => ['a1410102'],
            'map key array' => ['a1810102'],
            'map key empty array' => ['a18002'],
            'map key map' => ['a1a0' . '02'],
            'map key false' => ['a1f402'],
            'map key true' => ['a1f502'],
            'map key null' => ['a1f602'],
            'second map key invalid' => ['a2010241' . '0003'],

            // duplicate keys
            'duplicate int keys' => ['a201010102'],
            'duplicate negative int keys' => ['a220012002'],
            'duplicate text keys' => ['a2616101616102'],
            'duplicate key in nested map' => ['a1' . '6161' . 'a201010102'],

            // trailing bytes (decode() only)
            'trailing byte after uint' => ['0000'],
            'trailing bytes after array' => ['83010203' . '00'],
            'trailing break after map' => ['a0ff'],
            'trailing garbage after bstr' => ['4101' . '0102'],
        ];
    }

    #[DataProvider('malformedVectors')]
    public function test_decode_throws_cbor_exception_with_code_zero(string $hex): void
    {
        $data = hex2bin(str_replace(' ', '', $hex));

        try {
            CborDecoder::decode($data);
            $this->fail('Expected CborException for ' . $hex);
        } catch (CborException $e) {
            $this->assertSame(0, $e->getCode());
            $this->assertInstanceOf(\RuntimeException::class, $e);
        }
    }

    public static function malformedForDecodeFirst(): array
    {
        $all = self::malformedVectors();
        // Trailing-bytes cases are valid for decodeFirst.
        foreach (['trailing byte after uint', 'trailing bytes after array', 'trailing break after map', 'trailing garbage after bstr'] as $k) {
            unset($all[$k]);
        }

        return $all;
    }

    #[DataProvider('malformedForDecodeFirst')]
    public function test_decode_first_throws_for_malformed_first_item(string $hex): void
    {
        $data = hex2bin(str_replace(' ', '', $hex));

        $this->expectException(CborException::class);
        CborDecoder::decodeFirst($data);
    }

    public function test_decode_throws_when_trailing_bytes_follow_a_valid_item(): void
    {
        $this->expectException(CborException::class);
        CborDecoder::decode("\x01\x02");
    }

    public function test_decode_first_accepts_what_decode_rejects_for_trailing_bytes(): void
    {
        $this->assertSame(1, CborDecoder::decodeFirst("\x01\x02", $consumed));
        $this->assertSame(1, $consumed);
    }

    public function test_huge_declared_length_fails_fast_without_allocating(): void
    {
        $before = memory_get_peak_usage();

        foreach (["\x5b" . str_repeat("\xff", 8), "\x9b" . str_repeat("\xff", 8), "\xbb" . str_repeat("\xff", 8), "\x5b\x00\x00\x00\x00\xff\xff\xff\xff", "\x9a\x7f\xff\xff\xff"] as $data) {
            try {
                CborDecoder::decode($data);
                $this->fail('Expected CborException');
            } catch (CborException) {
                $this->addToAssertionCount(1);
            }
        }

        $this->assertLessThan(16 * 1024 * 1024, memory_get_peak_usage() - $before);
    }

    // ----------------------------------------------------------------- depth

    public function test_sixteen_nested_arrays_are_allowed(): void
    {
        $result = CborDecoder::decode(str_repeat("\x81", 15) . "\x80");

        $depth = 1;
        while ($result !== []) {
            $this->assertIsArray($result);
            $this->assertCount(1, $result);
            $result = $result[0];
            $depth++;
        }
        $this->assertSame(16, $depth);
    }

    public function test_seventeen_nested_arrays_are_rejected(): void
    {
        $this->expectException(CborException::class);
        CborDecoder::decode(str_repeat("\x81", 16) . "\x80");
    }

    public function test_deep_nesting_is_rejected_without_blowing_the_stack(): void
    {
        $this->expectException(CborException::class);
        CborDecoder::decode(str_repeat("\x81", 100000) . "\x80");
    }

    public function test_sixteen_nested_maps_are_allowed(): void
    {
        $data = str_repeat("\xa1\x01", 15) . "\xa0";

        $result = CborDecoder::decode($data);

        $this->assertIsArray($result);
    }

    public function test_seventeen_nested_maps_are_rejected(): void
    {
        $this->expectException(CborException::class);
        CborDecoder::decode(str_repeat("\xa1\x01", 16) . "\xa0");
    }

    public function test_nesting_depth_limit_applies_with_decode_first(): void
    {
        $this->expectException(CborException::class);
        CborDecoder::decodeFirst(str_repeat("\x81", 16) . "\x80" . "\x00");
    }
}
