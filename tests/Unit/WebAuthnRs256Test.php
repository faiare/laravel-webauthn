<?php

namespace Faiare\LaravelWebAuthn\Tests\Unit;

use Faiare\LaravelWebAuthn\Cbor\ByteString;
use Faiare\LaravelWebAuthn\Entities\RegisterPublicKey;
use Faiare\LaravelWebAuthn\Facades\WebAuthn;
use Faiare\LaravelWebAuthn\Tests\Support\CborEncoder;
use Faiare\LaravelWebAuthn\Tests\TestCase;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

/**
 * RS256 (COSE alg -257) registration / authentication tests.
 * Keys are generated at runtime; COSE and attestationObject are built with CborEncoder.
 */
class WebAuthnRs256Test extends TestCase
{
    private const APP_ID = 'localhost';

    // ---------------------------------------------------------------- helpers

    private function generateKey(int $bits): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($key, 'openssl_pkey_new failed: ' . openssl_error_string());

        return $key;
    }

    /** @return array{0: string, 1: string} raw big-endian [n, e] */
    private function rsaParams(OpenSSLAsymmetricKey $key): array
    {
        $d = openssl_pkey_get_details($key);

        return [$d['rsa']['n'], $d['rsa']['e']];
    }

    private function coseKey(?string $n, ?string $e, int $alg = -257): string
    {
        $map = [1 => 3, 3 => $alg];
        if ($n !== null) {
            $map[-1] = new ByteString($n);
        }
        if ($e !== null) {
            $map[-2] = new ByteString($e);
        }

        return CborEncoder::encode($map);
    }

    private function bytes(string $s): array
    {
        return array_values(unpack('C*', $s) ?: []);
    }

    private function registerInfo(string $cose, string $credId, int $flags = 0x41): string
    {
        $authData = hash('sha256', self::APP_ID, true)
            . chr($flags)
            . pack('N', 0)
            . str_repeat("\x00", 16)
            . pack('n', strlen($credId))
            . $credId
            . $cose;

        $ao = CborEncoder::encode([
            'fmt' => 'none',
            'attStmt' => [],
            'authData' => new ByteString($authData),
        ]);

        return json_encode([
            'rawId' => $this->bytes($credId),
            'id' => rtrim(strtr(base64_encode($credId), '+/', '-_'), '='),
            'type' => 'public-key',
            'response' => [
                'attestationObject' => $this->bytes($ao),
                'clientDataJSON' => [
                    'type' => 'webauthn.create',
                    'challenge' => 'O2xorCE-OAlp3KJYqYJXog',
                    'origin' => 'http://localhost:8000',
                    'crossOrigin' => false,
                ],
            ],
        ]);
    }

    private function registerKey(OpenSSLAsymmetricKey $key, string $credId): RegisterPublicKey
    {
        [$n, $e] = $this->rsaParams($key);

        return WebAuthn::register($this->registerInfo($this->coseKey($n, $e), $credId));
    }

    /** @return array{0: string, 1: object} [info JSON, user row] */
    private function assertion(OpenSSLAsymmetricKey $priv, RegisterPublicKey $reg, string $credId, bool $tamper = false): array
    {
        $challenge = random_bytes(16);
        $b64 = rtrim(strtr(base64_encode($challenge), '+/', '-_'), '=');
        $clientData = [
            'type' => 'webauthn.get',
            'challenge' => $b64,
            'origin' => 'http://localhost:8000',
            'crossOrigin' => false,
        ];
        $clientJson = json_encode($clientData);

        $rpIdHash = hash('sha256', self::APP_ID, true);
        $flags = chr(0x01);
        $counter = pack('N', 1);
        $authData = $rpIdHash . $flags . $counter;

        $signed = $authData . hash('sha256', $clientJson, true);
        openssl_sign($signed, $sig, $priv, OPENSSL_ALGO_SHA256);
        if ($tamper) {
            $sig[strlen($sig) - 1] = chr(ord($sig[strlen($sig) - 1]) ^ 0x01);
        }

        $info = json_encode([
            'type' => 'public-key',
            'originalChallenge' => $this->bytes($challenge),
            'rawId' => $this->bytes($credId),
            'response' => [
                'authenticatorData' => $this->bytes($authData),
                'clientData' => $clientData,
                'clientDataJSONarray' => $this->bytes($clientJson),
                'signature' => $this->bytes($sig),
            ],
        ]);

        $user = (object)['webauthn_id' => $reg->id, 'webauthn_key' => $reg->key];

        return [$info, $user];
    }

    // ------------------------------------------------------------------ tests

    public static function keySizes(): array
    {
        return [[2048], [3072], [4096]];
    }

    #[DataProvider('keySizes')]
    public function test_register_rs256_returns_pem_matching_original_n_and_e(int $bits): void
    {
        $key = $this->generateKey($bits);
        [$n, $e] = $this->rsaParams($key);
        $credId = random_bytes(16);

        $result = $this->registerKey($key, $credId);

        $this->assertInstanceOf(RegisterPublicKey::class, $result);
        $this->assertSame(bin2hex($credId), $result->id);
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $result->key);

        $pub = openssl_pkey_get_public($result->key);
        $this->assertNotFalse($pub, 'returned PEM is not a valid public key');
        $d = openssl_pkey_get_details($pub);
        $this->assertSame(OPENSSL_KEYTYPE_RSA, $d['type']);
        $this->assertSame($bits, $d['bits']);
        $this->assertSame(bin2hex($n), bin2hex($d['rsa']['n']));
        $this->assertSame(bin2hex($e), bin2hex($d['rsa']['e']));
    }

    public function test_register_rs256_handles_modulus_with_high_bit_set(): void
    {
        $key = $this->generateKey(2048);
        [$n] = $this->rsaParams($key);
        // openssl generates moduli with the top bit set: DER needs a leading 0x00 so n stays positive.
        $this->assertGreaterThanOrEqual(0x80, ord($n[0]));

        $d = openssl_pkey_get_details(openssl_pkey_get_public($this->registerKey($key, random_bytes(16))->key));
        $this->assertSame(bin2hex($n), bin2hex($d['rsa']['n']));
    }

    public function test_register_rs256_handles_modulus_with_high_bit_clear(): void
    {
        // Synthetic modulus (parsing only): first byte < 0x80 so no sign padding is required.
        $n = "\x40" . random_bytes(254) . "\x01";
        $credId = random_bytes(16);

        $result = WebAuthn::register($this->registerInfo($this->coseKey($n, "\x01\x00\x01"), $credId));

        $d = openssl_pkey_get_details(openssl_pkey_get_public($result->key));
        $this->assertSame(bin2hex($n), bin2hex($d['rsa']['n']));
        $this->assertSame('010001', bin2hex($d['rsa']['e']));
    }

    public static function exponents(): array
    {
        return [
            'e=3' => ["\x03"],
            'e=17' => ["\x11"],
            'e=65537' => ["\x01\x00\x01"],
            'e high bit set (0x8001)' => ["\x80\x01"],
        ];
    }

    #[DataProvider('exponents')]
    public function test_register_rs256_encodes_various_public_exponents(string $e): void
    {
        [$n] = $this->rsaParams($this->generateKey(2048));

        $result = WebAuthn::register($this->registerInfo($this->coseKey($n, $e), random_bytes(16)));

        $d = openssl_pkey_get_details(openssl_pkey_get_public($result->key));
        $this->assertSame(bin2hex($n), bin2hex($d['rsa']['n']));
        $this->assertSame(bin2hex($e), bin2hex($d['rsa']['e']));
    }

    public function test_returned_pem_verifies_rsa_sha256_signature(): void
    {
        $key = $this->generateKey(2048);
        $result = $this->registerKey($key, random_bytes(16));

        $data = random_bytes(100);
        openssl_sign($data, $sig, $key, OPENSSL_ALGO_SHA256);

        $this->assertSame(1, openssl_verify($data, $sig, $result->key, OPENSSL_ALGO_SHA256));
        $this->assertSame(0, openssl_verify($data . 'x', $sig, $result->key, OPENSSL_ALGO_SHA256));
    }

    public function test_register_then_authenticate_end_to_end_with_rs256(): void
    {
        $key = $this->generateKey(2048);
        $credId = random_bytes(16);
        $reg = $this->registerKey($key, $credId);

        [$info, $user] = $this->assertion($key, $reg, $credId);

        $this->assertTrue(WebAuthn::authenticate($info, $user));
        $this->assertSame(bin2hex($credId), WebAuthn::parseWebAuthnId($info));
    }

    public function test_authenticate_with_tampered_rs256_signature_is_not_accepted(): void
    {
        $key = $this->generateKey(2048);
        $credId = random_bytes(16);
        $reg = $this->registerKey($key, $credId);

        [$info, $user] = $this->assertion($key, $reg, $credId, tamper: true);

        // Implementation returns false for a bad signature (openssl_verify === 0).
        $this->assertFalse(WebAuthn::authenticate($info, $user));
    }

    public function test_authenticate_with_signature_from_another_rsa_key_is_not_accepted(): void
    {
        $key = $this->generateKey(2048);
        $other = $this->generateKey(2048);
        $credId = random_bytes(16);
        $reg = $this->registerKey($key, $credId);

        [$info, $user] = $this->assertion($other, $reg, $credId);

        $this->assertFalse(WebAuthn::authenticate($info, $user));
    }

    public function test_register_rs256_without_modulus_throws(): void
    {
        $this->expectException(RuntimeException::class);
        WebAuthn::register($this->registerInfo($this->coseKey(null, "\x01\x00\x01"), random_bytes(16)));
    }

    public function test_register_rs256_without_exponent_throws(): void
    {
        [$n] = $this->rsaParams($this->generateKey(2048));

        $this->expectException(RuntimeException::class);
        WebAuthn::register($this->registerInfo($this->coseKey($n, null), random_bytes(16)));
    }

    public static function invalidRegistrationFlags(): array
    {
        return [
            'no flags (0x00)' => [0x00],
            'UP only (0x01)' => [0x01],
            'AT only (0x40)' => [0x40],
        ];
    }

    #[DataProvider('invalidRegistrationFlags')]
    public function test_register_rejects_flags_missing_up_or_at(int $flags): void
    {
        [$n, $e] = $this->rsaParams($this->generateKey(2048));

        try {
            WebAuthn::register($this->registerInfo($this->coseKey($n, $e), random_bytes(16), $flags));
            $this->fail('Expected RuntimeException was not thrown');
        } catch (RuntimeException $ex) {
            $this->assertSame('cannot decode key response (6)', $ex->getMessage());
            $this->assertSame(0, $ex->getCode());
        }
    }

    public static function validRegistrationFlags(): array
    {
        return [
            'UP+AT (0x41)' => [0x41],
            'UP+UV+AT (0x45)' => [0x45],
        ];
    }

    #[DataProvider('validRegistrationFlags')]
    public function test_register_accepts_flags_with_up_and_at(int $flags): void
    {
        [$n, $e] = $this->rsaParams($this->generateKey(2048));
        $credId = random_bytes(16);

        $result = WebAuthn::register($this->registerInfo($this->coseKey($n, $e), $credId, $flags));

        $this->assertSame(bin2hex($credId), $result->id);
    }
}
