<?php

namespace Faiare\LaravelWebAuthn\Tests\Unit;

use Faiare\LaravelWebAuthn\Cbor\ByteString;
use Faiare\LaravelWebAuthn\Entities\RegisterPublicKey;
use Faiare\LaravelWebAuthn\Facades\WebAuthn;
use Faiare\LaravelWebAuthn\Tests\Support\CborEncoder;
use Faiare\LaravelWebAuthn\Tests\TestCase;
use Faiare\LaravelWebAuthn\WebAuthnHelper;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

/**
 * The `userVerification` setting: validation, challenge payloads, and the
 * UV flag (0x04) enforcement in register() / authenticate() when 'required'.
 */
class WebAuthnUserVerificationTest extends TestCase
{
    private const APP_ID = 'localhost';
    private const REG_CHALLENGE = 'O2xorCE-OAlp3KJYqYJXog';

    private static ?OpenSSLAsymmetricKey $key = null;

    // ---------------------------------------------------------------- helpers

    private function useUserVerification(string $value): void
    {
        config()->set('webauthn.userVerification', $value);
        WebAuthn::clearResolvedInstance('webauthn');
    }

    private function key(): OpenSSLAsymmetricKey
    {
        if (self::$key === null) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            $this->assertNotFalse($key, 'openssl_pkey_new failed: ' . openssl_error_string());
            self::$key = $key;
        }

        return self::$key;
    }

    private function bytes(string $s): array
    {
        return array_values(unpack('C*', $s) ?: []);
    }

    private function b64url(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    /** Registration payload whose authenticatorData carries the given flags byte. */
    private function registerInfo(string $credId, int $flags): string
    {
        $d = openssl_pkey_get_details($this->key());
        $cose = CborEncoder::encode([
            1 => 3,
            3 => -257,
            -1 => new ByteString($d['rsa']['n']),
            -2 => new ByteString($d['rsa']['e']),
        ]);

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
            'id' => $this->b64url($credId),
            'type' => 'public-key',
            'response' => [
                'attestationObject' => $this->bytes($ao),
                'clientDataJSON' => [
                    'type' => 'webauthn.create',
                    'challenge' => self::REG_CHALLENGE,
                    'origin' => 'http://localhost:8000',
                    'crossOrigin' => false,
                ],
            ],
        ]);
    }

    private function registerWithFlags(int $flags): RegisterPublicKey
    {
        return WebAuthn::register($this->registerInfo(random_bytes(16), $flags), self::REG_CHALLENGE);
    }

    /**
     * Register a credential (under the default 'discouraged' setting so the
     * helper doesn't matter), then build a signed assertion with the given flags.
     *
     * @return array{0: string, 1: object}
     */
    private function assertionWithFlags(int $flags): array
    {
        $this->useUserVerification('discouraged');
        $credId = random_bytes(16);
        $reg = WebAuthn::register($this->registerInfo($credId, 0x41), self::REG_CHALLENGE);

        $challenge = random_bytes(16);
        $clientJson = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $this->b64url($challenge),
            'origin' => 'http://localhost:8000',
            'crossOrigin' => false,
        ]);

        // The flags byte is part of the signed data.
        $authData = hash('sha256', self::APP_ID, true) . chr($flags) . pack('N', 1);
        openssl_sign($authData . hash('sha256', $clientJson, true), $sig, $this->key(), OPENSSL_ALGO_SHA256);

        $info = json_encode([
            'type' => 'public-key',
            'originalChallenge' => $this->bytes($challenge),
            'rawId' => $this->bytes($credId),
            'response' => [
                'authenticatorData' => $this->bytes($authData),
                'clientData' => json_decode($clientJson, true),
                'clientDataJSONarray' => $this->bytes($clientJson),
                'signature' => $this->bytes($sig),
            ],
        ]);

        return [$info, (object)['webauthn_id' => $reg->id, 'webauthn_key' => $reg->key]];
    }

    private function assertRejectedWithCode0(callable $fn): void
    {
        try {
            $fn();
            $this->fail('Expected RuntimeException was not thrown');
        } catch (RuntimeException $e) {
            $this->assertSame(0, $e->getCode());
        }
    }

    // ------------------------------------------------- config / constructor

    public function test_config_default_is_discouraged(): void
    {
        $config = require __DIR__ . '/../../config/webauthn.php';

        $this->assertArrayHasKey('userVerification', $config);
        $this->assertSame('discouraged', $config['userVerification']);
    }

    public static function validValues(): array
    {
        return [['required'], ['preferred'], ['discouraged']];
    }

    #[DataProvider('validValues')]
    public function test_constructor_accepts_allowed_values(string $value): void
    {
        $this->assertInstanceOf(WebAuthnHelper::class, new WebAuthnHelper('localhost', $value));
    }

    public function test_constructor_defaults_to_discouraged(): void
    {
        $this->assertSame('discouraged', (new WebAuthnHelper('localhost'))->prepareForAuthenticate()->userVerification);
    }

    public static function invalidValues(): array
    {
        return [
            'empty' => [''],
            'unknown' => ['mandatory'],
            'wrong case' => ['Required'],
            'padded' => [' required'],
        ];
    }

    #[DataProvider('invalidValues')]
    public function test_constructor_rejects_other_values_with_caller_error_code(string $value): void
    {
        try {
            new WebAuthnHelper('localhost', $value);
            $this->fail('Expected RuntimeException was not thrown');
        } catch (RuntimeException $e) {
            $this->assertSame(1, $e->getCode());
        }
    }

    // ------------------------------------------------- prepare payloads

    public function test_prepare_payloads_default_to_discouraged(): void
    {
        $this->assertSame('discouraged', WebAuthn::prepareForAuthenticate()->userVerification);
        $this->assertSame(
            'discouraged',
            WebAuthn::prepareChallengeForRegistration('user', 'id', false)->publicKey->authenticatorSelection->userVerification
        );
    }

    #[DataProvider('validValues')]
    public function test_prepare_payloads_reflect_configured_value(string $value): void
    {
        $this->useUserVerification($value);

        $this->assertSame($value, WebAuthn::prepareForAuthenticate()->userVerification);
        $this->assertSame(
            $value,
            WebAuthn::prepareChallengeForRegistration('user', 'id', false)->publicKey->authenticatorSelection->userVerification
        );
    }

    public function test_invalid_configured_value_throws_when_resolving(): void
    {
        $this->useUserVerification('bogus');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1);
        WebAuthn::prepareForAuthenticate();
    }

    // ------------------------------------------------- register()

    public function test_register_required_rejects_missing_uv_flag(): void
    {
        $this->useUserVerification('required');

        $this->assertRejectedWithCode0(fn () => $this->registerWithFlags(0x41));
    }

    public function test_register_required_accepts_uv_flag(): void
    {
        $this->useUserVerification('required');

        $this->assertInstanceOf(RegisterPublicKey::class, $this->registerWithFlags(0x45));
    }

    public function test_register_required_still_rejects_uv_without_up_and_at(): void
    {
        $this->useUserVerification('required');

        $this->assertRejectedWithCode0(fn () => $this->registerWithFlags(0x04));
    }

    #[DataProvider('relaxedValues')]
    public function test_register_without_required_does_not_need_uv_flag(string $value): void
    {
        $this->useUserVerification($value);

        $this->assertInstanceOf(RegisterPublicKey::class, $this->registerWithFlags(0x41));
    }

    public static function relaxedValues(): array
    {
        return [['preferred'], ['discouraged']];
    }

    // ------------------------------------------------- authenticate()

    public function test_authenticate_required_rejects_missing_uv_flag(): void
    {
        [$info, $user] = $this->assertionWithFlags(0x01);
        $this->useUserVerification('required');

        $this->assertRejectedWithCode0(fn () => WebAuthn::authenticate($info, $user));
    }

    public function test_authenticate_required_accepts_uv_flag(): void
    {
        [$info, $user] = $this->assertionWithFlags(0x05);
        $this->useUserVerification('required');

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    #[DataProvider('relaxedValues')]
    public function test_authenticate_without_required_does_not_need_uv_flag(string $value): void
    {
        [$info, $user] = $this->assertionWithFlags(0x01);
        $this->useUserVerification($value);

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    #[DataProvider('relaxedValues')]
    public function test_authenticate_without_required_accepts_uv_flag_too(string $value): void
    {
        [$info, $user] = $this->assertionWithFlags(0x05);
        $this->useUserVerification($value);

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }
}
