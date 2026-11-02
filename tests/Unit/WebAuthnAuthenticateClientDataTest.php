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
 * authenticate() must validate ONLY the client data decoded from the signed
 * `clientDataJSONarray` bytes. The separate, unsigned `response.clientData`
 * copy sent by the frontend must be ignored entirely.
 */
class WebAuthnAuthenticateClientDataTest extends TestCase
{
    private const APP_ID = 'localhost';
    private const REG_CHALLENGE = 'O2xorCE-OAlp3KJYqYJXog';

    private static ?OpenSSLAsymmetricKey $key = null;

    // ---------------------------------------------------------------- helpers

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

    private function registerKey(string $credId): RegisterPublicKey
    {
        $d = openssl_pkey_get_details($this->key());
        $cose = CborEncoder::encode([
            1 => 3,
            3 => -257,
            -1 => new ByteString($d['rsa']['n']),
            -2 => new ByteString($d['rsa']['e']),
        ]);

        $authData = hash('sha256', self::APP_ID, true)
            . chr(0x41)
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

        $info = json_encode([
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

        return WebAuthn::register($info, self::REG_CHALLENGE);
    }

    private function goodClientData(string $challenge): array
    {
        return [
            'type' => 'webauthn.get',
            'challenge' => $this->b64url($challenge),
            'origin' => 'http://localhost:8000',
            'crossOrigin' => false,
        ];
    }

    /**
     * Build a correctly signed assertion over the given raw clientDataJSON string.
     *
     * @param array<string, mixed> $overrides top-level info keys / 'response' keys to replace.
     *        Use the key '__unset_<name>' to remove a response key.
     * @return array{0: string, 1: object}
     */
    private function buildAssertion(
        string $signedClientJson,
        string $originalChallenge,
        mixed $unsignedClientData,
        ?string $storedChallenge = null,
        array $responseOverrides = [],
    ): array {
        $credId = random_bytes(16);
        $reg = $this->registerKey($credId);

        $authData = hash('sha256', self::APP_ID, true) . chr(0x01) . pack('N', 1);
        openssl_sign($authData . hash('sha256', $signedClientJson, true), $sig, $this->key(), OPENSSL_ALGO_SHA256);

        $response = [
            'authenticatorData' => $this->bytes($authData),
            'clientData' => $unsignedClientData,
            'clientDataJSONarray' => $this->bytes($signedClientJson),
            'signature' => $this->bytes($sig),
        ];
        foreach ($responseOverrides as $k => $v) {
            if ($v === '__unset__') {
                unset($response[$k]);
            } else {
                $response[$k] = $v;
            }
        }

        $info = json_encode([
            'type' => 'public-key',
            'originalChallenge' => $this->bytes($originalChallenge),
            'rawId' => $this->bytes($credId),
            'response' => $response,
        ]);

        $user = (object)['webauthn_id' => $reg->id, 'webauthn_key' => $reg->key];
        if ($storedChallenge !== null) {
            $user->challenge = $storedChallenge;
        }

        return [$info, $user];
    }

    /** Assertion whose signed client data is $signed (array to be JSON-encoded) for challenge bytes $challenge. */
    private function assertionWith(array $signed, ?string $challenge = null, mixed $unsigned = null, ?string $stored = null): array
    {
        $challenge ??= random_bytes(16);

        return $this->buildAssertion(
            json_encode($signed),
            $challenge,
            $unsigned ?? $signed,
            $stored,
        );
    }

    private function assertRejected(string $info, object $user, string $message): void
    {
        try {
            WebAuthn::authenticate($info, $user);
            $this->fail("Expected RuntimeException '{$message}' was not thrown");
        } catch (RuntimeException $ex) {
            $this->assertSame($message, $ex->getMessage());
            $this->assertSame(0, $ex->getCode());
        }
    }

    // ------------------------------------------------- 0. baseline

    public function test_validly_signed_assertion_is_accepted(): void
    {
        $challenge = random_bytes(16);
        [$info, $user] = $this->assertionWith($this->goodClientData($challenge), $challenge);

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    // ------------------------------------------------- 1. replay attack

    public function test_replay_with_swapped_challenge_and_unsigned_client_data_is_rejected(): void
    {
        $challengeA = random_bytes(16);
        $challengeB = random_bytes(16);

        // The authenticator really signed challenge A (e.g. captured earlier by an attacker).
        $signed = $this->goodClientData($challengeA);
        // Attacker rewrites the unsigned parts to claim the fresh server challenge B.
        $forged = $this->goodClientData($challengeB);

        [$info, $user] = $this->buildAssertion(
            json_encode($signed),
            $challengeB,
            $forged,
            $this->b64url($challengeB),
        );

        $this->assertRejected($info, $user, 'challenge mismatch');
    }

    public function test_replay_with_swapped_challenge_is_rejected_without_stored_challenge(): void
    {
        $challengeA = random_bytes(16);
        $challengeB = random_bytes(16);

        [$info, $user] = $this->buildAssertion(
            json_encode($this->goodClientData($challengeA)),
            $challengeB,
            $this->goodClientData($challengeB),
        );

        $this->assertRejected($info, $user, 'challenge mismatch');
    }

    // ------------------------------------------------- 2. unsigned copy lies about origin / type

    public function test_signed_bad_origin_is_rejected_even_if_unsigned_client_data_claims_good_origin(): void
    {
        $challenge = random_bytes(16);
        $signed = $this->goodClientData($challenge);
        $signed['origin'] = 'https://evil.example';

        [$info, $user] = $this->assertionWith($signed, $challenge, $this->goodClientData($challenge));

        $this->assertRejected($info, $user, 'origin mismatch');
    }

    public function test_signed_create_type_is_rejected_even_if_unsigned_client_data_claims_get(): void
    {
        $challenge = random_bytes(16);
        $signed = $this->goodClientData($challenge);
        $signed['type'] = 'webauthn.create';

        [$info, $user] = $this->assertionWith($signed, $challenge, $this->goodClientData($challenge));

        $this->assertRejected($info, $user, 'type mismatch');
    }

    // ------------------------------------------------- 3. unsigned copy is ignored

    public function test_missing_unsigned_client_data_is_still_accepted(): void
    {
        $challenge = random_bytes(16);
        [$info, $user] = $this->buildAssertion(
            json_encode($this->goodClientData($challenge)),
            $challenge,
            null,
            null,
            ['clientData' => '__unset__'],
        );

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    public static function garbageUnsignedClientData(): array
    {
        return [
            'null' => [null],
            'string' => ['garbage'],
            'integer' => [12345],
            'empty array' => [[]],
            'list' => [[1, 2, 3]],
            'bad type/origin/challenge' => [['type' => 'webauthn.create', 'challenge' => 'x', 'origin' => 'https://evil.example']],
            'wrong value types' => [['type' => 1, 'challenge' => [], 'origin' => false]],
        ];
    }

    #[DataProvider('garbageUnsignedClientData')]
    public function test_garbage_unsigned_client_data_is_ignored_when_signed_bytes_are_good(mixed $garbage): void
    {
        $challenge = random_bytes(16);
        [$info, $user] = $this->assertionWith($this->goodClientData($challenge), $challenge, $garbage);

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    // ------------------------------------------------- 4. each rule

    public static function invalidClientDataJsonArray(): array
    {
        return [
            'missing' => ['__unset__'],
            'null' => [null],
            'string' => ['abc'],
            'integer' => [42],
            'object' => [['a' => 1]],
        ];
    }

    #[DataProvider('invalidClientDataJsonArray')]
    public function test_client_data_json_array_missing_or_not_array_is_rejected(mixed $value): void
    {
        $challenge = random_bytes(16);
        [$info, $user] = $this->buildAssertion(
            json_encode($this->goodClientData($challenge)),
            $challenge,
            $this->goodClientData($challenge),
            null,
            ['clientDataJSONarray' => $value],
        );

        $this->assertRejected($info, $user, 'no clientDataJSONarray in info');
    }

    public static function nonObjectJson(): array
    {
        return [
            'not json' => ['this is not json'],
            'json null' => ['null'],
            'json string' => ['"webauthn.get"'],
            'json number' => ['123'],
            'json true' => ['true'],
            'empty bytes' => [''],
        ];
    }

    #[DataProvider('nonObjectJson')]
    public function test_signed_bytes_that_are_not_a_json_object_are_rejected(string $raw): void
    {
        $challenge = random_bytes(16);
        [$info, $user] = $this->buildAssertion($raw, $challenge, $this->goodClientData($challenge));

        $this->assertRejected($info, $user, 'no client data in info');
    }

    public static function badTypes(): array
    {
        return [
            'missing' => ['__unset__'],
            'create' => ['webauthn.create'],
            'empty' => [''],
            'wrong case' => ['WebAuthn.Get'],
            'null' => [null],
            'integer' => [1],
            'array' => [['webauthn.get']],
        ];
    }

    #[DataProvider('badTypes')]
    public function test_bad_signed_type_is_rejected(mixed $type): void
    {
        $challenge = random_bytes(16);
        $signed = $this->goodClientData($challenge);
        if ($type === '__unset__') {
            unset($signed['type']);
        } else {
            $signed['type'] = $type;
        }

        [$info, $user] = $this->assertionWith($signed, $challenge);

        $this->assertRejected($info, $user, 'type mismatch');
    }

    public static function badChallengeFields(): array
    {
        return [
            'missing' => ['__unset__'],
            'null' => [null],
            'integer' => [123],
            'array' => [['abc']],
            'boolean' => [true],
        ];
    }

    #[DataProvider('badChallengeFields')]
    public function test_missing_or_non_string_signed_challenge_is_rejected(mixed $value): void
    {
        $challenge = random_bytes(16);
        $signed = $this->goodClientData($challenge);
        if ($value === '__unset__') {
            unset($signed['challenge']);
        } else {
            $signed['challenge'] = $value;
        }

        [$info, $user] = $this->assertionWith($signed, $challenge);

        $this->assertRejected($info, $user, 'no challenge in client data');
    }

    public static function badOrigins(): array
    {
        return [
            'missing' => ['__unset__'],
            'null' => [null],
            'integer' => [8000],
            'array' => [['http://localhost:8000']],
            'no host (bare word)' => ['localhost'],
            'empty string' => [''],
            'scheme only' => ['https://'],
            'other host' => ['https://evil.example'],
            'host suffix' => ['http://localhost.evil.example'],
            'host prefix' => ['http://evil-localhost'],
            'userinfo trick' => ['http://localhost@evil.example'],
        ];
    }

    #[DataProvider('badOrigins')]
    public function test_bad_signed_origin_is_rejected(mixed $origin): void
    {
        $challenge = random_bytes(16);
        $signed = $this->goodClientData($challenge);
        if ($origin === '__unset__') {
            unset($signed['origin']);
        } else {
            $signed['origin'] = $origin;
        }

        [$info, $user] = $this->assertionWith($signed, $challenge);

        $this->assertRejected($info, $user, 'origin mismatch');
    }

    public static function goodOrigins(): array
    {
        return [
            'http with port' => ['http://localhost:8000'],
            'https' => ['https://localhost'],
            'https with port' => ['https://localhost:8443'],
        ];
    }

    #[DataProvider('goodOrigins')]
    public function test_signed_origin_with_matching_host_is_accepted(string $origin): void
    {
        $challenge = random_bytes(16);
        $signed = $this->goodClientData($challenge);
        $signed['origin'] = $origin;

        [$info, $user] = $this->assertionWith($signed, $challenge);

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    public function test_signed_challenge_different_from_original_challenge_is_rejected(): void
    {
        $signedChallenge = random_bytes(16);
        $original = random_bytes(16);

        [$info, $user] = $this->assertionWith($this->goodClientData($signedChallenge), $original);

        $this->assertRejected($info, $user, 'challenge mismatch');
    }

    public function test_signed_challenge_that_is_standard_base64_instead_of_base64url_is_rejected(): void
    {
        // Bytes chosen so that standard base64 differs from base64url ('+' and '/' and padding).
        $challenge = "\xfb\xff\xfe\xfb\xff\xfe\xfb";
        $signed = $this->goodClientData($challenge);
        $signed['challenge'] = base64_encode($challenge);
        $this->assertNotSame($signed['challenge'], $this->b64url($challenge));

        [$info, $user] = $this->assertionWith($signed, $challenge);

        $this->assertRejected($info, $user, 'challenge mismatch');
    }

    public function test_base64url_challenge_with_url_safe_characters_is_accepted(): void
    {
        $challenge = "\xfb\xff\xfe\xfb\xff\xfe\xfb";

        [$info, $user] = $this->assertionWith($this->goodClientData($challenge), $challenge);

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    public function test_stored_challenge_matching_signed_challenge_is_accepted(): void
    {
        $challenge = random_bytes(16);

        [$info, $user] = $this->assertionWith(
            $this->goodClientData($challenge),
            $challenge,
            null,
            $this->b64url($challenge),
        );

        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    public function test_stored_challenge_differing_from_signed_challenge_is_rejected(): void
    {
        $challenge = random_bytes(16);

        [$info, $user] = $this->assertionWith(
            $this->goodClientData($challenge),
            $challenge,
            null,
            $this->b64url(random_bytes(16)),
        );

        $this->assertRejected($info, $user, 'you cannot use the same login more than once');
    }

    public function test_absent_stored_challenge_skips_replay_check(): void
    {
        $challenge = random_bytes(16);
        [$info, $user] = $this->assertionWith($this->goodClientData($challenge), $challenge);

        $this->assertFalse(isset($user->challenge));
        $this->assertTrue(WebAuthn::authenticate($info, $user));
    }

    // ------------------------------------------------- ordering: checked before signature verification

    public function test_client_data_rules_are_checked_before_signature_verification(): void
    {
        $challenge = random_bytes(16);
        $signed = $this->goodClientData($challenge);
        $signed['origin'] = 'https://evil.example';

        [$info, $user] = $this->assertionWith($signed, $challenge);

        // Corrupt the signature; the client data error must still win.
        $decoded = json_decode($info, true);
        $decoded['response']['signature'][0] ^= 0xFF;
        $info = json_encode($decoded);

        $this->assertRejected($info, $user, 'origin mismatch');
    }

    public function test_tampering_signed_bytes_after_signing_does_not_verify(): void
    {
        $challenge = random_bytes(16);
        $good = json_encode($this->goodClientData($challenge));
        [$info, $user] = $this->buildAssertion($good, $challenge, null);

        // Swap in different (still rule-satisfying) bytes: signature no longer matches.
        $other = json_encode($this->goodClientData($challenge) + ['extra' => 'x']);
        $decoded = json_decode($info, true);
        $decoded['response']['clientDataJSONarray'] = $this->bytes($other);

        $this->assertFalse(WebAuthn::authenticate(json_encode($decoded), $user));
    }
}
