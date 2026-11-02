<?php

namespace Faiare\LaravelWebAuthn\Tests\Unit;

use Faiare\LaravelWebAuthn\Entities\RegisterPublicKey;
use Faiare\LaravelWebAuthn\Facades\WebAuthn;
use Faiare\LaravelWebAuthn\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

class WebAuthnRegisterClientDataTest extends TestCase
{
    private const CHALLENGE = WebAuthnTest::REGISTER_CHALLENGE;

    /** Recorded fixture from WebAuthnTest. */
    private function fixture(): array
    {
        return json_decode(WebAuthnTest::REGISTER_INFO, true, 512, JSON_THROW_ON_ERROR);
    }

    /** @param callable(array): array $mutate receives the clientDataJSON array */
    private function infoWith(callable $mutate): string
    {
        $info = $this->fixture();
        $info['response']['clientDataJSON'] = $mutate($info['response']['clientDataJSON']);

        return json_encode($info);
    }

    private function infoWithClientData(mixed $clientData): string
    {
        $info = $this->fixture();
        if ($clientData === '__unset__') {
            unset($info['response']['clientDataJSON']);
        } else {
            $info['response']['clientDataJSON'] = $clientData;
        }

        return json_encode($info);
    }

    private function assertRegisterFails(string $info, string $challenge, string $message, int $code): void
    {
        try {
            WebAuthn::register($info, $challenge);
            $this->fail('Expected RuntimeException');
        } catch (RuntimeException $e) {
            $this->assertSame($message, $e->getMessage());
            $this->assertSame($code, $e->getCode());
        }
    }

    public function test_fixture_is_valid_as_recorded(): void
    {
        $this->assertInstanceOf(RegisterPublicKey::class, WebAuthn::register(json_encode($this->fixture()), self::CHALLENGE));
    }

    public function test_empty_challenge_is_rejected_with_caller_error_code(): void
    {
        $this->assertRegisterFails(json_encode($this->fixture()), '', 'challenge must not be empty', 1);
    }

    public static function missingClientDataProvider(): array
    {
        return [
            'missing' => ['__unset__'],
            'null' => [null],
            'string' => ['abc'],
            'number' => [5],
            'bool' => [true],
        ];
    }

    #[DataProvider('missingClientDataProvider')]
    public function test_missing_or_non_object_client_data_is_rejected(mixed $clientData): void
    {
        $this->assertRegisterFails($this->infoWithClientData($clientData), self::CHALLENGE, 'no client data in info', 0);
    }

    public static function badTypeProvider(): array
    {
        return [
            'get' => ['webauthn.get'],
            'empty' => [''],
            'wrong case' => ['WebAuthn.Create'],
            'null' => [null],
            'number' => [1],
            'array' => [['webauthn.create']],
            'unset' => ['__unset__'],
        ];
    }

    #[DataProvider('badTypeProvider')]
    public function test_wrong_type_is_rejected(mixed $type): void
    {
        $info = $this->infoWith(function (array $cd) use ($type) {
            if ($type === '__unset__') {
                unset($cd['type']);
            } else {
                $cd['type'] = $type;
            }

            return $cd;
        });

        $this->assertRegisterFails($info, self::CHALLENGE, 'type mismatch', 0);
    }

    public static function badClientChallengeProvider(): array
    {
        return [
            'unset' => ['__unset__'],
            'null' => [null],
            'number' => [123],
            'array' => [[self::CHALLENGE]],
            'bool' => [true],
        ];
    }

    #[DataProvider('badClientChallengeProvider')]
    public function test_missing_or_non_string_client_challenge_is_rejected(mixed $challenge): void
    {
        $info = $this->infoWith(function (array $cd) use ($challenge) {
            if ($challenge === '__unset__') {
                unset($cd['challenge']);
            } else {
                $cd['challenge'] = $challenge;
            }

            return $cd;
        });

        $this->assertRegisterFails($info, self::CHALLENGE, 'no challenge in client data', 0);
    }

    public static function badOriginProvider(): array
    {
        return [
            'unset' => ['__unset__'],
            'null' => [null],
            'number' => [1],
            'array' => [['http://localhost']],
            'empty string' => [''],
            'no scheme' => ['localhost'],
            'other host' => ['https://evil.example'],
            'suffix host' => ['http://localhost.evil.example'],
            'prefix host' => ['http://evil.localhost'],
            'userinfo trick' => ['http://localhost@evil.example'],
            'unparseable' => ['http:///'],
            'scheme only' => ['https://'],
        ];
    }

    #[DataProvider('badOriginProvider')]
    public function test_bad_origin_is_rejected(mixed $origin): void
    {
        $info = $this->infoWith(function (array $cd) use ($origin) {
            if ($origin === '__unset__') {
                unset($cd['origin']);
            } else {
                $cd['origin'] = $origin;
            }

            return $cd;
        });

        $this->assertRegisterFails($info, self::CHALLENGE, 'origin mismatch', 0);
    }

    public static function goodOriginProvider(): array
    {
        return [
            'http with port' => ['http://localhost:8000'],
            'https' => ['https://localhost'],
            'https with port' => ['https://localhost:8443'],
            'http without port' => ['http://localhost'],
        ];
    }

    #[DataProvider('goodOriginProvider')]
    public function test_origin_with_matching_host_is_accepted(string $origin): void
    {
        $info = $this->infoWith(function (array $cd) use ($origin) {
            $cd['origin'] = $origin;

            return $cd;
        });

        $this->assertInstanceOf(RegisterPublicKey::class, WebAuthn::register($info, self::CHALLENGE));
    }

    public static function challengeMismatchProvider(): array
    {
        return [
            'different value' => ['AAAAAAAAAAAAAAAAAAAAAA'],
            'case differs' => [strtolower(self::CHALLENGE)],
            'trailing char' => [self::CHALLENGE . 'A'],
            'truncated' => [substr(self::CHALLENGE, 0, -1)],
        ];
    }

    #[DataProvider('challengeMismatchProvider')]
    public function test_client_challenge_differing_from_expected_is_rejected(string $expected): void
    {
        $this->assertRegisterFails(json_encode($this->fixture()), $expected, 'challenge mismatch', 0);
    }

    public function test_client_data_checks_run_before_attestation_decoding(): void
    {
        $info = $this->fixture();
        $info['response']['attestationObject'] = [0, 1, 2];
        $info['response']['clientDataJSON']['type'] = 'webauthn.get';

        $this->assertRegisterFails(json_encode($info), self::CHALLENGE, 'type mismatch', 0);
    }
}
