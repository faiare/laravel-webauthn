<?php

namespace Faiare\LaravelWebAuthn\Tests\Unit;

use Faiare\LaravelWebAuthn\Entities\PrepareChallengeForRegistration;
use Faiare\LaravelWebAuthn\Entities\PrepareAuthenticatePublicKey;
use Faiare\LaravelWebAuthn\Entities\RegisterPublicKey;
use Faiare\LaravelWebAuthn\Facades\WebAuthn;
use Faiare\LaravelWebAuthn\Tests\TestCase;
use Faiare\LaravelWebAuthn\WebAuthnHelper;

class WebAuthnTest extends TestCase
{

    public function test_the_facade_instance()
    {
        $this->assertInstanceOf(
            WebAuthnHelper::class,
            WebAuthn::getFacadeRoot()
        );
    }

    public function test_prepare_challenge_for_registration()
    {
        $result = WebAuthn::prepareChallengeForRegistration(
            username: 'test',
            userid: 'test',
            crossPlatform: true
        );

        $this->assertInstanceOf(PrepareChallengeForRegistration::class, $result);

        $this->assertArrayHasKey('publicKey', $result->jsonSerialize());
        $this->assertArrayHasKey('b64challenge', $result->jsonSerialize());
    }

    public function test_register()
    {
        $info = '{"rawId":[149,37,118,4,151,90,215,122,200,147,71,177,167,74,72,141],"id":"lSV2BJda13rIk0exp0pIjQ","type":"public-key","response":{"attestationObject":[163,99,102,109,116,100,110,111,110,101,103,97,116,116,83,116,109,116,160,104,97,117,116,104,68,97,116,97,88,148,73,150,13,229,136,14,140,104,116,52,23,15,100,118,96,91,143,228,174,185,162,134,50,199,153,92,243,186,131,29,151,99,93,0,0,0,0,186,218,85,102,167,170,64,31,189,150,69,97,154,85,18,13,0,16,149,37,118,4,151,90,215,122,200,147,71,177,167,74,72,141,165,1,2,3,38,32,1,33,88,32,45,153,31,31,0,220,130,97,81,187,139,116,236,46,130,204,140,179,215,110,179,198,67,59,67,103,188,208,117,203,252,35,34,88,32,6,203,159,57,132,216,96,14,8,27,141,35,81,4,115,45,162,132,191,161,89,226,11,140,127,227,12,29,72,61,218,129],"clientDataJSON":{"type":"webauthn.create","challenge":"O2xorCE-OAlp3KJYqYJXog","origin":"http://localhost:8000","crossOrigin":false}}}';

        $result = WebAuthn::register($info);

        $this->assertInstanceOf(RegisterPublicKey::class, $result);
    }

    public function test_prepare_for_authentication()
    {
        $result = WebAuthn::prepareForAuthenticate();

        $this->assertInstanceOf(PrepareAuthenticatePublicKey::class, $result);
    }

    public function test_parse_web_authn_id()
    {
        $info = '{"type":"public-key","originalChallenge":[65,235,69,70,56,70,132,168,29,161,228,236,71,183,71,90],"rawId":[149,37,118,4,151,90,215,122,200,147,71,177,167,74,72,141],"response":{"authenticatorData":[73,150,13,229,136,14,140,104,116,52,23,15,100,118,96,91,143,228,174,185,162,134,50,199,153,92,243,186,131,29,151,99,29,0,0,0,0],"clientData":{"type":"webauthn.get","challenge":"QetFRjhGhKgdoeTsR7dHWg","origin":"http://localhost:8000","crossOrigin":false},"clientDataJSONarray":[123,34,116,121,112,101,34,58,34,119,101,98,97,117,116,104,110,46,103,101,116,34,44,34,99,104,97,108,108,101,110,103,101,34,58,34,81,101,116,70,82,106,104,71,104,75,103,100,111,101,84,115,82,55,100,72,87,103,34,44,34,111,114,105,103,105,110,34,58,34,104,116,116,112,58,47,47,108,111,99,97,108,104,111,115,116,58,56,48,48,48,34,44,34,99,114,111,115,115,79,114,105,103,105,110,34,58,102,97,108,115,101,125],"signature":[48,68,2,32,61,99,177,97,40,208,25,58,59,187,218,62,136,244,47,195,156,249,107,103,138,195,217,203,11,187,11,68,119,138,136,167,2,32,22,130,126,84,13,109,45,27,174,150,112,155,14,244,212,48,69,189,148,245,40,165,8,153,153,87,88,118,53,4,207,166]}}';

        $webAuthnId = WebAuthn::parseWebAuthnId($info);

        $this->assertIsString($webAuthnId);
    }

    public function test_parse_and_authentication()
    {
        $info = '{"type":"public-key","originalChallenge":[65,235,69,70,56,70,132,168,29,161,228,236,71,183,71,90],"rawId":[149,37,118,4,151,90,215,122,200,147,71,177,167,74,72,141],"response":{"authenticatorData":[73,150,13,229,136,14,140,104,116,52,23,15,100,118,96,91,143,228,174,185,162,134,50,199,153,92,243,186,131,29,151,99,29,0,0,0,0],"clientData":{"type":"webauthn.get","challenge":"QetFRjhGhKgdoeTsR7dHWg","origin":"http://localhost:8000","crossOrigin":false},"clientDataJSONarray":[123,34,116,121,112,101,34,58,34,119,101,98,97,117,116,104,110,46,103,101,116,34,44,34,99,104,97,108,108,101,110,103,101,34,58,34,81,101,116,70,82,106,104,71,104,75,103,100,111,101,84,115,82,55,100,72,87,103,34,44,34,111,114,105,103,105,110,34,58,34,104,116,116,112,58,47,47,108,111,99,97,108,104,111,115,116,58,56,48,48,48,34,44,34,99,114,111,115,115,79,114,105,103,105,110,34,58,102,97,108,115,101,125],"signature":[48,68,2,32,61,99,177,97,40,208,25,58,59,187,218,62,136,244,47,195,156,249,107,103,138,195,217,203,11,187,11,68,119,138,136,167,2,32,22,130,126,84,13,109,45,27,174,150,112,155,14,244,212,48,69,189,148,245,40,165,8,153,153,87,88,118,53,4,207,166]}}';

        $key = (object)[];
        $key->webauthn_id = "95257604975ad77ac89347b1a74a488d";
        $key->webauthn_key = <<<PK
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELZkfHwDcgmFRu4t07C6CzIyz126z
xkM7Q2e80HXL/CMGy585hNhgDggbjSNRBHMtooS/oVniC4x/4wwdSD3agQ==
-----END PUBLIC KEY-----
PK;

        $result = WebAuthn::authenticate($info, $key);

        $this->assertIsBool($result);
        $this->assertTrue($result);
    }
}
