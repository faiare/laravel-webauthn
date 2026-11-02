<?php

namespace Faiare\LaravelWebAuthn;

use Exception;
use Faiare\LaravelWebAuthn\Cbor\ByteString;
use Faiare\LaravelWebAuthn\Cbor\CborDecoder;
use Faiare\LaravelWebAuthn\Cbor\CborException;
use Faiare\LaravelWebAuthn\Construct\WebAuthn;
use Faiare\LaravelWebAuthn\Entities\Extensions;
use Faiare\LaravelWebAuthn\Entities\PrepareChallengeForRegistration;
use Faiare\LaravelWebAuthn\Entities\PrepareAuthenticatePublicKey;
use Faiare\LaravelWebAuthn\Entities\RegisterPublicKey;
use Random\RandomException;
use RuntimeException;

/**
 * A class to help manage keys via the webauthn protocol.
 *
 * Webauthn allows for browser logins using a physical key (such as a
 * Yubikey 2) or, in due course, biometrics such as fingerprints, that
 * support the protocol.
 *
 * This is based on the Javascript example at
 * https://webauthn.bin.coffee/, but offers a PHP server side.
 *
 * You need to store a webauthn string (which does not need to be
 * indexed) in user records in your database, the value of which is
 * consulted and amended by the various functions in this class.
 *
 * Errors are thrown as simple Exception, with code 0 for user errors (such as validation failure) or 1 for
 * programming errors (wrong argument types etc)
 *
 * Dependencies
 * ------------
 *
 * - openssl that supports SHA256
 */
class WebAuthnHelper implements WebAuthn
{
    const ES256 = -7;

    const RS256 = -257; // Windows Hello support

    const USER_VERIFICATION_REQUIRED = 'required';

    const USER_VERIFICATION_PREFERRED = 'preferred';

    const USER_VERIFICATION_DISCOURAGED = 'discouraged';

    /** flag bits of authenticatorData */
    private const FLAG_UP = 0x01;

    private const FLAG_UV = 0x04;

    private const FLAG_AT = 0x40;

    private string $appid;

    private string $userVerification;

    /**
     * construct object on which to operate
     *
     * @param string $appid a string identifying your app, typically the domain of your website which people
     *                         are using the key to log in to. If you have the URL (ie including the
     *                         https:// on the front) to hand, give that;
     *                         if it's not https, well what are you doing using this code?
     * @param string $userVerification the WebAuthn userVerification requirement sent to the browser on both
     *                         registration and authentication: 'required', 'preferred' or 'discouraged'.
     *                         With 'required', register() and authenticate() also reject responses whose
     *                         authenticator data does not have the user verified (UV) flag set.
     */
    public function __construct(string $appid, string $userVerification = self::USER_VERIFICATION_DISCOURAGED)
    {
        $this->appid = $appid;
        if (str_starts_with($this->appid, 'https://')) {
            $this->appid = substr($this->appid, 8); /* drop the https:// */
        }

        if (!in_array($userVerification, [
            self::USER_VERIFICATION_REQUIRED,
            self::USER_VERIFICATION_PREFERRED,
            self::USER_VERIFICATION_DISCOURAGED,
        ], true)) {
            $this->oops("invalid userVerification '{$userVerification}': expected 'required', 'preferred' or 'discouraged'", 1);
        }
        $this->userVerification = $userVerification;
    }

    /**
     * generate a challenge ready for registering a hardware key, fingerprint or whatever:
     *
     * @param  $username  string by which the user is known potentially displayed on the hardware key
     * @param  $userid  string by which the user can be uniquely identified. Don't use email address as this can change,
     *                 user perhaps the database record id
     * @param  $crossPlatform  bool default=FALSE, whether to link the identity to the key (TRUE, so it
     *                        can be used cross-platofrm, on different computers) or the platform (FALSE, only on
     *                        this computer, but with any available authentication device, e.g. known to Windows Hello)
     * @return PrepareChallengeForRegistration pass this JSON string back to the browser
     *
     * @throws RandomException
     */
    public function prepareChallengeForRegistration(string $username, string $userid, bool $crossPlatform = false): PrepareChallengeForRegistration
    {
        $result = (object)[];
        $rbchallenge = self::randomBytes(16);
        $result->challenge = self::stringToArray($rbchallenge);
        $result->user = (object)[];
        $result->user->name = $result->user->displayName = $username;
        $result->user->id = self::stringToArray($userid);

        $result->rp = (object)[];
        $result->rp->name = $result->rp->id = $this->appid;

        $result->pubKeyCredParams = [
            [
                'alg' => self::ES256,
                'type' => 'public-key',
            ],
            [
                'alg' => self::RS256,
                'type' => 'public-key',
            ],
        ];

        $result->authenticatorSelection = (object)[];
        if ($crossPlatform) {
            $result->authenticatorSelection->authenticatorAttachment = 'cross-platform';
        }

        $result->authenticatorSelection->requireResidentKey = false;
        $result->authenticatorSelection->userVerification = $this->userVerification;

        $result->timeout = 60000;
        $result->excludeCredentials = []; // No excludeList
        $result->extensions = (object)[];
        $result->extensions->exts = true;

        return new PrepareChallengeForRegistration(
            publicKey: $result,
            b64challenge: rtrim(strtr(base64_encode($rbchallenge), '+/', '-_'), '='),
        );
    }

    /**
     * registers a new key for a user
     * requires info from the hardware via javascript given below
     *
     * @param string $info supplied to the PHP script via a POST, constructed by the Javascript given below, ultimately
     *                        provided by the key
     * @param string $challenge the b64challenge of the PrepareChallengeForRegistration issued for this registration,
     *                        kept on the server (e.g. in the session) between the two requests
     * @return RegisterPublicKey modified to store in the user's webauthn field in your database
     *
     * @throws Exception
     */
    public function register(string $info, string $challenge): RegisterPublicKey
    {
        if ($challenge === '') {
            $this->oops('challenge must not be empty', 1);
        }
        $info = json_decode($info);
        if (empty($info)) {
            $this->oops('info is not properly JSON encoded', 1);
        }
        if (empty($info->response->attestationObject)) {
            $this->oops('no attestationObject in info', 1);
        }
        if (empty($info->rawId)) {
            $this->oops('no rawId in info');
        }

        $clientData = $this->verifyClientData($info->response->clientDataJSON ?? null, 'webauthn.create');
        if (!hash_equals($challenge, $clientData->challenge)) {
            $this->oops('challenge mismatch');
        }

        /* check response from key and store as new identity. This is a hex string representing the raw CBOR
        attestation object received from the key */

        $aos = self::arrayToString($info->response->attestationObject);
        try {
            $decoded = CborDecoder::decode($aos);
        } catch (CborException $e) {
            $this->oops('cannot decode key response (1): ' . $e->getMessage());
        }
        if (!is_array($decoded) || $decoded === []) {
            $this->oops('cannot decode key response (1)');
        }
        $ao = (object)$decoded;
        if (empty($ao->fmt) || !is_string($ao->fmt)) {
            $this->oops('cannot decode key response (2)');
        }
        if (!isset($ao->authData) || !$ao->authData instanceof ByteString) {
            $this->oops('cannot decode key response (3)');
        }
        $bs = $ao->authData->bytes;
        if (strlen($bs) < 55) {
            $this->oops('cannot decode key response (3)');
        }

        if ($ao->fmt == 'fido-u2f') {
            $this->oops('cannot decode FIDO format responses, sorry');
        } elseif ($ao->fmt != 'none' && $ao->fmt != 'packed') {
            $this->oops('cannot decode key response (4)');
        }

        $ao->rpIdHash = substr($bs, 0, 32);
        $ao->flags = ord(substr($bs, 32, 1));
        $ao->counter = substr($bs, 33, 4);

        $hashId = hash('sha256', $this->appid, true);
        if ($hashId != $ao->rpIdHash) {
            //log(bin2hex($hashId).' '.bin2hex($ao->rpIdHash));
            $this->oops('cannot decode key response (5)');
        }

        if (($ao->flags & (self::FLAG_UP | self::FLAG_AT)) !== (self::FLAG_UP | self::FLAG_AT)) {
            $this->oops('cannot decode key response (6)');
        } /* TUP and AT must be set */

        $this->verifyUserVerified($ao->flags);

        $ao->attData = (object)[];
        $ao->attData->aaguid = substr($bs, 37, 16);
        $ao->attData->credIdLen = (ord($bs[53]) << 8) + ord($bs[54]);
        $ao->attData->credId = substr($bs, 55, $ao->attData->credIdLen);
        $cborPubKey = substr($bs, 55 + $ao->attData->credIdLen); // after credId to end of string

        $ao->attData->keyBytes = self::COSEECDHAtoPKCS($cborPubKey);

        if (is_null($ao->attData->keyBytes)) {
            /* There is a bug in Firefox whereby it provides only one byte for the aaguid field.
               This means everything else is shifted down by 15 bytes, resulting in a failure to pick up the
               key algortihm field in COSEECDHAtoPKCS. So if that happens, try again with just that one byte,
               and only then produce an error if that also fails.
               Thank you: https://www.antradar.com/blog-firefox-webauthn-incompability
             */
            $ao->attData->aaguid = substr($bs, 37, 1);
            $ao->attData->credIdLen = (ord($bs[38]) << 8) + ord($bs[39]);
            $ao->attData->credId = substr($bs, 40, $ao->attData->credIdLen);
            $cborPubKey = substr($bs, 40 + $ao->attData->credIdLen); // after credId to end of string
            $ao->attData->keyBytes = self::COSEECDHAtoPKCS($cborPubKey);
            if (is_null($ao->attData->keyBytes)) {
                $this->oops('cannot decode key response (8)');
            }
        }

        $rawId = self::arrayToString($info->rawId);
        if ($ao->attData->credId != $rawId) {
            $this->oops('cannot decode key response (16)');
        }

        return new RegisterPublicKey(
            key: $ao->attData->keyBytes,
            id: bin2hex(self::arrayToString($info->rawId)),
        );
    }

    /**
     * generates a new key string for the physical key, fingerprint
     * reader or whatever to respond to on login.
     * You should store the revised userwebauthn back to your database after calling this function
     * (to avoid replay attacks)
     *
     * @return PrepareAuthenticatePublicKey to pass to javascript webauthnAuthenticate
     *
     * @throws RandomException
     */
    public function prepareForAuthenticate(): PrepareAuthenticatePublicKey
    {
        $challengebytes = self::randomBytes(16);

        /* generate key request */
        return new PrepareAuthenticatePublicKey(
            challenge: self::stringToArray($challengebytes),
            timeout: 60000,
            userVerification: $this->userVerification,
            extensions: new Extensions(
                txAuthSimple: 'Execute order 66',
            ),
            rpId: str_replace('https://', '', $this->appid),
        );
    }

    /**
     * validates a response for login or 2fa
     * requires info from the hardware via javascript given below.
     * You should store the revised userwebauthn back to your database after calling this function
     * (to avoid replay attacks)
     *
     * @param string $info supplied to the PHP script via a POST, constructed by the Javascript given below, ultimately
     *                        provided by the key
     * @param mixed $userwebauthn the exisiting webauthn field for the user from your
     *                               database (it's actaully a JSON string, but that's entirely internal to
     *                               this code)
     * @return bool true for valid authentication or false for failed validation
     */
    public function authenticate(string $info, mixed $userwebauthn): bool
    {
        $info = json_decode($info);
        if (empty($info)) {
            $this->oops('info is not properly JSON encoded', 1);
        }
        $webauthn = $userwebauthn;

        /* find appropriate key from those stored for user (usually there'll only be one, but if
        someone has, say, a physical yubikey on desktop and fingerprint reader on mobile, for
        example, may be more than one. */
        $key = null;
        if (implode(',', self::stringToArray(hex2bin($userwebauthn->webauthn_id))) == implode(',', $info->rawId)) {
            $key = $userwebauthn;
        }
        if (empty($key)) {
            $this->oops('no key with id ' . implode(',', $info->rawId));
        }

        /* the checks below must use the client data the signature covers (clientDataJSONarray), not the
           separately supplied decoded copy, which an attacker could swap for one with a fresh challenge */
        if (!isset($info->response->clientDataJSONarray) || !is_array($info->response->clientDataJSONarray)) {
            $this->oops('no clientDataJSONarray in info');
        }
        $clientdata = self::arrayToString($info->response->clientDataJSONarray);
        $clientData = $this->verifyClientData(json_decode($clientdata), 'webauthn.get');

        /* cross-check challenge */
        $oc = rtrim(strtr(base64_encode(self::arrayToString($info->originalChallenge)), '+/', '-_'), '=');
        if (!hash_equals($oc, $clientData->challenge)) {
            $this->oops('challenge mismatch');
        }

        /* Does the challenge Correspond to the one we stored for the user? If no challenge is stored, that
           implies $userwebauthn was not saved back to the user database after prepareForLogin. It
           would be better to produce an error here, but for the purposes of backward compatibility, it'll
           allow it, but with a replay vulnerability */
        if (isset($key->challenge) && !hash_equals((string)$key->challenge, $clientData->challenge)) {
            $this->oops('you cannot use the same login more than once');
        }

        $bs = self::arrayToString($info->response->authenticatorData);
        $ao = (object)[];

        $ao->rpIdHash = substr($bs, 0, 32);
        $ao->flags = ord(substr($bs, 32, 1));
        $ao->counter = substr($bs, 33, 4);

        $hashId = hash('sha256', $this->appid, true);
        if ($hashId != $ao->rpIdHash) {
            // log(bin2hex($hashId).' '.bin2hex($ao->rpIdHash));
            $this->oops('cannot decode key response (2b)');
        }

        /* experience shows that at least one device (OnePlus 6T/Pie (Android phone)) doesn't set this,
        so this test would fail. This is not correct according to the spec, so  pragmatically it may
        have to be removed */
        if (($ao->flags & self::FLAG_UP) !== self::FLAG_UP) {
            $this->oops('cannot decode key response (2c)');
        } /* TUP must be set */

        $this->verifyUserVerified($ao->flags);

        /* assemble signed data */
        $signeddata = $hashId . chr($ao->flags) . $ao->counter . hash('sha256', $clientdata, true);

        if (count($info->response->signature) < 70) {
            $this->oops('cannot decode key response (3)');
        }

        $signature = self::arrayToString($info->response->signature);

        //$key = str_replace(chr(13), '', $key->key);
        $key = $key->webauthn_key;

        // log($key);
        return match (@openssl_verify($signeddata, $signature, $key, OPENSSL_ALGO_SHA256)) {
            1 => true,
            0 => false,
            default => $this->oops('cannot decode key response (4) ' . openssl_error_string()),
        };
    }

    public function parseWebAuthnId(string $info): string
    {
        $dInfo = json_decode($info);
        $rawId = $dInfo->rawId;
        return bin2hex(self::arrayToString($rawId));
    }

    /**
     * when user verification is required, check that the authenticator verified the user (UV flag)
     *
     * Requesting userVerification 'required' only makes the browser ask the authenticator for it; a modified
     * client can ignore the request, so the flag in the authenticator data is what the server has to check.
     */
    private function verifyUserVerified(int $flags): void
    {
        if ($this->userVerification === self::USER_VERIFICATION_REQUIRED && ($flags & self::FLAG_UV) !== self::FLAG_UV) {
            $this->oops('user verification required but the authenticator did not verify the user');
        }
    }

    /**
     * check the type and origin of the collected client data and that it carries a challenge
     *
     * @param mixed $clientData decoded clientDataJSON
     * @param string $type expected type, webauthn.create or webauthn.get
     * @return object the client data, with type, challenge and origin known to be strings
     */
    private function verifyClientData(mixed $clientData, string $type): object
    {
        if (!is_object($clientData)) {
            $this->oops('no client data in info');
        }
        if (!isset($clientData->type) || $clientData->type !== $type) {
            $this->oops('type mismatch');
        }
        if (!isset($clientData->challenge) || !is_string($clientData->challenge)) {
            $this->oops('no challenge in client data');
        }
        $origin = isset($clientData->origin) && is_string($clientData->origin) ? parse_url($clientData->origin) : false;
        if (!is_array($origin) || !isset($origin['host']) || $origin['host'] !== $this->appid) {
            $this->oops('origin mismatch');
        }

        return $clientData;
    }

    /**
     * convert an array of uint8's to a binary string
     *
     * @param array $a to be converted (array of unsigned 8 bit integers)
     * @return string converted to bytes
     */
    protected static function arrayToString(array $a): string
    {
        $s = '';
        foreach ($a as $c) {
            $s .= chr($c);
        }

        return $s;
    }

    /**
     * convert a binary string to an array of uint8's
     *
     * @param int|string $s to be converted
     * @return array converted to array of unsigned integers
     */
    private static function stringToArray(int|string $s): array
    {
        /* convert binary string to array of uint8 */
        $a = [];
        for ($idx = 0; $idx < strlen($s); $idx++) {
            $a[] = ord(((string)$s)[$idx]);
        }

        return $a;
    }

    /**
     * convert a public key from the hardware to PEM format
     *
     * @param string $key to be converted to PEM format
     * @return string|null converted to PEM format
     */
    private function pubkeyToPem(string $key): ?string
    {
        /* see https://github.com/Yubico/php-u2flib-server/blob/master/src/u2flib_server/U2F.php */
        if (strlen($key) !== 65 || $key[0] !== "\x04") {
            return null;
        }
        /*
        * Convert the public key to binary DER format first
        * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
        *
        *  SEQUENCE(2 elem)                        30 59
        *   SEQUENCE(2 elem)                       30 13
        *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
        *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
        *   BIT STRING(520 bit)                    03 42 ..key..
        */
        $der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
        $der .= "\x00" . $key;
        $pem = "-----BEGIN PUBLIC KEY-----\x0A";
        $pem .= chunk_split(base64_encode($der), 64, "\x0A");
        $pem .= "-----END PUBLIC KEY-----\x0A";

        return $pem;
    }

    /**
     * Build a PEM encoded RSA public key (SubjectPublicKeyInfo, RFC 8017 / RFC 5280) from its components
     *
     *  SEQUENCE                                         30 ..
     *   SEQUENCE                                        30 0d
     *    OID 1.2.840.113549.1.1.1 (rsaEncryption)       06 09 2a 86 48 86 f7 0d 01 01 01
     *    NULL                                           05 00
     *   BIT STRING                                      03 .. 00
     *    SEQUENCE (RSAPublicKey)                        30 ..
     *     INTEGER modulus                               02 .. n
     *     INTEGER publicExponent                        02 .. e
     *
     * @param string $n modulus as big-endian unsigned bytes
     * @param string $e public exponent as big-endian unsigned bytes
     * @return string PEM encoded public key
     */
    private function rsaPubkeyToPem(string $n, string $e): string
    {
        $n = ltrim($n, "\x00");
        $e = ltrim($e, "\x00");
        if ($n === '' || $e === '') {
            $this->oops('cannot decode key response (18)');
        }

        $rsaPublicKey = self::derEncode("\x30", self::derUnsignedInteger($n) . self::derUnsignedInteger($e));
        $algorithm = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $der = self::derEncode("\x30", $algorithm . self::derEncode("\x03", "\x00" . $rsaPublicKey));

        $pem = "-----BEGIN PUBLIC KEY-----\x0A";
        $pem .= chunk_split(base64_encode($der), 64, "\x0A");
        $pem .= "-----END PUBLIC KEY-----\x0A";

        return $pem;
    }

    /**
     * DER encode a non-negative INTEGER from big-endian unsigned bytes without leading zero bytes
     *
     * @param string $bytes big-endian unsigned bytes
     * @return string DER encoded INTEGER
     */
    private static function derUnsignedInteger(string $bytes): string
    {
        /* a set high bit would make the value negative in two's complement, so pad it */
        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }

        return self::derEncode("\x02", $bytes);
    }

    /**
     * DER encode a value as tag, definite length and contents
     *
     * @param string $tag single byte tag
     * @param string $value contents
     * @return string DER encoded value
     */
    private static function derEncode(string $tag, string $value): string
    {
        $length = strlen($value);
        if ($length < 0x80) {
            return $tag . chr($length) . $value;
        }

        $lengthBytes = ltrim(pack('N', $length), "\x00");

        return $tag . chr(0x80 | strlen($lengthBytes)) . $lengthBytes . $value;
    }

    /**
     * Convert COSE ECDHA to PKCS
     *
     * @param string $binary binary string to be converted
     * @return string|null converted public key
     *
     * @throws Exception
     */
    private function COSEECDHAtoPKCS($binary): ?string
    {
        try {
            // the COSE key may be followed by extension data, so only the first item is decoded
            $cosePubKey = CborDecoder::decodeFirst($binary);
        } catch (CborException) {
            return null;
        }

        if (!is_array($cosePubKey) || !isset($cosePubKey[3] /* cose_alg */) || !is_int($cosePubKey[3])) {
            return null;
        }

        switch ($cosePubKey[3]) {
            case self::ES256:
                /* COSE Alg: ECDSA w/ SHA-256 */
                if (!isset($cosePubKey[-1] /* cose_crv */)) {
                    $this->oops('cannot decode key response (9)');
                }

                if (!isset($cosePubKey[-2] /* cose_crv_x */)) {
                    $this->oops('cannot decode key response (10)');
                }

                if ($cosePubKey[-1] !== 1 /* cose_crv_P256 */) {
                    $this->oops('cannot decode key response (14)');
                }

                if (!isset($cosePubKey[-2] /* cose_crv_x */)) {
                    $this->oops('x coordinate for curve missing');
                }

                if (!isset($cosePubKey[1] /* cose_kty */)) {
                    $this->oops('cannot decode key response (7)');
                }

                if (!isset($cosePubKey[-3] /* cose_crv_y */)) {
                    $this->oops('cannot decode key response (11)');
                }

                if (!isset($cosePubKey[-3] /* cose_crv_y */)) {
                    $this->oops('y coordinate for curve missing');
                }

                if ($cosePubKey[1] !== 2 /* cose_kty_ec2 */) {
                    $this->oops('cannot decode key response (12)');
                }

                if (!$cosePubKey[-2] instanceof ByteString || !$cosePubKey[-3] instanceof ByteString) {
                    $this->oops('cannot decode key response (15)');
                }
                $x = $cosePubKey[-2]->bytes;
                $y = $cosePubKey[-3]->bytes;
                if (strlen($x) != 32 || strlen($y) != 32) {
                    $this->oops('cannot decode key response (15)');
                }
                $tag = "\x04";

                return $this->pubkeyToPem($tag . $x . $y);
            case self::RS256:
                /* COSE Alg: RSASSA-PKCS1-v1_5 w/ SHA-256 */
                if (!isset($cosePubKey[-2])) {
                    $this->oops('RSA Exponent missing');
                }
                if (!isset($cosePubKey[-1])) {
                    $this->oops('RSA Modulus missing');
                }
                if (!$cosePubKey[-1] instanceof ByteString || !$cosePubKey[-2] instanceof ByteString) {
                    $this->oops('cannot decode key response (17)');
                }

                return $this->rsaPubkeyToPem(
                    $cosePubKey[-1]->bytes,
                    $cosePubKey[-2]->bytes,
                );
            default:
                $this->oops('cannot decode key response (13)');
        }
    }

    /**
     * shim for random_bytes which doesn't exist pre php7
     *
     * @param int $length the number of bytes required
     * @return string length cryptographically random bytes
     *
     * @throws RandomException
     */
    private static function randomBytes(int $length): string
    {
        if (function_exists('random_bytes')) {
            return random_bytes($length);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($length, $crypto_strong);
            if (!$crypto_strong) {
                throw new RuntimeException('openssl_random_pseudo_bytes did not return a cryptographically strong result', 1);
            }

            return $bytes;
        } else {
            throw new RuntimeException('Neither random_bytes not openssl_random_pseudo_bytes exists. PHP too old? openssl PHP extension not installed?', 1);
        }
    }

    /**
     * just an abbreviation to throw an error: never returns
     *
     * @param string $s error message
     * @param int $c error code (0 for user error, 1 for incorrect usage)
     */
    private function oops(string $s, int $c = 0): never
    {
        error_log("oops: $s $c");
        throw new RuntimeException($s, $c);
    }

    protected function getUrlSuffix()
    {
    }
}
