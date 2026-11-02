<?php

/*
 * Router script for trying the package with PHP's built-in web server, without Laravel, a database or Docker.
 *
 *   composer demo
 *   # or: php -S localhost:8000 -t examples/demo examples/demo/router.php
 *
 * then open http://localhost:8000 (not 127.0.0.1: WebAuthn does not accept an IP address as the RP ID).
 *
 * Challenges are kept in the PHP session and registered credentials in a JSON file in the system temp
 * directory. This is a demo only: do not use it as a template for production storage or session handling.
 */

declare(strict_types=1);

use Faiare\LaravelWebAuthn\WebAuthnHelper;

require __DIR__ . '/../../vendor/autoload.php';

if (PHP_SAPI !== 'cli-server') {
    http_response_code(404);
    exit;
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (!str_starts_with($path, '/api/')) {
    // let the built-in server serve the static files, and nothing else (it would execute this script directly)
    if (in_array($path, ['/', '/index.html', '/app.js', '/webauthn.js'], true)) {
        return false;
    }
    http_response_code(404);
    exit;
}

$appId = getenv('WEBAUTHN_DEMO_APP_ID') ?: 'localhost';
$storeFile = sys_get_temp_dir() . '/faiare-laravel-webauthn-demo.json';

session_start();
header('Content-Type: application/json');

function respond(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Run $fn with an exclusive lock on the credential store, passing the stored credentials by reference.
 *
 * @template T
 * @param callable(array<int, array{username: string, userid: string, webauthn_id: string, webauthn_key: string, created_at: string}>&): T $fn
 * @return T
 */
function withStore(string $file, callable $fn): mixed
{
    $fp = fopen($file, 'c+');
    if ($fp === false) {
        respond(500, ['error' => "cannot open $file"]);
    }
    try {
        flock($fp, LOCK_EX);
        $contents = stream_get_contents($fp);
        $credentials = $contents === '' || $contents === false ? [] : json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        $before = $credentials;
        $result = $fn($credentials);
        if ($credentials !== $before) {
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($credentials, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
            fflush($fp);
        }

        return $result;
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

function input(): array
{
    $body = json_decode((string) file_get_contents('php://input'), true);

    return is_array($body) ? $body : [];
}

function requireString(array $input, string $key): string
{
    $value = $input[$key] ?? null;
    if (!is_string($value) || trim($value) === '') {
        respond(400, ['error' => "$key is required"]);
    }

    return trim($value);
}

$method = $_SERVER['REQUEST_METHOD'];
$webauthn = new WebAuthnHelper($appId);

try {
    switch ("$method $path") {
        case 'GET /api/state':
            $credentials = withStore($storeFile, fn (array &$c) => $c);
            respond(200, [
                'appId' => $appId,
                'storeFile' => $storeFile,
                'credentials' => array_map(fn (array $c) => [
                    'username' => $c['username'],
                    'webauthn_id' => $c['webauthn_id'],
                    'created_at' => $c['created_at'],
                ], $credentials),
            ]);

        case 'POST /api/register/options':
            $username = requireString(input(), 'username');
            // reuse the user ID of an existing user so that the authenticator can replace its credential for them
            $userid = withStore($storeFile, function (array &$c) use ($username) {
                foreach ($c as $credential) {
                    if ($credential['username'] === $username) {
                        return $credential['userid'];
                    }
                }

                return bin2hex(random_bytes(16));
            });
            $options = $webauthn->prepareChallengeForRegistration(username: $username, userid: $userid, crossPlatform: false);
            $_SESSION['register'] = [
                'challenge' => $options->b64challenge,
                'username' => $username,
                'userid' => $userid,
            ];
            respond(200, ['options' => $options]);

        case 'POST /api/register':
            $pending = $_SESSION['register'] ?? null;
            unset($_SESSION['register']); // a challenge is good for one attempt only
            if (!is_array($pending)) {
                respond(400, ['error' => 'no registration in progress']);
            }
            $publicKey = $webauthn->register(requireString(input(), 'credential'), $pending['challenge']);
            withStore($storeFile, function (array &$c) use ($pending, $publicKey) {
                $c = array_values(array_filter($c, fn (array $credential) => $credential['webauthn_id'] !== $publicKey->id));
                $c[] = [
                    'username' => $pending['username'],
                    'userid' => $pending['userid'],
                    'webauthn_id' => $publicKey->id,
                    'webauthn_key' => $publicKey->key,
                    'created_at' => date(DATE_ATOM),
                ];
            });
            respond(200, ['username' => $pending['username'], 'webauthn_id' => $publicKey->id, 'webauthn_key' => $publicKey->key]);

        case 'POST /api/authenticate/options':
            // an empty username asks the browser for any passkey for this site (needs a discoverable credential)
            $username = trim((string) (input()['username'] ?? ''));
            $options = $webauthn->prepareForAuthenticate();
            $allowCredentials = [];
            if ($username !== '') {
                $ids = withStore($storeFile, fn (array &$c) => array_column(
                    array_filter($c, fn (array $credential) => $credential['username'] === $username),
                    'webauthn_id',
                ));
                if ($ids === []) {
                    respond(404, ['error' => "no passkey registered for $username"]);
                }
                $allowCredentials = array_map(fn (string $id) => [
                    'type' => 'public-key',
                    'id' => array_values(unpack('C*', hex2bin($id))),
                ], $ids);
            }
            $_SESSION['authenticate'] = [
                'challenge' => rtrim(strtr(base64_encode(pack('C*', ...$options->challenge)), '+/', '-_'), '='),
            ];
            respond(200, ['options' => [...$options->jsonSerialize(), 'allowCredentials' => $allowCredentials]]);

        case 'POST /api/authenticate':
            $pending = $_SESSION['authenticate'] ?? null;
            unset($_SESSION['authenticate']);
            if (!is_array($pending)) {
                respond(400, ['error' => 'no authentication in progress']);
            }
            $info = requireString(input(), 'credential');
            $webAuthnId = $webauthn->parseWebAuthnId($info);
            $credential = withStore($storeFile, function (array &$c) use ($webAuthnId) {
                foreach ($c as $credential) {
                    if ($credential['webauthn_id'] === $webAuthnId) {
                        return $credential;
                    }
                }

                return null;
            });
            if ($credential === null) {
                respond(404, ['error' => 'unknown passkey: register it again (the demo store may have been reset)']);
            }
            // the row object authenticate() expects; challenge enables the replay check
            $row = (object) [
                'webauthn_id' => $credential['webauthn_id'],
                'webauthn_key' => $credential['webauthn_key'],
                'challenge' => $pending['challenge'],
            ];
            if (!$webauthn->authenticate($info, $row)) {
                respond(401, ['error' => 'signature verification failed']);
            }
            respond(200, ['username' => $credential['username'], 'webauthn_id' => $credential['webauthn_id']]);

        case 'POST /api/reset':
            withStore($storeFile, function (array &$c) {
                $c = [];
            });
            $_SESSION = [];
            respond(200, ['ok' => true]);

        default:
            respond(404, ['error' => 'not found']);
    }
} catch (RuntimeException $e) {
    // WebAuthnHelper::oops(): code 0 = verification failed, 1 = wrong usage
    respond(400, ['error' => $e->getMessage(), 'code' => $e->getCode()]);
}
