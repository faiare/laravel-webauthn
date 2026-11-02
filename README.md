# Laravel WebAuthn

This project is currently under development.

It references the following repository extensively:
https://github.com/davidearl/webauthn

For a comprehensive solution, consider using the well-established adapter available at:
https://github.com/asbiin/laravel-webauthn

This adapter offers a seamless integration of both front-end and back-end components. 

In contrast, this library provides only a simple authentication Facade.

## Included Features

- Back-end Registration [x]
- Back-end Authentication [x]
- Front-end Registration []
- Front-end Authentication []
- Store WebAuthn keys in database []

## Requirements

- PHP 8.3 or higher
- Laravel 12.0 or higher
- ext-openssl

## Installation

```bash
composer require faiare/laravel-webauthn
```

## Configuration

Publish the config file to change it, or set the environment variables:

```bash
php artisan vendor:publish --tag=faiare-webauthn-config
```

| Key | Env | Default | |
|---|---|---|---|
| `appId` | `WEB_AUTHN_APP_ID` | `APP_URL` | Relying party ID. A leading `https://` is dropped; it must otherwise be the bare host. |
| `userVerification` | `WEB_AUTHN_USER_VERIFICATION` | `discouraged` | `required`, `preferred` or `discouraged`. |

`userVerification` is sent to the browser on both registration and authentication. With `discouraged` or
`preferred`, an unlocked password manager such as 1Password may sign in without asking for biometrics. With
`required`, the authenticator must verify the user (biometrics, PIN, or the password manager's re-prompt), and
`register()` and `authenticate()` reject responses without the user verified (UV) flag.

## Usage

### Register Passkey

```php
use Faiare\LaravelWebAuthn\Facades\WebAuthn;

$publicKey = WebAuthn::prepareChallengeForRegistration(
    username: 'username',
    userid: '100',
    crossPlatform: true,
);

// keep the challenge on the server until the browser sends the credential back
session()->put('webauthn_register_challenge', $publicKey->b64challenge);
```

Frontend example is in the examples directory.

```php
use Faiare\LaravelWebAuthn\Facades\WebAuthn;
use Illuminate\Support\Facades\DB;

// info must be a string
$info = request()->input('credential');

// the challenge issued above; register() rejects a credential created for any other challenge
$challenge = session()->pull('webauthn_register_challenge');
abort_unless(is_string($challenge), 400);

$publicKey = WebAuthn::register($info, $challenge);

// store the public key, example...
DB::table('web_authn_keys')->insert([
    'webauthn_id' => $publicKey->id,
    'webauthn_key' => $publicKey->key,
]);
```

### Authenticate Passkey

```php
use Faiare\LaravelWebAuthn\Facades\WebAuthn;

$publicKey = WebAuthn::prepareForAuthenticate();
```

Frontend example is in the examples directory.

```php
use Faiare\LaravelWebAuthn\Facades\WebAuthn;
use \Illuminate\Support\Facades\DB;

// info must be a string
$info = request()->input('credential');
$webAuthnId = WebAuthn::parseWebAuthnId($info);

// table must have a column named webauthn_id, webauthn_key
$webAuthnKey = DB::table('web_authn_keys')->where('webauthn_id', $webAuthnId)->first();

$success = WebAuthn::authenticate($info, $webAuthnKey);
```

## Try it locally

`examples/demo` runs the registration and authentication flow in the browser with PHP's built-in web server.
It needs neither Laravel nor a database nor Docker: challenges are kept in the PHP session and public keys in a
JSON file in the system temp directory.

```bash
composer install
composer demo
```

Open http://localhost:8000 (`localhost`, not `127.0.0.1`: WebAuthn does not accept an IP address as the RP ID),
register a passkey for a username, then sign in with it. Leave the username empty when signing in to let the
browser offer any passkey for the site (this needs a discoverable credential). The demo uses `localhost` as the
app ID; set `WEBAUTHN_DEMO_APP_ID` to change it. Set `WEBAUTHN_DEMO_USER_VERIFICATION` to `required` or `preferred`
to try user verification (default `discouraged`).

The demo is for trying the package out only. Do not use its storage or session handling in production.
