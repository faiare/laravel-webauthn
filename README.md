# Laravel WebAuthn

This project is a work in progress.

The following repository is heavily referenced:
https://github.com/davidearl/webauthn

## Requirements

- PHP 8.2 or higher
- Laravel 10.0 or higher
- ext-openssl

## Installation

```bash
composer require faiare/laravel-webauthn
```

## Usage

### Register Passkey

```php
use Faiare\LaravelWebAuthn\Facades\WebAuthn;

$publicKey = WebAuthn::prepareChallengeForRegistration(
    username: 'username',
    userid: '100',
    crossPlatform: true,
);
```

Frontend example is in the examples directory.

```php
use Faiare\LaravelWebAuthn\Facades\WebAuthn;

// info must be a string
$info = request()->input('credential');

WebAuthn::register($info);
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

WebAuthn::authenticate($info, $webAuthnKey);
```
