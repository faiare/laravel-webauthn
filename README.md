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
use Illuminate\Support\Facades\DB;

// info must be a string
$info = request()->input('credential');

$publicKey = WebAuthn::register($info);

// store the public key, example...
DB::table('web_authn_keys')->insert([
    'webauthn_id' => $publicKey->webauthnId,
    'webauthn_key' => $publicKey->webauthnKey,
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
