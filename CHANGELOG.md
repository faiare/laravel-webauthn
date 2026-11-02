# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is below 1.0.0, a minor version bump may contain breaking changes.

## [Unreleased]

## [0.3.0] - 2026-11-02

### Breaking changes

- `register()` now requires the challenge issued for the registration:
  `register(string $info)` became `register(string $info, string $challenge)`.
  Keep `PrepareChallengeForRegistration::$b64challenge` on the server (for example in the session)
  between `prepareChallengeForRegistration()` and `register()`, and pass it in. See the README.
- Dropped support for Laravel 10 and 11 and for PHP 8.2.

### Added

- `userVerification` config option (`WEB_AUTHN_USER_VERIFICATION`): `required`, `preferred` or `discouraged`
  (default, the previous fixed value). It is sent to the browser on both registration and authentication.
  With `required`, `register()` and `authenticate()` also reject responses whose authenticator data does not
  have the user verified (UV) flag set. `WebAuthnHelper::__construct()` takes it as an optional second
  argument and throws for any other value. If you published `config/webauthn.php`, add the key to it or
  rely on the default.
- Laravel 13 support.

### Changed

- Replaced `2tvenom/cborencode` with a built-in CBOR decoder that handles only what WebAuthn needs.
  It rejects indefinite lengths, tags, floats, oversized lengths and deep nesting. Decoded
  attestation and COSE key fields are now type-checked.
- Removed `phpseclib/phpseclib`. The RS256 public key is now encoded natively.

### Security

- `register()` now verifies `clientDataJSON`: its `type` must be `webauthn.create`, its `challenge`
  must equal the issued challenge, and the host of its `origin` must match the app ID. Previously
  none of these were checked, so a credential created for any challenge or origin was accepted.
- `authenticate()` now takes the challenge, origin and type from the signed `clientDataJSONarray`
  instead of the separately sent `response.clientData`. Previously an attacker could replay a
  captured assertion with a fresh `clientData` and pass the challenge check. No change is needed in
  the frontend; `response.clientData` is now ignored.
- `register()` now requires both the user presence (UP) and attested credential data (AT) flags.
  Previously either flag alone was accepted.
- Challenges are compared in constant time (`hash_equals`).

## [0.2.0] - 2026-03-02

### Added

- Laravel 12 support.
- PHP 8.4 and 8.5 support.

## [0.1.0] - 2024-07-22

### Added

- Initial release: back-end passkey registration (`prepareChallengeForRegistration()`, `register()`)
  and authentication (`prepareForAuthenticate()`, `authenticate()`, `parseWebAuthnId()`) through the
  `WebAuthn` facade, for Laravel 10 and 11 on PHP 8.2 and 8.3.

[Unreleased]: https://github.com/faiare/laravel-webauthn/compare/0.3.0...HEAD
[0.3.0]: https://github.com/faiare/laravel-webauthn/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/faiare/laravel-webauthn/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/faiare/laravel-webauthn/releases/tag/0.1.0
