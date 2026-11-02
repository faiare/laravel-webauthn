# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 概要

`faiare/laravel-webauthn` は、WebAuthn (パスキー) のバックエンド側の登録・認証だけを提供する Laravel 用の小さなパッケージ（アプリではなくライブラリ）。実装は https://github.com/davidearl/webauthn を移植したもの。フロントエンドの統合や DB への鍵保存は範囲外で、鍵の保存は利用側アプリの責任（README の使用例を参照）。README では「開発中」とされている。

## コマンド

```bash
composer install
vendor/bin/phpunit                                   # 全テスト
vendor/bin/phpunit --filter test_register            # 単一テスト
vendor/bin/phpunit tests/Unit/WebAuthnTest.php       # 単一ファイル
```

linter / フォーマッタの設定はない。`phpunit.xml.dist` に `failOnNotice` / `failOnWarning` が設定されているため、PHP の notice や deprecation の warning が出るとテストが失敗する。

## サポートするバージョン（CI）

`.github/workflows/test.yml` は PHP 8.3–8.5 × Laravel 12/13 × `prefer-lowest`/`prefer-stable` のマトリクスで実行する。CI は `laravel/framework=^N` を require してから `composer update --prefer-lowest|--prefer-stable` を行うので、`composer.json` の制約は下限まで実際に動く必要がある（例: `phpunit/phpunit` の下限を `^11.5.50|^12.5.8` にしているのは、それ未満がセキュリティ勧告の対象で解決できないため）。Composer 2.9 以降はセキュリティ勧告の対象バージョンを依存解決から除外するので、サポートが終了して未修正の勧告が残る Laravel のメジャーバージョンはインストールできなくなる。Laravel 10/11 はこの理由でサポートを外した。Laravel / PHP のサポートを追加するときは、`composer.json` の `require`（`illuminate/support`, `php`）、`require-dev`（`orchestra/testbench`, `phpunit/phpunit`）と CI のマトリクスを合わせて更新する。

## アーキテクチャ

- `WebAuthnServiceProvider` は `config/webauthn.php` をマージし、`webauthn` に `WebAuthnHelper` をバインドする（`appId` を渡す。`WEB_AUTHN_APP_ID` が未設定なら `APP_URL`）。設定ファイルは `faiare-webauthn-config` タグで publish できる。provider と `WebAuthn` facade は `composer.json` の `extra.laravel` で自動検出される。
- `Construct\WebAuthn` が公開インターフェース。`Facades\WebAuthn` の `@method` docblock はこれと一致させておく必要がある。
- `WebAuthnHelper` がすべてのプロトコル処理を持つ: CBOR デコード（自前の `Cbor\CborDecoder`。WebAuthn に必要な型だけを扱い、不定長・タグ・浮動小数点は拒否する）、COSE 鍵から PEM への変換（ES256・RS256 とも SubjectPublicKeyInfo の DER を手組みする）、openssl による署名検証。エラーは `oops()` 経由で `RuntimeException` として送出される（code 0 = 検証失敗、1 = 呼び出し側の誤り）。`authenticate()` も失敗時は `false` を返すのではなく、多くの場合例外を投げる。
- `Entities\*` は readonly な値オブジェクト。`Prepare*` はブラウザに返す challenge のペイロード（`JsonSerializable`）。`register()` が返す `RegisterPublicKey` のプロパティは `id`（credential ID の hex）と `key`（PEM）。

### 押さえておくべきプロトコル上の挙動

- `appid` から取り除かれるのは先頭の `https://` だけ。`authenticate()` ではこれを `clientData.origin` の **ホスト部分** とだけ比較し、`rpId` としても使う。そのため `http://` やポート、パスを含む `APP_URL` だと origin mismatch になる。テストでは `appId` を `localhost` に設定している（`tests/TestCase.php`）。
- `authenticate($info, $userwebauthn)` は、`webauthn_id`（hex）と `webauthn_key`（PEM）を持つ行オブジェクトを想定しており、任意で `challenge` を持てる（リプレイ対策。保存されていなければ確認はスキップされる）。
- `$info` はフロントエンドが作る JSON 文字列で、バイト列は数値配列として入っている。その形は `examples/*.ts` が決めている。登録の `$info` は `rawId` / `response.attestationObject` / `response.clientDataJSON` を、認証の `$info` は `rawId` / `originalChallenge` / `response.{authenticatorData,clientData,clientDataJSONarray,signature}` を持つ。ペイロードの形を変えるときは、PHP 側と TS の examples の両方を更新する。
- 受け付けるアテステーション形式は `none` と `packed`。`fido-u2f` などそれ以外は拒否する。

## テスト

テストは Orchestra Testbench（`tests/TestCase.php`）を使い、facade 経由で呼び出す。fixture は記録済みのブラウザペイロードをインラインに埋め込んだもの（origin は `http://localhost:8000`）。`tests/Feature` はプレースホルダーのみ。
