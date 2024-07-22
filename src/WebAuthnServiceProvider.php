<?php

namespace Faiare\LaravelWebAuthn;

use Faiare\LaravelWebAuthn\Construct\WebAuthn;
use Illuminate\Support\ServiceProvider;

class WebAuthnServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/webauthn.php', 'webauthn'
        );

        $this->app->bind('webauthn', function ($app): WebAuthn {
            return new WebAuthnHelper($app['config']['webauthn']['appId']);
        });
    }

    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../config/webauthn.php' => config_path('webauthn.php'),
        ], 'faiare-webauthn-config');
    }
}
