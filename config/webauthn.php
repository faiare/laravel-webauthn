<?php

return [
    'appId' => env('WEB_AUTHN_APP_ID', env('APP_URL')),

    /*
     * userVerification requirement for registration and authentication: 'required', 'preferred' or 'discouraged'.
     * With 'required', the authenticator must verify the user (biometrics, PIN or password manager re-prompt)
     * and the server rejects responses without the user verified (UV) flag.
     */
    'userVerification' => env('WEB_AUTHN_USER_VERIFICATION', 'discouraged'),
];
