/*

This is login part of the client (browser) side of webauthn authentication.

This really does little more than fetch the info from the physical key
or fingerprint reader etc, and repackage it in a palatable form for
sending to the server.

When generating the login page on the server, request a challenge from
webauthn->challenge(), and put the result into a hidden field on the
login form (which will also need your means to identify the user,
e.g. email address), probably as well as alternative means to log in
(such as a password login), or perhaps you're using the key as a
second factor, so this will be the second page or step in the login
sequence.

When they submit the form, call:
  webauthnAuthenticate(key, cb)
where key is the contents of the hidden field (or however else you stored
the challenge string).

The function will ask the browser to get credentials from the user, prompting
them to plug in the key, or touch finger or whatever.

On completion it will call the callback function cb:
  function cb(success, info)
success is a boolean, true for successful acquisition of info from the key,
in which case put info in the hidden field and continue with the submit
(or do an Ajax POST with the info, or whatever) and when received on the
server side call webauthn->authenticate.

If success is false, then either info is the string 'abort', meaning the
user failed to complete the process, or an error message of whatever else
went wrong.
*/

export type AuthenticateKeyType = {
  challenge: number[]
  allowCredentials: {
    type: 'public-key'
    id: number[]
  }[]
  timeout: number
  rpId: string
}

export async function webauthnAuthenticate(key: AuthenticateKeyType) {
  const originalChallenge = key.challenge
  const pk = {
    ...key,
    challenge: new Uint8Array(key.challenge),
    allowCredentials: key.allowCredentials?.map((k) => {
      return {
        type: k.type,
        id: new Uint8Array(k.id),
      }
    }),
  }

  try {
    const aAssertion = (await navigator.credentials.get({ publicKey: pk })) as PublicKeyCredential
    const response = aAssertion.response as AuthenticatorAssertionResponse

    // console.log("Credentials.Get response: ", aAssertion);
    const ida = [] as number[]
    new Uint8Array(aAssertion.rawId).forEach(function (v) {
      ida.push(v)
    })
    const cd = JSON.parse(
      String.fromCharCode.apply(
        null,
        new Uint8Array(response.clientDataJSON) as unknown as number[]
      )
    )
    const cda = [] as number[]
    new Uint8Array(response.clientDataJSON).forEach(function (v) {
      cda.push(v)
    })
    const ad = [] as number[]
    new Uint8Array(response.authenticatorData).forEach(function (v) {
      ad.push(v)
    })
    const sig = [] as number[]
    new Uint8Array(response.signature).forEach(function (v) {
      sig.push(v)
    })
    const info = {
      type: aAssertion.type,
      originalChallenge: originalChallenge,
      rawId: ida,
      response: {
        authenticatorData: ad,
        clientData: cd,
        clientDataJSONarray: cda,
        signature: sig,
      },
    }
    return {
      success: true,
      info: JSON.stringify(info),
    }
  } catch (aErr) {
    if (!(aErr instanceof Error)) {
      return {
        success: false,
        info: 'Unknown error',
      }
    }
    if (
      'name' in aErr &&
      (aErr.name == 'AbortError' || aErr.name == 'NS_ERROR_ABORT' || aErr.name == 'NotAllowedError')
    ) {
      return {
        success: false,
        info: 'abort',
      }
    } else {
      return {
        success: false,
        info: aErr.toString(),
      }
    }
  }
}
