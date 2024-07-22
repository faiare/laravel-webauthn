/*
This is key registration part of the client (browser) side of webauthn
authentication.

This really does little more than fetch the info from the physical key
or fingerprint reader etc, and repackage it in a palatable form for
sending to the server.

When registering a user account, or allowing them to add a key in their profile,
or whatever, request a challenge from $webauthn->challenge() (e.g. using Ajax)
and pass the resulting key string to
  webauthnRegister(key, callback)
where key is the contents of the hidden field (or however else you stored
the challenge string).

The function will ask the browser to identify their key or touch fingerprint
or whatever.

On completion it will call the callback function callback:
  function callback(success, info)
success is a boolean, true for successful acquisition of info from the key,
in which case pass the info back to the server, call $webauth->register to
validate it, and put the resulting string back in the user record for use
in future logins.

If success is false, then either info is the string 'abort', meaning the
user failed to complete the process, or an error message of whatever else
went wrong.
*/

export type RegisterKeyType = {
  b64challenge: string
  publicKey: {
    challenge: number[]
    rp: {
      id: string
      name: string
    }
    user: {
      id: number[]
      name: string
      displayName: string
    }
    pubKeyCredParams: {
      type: 'public-key'
      alg: number
    }[]
    timeout: number
    attestation: string
  }
}

function arrayBufferToString(buf: ArrayBuffer) {
  return String.fromCharCode.apply(null, new Uint8Array(buf) as unknown as number[])
}

export async function webauthnRegister(key: RegisterKeyType) {
  const sendKey = {
    ...key,
    publicKey: {
      ...key.publicKey,
      attestation: undefined,
      challenge: new Uint8Array(key.publicKey.challenge).buffer,
      user: {
        ...key.publicKey.user,
        id: new Uint8Array(key.publicKey.user.id),
      },
    },
  }

  try {
    const aNewCredentialInfo = (await navigator.credentials.create({
      publicKey: sendKey.publicKey,
    })) as PublicKeyCredential
    if (!aNewCredentialInfo) {
      return {
        success: false,
        info: 'key returned nothing',
      }
    }
    const cd = JSON.parse(arrayBufferToString(aNewCredentialInfo.response.clientDataJSON))
    if (sendKey.b64challenge != cd.challenge) {
      return {
        success: false,
        info: 'key returned something unexpected (1)',
      }
    }
    const url = new URL(cd.origin)
    if (sendKey.publicKey.rp.name != url.hostname) {
      return {
        success: false,
        info: 'key returned something unexpected (2)',
      }
    }
    if (!('type' in cd)) {
      return {
        success: false,
        info: 'key returned something unexpected (3)',
      }
    }
    if (cd.type != 'webauthn.create') {
      return {
        success: false,
        info: 'key returned something unexpected (4)',
      }
    }

    const ao = [] as number[]
    const response = aNewCredentialInfo.response as AuthenticatorAttestationResponse
    new Uint8Array(response.attestationObject).forEach(function (v) {
      ao.push(v)
    })
    const rawId = [] as number[]
    new Uint8Array(aNewCredentialInfo.rawId).forEach(function (v) {
      rawId.push(v)
    })
    const info = {
      rawId: rawId,
      id: aNewCredentialInfo.id,
      type: aNewCredentialInfo.type,
      response: {
        attestationObject: ao,
        clientDataJSON: JSON.parse(arrayBufferToString(aNewCredentialInfo.response.clientDataJSON)),
      },
    }
    return {
      success: true,
      info: JSON.stringify(info),
    }
  } catch (aErr: unknown) {
    if (!(aErr instanceof Error)) {
      return {
        success: false,
        info: 'unknown error',
      }
    }
    if (
      ('name' in aErr && (aErr.name == 'AbortError' || aErr.name == 'NS_ERROR_ABORT')) ||
      aErr.name == 'NotAllowedError'
    ) {
      return {
        success: false,
        info: 'abort',
      }
    } else {
      return {
        success: false,
        info: aErr.message,
      }
    }
  }
}
