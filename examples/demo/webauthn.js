/*
 * Plain JavaScript versions of ../webauthnRegister.ts and ../webauthnAuthenticate.ts, so that the demo runs
 * in the browser without a build step. They build exactly the same $info payloads as the TS examples;
 * when the payload shape changes, update both.
 */

function toNumberArray(buf) {
  return Array.from(new Uint8Array(buf))
}

function arrayBufferToString(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf))
}

function failure(aErr) {
  if (!(aErr instanceof Error)) {
    return { success: false, info: 'unknown error' }
  }
  if (aErr.name === 'AbortError' || aErr.name === 'NS_ERROR_ABORT' || aErr.name === 'NotAllowedError') {
    return { success: false, info: 'abort' }
  }
  return { success: false, info: aErr.message }
}

// key: the PrepareChallengeForRegistration returned by prepareChallengeForRegistration()
export async function webauthnRegister(key) {
  const publicKey = {
    ...key.publicKey,
    attestation: undefined,
    challenge: new Uint8Array(key.publicKey.challenge).buffer,
    user: {
      ...key.publicKey.user,
      id: new Uint8Array(key.publicKey.user.id),
    },
  }

  try {
    const credential = await navigator.credentials.create({ publicKey })
    if (!credential) {
      return { success: false, info: 'key returned nothing' }
    }
    const cd = JSON.parse(arrayBufferToString(credential.response.clientDataJSON))
    if (key.b64challenge !== cd.challenge) {
      return { success: false, info: 'key returned something unexpected (1)' }
    }
    if (publicKey.rp.name !== new URL(cd.origin).hostname) {
      return { success: false, info: 'key returned something unexpected (2)' }
    }
    if (cd.type !== 'webauthn.create') {
      return { success: false, info: 'key returned something unexpected (4)' }
    }

    const info = {
      rawId: toNumberArray(credential.rawId),
      id: credential.id,
      type: credential.type,
      response: {
        attestationObject: toNumberArray(credential.response.attestationObject),
        clientDataJSON: cd,
      },
    }
    return { success: true, info: JSON.stringify(info) }
  } catch (aErr) {
    return failure(aErr)
  }
}

// key: the PrepareAuthenticatePublicKey returned by prepareForAuthenticate(), plus allowCredentials
export async function webauthnAuthenticate(key) {
  const originalChallenge = key.challenge
  const publicKey = {
    ...key,
    challenge: new Uint8Array(key.challenge),
    allowCredentials: key.allowCredentials?.map((k) => ({ type: k.type, id: new Uint8Array(k.id) })),
  }

  try {
    const assertion = await navigator.credentials.get({ publicKey })
    const response = assertion.response
    const info = {
      type: assertion.type,
      originalChallenge: originalChallenge,
      rawId: toNumberArray(assertion.rawId),
      response: {
        authenticatorData: toNumberArray(response.authenticatorData),
        clientData: JSON.parse(arrayBufferToString(response.clientDataJSON)),
        clientDataJSONarray: toNumberArray(response.clientDataJSON),
        signature: toNumberArray(response.signature),
      },
    }
    return { success: true, info: JSON.stringify(info) }
  } catch (aErr) {
    return failure(aErr)
  }
}
