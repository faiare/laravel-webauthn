import { webauthnAuthenticate, webauthnRegister } from './webauthn.js'

const $ = (id) => document.getElementById(id)

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const json = await res.json()
  if (!res.ok) {
    throw new Error(json.error ?? `HTTP ${res.status}`)
  }
  return json
}

function show(ok, message, detail = '') {
  $('status').className = ok ? 'ok' : 'ng'
  $('status').textContent = message
  $('detail').textContent = typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2)
}

async function refresh() {
  const state = await api('/api/state')
  $('app-id').textContent = state.appId
  $('store-file').textContent = state.storeFile
  $('credentials').replaceChildren(
    ...state.credentials.map((c) => {
      const tr = document.createElement('tr')
      for (const value of [c.username, c.webauthn_id, c.created_at]) {
        const td = document.createElement('td')
        td.textContent = value
        tr.append(td)
      }
      return tr
    }),
  )
  if (location.hostname !== state.appId) {
    $('warning').style.display = 'block'
    $('warning').textContent =
      `This page is served from "${location.hostname}" but the app ID is "${state.appId}". ` +
      `Open http://${state.appId}:${location.port}/ instead, or registration and sign-in will fail.`
  }
}

async function run(label, fn) {
  try {
    show(true, `${label}: waiting for the authenticator…`)
    await fn()
  } catch (e) {
    show(false, `${label} failed: ${e.message}`)
  } finally {
    await refresh().catch(() => {})
  }
}

$('register-form').addEventListener('submit', (event) => {
  event.preventDefault()
  const username = new FormData(event.target).get('username')
  run('Register', async () => {
    const { options } = await api('/api/register/options', { username })
    const result = await webauthnRegister(options)
    if (!result.success) {
      throw new Error(result.info)
    }
    const registered = await api('/api/register', { credential: result.info })
    show(true, `Registered a passkey for ${registered.username}`, registered)
  })
})

$('authenticate-form').addEventListener('submit', (event) => {
  event.preventDefault()
  const username = new FormData(event.target).get('username')
  run('Authenticate', async () => {
    const { options } = await api('/api/authenticate/options', { username })
    const result = await webauthnAuthenticate(options)
    if (!result.success) {
      throw new Error(result.info)
    }
    const user = await api('/api/authenticate', { credential: result.info })
    show(true, `Authenticated as ${user.username}`, user)
  })
})

$('reset').addEventListener('click', () => {
  run('Reset', async () => {
    await api('/api/reset', {})
    show(true, 'Cleared the stored credentials (passkeys remain on the authenticator; delete them there if needed)')
  })
})

refresh().catch((e) => show(false, `Cannot reach the demo server: ${e.message}`))
