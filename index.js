/**
 * Host half of the access gateway for the DSH Web GUI.
 *
 * One TCP listener on a local network address admits a browser, then forwards
 * the connection's bytes to the loopback listener. Each connection's first
 * request head is sniffed: a valid gateway cookie pipes the whole connection
 * untouched — so HTTP keep-alive and WebSocket upgrades keep working — while
 * anything else receives the login page, which redirects to the Web GUI with
 * this process's launch token once the password matches. With no password set
 * the gate is open: every request is handed the cookie and redirected at once.
 *
 * The address, port, password and session lifetime are edited from the Web
 * GUI's Settings through one POST route; the plugin configuration only supplies
 * the defaults a first run starts from. The upstream address comes from the
 * `webServer` service, so no port is hardcoded, and the launch token is read per
 * redirect, so a Host restart needs no configuration change.
 */

import z from '@deepseek-ai/schemastery'
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { connect, createServer } from 'node:net'
import { homedir, networkInterfaces } from 'node:os'
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

/** Stable loader identity. */
export const name = 'dsh-access-gateway'

/** Services this plugin cannot work without. */
export const inject = ['webServer', 'connection']

/** Route the settings page posts to; exact, so it never shadows another mount. */
export const RPC_PATH = '/dsh-access-gateway/rpc'

/** Largest request head accepted before the gateway gives up. */
const HEAD_LIMIT = 16384

/** Largest login body accepted, which carries one password field. */
const BODY_LIMIT = 4096

/** Largest settings body accepted; a save is a few hundred bytes. */
const RPC_BODY_LIMIT = 16384

/** Path the login form posts to. */
const LOGIN_PATH = '/__login'

/** Gateway cookie name; the value is `<expiry>.<hmac>`. */
const COOKIE_NAME = 'dsh_access_gateway'

/** Wait before a rejected login answers, so guessing costs time. */
const FAILURE_DELAY_MS = 600

/** Longest a connection may take to send its request head. */
const REQUEST_TIMEOUT_MS = 10000

/** Status reason phrases the gateway emits. */
const REASONS = {
  302: 'Found',
  400: 'Bad Request',
  401: 'Unauthorized',
  408: 'Request Timeout',
  431: 'Request Header Fields Too Large',
}

/** Plugin configuration: the defaults a first run starts from. */
export const Config = z.object({
  bind: z.string().default(''),
  port: z.natural().default(3081),
  password: z.string().default(''),
  sessionDays: z.natural().default(30),
})

// ---------------------------------------------------------------------------
// Address selection
// ---------------------------------------------------------------------------

/** List the concrete IPv4 addresses this machine could offer a phone. */
export function addressCandidates(interfaces = networkInterfaces()) {
  const found = []
  for (const [label, list] of Object.entries(interfaces)) {
    for (const address of list ?? []) {
      if (address.family === 'IPv4' && !address.internal) found.push({ label, address: address.address })
    }
  }
  return found
}

/** Choose the listening address: the configured one, else the first candidate. */
export function chooseBindAddress(configured, interfaces = networkInterfaces()) {
  if (configured !== '') return configured
  return addressCandidates(interfaces)[0]?.address ?? ''
}

/** The wildcard address, which serves every interface instead of one. */
export const WILDCARD = '0.0.0.0'

/** Whether a configured value asks for every interface. */
export function isWildcardAddress(value) {
  return value === WILDCARD
}

/**
 * Turn one configured value into the address to listen on and the authorities
 * the Host fence has to accept for it. A wildcard has no single authority, so
 * every interface address counts.
 * @param configured - the stored setting.
 * @param interfaces - the interface table to read, `os.networkInterfaces` by default.
 */
export function resolveBind(configured, interfaces = networkInterfaces()) {
  if (isWildcardAddress(configured)) {
    return { host: WILDCARD, wildcard: true, accepted: addressCandidates(interfaces).map((candidate) => candidate.address) }
  }
  if (configured !== '') return { host: configured, wildcard: false, accepted: [configured] }
  // Detection stays in one place: the empty setting still means "first address found".
  const first = chooseBindAddress('', interfaces)
  return { host: first, wildcard: false, accepted: first === '' ? [] : [first] }
}

/** Whether an address is loopback, which the /api fence accepts without an entry. */
export function isLoopbackAddress(address) {
  return address === 'localhost' || address.startsWith('127.') || address === '::1'
}

/**
 * Add one authority to the Connection fence's accepted list.
 * The fence reads this list on every request, so the address works at once.
 * @param connection - the Connection service owning the list.
 * @param address - the bare host the gateway listens on.
 * @returns the address when it was added, otherwise undefined.
 */
export function trustAuthority(connection, address) {
  const list = connection?.trustedHosts
  if (Array.isArray(list) !== true) return undefined
  if (address === '' || isLoopbackAddress(address) || list.includes(address)) return undefined
  list.push(address)
  return address
}

/** Remove one authority from that list, leaving entries this plugin did not add. */
export function forgetAuthority(connection, address) {
  const list = connection?.trustedHosts
  if (Array.isArray(list) !== true || address === undefined) return
  const at = list.indexOf(address)
  if (at !== -1) list.splice(at, 1)
}

/** Whether a string is a concrete IPv4 literal. */
function isIpv4(value) {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/** Derive the verification hash of a password. */
export function hashPassword(password, salt) {
  return scryptSync(password, salt, 32)
}

/** Compare two hashes without leaking their difference through timing. */
function sameHash(left, right) {
  return left.length === right.length && timingSafeEqual(left, right)
}

/** Sign one session payload with the gateway key. */
export function signSession(key, expiresAt) {
  return `${expiresAt}.${createHmac('sha256', key).update(String(expiresAt)).digest('base64url')}`
}

/** Accept a session payload only while it is unexpired and correctly signed. */
export function verifySession(key, value, now = Date.now()) {
  const text = String(value ?? '')
  const dot = text.indexOf('.')
  if (dot <= 0) return false
  const expiresAt = Number(text.slice(0, dot))
  if (Number.isFinite(expiresAt) !== true || expiresAt <= now) return false
  const expected = signSession(key, expiresAt)
  return text.length === expected.length && timingSafeEqual(Buffer.from(text), Buffer.from(expected))
}

/** Home directory of this DSH installation, holding both stores. */
function homePath(file) {
  return join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), 'dsh-access-gateway', file)
}

/** Read one JSON store, tolerating a first run or a lost file. */
function readJson(path) {
  try {
    const stored = JSON.parse(readFileSync(path, 'utf8'))
    return stored !== null && typeof stored === 'object' ? stored : {}
  } catch {
    return {}
  }
}

/** Persist one JSON store with owner-only permissions. */
function writeJson(path, value) {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    writeFileSync(path, JSON.stringify(value), { mode: 0o600 })
    chmodSync(path, 0o600)
  } catch (error) {
    throw new Error(`dsh-access-gateway: cannot write ${path}: ${error.message}`)
  }
}

/**
 * Own the credential file: the session signing key plus the password hash.
 * No stored hash means the entry has no password and admits every request.
 * @param {object} options - where the store lives.
 */
export function createCredentials({ path = homePath('secret.json') } = {}) {
  const stored = readJson(path)
  const state = {
    key: typeof stored.key === 'string' ? Buffer.from(stored.key, 'hex') : randomBytes(32),
    salt: typeof stored.salt === 'string' ? Buffer.from(stored.salt, 'hex') : randomBytes(16),
    hash: typeof stored.hash === 'string' ? Buffer.from(stored.hash, 'hex') : undefined,
  }
  const persist = () => {
    writeJson(path, {
      key: state.key.toString('hex'),
      salt: state.salt.toString('hex'),
      ...(state.hash === undefined ? {} : { hash: state.hash.toString('hex') }),
    })
  }
  /** Replace the password; a new salt makes the old hash useless. */
  const replace = (password) => {
    state.salt = randomBytes(16)
    state.hash = hashPassword(password, state.salt)
    persist()
  }
  /** Forget the password, so the entry admits anyone who can reach it. */
  const clear = () => {
    state.salt = randomBytes(16)
    state.hash = undefined
    persist()
  }
  // Write only what the file did not already hold; a plain read leaves it alone.
  if (typeof stored.key !== 'string' || typeof stored.salt !== 'string') persist()
  const credentials = {
    key: state.key,
    /** Whether a password exists; a store without one leaves the entry open. */
    hasPassword: () => state.hash !== undefined,
    verify: (password) => state.hash !== undefined && sameHash(hashPassword(password, state.salt), state.hash),
    replace,
    clear,
  }
  return credentials
}

// ---------------------------------------------------------------------------
// Settings store
// ---------------------------------------------------------------------------

/** Merge the stored settings over the Plugin defaults. */
export function readSettings(defaults, path = homePath('settings.json')) {
  const stored = readJson(path)
  return {
    bind: typeof stored.bind === 'string' ? stored.bind : (defaults.bind ?? ''),
    port: Number.isInteger(stored.port) ? stored.port : (defaults.port ?? 3081),
    sessionDays: Number.isInteger(stored.sessionDays) ? stored.sessionDays : (defaults.sessionDays ?? 30),
  }
}

/** Validate one settings payload against the current values and normalize it. */
export function normalizeSettings(payload, base) {
  const bind = String(payload.bind ?? base.bind).trim()
  const port = Number(payload.port ?? base.port)
  const sessionDays = Number(payload.sessionDays ?? base.sessionDays)
  if (bind !== '' && isIpv4(bind) !== true) {
    throw new Error('bind must be an IPv4 address (`0.0.0.0` for every interface), or empty to serve the first one found')
  }
  if (Number.isInteger(port) !== true || port < 1 || port > 65535) {
    throw new Error('port must be an integer between 1 and 65535')
  }
  if (Number.isInteger(sessionDays) !== true || sessionDays < 1 || sessionDays > 365) {
    throw new Error('sessionDays must be an integer between 1 and 365')
  }
  return { bind, port, sessionDays }
}

/** Persist the settings the page saved. */
export function writeSettings(settings, path = homePath('settings.json')) {
  writeJson(path, settings)
  return settings
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/** Parse a request head into its method, target, and lowercase header map. */
export function parseHead(text) {
  const [requestLine, ...lines] = text.split('\r\n')
  const [method, target] = requestLine.split(' ')
  const headers = {}
  for (const line of lines) {
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim()
  }
  return { method: method ?? '', path: target ?? '/', headers }
}

/** Read one cookie value out of a Cookie header. */
export function cookieValue(header, cookieName) {
  for (const part of String(header ?? '').split(';')) {
    const at = part.indexOf('=')
    if (at <= 0) continue
    if (part.slice(0, at).trim() === cookieName) return part.slice(at + 1).trim()
  }
  return undefined
}

/** Read one request head, plus the body a POST carries, from a connection. */
function readRequest(socket) {
  return new Promise((resolve) => {
    let buffer = Buffer.alloc(0)
    const settle = (value) => {
      socket.off('data', onData)
      socket.setTimeout(0)
      socket.pause()
      resolve(value)
    }
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      const end = buffer.indexOf('\r\n\r\n')
      if (end === -1) {
        if (buffer.length > HEAD_LIMIT) settle(undefined)
        return
      }
      const request = parseHead(buffer.subarray(0, end).toString('latin1'))
      const length = Number(request.headers['content-length'] ?? 0)
      if (Number.isFinite(length) !== true || length > BODY_LIMIT) {
        settle(undefined)
        return
      }
      const body = buffer.subarray(end + 4)
      if (body.length < length) return
      settle({ ...request, body: body.subarray(0, length), raw: buffer.subarray(0, end + 4 + length) })
    }
    socket.setTimeout(REQUEST_TIMEOUT_MS, () => socket.destroy())
    socket.on('data', onData)
  })
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/** Write one self-contained response and close the connection. */
function respond(socket, status, headers, body = '') {
  const payload = Buffer.from(body, 'utf8')
  const lines = [`HTTP/1.1 ${status} ${REASONS[status] ?? 'OK'}`]
  for (const [key, value] of Object.entries(headers)) lines.push(`${key}: ${value}`)
  lines.push(`Content-Length: ${payload.length}`, 'Connection: close', '', '')
  socket.end(Buffer.concat([Buffer.from(lines.join('\r\n'), 'latin1'), payload]))
}

/** Copy the login page shows, per language. */
const LOGIN_COPY = {
  zh: {
    lang: 'zh',
    title: 'HARNESS',
    hint: '输入网关密码',
    submit: '进入',
    failed: '密码不对，请重试',
    label: '网关密码',
  },
  en: {
    lang: 'en',
    title: 'HARNESS',
    hint: 'Enter the gateway password',
    submit: 'Enter',
    failed: 'Wrong password, try again',
    label: 'Gateway password',
  },
}

/** Pick the login copy from the browser's Accept-Language header. */
export function loginLanguage(acceptLanguage) {
  return /^zh/i.test(String(acceptLanguage ?? '').trim()) ? 'zh' : 'en'
}

/**
 * Serve the password form to a browser that has not passed the gate.
 * The page stands alone — the Web GUI's stylesheet is behind the same gate —
 * so it carries the theme's tokens and the boot screen's geometry inline.
 * @param failed - whether the previous password was rejected.
 * @param language - the copy to render, `zh` or `en`.
 */
export function renderLogin(failed, language = 'en') {
  const copy = LOGIN_COPY[language] ?? LOGIN_COPY.en
  return `<!doctype html>
<html lang="${copy.lang}" translate="no">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<!-- The page already picks its language from Accept-Language; a translation
     extension that injects nodes only moves the card around. -->
<meta name="google" content="notranslate">
<title>${copy.title}</title>
<style>
/* Theme tokens, inlined from the Web GUI theme for both schemes. */
:root {
  color-scheme: light;
  --bg-base: #fff;
  --label-primary: #0f1115;
  --label-tertiary: #81858c;
  --border-l4: #00000029;
  --bg-layer-3: #fff;
  --button-primary-fill: #0f1115;
  --label-primary-foreground: #fff;
  --state-error: #ec1313;
  --radius-md: 12px;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg-base: #151517;
    --label-primary: #f9fafb;
    --label-tertiary: #adb2b8;
    --border-l4: #ffffff33;
    --bg-layer-3: #353638;
    --button-primary-fill: #f9fafb;
    --label-primary-foreground: #0f1115;
    --state-error: #f25a5a;
  }
}
html { height: 100%; }
body {
  box-sizing: border-box; margin: 0;
  /* svh ignores the toolbar and the keyboard, so the card does not re-centre
     when either one changes the height. */
  min-height: 100vh; min-height: 100svh;
  display: grid; place-items: center; padding: 24px;
  background: var(--bg-base); color: var(--label-primary);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
    "Hiragino Sans GB", "Microsoft YaHei", "Helvetica Neue", Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
/* A phone keyboard shrinks the viewport; anchoring the card near the top keeps
   the input in place instead of letting the browser scroll it away. */
@media (pointer: coarse), (max-height: 520px) {
  body { place-items: start center; padding-top: max(40px, 12svh); }
}
/* Geometry follows the boot screen: one narrow column, 16px between blocks. */
main { display: flex; flex-direction: column; align-items: center; gap: 16px; width: min(300px, 100%); }
.wordmark { font-size: 16px; line-height: 24px; font-weight: 600; letter-spacing: .08em; }
form { display: flex; flex-direction: column; gap: 10px; width: 100%; }
input {
  box-sizing: border-box; height: 34px; padding: 0 12px;
  border: .5px solid var(--border-l4); border-radius: var(--radius-md);
  background: var(--bg-layer-3); color: var(--label-primary);
  font: inherit; font-size: 13px; line-height: 1.5;
}
input:focus-visible { outline: 2px solid var(--label-primary); outline-offset: 1px; }
button {
  height: 36px; padding: 0 14px; border: none; border-radius: var(--radius-md);
  background: var(--button-primary-fill); color: var(--label-primary-foreground);
  font: inherit; font-size: 14px; line-height: 22px; cursor: pointer;
}
button:hover { opacity: .88; }
.note { margin: 0; font-size: 12px; line-height: 18px; color: var(--label-tertiary); }
.note.error { color: var(--state-error); }
</style>
</head>
<body class="notranslate">
<main>
<div class="wordmark">${copy.title}</div>
<form method="post" action="${LOGIN_PATH}">
<input type="password" name="password" autocomplete="current-password" autofocus required
  placeholder="${copy.hint}" aria-label="${copy.label}">
<button type="submit">${copy.submit}</button>
</form>
${failed === true ? `<p class="note error">${copy.failed}</p>` : ''}
</main>
</body>
</html>`
}

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------

/** Wait, so a wrong password costs the same order of time as a right one. */
function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

/** Hand an accepted connection to the upstream listener, byte for byte. */
function pipeUpstream(client, raw, options) {
  const upstream = connect(options.upstream.port, options.upstream.host)
  upstream.on('error', () => client.destroy())
  client.on('error', () => upstream.destroy())
  upstream.once('connect', () => {
    upstream.write(raw)
    client.pipe(upstream)
    upstream.pipe(client)
  })
}

/** Answer with the login form, rejecting a wrong password after a delay. */
async function answerLogin(client, request, options) {
  const language = loginLanguage(request.headers['accept-language'])
  const submitted = request.method === 'POST' && request.path === LOGIN_PATH
  if (submitted !== true) {
    // Only the page itself gets the form; a bare asset request from a logged-out
    // browser is sent back to it instead of receiving HTML.
    if (request.path.split('?')[0] !== '/') {
      respond(client, 302, { Location: '/' })
      return
    }
    respond(client, 200, { 'Content-Type': 'text/html; charset=utf-8' }, renderLogin(false, language))
    return
  }
  const password = new URLSearchParams(request.body.toString('utf8')).get('password') ?? ''
  if (options.verify(password) !== true) {
    await delay(options.failureDelayMs)
    respond(client, 401, { 'Content-Type': 'text/html; charset=utf-8' }, renderLogin(true, language))
    return
  }
  admit(client, options)
}

/** Send a browser on to the GUI with the launch token and a session cookie. */
function admit(client, options) {
  const token = options.token()
  const location = token === '' ? '/' : `/?token=${encodeURIComponent(token)}`
  respond(client, 302, {
    Location: location,
    'Set-Cookie': `${COOKIE_NAME}=${options.issue()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${options.maxAgeSeconds}`,
  })
}

/** Decide one connection: pipe it through, or answer it at the gateway. */
async function handleConnection(client, options) {
  client.on('error', () => {})
  const request = await readRequest(client)
  if (request === undefined) {
    respond(client, 400, { 'Content-Type': 'text/plain; charset=utf-8' }, 'bad request\n')
    return
  }
  if (options.accepts(cookieValue(request.headers.cookie, COOKIE_NAME))) {
    pipeUpstream(client, request.raw, options)
    return
  }
  // No password set: every browser gets the launch URL, and only that.
  if (options.open() === true && (request.method === 'GET' || request.method === 'POST')) {
    admit(client, options)
    return
  }
  if (request.method === 'GET' || request.method === 'POST') {
    await answerLogin(client, request, options)
    return
  }
  respond(client, 401, { 'Content-Type': 'text/plain; charset=utf-8' }, 'no gateway session; open the entry URL in a browser first\n')
}

/**
 * Build the gateway listener.
 * @param {object} options - the upstream address plus the five request
 * decisions: `verify`, `accepts`, `issue`, `token`, `open`.
 * @returns {{ server: import('node:net').Server, close: () => Promise<void> }}
 */
export function createGateway(options) {
  // A net server has no `closeAllConnections`, so the gateway keeps its own set:
  // a settings change has to reopen the listener even while a phone is connected.
  const sockets = new Set()
  const server = createServer((client) => {
    sockets.add(client)
    client.on('close', () => sockets.delete(client))
    handleConnection(client, options).catch(() => client.destroy())
  })
  return {
    server,
    close: () => new Promise((resolve) => {
      server.close(() => resolve())
      for (const socket of sockets) socket.destroy()
    }),
  }
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/** Read this process's launch token from the Connection service. */
function launchToken(ctx) {
  try {
    const authenticatedUrl = ctx.connection?.authenticatedUrl
    if (typeof authenticatedUrl !== 'function') return ''
    const url = new URL(authenticatedUrl.call(ctx.connection, `http://127.0.0.1:${ctx.webServer.port}`))
    return url.searchParams.get('token') ?? ''
  } catch {
    return ''
  }
}

/**
 * Own the listener and both stores, so the Settings page can change the entry
 * without restarting the Host.
 * @param {object} options - the Host context, the Plugin defaults, and test
 * overrides for the two store paths.
 */
export function createController({ ctx, defaults, paths = {}, log = console }) {
  const settingsFile = paths.settings ?? homePath('settings.json')
  const secretFile = paths.secret ?? homePath('secret.json')
  const credentials = createCredentials({ path: secretFile })
  // A password in the Plugin configuration seeds the first run; afterwards the
  // Settings page owns it, so a configured default never overwrites a real one.
  if (defaults.password !== undefined && defaults.password !== '' && credentials.hasPassword() !== true) {
    credentials.replace(defaults.password)
  }
  let current = readSettings(defaults, settingsFile)
  let gateway
  let bind = { host: '', wildcard: false, accepted: [] }
  let error
  let trusted = []

  /** The gate decisions; each one reads the state in force when a request arrives. */
  const decisions = () => ({
    upstream: { host: '127.0.0.1', port: ctx.webServer.port },
    verify: credentials.verify,
    accepts: (value) => verifySession(credentials.key, value),
    issue: () => signSession(credentials.key, Date.now() + current.sessionDays * 86400000),
    token: () => launchToken(ctx),
    open: () => credentials.hasPassword() !== true,
    // A getter, so a new lifetime applies to the next cookie without a restart.
    get maxAgeSeconds() { return current.sessionDays * 86400 },
    failureDelayMs: FAILURE_DELAY_MS,
  })

  /** Every URL the entry answers on: one address, or each interface for a wildcard. */
  const entryUrls = () => {
    const addresses = bind.wildcard ? bind.accepted : (bind.host === '' ? [] : [bind.host])
    if (addresses.length === 0) return bind.wildcard ? [`http://${WILDCARD}:${current.port}/`] : []
    return addresses.map((address) => `http://${address}:${current.port}/`)
  }

  /** Answer what the Settings page shows: current values, the live state and the password state. */
  const snapshot = () => {
    const urls = entryUrls()
    return {
      settings: { ...current },
      passwordSet: credentials.hasPassword(),
      effective: {
        host: bind.host,
        port: current.port,
        wildcard: bind.wildcard,
        url: urls[0] ?? '',
        urls,
        running: gateway !== undefined && error === undefined,
        error: error ?? '',
        upstreamPort: ctx.webServer.port,
      },
      candidates: addressCandidates(),
    }
  }

  /** Drop every authority this plugin added, leaving what `--trusted-host` put there. */
  const forgetFence = () => {
    for (const address of trusted) forgetAuthority(ctx.connection, address)
    trusted = []
  }

  /**
   * Teach the /api and WebSocket fence this gateway's own addresses.
   * `--trusted-host` fills the same list at boot; this covers the address the
   * Settings page picks, and the case where the Host was started without it.
   */
  const trustFence = () => {
    forgetFence()
    for (const address of bind.accepted) {
      if (trustAuthority(ctx.connection, address) !== undefined) trusted.push(address)
    }
    if (trusted.length > 0) {
      log.log(`dsh-access-gateway: accepting ${trusted.join(', ')} for /api and WebSocket (this process only)`)
      return
    }
    const managed = Array.isArray(ctx.connection?.trustedHosts)
    const remote = bind.accepted.filter((address) => isLoopbackAddress(address) !== true)
    if (remote.length > 0 && managed !== true) {
      log.warn(`dsh-access-gateway: cannot add ${remote.join(', ')} to the Host fence; start the Host with \`--trusted-host ${remote[0]}\``)
    }
  }

  const stop = async () => {
    forgetFence()
    if (gateway === undefined) return
    const closing = gateway
    gateway = undefined
    await closing.close()
  }

  /** Open the listener and settle once it either listens or reports why not. */
  const start = () => new Promise((resolve) => {
    bind = resolveBind(current.bind)
    error = undefined
    if (bind.host === '') {
      error = 'no local address found; set one to serve the Web GUI on the network'
      log.warn(`dsh-access-gateway: ${error}`)
      resolve()
      return
    }
    const created = createGateway(decisions())
    gateway = created
    created.server.on('error', (cause) => {
      error = cause.message
      // A listener that never came up must not leave an accepted authority behind.
      forgetFence()
      log.warn(`dsh-access-gateway: ${cause.message}`)
      resolve()
    })
    created.server.listen(current.port, bind.host, () => {
      error = undefined
      trustFence()
      log.log(`dsh-access-gateway: listening on ${entryUrls().join(' ')}`)
      if (credentials.hasPassword() !== true) {
        log.warn('dsh-access-gateway: no access password set; anyone who can reach the entry is admitted')
      }
      resolve()
    })
  })

  /** Close and reopen the listener, settling once it listens again. */
  const restart = async () => {
    await stop()
    await start()
  }

  return {
    start,
    stop,
    restart,
    snapshot,
    /**
     * Persist what the page saved, replace the password when one was typed, and
     * reopen the listener only when the address or the port moved.
     */
    save: async ({ settings, password } = {}) => {
      const next = normalizeSettings(settings ?? {}, current)
      // Only the listening socket needs reopening; every gate decision is a
      // closure over live state, so a new password applies to the next request.
      const moved = next.bind !== current.bind || next.port !== current.port
      // `undefined` or `null` means the page asked to drop the password; `''`
      // keeps the current one.
      const typed = password === undefined || password === null ? '' : String(password)
      if (typed !== '' && typed.length < 4) throw new Error('password must be at least 4 characters')
      writeSettings(next, settingsFile)
      current = next
      if (typed !== '') credentials.replace(typed)
      else if (password === null) credentials.clear()
      if (moved) await restart()
      return snapshot()
    },
  }
}

// ---------------------------------------------------------------------------
// Settings route
// ---------------------------------------------------------------------------

/** Read one JSON body, bounded by the RPC limit. */
function readBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    request.on('data', (chunk) => {
      size += chunk.length
      if (size > RPC_BODY_LIMIT) {
        reject(new Error('request body too large'))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8')
      if (text === '') {
        resolve({})
        return
      }
      try {
        const parsed = JSON.parse(text)
        resolve(parsed !== null && typeof parsed === 'object' ? parsed : {})
      } catch (error) {
        reject(new Error(`invalid JSON: ${error.message}`))
      }
    })
    request.on('error', reject)
  })
}

/** Write one JSON envelope. */
function sendJson(response, status, value) {
  const payload = JSON.stringify(value)
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
  })
  response.end(payload)
}

/**
 * Serve the Settings route: admission first, then one endpoint per action.
 * @param {object} ctx - the Host context carrying the Connection service.
 * @param {object} controller - the gateway controller.
 * @param {object} request - the incoming request.
 * @param {object} response - the response to write.
 */
export async function handleRpc(ctx, controller, request, response) {
  // The same admission `/api` uses: cookie plus Host/Origin.
  const connection = ctx.connection
  if (connection === undefined) {
    sendJson(response, 503, { ok: false, error: { message: 'connection service unavailable' } })
    return
  }
  const rejection = connection.requestRejection(request)
  if (rejection !== undefined) {
    sendJson(response, rejection, { ok: false, error: { message: 'not admitted' } })
    return
  }
  if (request.method !== 'POST') {
    sendJson(response, 405, { ok: false, error: { message: 'POST only' } })
    return
  }
  let body
  try {
    body = await readBody(request)
  } catch (error) {
    sendJson(response, 400, { ok: false, error: { message: error.message } })
    return
  }
  const endpoint = String(body.endpoint ?? '')
  // Resolve the value first, so a failure answers once instead of after a partial write.
  let value
  try {
    if (endpoint === 'get') value = controller.snapshot()
    else if (endpoint === 'save') value = await controller.save(body)
    else {
      sendJson(response, 400, { ok: false, error: { message: `unknown endpoint "${endpoint}"` } })
      return
    }
  } catch (error) {
    sendJson(response, 400, { ok: false, error: { message: error instanceof Error ? error.message : String(error) } })
    return
  }
  sendJson(response, 200, { ok: true, value })
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/** Mount the listener and the Settings route for this profile. */
export function apply(ctx, config) {
  if (config.password !== '' && config.password.length < 4) {
    throw new Error('dsh-access-gateway: `password` must be at least 4 characters')
  }
  const controller = createController({ ctx, defaults: config })
  ctx.effect(() => {
    void controller.start()
    return () => controller.stop()
  }, 'dsh-access-gateway: access entry')
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'exact',
      path: RPC_PATH,
      handler: (request, response) => handleRpc(ctx, controller, request, response),
    }),
    'dsh-access-gateway: settings route',
  )
}
