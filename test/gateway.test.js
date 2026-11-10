/**
 * Tests for the address choice, the credential store, the request parser, the
 * session cookie, and one end-to-end pass through the gateway.
 */

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { Agent, createServer as createHttpServer, request as httpRequest } from 'node:http'
import { createServer as createNetServer } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, it } from 'node:test'
import {
  addressCandidates,
  chooseBindAddress,
  cookieValue,
  createController,
  createCredentials,
  createGateway,
  forgetAuthority,
  generatePassword,
  handleRpc,
  hashPassword,
  isLoopbackAddress,
  loginLanguage,
  normalizeSettings,
  parseHead,
  readSettings,
  renderLogin,
  resolveBind,
  signSession,
  trustAuthority,
  verifySession,
  writeSettings,
} from '../index.js'

/** The shape one generated password has: four groups of four. */
const GENERATED_PASSWORD = /^[a-hj-km-np-z2-9]{4}(-[a-hj-km-np-z2-9]{4}){3}$/

const INTERFACES = {
  lo0: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
  en0: [{ address: '192.168.1.20', family: 'IPv4', internal: false }],
  utun0: [
    { address: '10.8.0.2', family: 'IPv4', internal: false },
    { address: 'fe80::c0ff:ee01', family: 'IPv6', internal: false },
  ],
}

describe('address choice', () => {
  it('lists every non-loopback IPv4 address and skips IPv6', () => {
    assert.deepEqual(addressCandidates(INTERFACES), [
      { label: 'en0', address: '192.168.1.20' },
      { label: 'utun0', address: '10.8.0.2' },
    ])
  })

  it('keeps a configured address instead of choosing one', () => {
    assert.equal(chooseBindAddress('10.8.0.2', INTERFACES), '10.8.0.2')
  })

  it('chooses the first candidate when none is configured', () => {
    assert.equal(chooseBindAddress('', INTERFACES), '192.168.1.20')
  })

  it('reports no address when the machine has only loopback', () => {
    assert.equal(chooseBindAddress('', { lo0: INTERFACES.lo0 }), '')
  })
})

describe('request parsing', () => {
  it('reads the method, target, and lowercase headers', () => {
    const parsed = parseHead('POST /__login HTTP/1.1\r\nHost: 10.8.0.2:3081\r\nContent-Length: 12')
    assert.equal(parsed.method, 'POST')
    assert.equal(parsed.path, '/__login')
    assert.equal(parsed.headers.host, '10.8.0.2:3081')
    assert.equal(parsed.headers['content-length'], '12')
  })

  it('returns one cookie out of a header that carries several', () => {
    const header = 'dsh_session=abc; dsh_access_gateway=123.xyz; other=1'
    assert.equal(cookieValue(header, 'dsh_access_gateway'), '123.xyz')
    assert.equal(cookieValue(header, 'missing'), undefined)
    assert.equal(cookieValue(undefined, 'dsh_access_gateway'), undefined)
  })
})

describe('session cookie', () => {
  it('accepts a payload signed by the same key', () => {
    const key = Buffer.alloc(32, 7)
    assert.equal(verifySession(key, signSession(key, Date.now() + 1000), Date.now()), true)
  })

  it('rejects an expired payload', () => {
    const key = Buffer.alloc(32, 7)
    assert.equal(verifySession(key, signSession(key, Date.now() - 1000), Date.now()), false)
  })

  it('rejects a payload signed by another key', () => {
    const value = signSession(Buffer.alloc(32, 7), Date.now() + 1000)
    assert.equal(verifySession(Buffer.alloc(32, 8), value, Date.now()), false)
  })
})

describe('credential store', () => {
  let root
  before(() => {
    root = mkdtempSync(join(tmpdir(), 'dsh-access-gateway-'))
  })
  after(() => {
    rmSync(root, { recursive: true, force: true })
  })

  it('starts without a password and admits nothing until one is set', () => {
    const path = join(root, 'fresh.json')
    const first = createCredentials({ path })
    assert.equal(first.hasPassword(), false)
    assert.equal(first.verify(''), false)
    assert.equal(first.verify('anything'), false)

    first.replace('hunter2')
    assert.equal(first.hasPassword(), true)
    assert.equal(first.verify('hunter2'), true)

    const second = createCredentials({ path })
    assert.equal(second.verify('hunter2'), true)
    assert.equal(first.key.equals(second.key), true)
  })

  it('drops the password again on request', () => {
    const path = join(root, 'dropped.json')
    const credentials = createCredentials({ path })
    credentials.replace('hunter2')
    credentials.clear()
    assert.equal(credentials.hasPassword(), false)
    assert.equal(credentials.verify('hunter2'), false)
    assert.equal(createCredentials({ path }).hasPassword(), false)
  })

  it('checks a configured password without storing it', () => {
    const path = join(root, 'configured.json')
    const credentials = createCredentials({ path })
    credentials.replace('hunter2')
    assert.equal(credentials.verify('hunter2'), true)
    assert.equal(credentials.verify('hunter3'), false)
    assert.equal(hashPassword('hunter2', Buffer.alloc(16)).length, 32)
  })
})

describe('generated password', () => {
  it('is typeable on a phone: grouped, and without look-alike characters', () => {
    const password = generatePassword()
    assert.match(password, GENERATED_PASSWORD)
    assert.equal(password.length, 19)
    assert.equal(/[01ilo]/.test(password), false)
  })

  it('differs from one call to the next', () => {
    assert.notEqual(generatePassword(), generatePassword())
  })
})

describe('gateway', () => {
  let upstream
  let gateway
  let base
  let key

  before(async () => {
    upstream = createHttpServer((request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end(`upstream:${request.url}`)
    })
    await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
    key = Buffer.alloc(32, 3)
    gateway = createGateway({
      upstream: { host: '127.0.0.1', port: upstream.address().port },
      verify: (password) => password === 'open-sesame',
      accepts: (value) => verifySession(key, value),
      issue: () => signSession(key, Date.now() + 60000),
      token: () => 'launch-token',
      open: () => false,
      maxAgeSeconds: 60,
      failureDelayMs: 0,
    })
    await new Promise((resolve) => gateway.server.listen(0, '127.0.0.1', resolve))
    base = `http://127.0.0.1:${gateway.server.address().port}`
  })

  after(async () => {
    await gateway.close()
    await new Promise((resolve) => upstream.close(resolve))
  })

  it('serves the password form to a browser without a cookie', async () => {
    const response = await fetch(`${base}/`)
    const body = await response.text()
    assert.equal(response.status, 200)
    assert.match(body, /name="password"/)
  })

  it('sends a bare asset request back to the form', async () => {
    const response = await fetch(`${base}/assets/index.js`, { redirect: 'manual' })
    assert.equal(response.status, 302)
    assert.equal(response.headers.get('location'), '/')
  })

  it('rejects a wrong password', async () => {
    const response = await fetch(`${base}/__login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=wrong',
    })
    assert.equal(response.status, 401)
  })

  it('answers a right password with a session cookie and the launch token', async () => {
    const response = await fetch(`${base}/__login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=open-sesame',
      redirect: 'manual',
    })
    assert.equal(response.status, 302)
    assert.equal(response.headers.get('location'), '/?token=launch-token')
    assert.match(response.headers.get('set-cookie'), /^dsh_access_gateway=\d+\./)
  })

  it('admits a browser straight away when no password is set', async () => {
    const open = createGateway({
      upstream: { host: '127.0.0.1', port: upstream.address().port },
      verify: () => false,
      accepts: (value) => verifySession(key, value),
      issue: () => signSession(key, Date.now() + 60000),
      token: () => 'launch-token',
      open: () => true,
      maxAgeSeconds: 60,
      failureDelayMs: 0,
    })
    await new Promise((resolve) => open.server.listen(0, '127.0.0.1', resolve))
    const at = `http://127.0.0.1:${open.server.address().port}`
    try {
      const response = await fetch(`${at}/`, { redirect: 'manual' })
      assert.equal(response.status, 302)
      assert.equal(response.headers.get('location'), '/?token=launch-token')
      const cookie = response.headers.get('set-cookie').split(';')[0]
      const page = await fetch(`${at}/the-page`, { headers: { cookie } })
      assert.equal(await page.text(), 'upstream:/the-page')
    } finally {
      await open.close()
    }
  })

  it('forwards a connection that carries the session cookie', async () => {
    const login = await fetch(`${base}/__login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=open-sesame',
      redirect: 'manual',
    })
    const cookie = login.headers.get('set-cookie').split(';')[0]
    const response = await fetch(`${base}/the-page`, { headers: { cookie } })
    assert.equal(await response.text(), 'upstream:/the-page')
  })
})

describe('settings store', () => {
  let root
  before(() => {
    root = mkdtempSync(join(tmpdir(), 'dsh-access-gateway-settings-'))
  })
  after(() => {
    rmSync(root, { recursive: true, force: true })
  })

  it('falls back to the Plugin defaults on a first run', () => {
    const settings = readSettings({ bind: '10.0.0.4', port: 4000, sessionDays: 7 }, join(root, 'missing.json'))
    assert.deepEqual(settings, { bind: '10.0.0.4', port: 4000, sessionDays: 7, passwordEnabled: true })
  })

  it('round-trips what the page saved, switch included', () => {
    const path = join(root, 'settings.json')
    writeSettings({ bind: '10.8.0.2', port: 3081, sessionDays: 12, passwordEnabled: false }, path)
    assert.deepEqual(readSettings({ bind: '', port: 1, sessionDays: 1 }, path), {
      bind: '10.8.0.2',
      port: 3081,
      sessionDays: 12,
      passwordEnabled: false,
    })
  })

  it('rejects an address that is not IPv4, a port out of range and a switch that is not a boolean', () => {
    const base = { bind: '', port: 3081, sessionDays: 30, passwordEnabled: true }
    assert.throws(() => normalizeSettings({ bind: 'example.com' }, base), /IPv4/)
    assert.throws(() => normalizeSettings({ port: 0 }, base), /port/)
    assert.throws(() => normalizeSettings({ port: 70000 }, base), /port/)
    assert.throws(() => normalizeSettings({ sessionDays: 0 }, base), /sessionDays/)
    assert.throws(() => normalizeSettings({ passwordEnabled: 'off' }, base), /passwordEnabled/)
  })
})

describe('controller', () => {
  let root
  let controller
  let port

  /** Ask the OS for a free port, then hand it back. */
  const freePort = async () => {
    const server = createNetServer()
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    const chosen = server.address().port
    await new Promise((resolve) => server.close(resolve))
    return chosen
  }

  before(async () => {
    root = mkdtempSync(join(tmpdir(), 'dsh-access-gateway-controller-'))
    port = await freePort()
    controller = createController({
      ctx: { webServer: { port: 5555 }, connection: { authenticatedUrl: (base) => `${base}/?token=live-token` } },
      defaults: { bind: '127.0.0.1', port, password: '', sessionDays: 30 },
      paths: { settings: join(root, 'settings.json'), secret: join(root, 'secret.json') },
      log: { log: () => {}, warn: () => {} },
    })
    await controller.start()
  })

  after(async () => {
    await controller.stop()
    rmSync(root, { recursive: true, force: true })
  })

  it('reports the address it listens on', () => {
    const state = controller.snapshot()
    assert.equal(state.effective.host, '127.0.0.1')
    assert.equal(state.effective.url, `http://127.0.0.1:${port}/`)
    assert.equal(state.effective.upstreamPort, 5555)
  })

  it('starts a fresh store with a generated password the page can show', async () => {
    const state = controller.snapshot()
    assert.equal(state.settings.passwordEnabled, true)
    assert.equal(state.passwordSet, true)
    assert.match(state.generatedPassword, GENERATED_PASSWORD)
    const login = await fetch(`http://127.0.0.1:${port}/__login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `password=${encodeURIComponent(state.generatedPassword)}`,
      redirect: 'manual',
    })
    assert.equal(login.status, 302)
  })

  it('sets, keeps and drops the password through the same save', async () => {
    const base = { bind: '127.0.0.1', port, sessionDays: 30 }
    const set = await controller.save({ settings: base, password: 'replacement' })
    assert.equal(set.passwordSet, true)
    assert.equal(set.generatedPassword, '')
    const kept = await controller.save({ settings: base, password: '' })
    assert.equal(kept.passwordSet, true)
    const dropped = await controller.save({ settings: base, password: null })
    assert.equal(dropped.passwordSet, false)
    assert.equal(dropped.settings.passwordEnabled, false)
    await assert.rejects(
      () => controller.save({ settings: base, password: 'x' }),
      /at least 4 characters/,
    )
  })

  it('keeps the switch off across a restart instead of putting a password back', async () => {
    const offPort = await freePort()
    const ctx = { webServer: { port: 5555 }, connection: { authenticatedUrl: (base) => `${base}/?token=live-token` } }
    const paths = { settings: join(root, 'off-settings.json'), secret: join(root, 'off-secret.json') }
    const first = createController({
      ctx,
      defaults: { bind: '127.0.0.1', port: offPort, password: '', sessionDays: 30 },
      paths,
      log: { log: () => {}, warn: () => {} },
    })
    await first.start()
    const off = await first.save({
      settings: { bind: '127.0.0.1', port: offPort, sessionDays: 30, passwordEnabled: false },
      password: null,
    })
    assert.equal(off.passwordSet, false)
    assert.equal(off.generatedPassword, '')
    const open = await fetch(`http://127.0.0.1:${offPort}/`, { redirect: 'manual' })
    assert.equal(open.status, 302)
    assert.equal(open.headers.get('location'), '/?token=live-token')
    await first.stop()

    const again = createController({
      ctx,
      defaults: { bind: '127.0.0.1', port: offPort, password: '', sessionDays: 30 },
      paths,
      log: { log: () => {}, warn: () => {} },
    })
    await again.start()
    const state = again.snapshot()
    assert.equal(state.settings.passwordEnabled, false)
    assert.equal(state.passwordSet, false)
    assert.equal(state.generatedPassword, '')
    await again.stop()
  })

  it('generates a password when the switch is turned on with an empty field', async () => {
    const onPort = await freePort()
    const paths = { settings: join(root, 'on-settings.json'), secret: join(root, 'on-secret.json') }
    const on = createController({
      ctx: { webServer: { port: 5555 }, connection: { authenticatedUrl: (base) => `${base}/?token=t` } },
      defaults: { bind: '127.0.0.1', port: onPort, password: '', sessionDays: 30 },
      paths,
      log: { log: () => {}, warn: () => {} },
    })
    const enabled = await on.save({
      settings: { bind: '127.0.0.1', port: onPort, sessionDays: 30, passwordEnabled: true },
      password: '',
    })
    assert.equal(enabled.settings.passwordEnabled, true)
    assert.equal(enabled.passwordSet, true)
    assert.match(enabled.generatedPassword, GENERATED_PASSWORD)
    const typed = await on.save({
      settings: { bind: '127.0.0.1', port: onPort, sessionDays: 30, passwordEnabled: true },
      password: 'typed-again',
    })
    assert.equal(typed.generatedPassword, '')
    assert.equal(typed.passwordSet, true)
    await on.stop()
  })

  it('accepts the password the configuration names on a fresh store', async () => {
    const seededPort = await freePort()
    const seeded = createController({
      ctx: { webServer: { port: 5555 }, connection: { authenticatedUrl: (base) => `${base}/?token=t` } },
      defaults: { bind: '127.0.0.1', port: seededPort, password: 'seeded-pass', sessionDays: 30 },
      paths: { settings: join(root, 'seeded-settings.json'), secret: join(root, 'seeded-secret.json') },
      log: { log: () => {}, warn: () => {} },
    })
    await seeded.start()
    const response = await fetch(`http://127.0.0.1:${seededPort}/__login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=seeded-pass',
      redirect: 'manual',
    })
    assert.equal(response.status, 302)
    await seeded.stop()
  })

  it('reopens the listener with the saved port', async () => {
    const next = await controller.save({ settings: { bind: '127.0.0.1', port: await freePort(), sessionDays: 5 } })
    assert.equal(next.settings.sessionDays, 5)
    assert.equal(next.effective.running, true)
    assert.equal(next.effective.url.endsWith(`:${next.settings.port}/`), true)
  })

  it('reports a port that is already taken instead of claiming to listen', async () => {
    const taken = createNetServer()
    await new Promise((resolve) => taken.listen(0, '127.0.0.1', resolve))
    const blocked = createController({
      ctx: { webServer: { port: 5555 }, connection: {} },
      defaults: { bind: '127.0.0.1', port: taken.address().port, password: '', sessionDays: 30 },
      paths: { settings: join(root, 'busy-settings.json'), secret: join(root, 'busy-secret.json') },
      log: { log: () => {}, warn: () => {} },
    })
    await blocked.start()
    const state = blocked.snapshot()
    assert.equal(state.effective.running, false)
    assert.match(state.effective.error, /EADDRINUSE|in use/i)
    await blocked.stop()
    await new Promise((resolve) => taken.close(resolve))
  })

  it('applies a new password to an open connection instead of reopening the listener', async () => {
    const upstream = createHttpServer((request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' })
      response.end(`upstream:${request.url}`)
    })
    await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
    const livePort = await freePort()
    const live = createController({
      ctx: {
        webServer: { port: upstream.address().port },
        connection: { authenticatedUrl: (base) => `${base}/?token=live-token` },
      },
      defaults: { bind: '127.0.0.1', port: livePort, password: '', passwordEnabled: false, sessionDays: 30 },
      paths: { settings: join(root, 'live-settings.json'), secret: join(root, 'live-secret.json') },
      log: { log: () => {}, warn: () => {} },
    })
    await live.start()
    const agent = new Agent({ keepAlive: true, maxSockets: 1 })
    const get = (path, headers = {}) => new Promise((resolve, reject) => {
      const sent = httpRequest({ host: '127.0.0.1', port: livePort, path, headers, agent }, (response) => {
        let body = ''
        response.on('data', (chunk) => { body += chunk })
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body, reused: sent.reusedSocket }))
      })
      // A closed listener must fail this probe, not leave it waiting forever.
      sent.setTimeout(2000, () => sent.destroy(new Error('gateway connection closed')))
      sent.on('error', reject)
      sent.end()
    })
    // The open entry hands out the cookie, then the connection it pipes must survive the save.
    const login = await get('/open')
    const cookie = String(login.headers['set-cookie']).split(';')[0]
    await get('/warm', { cookie })
    await live.save({
      settings: { bind: '127.0.0.1', port: livePort, sessionDays: 30, passwordEnabled: true },
      password: 'typed-once',
    })
    const after = await get('/after', { cookie })
    assert.equal(after.body, 'upstream:/after')
    assert.equal(after.reused, true)
    agent.destroy()
    await live.stop()
    await new Promise((resolve) => upstream.close(resolve))
  })
})

describe('settings route', () => {
  it('answers one envelope per endpoint', async () => {
    const controller = {
      snapshot: () => ({ settings: { bind: '', port: 3081, sessionDays: 30 } }),
    }
    const ctx = { connection: { requestRejection: () => undefined } }
    const ask = async (body) => {
      const request = Object.assign(new EventEmitter(), { method: 'POST' })
      let written
      const response = {
        writeHead: (status) => { written = { status } },
        end: (payload) => { written = { ...written, body: JSON.parse(payload) } },
      }
      const answered = handleRpc(ctx, controller, request, response)
      request.emit('data', Buffer.from(JSON.stringify(body)))
      request.emit('end')
      await answered
      return written
    }
    assert.deepEqual((await ask({ endpoint: 'get' })).body.ok, true)
    assert.equal((await ask({ endpoint: 'nope' })).status, 400)
  })
})

describe('Host fence trust', () => {
  it('adds a bare host once and leaves loopback alone', () => {
    const connection = { trustedHosts: [] }
    assert.equal(isLoopbackAddress('127.0.0.1'), true)
    assert.equal(isLoopbackAddress('::1'), true)
    assert.equal(trustAuthority(connection, '127.0.0.1'), undefined)
    assert.deepEqual(connection.trustedHosts, [])
    assert.equal(trustAuthority(connection, '10.8.0.2'), '10.8.0.2')
    assert.equal(trustAuthority(connection, '10.8.0.2'), undefined)
    assert.deepEqual(connection.trustedHosts, ['10.8.0.2'])
  })

  it('removes only the entry it added', () => {
    const connection = { trustedHosts: ['app.example'] }
    trustAuthority(connection, '10.8.0.2')
    forgetAuthority(connection, '10.8.0.2')
    assert.deepEqual(connection.trustedHosts, ['app.example'])
  })

  it('reports an unusable list instead of throwing', () => {
    assert.equal(trustAuthority({}, '10.8.0.2'), undefined)
    assert.equal(trustAuthority({ trustedHosts: '10.8.0.2' }, '10.8.0.2'), undefined)
    forgetAuthority({}, '10.8.0.2')
  })
})

describe('login page', () => {
  it('picks its copy from Accept-Language', () => {
    assert.equal(loginLanguage('zh-CN,zh;q=0.9'), 'zh')
    assert.equal(loginLanguage('en-US,en;q=0.9'), 'en')
    assert.equal(loginLanguage(undefined), 'en')
  })

  it('renders one self-contained page per language', () => {
    const chinese = renderLogin(false, 'zh')
    assert.match(chinese, /<html lang="zh" translate="no">/)
    assert.match(chinese, /name="google" content="notranslate"/)
    assert.match(chinese, /placeholder="输入网关密码"/)
    assert.equal(renderLogin(false, 'zh').includes('class="note'), false)
    assert.equal(chinese.includes('<script'), false)
    assert.equal(chinese.includes('http://'), false)
    assert.match(renderLogin(true, 'en'), /Wrong password/)
  })
})

describe('bind resolution', () => {
  /** A two-interface machine: Wi-Fi plus a VPN, and loopback. */
  const interfaces = {
    lo0: [{ family: 'IPv4', internal: true, address: '127.0.0.1' }],
    en0: [{ family: 'IPv4', internal: false, address: '192.168.0.10' }],
    utun0: [{ family: 'IPv4', internal: false, address: '10.8.0.2' }],
  }

  it('serves the first non-loopback address when nothing is set', () => {
    assert.deepEqual(resolveBind('', interfaces), {
      host: '192.168.0.10',
      wildcard: false,
      accepted: ['192.168.0.10'],
    })
  })

  it('serves every interface for the wildcard and accepts each address', () => {
    assert.deepEqual(resolveBind('0.0.0.0', interfaces), {
      host: '0.0.0.0',
      wildcard: true,
      accepted: ['192.168.0.10', '10.8.0.2'],
    })
  })

  it('serves one pinned address', () => {
    assert.deepEqual(resolveBind('10.8.0.2', interfaces), {
      host: '10.8.0.2',
      wildcard: false,
      accepted: ['10.8.0.2'],
    })
  })
})
