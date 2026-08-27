import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { createHash, randomBytes } from 'node:crypto'
import bcrypt from 'bcryptjs'

import { runtime } from 'mikser-io'
import { auth } from '../index.js'

// Boot the plugin against a REAL express app and a REAL mikser database, by
// driving the lifecycle hooks the engine itself drives. The grant store is
// sqlite-backed (ADR-0009), so faking it would test nothing about the code
// that actually runs.
let server, port, dir

// There is no config path for a client — every one registers itself, so the
// tests do too. CLIENT is filled in by before().
let CLIENT
const REDIRECT = 'http://127.0.0.1/callback'

before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'mikser-auth-flow-'))
    const runtimeFolder = path.join(dir, 'runtime')
    await mkdir(runtimeFolder, { recursive: true })

    await writeFile(path.join(dir, 'users.htpasswd'),
        `alice:${bcrypt.hashSync('alice-pw', 10)}\ncarol:${bcrypt.hashSync('carol-pw', 10)}\n`)
    await writeFile(path.join(dir, 'groups.htgroup'), 'editors: alice\n')

    const { default: express } = await import('express')
    const app = express()

    runtime.options = {
        ...runtime.options,
        app,
        workingFolder: dir,
        runtimeFolder,
    }
    runtime.config = { ...runtime.config, database: { filename: 'test.sqlite' } }
    // The engine's own subsystems log through runtime.engine.logger.
    const quiet = { info(){}, warn(){}, error(){}, debug(){}, trace(){}, fatal(){} }
    runtime.engine = { ...runtime.engine, logger: quiet }

    // Drive the engine's real lifecycle. Order matters and is not obvious:
    // some engine schemas (mikser_journal) register in onInitialize rather
    // than at module eval, because registering at module-eval would hit the
    // schemas Map while database/index.js is still evaluating. So initialize
    // has to run before loaded, or the database opens without them.
    for (const hook of runtime.hooks.initialize) await hook()
    for (const hook of runtime.hooks.loaded) await hook()

    runtime.options.url = 'https://test-mikser.example'

    const plugin = auth({
        capabilities: { editors: ['api:list', 'api:update'] },
        scopes:       { editors: { 'meta.href': { $regex: '^/web' } } },
        dcr:          { maxPerIp: 500 },
    })

    const load = [], loaded = []
    plugin({
        runtime,
        onLoad:    (cb) => load.push(cb),
        onLoaded:  (cb) => loaded.push(cb),
        useLogger: () => ({ info(){}, warn(){}, error(){}, debug(){}, trace(){} }),
    })
    for (const cb of load)   await cb()
    for (const cb of loaded) await cb()

    server = await new Promise(resolve => {
        const s = app.listen(0, () => resolve(s))
    })
    port = server.address().port

    const reg = await fetch(`http://127.0.0.1:${port}/auth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_name: 'Test Client', redirect_uris: [REDIRECT] }),
    })
    CLIENT = (await reg.json()).client_id
})

after(async () => {
    await new Promise(r => server?.close(r))
    await rm(dir, { recursive: true, force: true })
})

const url = (p) => `http://127.0.0.1:${port}${p}`
const b64url = (b) => b.toString('base64url')

function pkcePair() {
    const verifier = b64url(randomBytes(32))
    const challenge = b64url(createHash('sha256').update(verifier).digest())
    return { verifier, challenge }
}

const authorizeUrl = (challenge, over = {}) => {
    const q = new URLSearchParams({
        response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT,
        code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz',
        ...over,
    })
    return url(`/auth/authorize?${q}`)
}

const signIn = (challenge, creds, over = {}) => fetch(url('/auth/authorize'), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    redirect: 'manual',
    body: new URLSearchParams({
        response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT,
        code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz',
        ...creds, ...over,
    }),
})

const token = (body) => fetch(url('/auth/token'), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body),
})

describe('GET /authorize — the login page', () => {
    it('renders the form, naming the deployment and the client asking', async () => {
        const res = await fetch(authorizeUrl(pkcePair().challenge))
        assert.equal(res.status, 200)
        assert.match(res.headers.get('content-type'), /text\/html/)
        const html = await res.text()
        assert.match(html, /Sign in to test-mikser\.example/)
        assert.match(html, /to give <strong>Test Client<\/strong> access/)
        assert.match(html, /name="username"[^>]*autocomplete="username"/)
        assert.match(html, /autocomplete="current-password"/)
    })

    it('threads the authorization request through hidden fields', async () => {
        const { challenge } = pkcePair()
        const html = await (await fetch(authorizeUrl(challenge))).text()
        for (const [name, value] of [
            ['response_type', 'code'], ['client_id', CLIENT],
            ['redirect_uri', REDIRECT], ['code_challenge', challenge],
            ['code_challenge_method', 'S256'], ['state', 'xyz'],
        ]) {
            assert.ok(html.includes(`name="${name}" value="${value.replace(/&/g, '&amp;')}"`),
                      `hidden field ${name} missing`)
        }
    })

    it('serves the mikser mark', async () => {
        const html = await (await fetch(authorizeUrl(pkcePair().challenge))).text()
        assert.match(html, /<img src="\/auth\/logo\.svg"/)
        const logo = await fetch(url('/auth/logo.svg'))
        assert.equal(logo.status, 200)
        assert.match(logo.headers.get('content-type'), /image\/svg\+xml/)
        assert.match(await logo.text(), /aria-label="mikser"/)
    })

    it('refuses an unknown client and an unregistered redirect WITHOUT redirecting', async () => {
        // Redirecting to an unvalidated URI is itself the vulnerability —
        // an open redirect through the authorization endpoint.
        const bad = await fetch(authorizeUrl(pkcePair().challenge, { client_id: 'nope' }), { redirect: 'manual' })
        assert.equal(bad.status, 400)
        assert.equal(bad.headers.get('location'), null)

        const evil = await fetch(authorizeUrl(pkcePair().challenge, { redirect_uri: 'https://evil.example.com/' }),
                                 { redirect: 'manual' })
        assert.equal(evil.status, 400)
        assert.equal(evil.headers.get('location'), null)
    })

    it('requires PKCE S256, redirecting the error to the validated client', async () => {
        const plain = await fetch(authorizeUrl('abc', { code_challenge_method: 'plain' }), { redirect: 'manual' })
        assert.equal(plain.status, 302)
        const loc = new URL(plain.headers.get('location'))
        assert.equal(loc.searchParams.get('error'), 'invalid_request')
        assert.match(loc.searchParams.get('error_description'), /PKCE/)
        assert.equal(loc.searchParams.get('state'), 'xyz')
    })
})

describe('POST /authorize — sign in', () => {
    it('redirects back with a code and the original state', async () => {
        const res = await signIn(pkcePair().challenge, { username: 'alice', password: 'alice-pw' })
        assert.equal(res.status, 302)
        const loc = new URL(res.headers.get('location'))
        assert.equal(loc.origin + loc.pathname, REDIRECT)
        assert.ok(loc.searchParams.get('code'))
        assert.equal(loc.searchParams.get('state'), 'xyz')
    })

    it('re-renders with an error on bad credentials, keeping the request intact', async () => {
        const { challenge } = pkcePair()
        const res = await signIn(challenge, { username: 'alice', password: 'wrong' })
        assert.equal(res.status, 401)
        const html = await res.text()
        assert.match(html, /Incorrect username or password/)
        // The hidden fields survive, so retrying does not lose the request.
        assert.ok(html.includes(`name="code_challenge" value="${challenge}"`))
    })

    it('does not reveal whether the username exists', async () => {
        const a = await signIn(pkcePair().challenge, { username: 'alice',  password: 'wrong' })
        const b = await signIn(pkcePair().challenge, { username: 'ghost',  password: 'wrong' })
        assert.equal(a.status, b.status)
        assert.equal((await a.text()).replace(/value="[^"]*"/g, ''),
                     (await b.text()).replace(/value="[^"]*"/g, ''))
    })
})

describe('POST /token — authorization_code', () => {
    async function getCode(challenge, username = 'alice', password = 'alice-pw') {
        const res = await signIn(challenge, { username, password })
        return new URL(res.headers.get('location')).searchParams.get('code')
    }

    it('exchanges code + verifier for an access token carrying file-derived claims', async () => {
        const { verifier, challenge } = pkcePair()
        const code = await getCode(challenge)
        const res = await token({
            grant_type: 'authorization_code', code,
            redirect_uri: REDIRECT, code_verifier: verifier, client_id: CLIENT,
        })
        assert.equal(res.status, 200)
        const body = await res.json()
        assert.equal(body.token_type, 'Bearer')
        assert.ok(body.refresh_token)
        assert.equal(body.scope, 'api:list api:update')

        const claims = JSON.parse(Buffer.from(body.access_token.split('.')[1], 'base64url').toString())
        assert.equal(claims.sub, 'alice')
        assert.equal(claims.scope, 'api:list api:update')
        assert.deepEqual(claims.mks_scope, { 'meta.href': { $regex: '^/web' } })
    })

    it('rejects a wrong PKCE verifier', async () => {
        const { challenge } = pkcePair()
        const code = await getCode(challenge)
        const res = await token({
            grant_type: 'authorization_code', code,
            redirect_uri: REDIRECT, code_verifier: pkcePair().verifier, client_id: CLIENT,
        })
        assert.equal(res.status, 400)
        assert.equal((await res.json()).error, 'invalid_grant')
    })

    it('burns the code — a replay is refused', async () => {
        const { verifier, challenge } = pkcePair()
        const code = await getCode(challenge)
        const first = await token({
            grant_type: 'authorization_code', code,
            redirect_uri: REDIRECT, code_verifier: verifier, client_id: CLIENT,
        })
        assert.equal(first.status, 200)
        const replay = await token({
            grant_type: 'authorization_code', code,
            redirect_uri: REDIRECT, code_verifier: verifier, client_id: CLIENT,
        })
        assert.equal(replay.status, 400)
    })

    it('refuses a code redeemed against a different redirect_uri or client', async () => {
        const { verifier, challenge } = pkcePair()
        const code = await getCode(challenge)
        const wrongRedirect = await token({
            grant_type: 'authorization_code', code,
            redirect_uri: 'http://127.0.0.1/other', code_verifier: verifier, client_id: CLIENT,
        })
        assert.equal(wrongRedirect.status, 400)

        const wrongClient = await token({
            grant_type: 'authorization_code', code,
            redirect_uri: REDIRECT, code_verifier: verifier, client_id: 'someone-else',
        })
        assert.equal(wrongClient.status, 400)
    })

    it('gives a user in no group a token with no capabilities and no scope', async () => {
        const { verifier, challenge } = pkcePair()
        const code = await getCode(challenge, 'carol', 'carol-pw')
        const body = await (await token({
            grant_type: 'authorization_code', code,
            redirect_uri: REDIRECT, code_verifier: verifier, client_id: CLIENT,
        })).json()
        const claims = JSON.parse(Buffer.from(body.access_token.split('.')[1], 'base64url').toString())
        assert.equal(claims.sub, 'carol')
        assert.equal(claims.scope, '')
        assert.equal(claims.mks_scope, undefined)
    })
})

describe('POST /token — refresh_token', () => {
    async function fullFlow() {
        const { verifier, challenge } = pkcePair()
        const res = await signIn(challenge, { username: 'alice', password: 'alice-pw' })
        const code = new URL(res.headers.get('location')).searchParams.get('code')
        return (await token({
            grant_type: 'authorization_code', code,
            redirect_uri: REDIRECT, code_verifier: verifier, client_id: CLIENT,
        })).json()
    }

    it('rotates: the old token stops working, the new one works', async () => {
        const first = await fullFlow()
        const second = await (await token({
            grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: CLIENT,
        })).json()
        assert.ok(second.access_token)
        assert.ok(second.refresh_token)
        assert.notEqual(second.refresh_token, first.refresh_token)

        const reuse = await token({
            grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: CLIENT,
        })
        assert.equal(reuse.status, 400)

        const again = await token({
            grant_type: 'refresh_token', refresh_token: second.refresh_token, client_id: CLIENT,
        })
        assert.equal(again.status, 200)
    })

    it('refuses a refresh token presented by another client', async () => {
        const first = await fullFlow()
        const res = await token({
            grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: 'someone-else',
        })
        assert.equal(res.status, 400)
    })
})

describe('discovery', () => {
    it('advertises the endpoints an MCP client needs', async () => {
        const doc = await (await fetch(url('/auth/.well-known/oauth-authorization-server'))).json()
        assert.match(doc.authorization_endpoint, /\/auth\/authorize$/)
        assert.match(doc.token_endpoint, /\/auth\/token$/)
        assert.match(doc.jwks_uri, /\/auth\/jwks\.json$/)
        assert.deepEqual(doc.code_challenge_methods_supported, ['S256'])
        assert.deepEqual(doc.response_types_supported, ['code'])
        assert.ok(doc.grant_types_supported.includes('authorization_code'))
    })

    // RFC 8414 §3.1: the metadata for an issuer with no path component lives
    // at <origin>/.well-known/oauth-authorization-server. The document names
    // the origin as its issuer, so serving it only under /auth makes it
    // unreachable at the one address a conforming client derives — and every
    // MCP client is a conforming client, sent here by the resource's RFC 9728
    // document. Dynamic registration then fails with the metadata present.
    it('serves the metadata at the origin, where the issuer it declares says it is', async () => {
        const res = await fetch(url('/.well-known/oauth-authorization-server'))
        assert.equal(res.status, 200)
        const doc = await res.json()
        assert.match(doc.registration_endpoint, /\/auth\/register$/)
    })

    it('is reachable by deriving the URL from the issuer it declares', async () => {
        const doc = await (await fetch(url('/auth/.well-known/oauth-authorization-server'))).json()
        // What a client actually does: take `issuer`, append the well-known
        // path, fetch. If that 404s, discovery is broken however correct the
        // document's contents are.
        const derived = await fetch(`${doc.issuer}/.well-known/oauth-authorization-server`)
        assert.equal(derived.status, 200)
    })

    it('serves the same document at both mounts', async () => {
        const atBase = await (await fetch(url('/auth/.well-known/oauth-authorization-server'))).json()
        const atRoot = await (await fetch(url('/.well-known/oauth-authorization-server'))).json()
        assert.deepEqual(atRoot, atBase)
    })

    it('publishes a JWKS with no private component', async () => {
        const doc = await (await fetch(url('/auth/jwks.json'))).json()
        assert.equal(doc.keys.length, 1)
        assert.equal(doc.keys[0].d, undefined)
        assert.ok(doc.keys[0].kid)
    })
})

describe('POST /register — any agent, no operator config (RFC 7591)', () => {
    const register = (body) => fetch(url('/auth/register'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
    })

    it('lets an agent name itself and get a usable client_id', async () => {
        const res = await register({
            client_name: 'Some Other Agent',
            redirect_uris: ['http://127.0.0.1:9321/oauth/callback'],
        })
        assert.equal(res.status, 201)
        const body = await res.json()
        assert.ok(body.client_id)
        assert.equal(body.client_name, 'Some Other Agent')
        assert.equal(body.token_endpoint_auth_method, 'none')
        assert.equal(body.client_secret, undefined)
        assert.deepEqual(body.response_types, ['code'])
    })

    it('the registered client completes a whole sign-in, and the page names IT', async () => {
        // The point of the whole feature: an agent nobody configured can
        // connect, and the person signing in is told which agent it is.
        const reg = await (await register({
            client_name: 'Fancy Agent',
            redirect_uris: ['http://127.0.0.1/cb'],
        })).json()

        const { verifier, challenge } = pkcePair()
        const q = new URLSearchParams({
            response_type: 'code', client_id: reg.client_id, redirect_uri: 'http://127.0.0.1:7788/cb',
            code_challenge: challenge, code_challenge_method: 'S256', state: 'zz',
        })
        const page = await fetch(url(`/auth/authorize?${q}`))
        assert.equal(page.status, 200)
        assert.match(await page.text(), /to give <strong>Fancy Agent<\/strong> access/)

        const signed = await fetch(url('/auth/authorize'), {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            redirect: 'manual',
            body: new URLSearchParams({
                response_type: 'code', client_id: reg.client_id,
                redirect_uri: 'http://127.0.0.1:7788/cb',
                code_challenge: challenge, code_challenge_method: 'S256', state: 'zz',
                username: 'alice', password: 'alice-pw',
            }),
        })
        assert.equal(signed.status, 302)
        const code = new URL(signed.headers.get('location')).searchParams.get('code')

        const tok = await (await token({
            grant_type: 'authorization_code', code,
            redirect_uri: 'http://127.0.0.1:7788/cb',
            code_verifier: verifier, client_id: reg.client_id,
        })).json()
        assert.equal(tok.scope, 'api:list api:update')
    })

    it('escapes a client name — it is attacker-controlled and lands on the page', async () => {
        const reg = await (await register({
            client_name: '<script>alert(1)</script>',
            redirect_uris: ['http://127.0.0.1/cb'],
        })).json()
        const q = new URLSearchParams({
            response_type: 'code', client_id: reg.client_id, redirect_uri: 'http://127.0.0.1/cb',
            code_challenge: pkcePair().challenge, code_challenge_method: 'S256',
        })
        const html = await (await fetch(url(`/auth/authorize?${q}`))).text()
        assert.ok(!html.includes('<script>alert(1)</script>'), 'raw script tag must not reach the page')
        assert.match(html, /&lt;script&gt;/)
    })

    it('gives a nameless client a neutral name rather than a blank line', async () => {
        const body = await (await register({ redirect_uris: ['http://127.0.0.1/cb'] })).json()
        assert.equal(body.client_name, 'Unnamed client')
    })

    it('refuses redirect URIs that are not https or loopback http', async () => {
        for (const uri of ['http://evil.example.com/cb', 'ftp://x/cb', 'not-a-uri', 'https://x/cb#frag']) {
            const res = await register({ client_name: 'X', redirect_uris: [uri] })
            assert.equal(res.status, 400, `${uri} should be refused`)
            assert.equal((await res.json()).error, 'invalid_redirect_uri')
        }
        const ok = await register({ client_name: 'X', redirect_uris: ['https://agent.example.com/cb'] })
        assert.equal(ok.status, 201)
    })

    it('requires a non-empty redirect_uris array', async () => {
        assert.equal((await register({ client_name: 'X' })).status, 400)
        assert.equal((await register({ client_name: 'X', redirect_uris: [] })).status, 400)
    })

    it('is the only way a client exists — an unregistered id is refused', async () => {
        const res = await fetch(authorizeUrl(pkcePair().challenge, { client_id: 'never-registered' }),
                                { redirect: 'manual' })
        assert.equal(res.status, 400)
        assert.equal(res.headers.get('location'), null)
    })
})
