import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import bcrypt from 'bcryptjs'

// The point of this file: prove these verifiers satisfy the engine's
// contract (ADR-0012) by driving them through the engine's own authorize(),
// rather than asserting against a local re-implementation of the rule.
import { authorize, resolveAuth } from 'mikser-io'

import { createIdentityStore } from '../lib/htpasswd.js'
import { loadOrCreateKey } from '../lib/keys.js'
import { issueToken, createTokenVerifier } from '../lib/tokens.js'
import { basic, jwt } from '../lib/verifiers.js'

const ISSUER = 'https://cms.example.com'
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64')
const req = (header, ip = '203.0.113.9') => ({ headers: header ? { authorization: header } : {}, ip })

let dir, store, key

before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'mikser-auth-s-'))
    const usersFile  = path.join(dir, 'users.htpasswd')
    const groupsFile = path.join(dir, 'groups.htgroup')
    await writeFile(usersFile, `alice:${bcrypt.hashSync('alice-pw', 10)}\n`)
    await writeFile(groupsFile, 'editors: alice\n')
    store = createIdentityStore({ usersFile, groupsFile, groups: { editors: ['api:update'] } })
    key = await loadOrCreateKey({ keyFile: path.join(dir, 'auth.key') })
})

after(async () => { await rm(dir, { recursive: true, force: true }) })

describe('verifiers satisfy the engine seam', () => {
    it('resolveAuth passes a verifier through untouched', () => {
        const v = basic({ store })
        assert.equal(resolveAuth(v), v)
    })

    it('basic: valid credentials authorize from anywhere', async () => {
        const out = await authorize(req(`Basic ${b64('alice:alice-pw')}`), basic({ store }))
        assert.equal(out.ok, true)
        assert.deepEqual(out.principal.capabilities, ['api:update'])
    })

    it('basic: a wrong password is 401 even from loopback with trustLoopback on', async () => {
        const out = await authorize(
            req(`Basic ${b64('alice:nope')}`, '127.0.0.1'),
            basic({ store }),
            { trustLoopback: true },
        )
        assert.equal(out.ok, false)
        assert.equal(out.status, 401)
        assert.equal(out.reason, 'invalid')
    })

    it('basic: no credential is "missing", which loopback policy may still rescue', async () => {
        const v = basic({ store })
        assert.equal((await authorize(req(null, '127.0.0.1'), v)).reason, 'missing')
        assert.equal((await authorize(req(null, '127.0.0.1'), v, { trustLoopback: true })).ok, true)
    })

    it('jwt: a token minted from the files authorizes, carrying its scope', async () => {
        const principal = await store.authenticate('alice', 'alice-pw')
        const token = await issueToken({
            key, issuer: ISSUER, audience: ISSUER,
            subject: principal.subject, capabilities: principal.capabilities,
        })
        const v = jwt({ verifyToken: createTokenVerifier({ key, issuer: ISSUER, audience: ISSUER }), issuer: ISSUER })
        const out = await authorize(req(`Bearer ${token}`), v)
        assert.equal(out.ok, true)
        assert.equal(out.principal.subject, 'alice')
        assert.deepEqual(out.principal.capabilities, ['api:update'])
    })

    it('jwt: an OAuth-gated surface gets no loopback bypass by default', async () => {
        const v = jwt({ verifyToken: createTokenVerifier({ key, issuer: ISSUER, audience: ISSUER }), issuer: ISSUER })
        const out = await authorize(req(null, '127.0.0.1'), v)
        assert.equal(out.ok, false)
        assert.equal(out.status, 401)
    })

    it('scope is never taken from the client — it comes from the files', async () => {
        // A user whose group grants api:update cannot obtain api:delete by
        // asking for it; the only input to the token's scope is the store.
        const principal = await store.authenticate('alice', 'alice-pw')
        assert.deepEqual(principal.capabilities, ['api:update'])
        const token = await issueToken({
            key, issuer: ISSUER, audience: ISSUER,
            subject: principal.subject, capabilities: principal.capabilities,
        })
        const v = jwt({
            verifyToken: createTokenVerifier({ key, issuer: ISSUER, audience: ISSUER }),
            issuer: ISSUER,
            requiredCapability: 'api:delete',
        })
        assert.equal((await authorize(req(`Bearer ${token}`), v)).ok, false)
    })
})

describe('the plugin is itself a verifier — one line at the call site', () => {
    // The config burden this removes: every gated endpoint used to have to
    // pick .basic() or .jwt() when the honest answer is "whichever the
    // caller has".
    it('resolveAuth takes it unchanged, despite being a function', async () => {
        const { auth } = await import('../index.js')
        const identity = auth({})
        assert.equal(typeof identity, 'function', 'still the plugin')
        assert.equal(resolveAuth(identity), identity, 'and also the verifier')
    })

    it('reports "nothing presented" with no credential, so loopback policy still applies', async () => {
        const { auth } = await import('../index.js')
        assert.equal(await auth({}).verify(req(null)), null)
    })

    it('routes each scheme to the verifier that owns it', async () => {
        // Basic and Bearer never collide: each verifier reports "not mine"
        // for the other's scheme, so the composite reaches the right one
        // rather than the first one.
        const { basic, jwt } = await import('../lib/verifiers.js')
        const composite = (await import('mikser-io')).anyOf(
            basic({ store }),
            jwt({ verifyToken: createTokenVerifier({ key, issuer: ISSUER, audience: ISSUER }), issuer: ISSUER }),
        )
        const viaBasic = await composite.verify(req(`Basic ${b64('alice:alice-pw')}`))
        assert.equal(viaBasic.subject, 'alice')

        const token = await issueToken({
            key, issuer: ISSUER, audience: ISSUER, subject: 'alice', capabilities: ['api:update'],
        })
        const viaBearer = await composite.verify(req(`Bearer ${token}`))
        assert.equal(viaBearer.subject, 'alice')
        assert.deepEqual(viaBearer.capabilities, ['api:update'])
    })
})

describe('the simplest possible setup', () => {
    it('with no capability map, an authenticated user behaves like a static token', async () => {
        // capabilities: null means "not capability-scoped" — the endpoint's
        // own `operations` list is the only limit, exactly as for a bare
        // token. Returning [] here would authenticate people and then refuse
        // them everything, making the capability map effectively mandatory.
        const { hasCapability } = await import('mikser-io')
        const bare = createIdentityStore({ usersFile: path.join(dir, 'users.htpasswd') })
        const p = await bare.authenticate('alice', 'alice-pw')
        assert.equal(p.capabilities, null)
        assert.equal(hasCapability(p, 'api:delete'), true)
    })

    it('once a capability map exists, an ungranted user is refused rather than unscoped', async () => {
        const { hasCapability } = await import('mikser-io')
        const scoped = createIdentityStore({
            usersFile:  path.join(dir, 'users.htpasswd'),
            groupsFile: path.join(dir, 'groups.htgroup'),
            groups:     { someone_else: ['api:delete'] },
        })
        const p = await scoped.authenticate('alice', 'alice-pw')
        assert.deepEqual(p.capabilities, [])
        assert.equal(hasCapability(p, 'api:delete'), false)
    })
})
