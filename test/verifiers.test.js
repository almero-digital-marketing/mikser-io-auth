import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm, readFile, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import bcrypt from 'bcryptjs'

import { createIdentityStore } from '../lib/htpasswd.js'
import { loadOrCreateKey, jwks } from '../lib/keys.js'
import { issueToken, createTokenVerifier } from '../lib/tokens.js'
import { basic, jwt } from '../lib/verifiers.js'

const req = (header) => ({ headers: header ? { authorization: header } : {} })
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64')

let dir, store, key

before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'mikser-auth-v-'))
    const usersFile  = path.join(dir, 'users.htpasswd')
    const groupsFile = path.join(dir, 'groups.htgroup')
    await writeFile(usersFile, `alice:${bcrypt.hashSync('alice-pw', 10)}\n`)
    await writeFile(groupsFile, 'editors: alice\n')
    store = createIdentityStore({ usersFile, groupsFile, groups: { editors: ['api:update', 'mcp:use'] } })
    key = await loadOrCreateKey({ keyFile: path.join(dir, 'auth.key') })
})

after(async () => { await rm(dir, { recursive: true, force: true }) })

describe('basic verifier', () => {
    it('accepts valid credentials and carries the capabilities through', async () => {
        const p = await basic({ store }).verify(req(`Basic ${b64('alice:alice-pw')}`))
        assert.equal(p.subject, 'alice')
        assert.deepEqual(p.capabilities.sort(), ['api:update', 'mcp:use'])
    })

    it('returns null when nothing is presented, so loopback policy can still apply', async () => {
        assert.equal(await basic({ store }).verify(req(null)), null)
    })

    it('rejects a wrong password', async () => {
        assert.equal(await basic({ store }).verify(req(`Basic ${b64('alice:nope')}`)), false)
    })

    it('treats a Bearer on a Basic endpoint as rejected, not as absent', async () => {
        // If this returned null it would fall through to a loopback bypass —
        // a presented-but-unusable credential must never do that.
        assert.equal(await basic({ store }).verify(req('Bearer something')), false)
    })

    it('survives malformed base64 and a missing colon', async () => {
        assert.equal(await basic({ store }).verify(req('Basic !!!not-base64!!!')), false)
        assert.equal(await basic({ store }).verify(req(`Basic ${b64('nocolon')}`)), false)
    })

    it('handles a password containing a colon', async () => {
        const usersFile = path.join(dir, 'colon.htpasswd')
        await writeFile(usersFile, `dave:${bcrypt.hashSync('pa:ss:word', 10)}\n`)
        const s = createIdentityStore({ usersFile })
        assert.equal((await basic({ store: s }).verify(req(`Basic ${b64('dave:pa:ss:word')}`))).subject, 'dave')
    })

    it('challenges with a realm and UTF-8 charset', () => {
        const res = { headers: {}, set(k, v) { this.headers[k] = v } }
        basic({ store, realm: 'cms' }).challenge({}, res)
        assert.equal(res.headers['WWW-Authenticate'], 'Basic realm="cms", charset="UTF-8"')
    })
})

describe('key file', () => {
    it('is stable across loads — a restart must not invalidate live tokens', async () => {
        const keyFile = path.join(dir, 'stable.key')
        const a = await loadOrCreateKey({ keyFile })
        const b = await loadOrCreateKey({ keyFile })
        assert.equal(a.kid, b.kid)
        assert.deepEqual(a.publicJwk, b.publicJwk)
    })

    it('is written 0600 — it is a signing key sitting in a content folder', async () => {
        const keyFile = path.join(dir, 'perms.key')
        await loadOrCreateKey({ keyFile })
        assert.equal((await stat(keyFile)).mode & 0o777, 0o600)
    })

    it('fails loudly on a corrupt key file rather than silently rotating', async () => {
        const keyFile = path.join(dir, 'corrupt.key')
        await writeFile(keyFile, 'not json at all')
        await assert.rejects(() => loadOrCreateKey({ keyFile }), /unreadable or not JSON/)
    })

    it('publishes only the public half', async () => {
        const doc = jwks({ publicJwk: key.publicJwk })
        assert.equal(doc.keys.length, 1)
        assert.equal(doc.keys[0].d, undefined)
        assert.ok(doc.keys[0].kid)
    })

    it('refuses to publish a JWKS carrying a private component', async () => {
        const stored = JSON.parse(await readFile(path.join(dir, 'auth.key'), 'utf8'))
        assert.throws(() => jwks({ publicJwk: stored.privateJwk }), /private component/)
    })
})

describe('jwt verifier', () => {
    const issuer = 'https://cms.example.com'
    const mint = (over = {}) => issueToken({
        key, issuer, audience: issuer, subject: 'alice',
        capabilities: ['api:update', 'mcp:use'], ...over,
    })
    const verifier = (over = {}) => jwt({
        verifyToken: createTokenVerifier({ key, issuer, audience: issuer }),
        issuer, ...over,
    })

    it('round-trips a token and recovers subject + capabilities', async () => {
        const p = await verifier().verify(req(`Bearer ${await mint()}`))
        assert.equal(p.subject, 'alice')
        assert.deepEqual(p.capabilities, ['api:update', 'mcp:use'])
    })

    it('returns null with no header, false for a non-Bearer scheme', async () => {
        assert.equal(await verifier().verify(req(null)), null)
        assert.equal(await verifier().verify(req(`Basic ${b64('alice:alice-pw')}`)), false)
    })

    it('rejects garbage and an expired token as false, never as a throw', async () => {
        assert.equal(await verifier().verify(req('Bearer not.a.jwt')), false)
        const expired = await mint({ ttl: '-1s' })
        assert.equal(await verifier().verify(req(`Bearer ${expired}`)), false)
    })

    it('rejects a token minted for a different audience', async () => {
        const other = await mint({ audience: 'https://elsewhere.example.com' })
        assert.equal(await verifier().verify(req(`Bearer ${other}`)), false)
    })

    it('rejects a token signed by a different key', async () => {
        const foreign = await loadOrCreateKey({ keyFile: path.join(dir, 'foreign.key') })
        const token = await issueToken({ key: foreign, issuer, audience: issuer, subject: 'mallory' })
        assert.equal(await verifier().verify(req(`Bearer ${token}`)), false)
    })

    it('enforces requiredCapability', async () => {
        const v = verifier({ requiredCapability: 'api:delete' })
        assert.equal(await v.verify(req(`Bearer ${await mint()}`)), false)
        const ok = await mint({ capabilities: ['api:delete'] })
        assert.equal((await v.verify(req(`Bearer ${ok}`))).subject, 'alice')
    })

    it('advertises the issuer for RFC 9728 discovery', () => {
        const v = verifier({ scopes: ['mcp:use'] })
        assert.deepEqual(v.authorizationServers, [issuer])
        assert.deepEqual(v.scopesSupported, ['mcp:use'])
    })
})

describe('row scope survives the JWT round trip', () => {
    const issuer = 'https://cms.example.com'
    const ROWS = { 'meta.href': { $regex: '^/web' } }

    it('travels as a private claim, not as OAuth `scope`', async () => {
        const token = await issueToken({
            key, issuer, audience: issuer, subject: 'alice',
            capabilities: ['api:list'], scope: ROWS,
        })
        const [, payload] = token.split('.')
        const claims = JSON.parse(Buffer.from(payload, 'base64url').toString())
        // OAuth's `scope` is the capability list — a client library parses it
        // as one, so the row filter must not be in there.
        assert.equal(claims.scope, 'api:list')
        assert.deepEqual(claims.mks_scope, ROWS)
    })

    it('is recovered by the verifier and reaches the principal', async () => {
        const token = await issueToken({
            key, issuer, audience: issuer, subject: 'alice',
            capabilities: ['api:list'], scope: ROWS,
        })
        const v = jwt({ verifyToken: createTokenVerifier({ key, issuer, audience: issuer }), issuer })
        const p = await v.verify(req(`Bearer ${token}`))
        assert.deepEqual(p.scope, ROWS)
    })

    it('is null when the user has none', async () => {
        const token = await issueToken({ key, issuer, audience: issuer, subject: 'carol', capabilities: [] })
        const v = jwt({ verifyToken: createTokenVerifier({ key, issuer, audience: issuer }), issuer })
        assert.equal((await v.verify(req(`Bearer ${token}`))).scope, null)
    })

    it('cannot be widened by a client — the token is signed', async () => {
        const token = await issueToken({
            key, issuer, audience: issuer, subject: 'alice',
            capabilities: ['api:list'], scope: ROWS,
        })
        const [head, payload, sig] = token.split('.')
        const tampered = JSON.parse(Buffer.from(payload, 'base64url').toString())
        tampered.mks_scope = {}                      // "show me everything"
        const forged = [head, Buffer.from(JSON.stringify(tampered)).toString('base64url'), sig].join('.')
        const v = jwt({ verifyToken: createTokenVerifier({ key, issuer, audience: issuer }), issuer })
        assert.equal(await v.verify(req(`Bearer ${forged}`)), false)
    })
})
