// The jwt verifier comparing a token's stamp against the current identity.
//
// This is where the revocation actually bites. The store knowing that alice
// changed is worth nothing if the gate still accepts her old token.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { jwt } from '../lib/verifiers.js'
import { issueToken, createTokenVerifier } from '../lib/tokens.js'
import { loadOrCreateKey } from '../lib/keys.js'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const ISSUER = 'https://mikser.test'
const REASON = Symbol.for('mikser-io-auth.rejection')

async function gate({ stamp, currentStamp }) {
    const dir = await mkdtemp(path.join(tmpdir(), 'auth-gate-'))
    const key = await loadOrCreateKey({ keyFile: path.join(dir, 'auth.key') })
    const token = await issueToken({
        key, issuer: ISSUER, audience: ISSUER, subject: 'alice',
        capabilities: ['drive:styles:write'], roles: ['editors'], stamp,
    })
    const verifier = jwt({
        verifyToken: createTokenVerifier({ key, issuer: ISSUER, audience: ISSUER }),
        issuer: ISSUER, currentStamp,
    })
    const req = { headers: { authorization: `Bearer ${token}` } }
    const principal = await verifier.verify(req)
    await rm(dir, { recursive: true, force: true })
    return { principal, rejection: req[REASON] }
}

describe('a token whose identity still matches', () => {
    it('is accepted, with its capabilities', async () => {
        const { principal } = await gate({ stamp: 'abc', currentStamp: async () => 'abc' })
        assert.equal(principal.subject, 'alice')
        assert.deepEqual(principal.capabilities, ['drive:styles:write'])
    })
})

describe('a token whose identity has changed', () => {
    it('is refused, and told to authenticate again', async () => {
        // 401 rather than 403: re-authenticating is the correct response and
        // will mint a token with whatever the user now holds. 403 would tell
        // the client to give up on a subject that has merely moved group.
        const { principal, rejection } = await gate({ stamp: 'abc', currentStamp: async () => 'xyz' })
        assert.equal(principal, false)
        assert.equal(rejection.status, 401)
        assert.match(rejection.description, /changed/)
    })

    it('says plainly when the account is gone', async () => {
        // A deleted user and a regrouped one are different situations for
        // whoever reads the log.
        const { principal, rejection } = await gate({ stamp: 'abc', currentStamp: async () => null })
        assert.equal(principal, false)
        assert.match(rejection.description, /no longer exists/)
    })

    it('refuses rather than failing open when the store cannot answer', async () => {
        // A store that throws must not become an accept. This is the
        // direction the failure has to fall.
        const { principal, rejection } = await gate({
            stamp: 'abc',
            currentStamp: async () => { throw new Error('files unreadable') },
        })
        assert.equal(principal, false)
        assert.equal(rejection.status, 401)
    })
})

describe('tokens minted before stamps existed', () => {
    it('still work, so an upgrade does not log everyone out', async () => {
        // Deploying this must not invalidate every live session at once. A
        // token with no stamp claim is checked exactly as it was before, and
        // ages out normally.
        const { principal } = await gate({ stamp: null, currentStamp: async () => 'xyz' })
        assert.equal(principal.subject, 'alice')
    })

    it('and a deployment with no store to ask is unchanged too', async () => {
        const { principal } = await gate({ stamp: 'abc', currentStamp: undefined })
        assert.equal(principal.subject, 'alice')
    })
})
