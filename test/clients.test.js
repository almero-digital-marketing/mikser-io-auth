import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
    redirectUriAllowed, validateRedirectUri,
    registerDynamicClient, RegistrationError,
} from '../lib/clients.js'

describe('redirectUriAllowed', () => {
    const client = { redirectUris: ['http://127.0.0.1/callback', 'https://agent.example.com/cb'] }

    it('matches exactly', () => {
        assert.equal(redirectUriAllowed(client, 'https://agent.example.com/cb'), true)
        assert.equal(redirectUriAllowed(client, 'https://agent.example.com/other'), false)
    })

    it('ignores the port on loopback (RFC 8252 §7.3) — native agents bind an ephemeral one', () => {
        assert.equal(redirectUriAllowed(client, 'http://127.0.0.1:49821/callback'), true)
        assert.equal(redirectUriAllowed(client, 'http://127.0.0.1:1/callback'), true)
    })

    it('does not let the loopback exception loosen anything else', () => {
        assert.equal(redirectUriAllowed(client, 'http://127.0.0.1:49821/evil'), false, 'path must still match')
        assert.equal(redirectUriAllowed(client, 'https://127.0.0.1:49821/callback'), false, 'scheme must still match')
        assert.equal(redirectUriAllowed(client, 'http://evil.example.com:49821/callback'), false)
        assert.equal(redirectUriAllowed(client, 'https://agent.example.com:8443/cb'), false, 'non-loopback keeps its port')
    })

    it('refuses junk without throwing', () => {
        assert.equal(redirectUriAllowed(client, undefined), false)
        assert.equal(redirectUriAllowed(client, 'not-a-uri'), false)
    })
})

describe('validateRedirectUri', () => {
    it('allows https anywhere and http only on loopback', () => {
        assert.equal(validateRedirectUri('https://agent.example.com/cb'), null)
        assert.equal(validateRedirectUri('http://127.0.0.1:1234/cb'), null)
        assert.equal(validateRedirectUri('http://localhost/cb'), null)
        assert.match(validateRedirectUri('http://evil.example.com/cb'), /https, except on loopback/)
    })

    it('refuses a fragment and an unknown scheme', () => {
        assert.match(validateRedirectUri('https://a/cb#x'), /fragment/)
        assert.match(validateRedirectUri('ftp://a/cb'), /is not allowed/)
    })
})

describe('registerDynamicClient bounds', () => {
    const fakeStore = (count = 0) => ({
        countDynamicClients: () => count,
        insertDynamicClient: (c) => ({ ...c, createdAt: 1 }),
    })

    it('caps the number of redirect URIs', () => {
        const many = Array.from({ length: 11 }, (_, i) => `https://a/cb${i}`)
        assert.throws(() => registerDynamicClient({ redirectUris: many, store: fakeStore() }),
                      (e) => e instanceof RegistrationError && e.code === 'invalid_redirect_uri')
    })

    it('caps the name, because it renders on the sign-in page', () => {
        const out = registerDynamicClient({
            name: 'x'.repeat(500), redirectUris: ['https://a/cb'], store: fakeStore(),
        })
        assert.equal(out.name.length, 80)
    })

    it('refuses once the table is full — the durable bound, not the rate limiter', () => {
        // The per-IP limiter lives in process memory and does not survive a
        // restart; rows do. This is what actually bounds the table.
        assert.throws(
            () => registerDynamicClient({ redirectUris: ['https://a/cb'], maxClients: 10, store: fakeStore(10) }),
            (e) => e.code === 'invalid_client_metadata',
        )
    })

    it('mints a distinct client_id every time — RFC 7591 has no get-or-create', () => {
        const store = fakeStore()
        const a = registerDynamicClient({ redirectUris: ['https://a/cb'], store })
        const b = registerDynamicClient({ redirectUris: ['https://a/cb'], store })
        assert.notEqual(a.clientId, b.clientId)
    })
})
