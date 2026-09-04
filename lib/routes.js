import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { jwks, ALG } from './keys.js'
import { issueToken } from './tokens.js'
import { verifyPkce } from './pkce.js'
import { redirectUriAllowed, registerDynamicClient, RegistrationError } from './clients.js'
import { loginPage } from './login-page.js'
import * as grants from './grants.js'

const CODE_TTL_SEC    = 60
const REFRESH_TTL_SEC = 30 * 24 * 60 * 60

// RFC 6749 §3.3 / OIDC's name for "this client may hold a refresh token and use
// it without the user present". It is not one of this deployment's capabilities
// — it grants no access to anything — but it is the only standard way to TELL a
// client that unattended renewal is available to it.
const OFFLINE_ACCESS = 'offline_access'

// The subset of an authorization request threaded through the login form's
// hidden fields, untouched.
function authParams(src) {
    const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, scope, state } = src
    return { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, scope, state }
}

// The authorization server metadata document.
//
// Exported because WHERE it is served is part of the contract, and one mount
// cannot satisfy it. `issuerFor` returns the origin, and RFC 8414 §3.1 says
// an issuer with no path component publishes at
// <origin>/.well-known/oauth-authorization-server. This router is mounted
// under `base`, so its own copy answers one level down — where a client that
// appends to the issuer looks, and nowhere a client following RFC 8414 does.
// index.js mounts this at the root as well; both paths return this document.
export function metadataHandler({ base, issuerFor, scopes = [] }) {
    return (req, res) => {
        const issuer = issuerFor(req)
        res.json({
            issuer,
            // RECOMMENDED by RFC 8414 §2 and load-bearing here: without it a
            // client cannot discover that offline_access is available, so it
            // never asks, so it never learns it may renew unattended — while a
            // refresh token sits unused in every token response.
            scopes_supported: [...new Set([...scopes, OFFLINE_ACCESS])],
            authorization_endpoint:                `${issuer}${base}/authorize`,
            token_endpoint:                        `${issuer}${base}/token`,
            jwks_uri:                              `${issuer}${base}/jwks.json`,
            response_types_supported:              ['code'],
            grant_types_supported:                 ['authorization_code', 'refresh_token', 'password'],
            code_challenge_methods_supported:      ['S256'],
            token_endpoint_auth_methods_supported: ['none'],
            id_token_signing_alg_values_supported: [ALG],
            registration_endpoint:                 `${issuer}${base}/register`,
        })
    }
}

export function mountRoutes(router, ctx) {
    const { base, nameOf, ready, logoUrl, ttl, issuerFor, audienceFor, dcr, scopes = [], logger } = ctx

    const { windowMs = 60 * 60 * 1000, maxPerIp = 5, maxClients = 1000 } = dcr ?? {}

    // ── the mark ─────────────────────────────────────────────────────────
    const logoFile = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'assets', 'logo.svg')
    let logoCache = null
    router.get('/logo.svg', async (req, res) => {
        try {
            logoCache ??= await readFile(logoFile, 'utf8')
            res.type('image/svg+xml').set('Cache-Control', 'public, max-age=3600').send(logoCache)
        } catch {
            res.status(404).end()   // the page's onerror drops the <img>
        }
    })

    // ── discovery ────────────────────────────────────────────────────────
    router.get('/jwks.json', async (req, res) => {
        res.json(jwks({ publicJwk: ready().key.publicJwk }))
    })

    router.get('/.well-known/oauth-authorization-server', metadataHandler({ base, issuerFor, scopes }))

    // ── /authorize ───────────────────────────────────────────────────────
    //
    // Validate client_id and redirect_uri BEFORE anything else, and render an
    // error directly rather than redirecting. Redirecting to an unvalidated
    // URI is itself the vulnerability — an open redirect through the
    // authorization endpoint.
    async function resolveClient(params, res) {
        const client = params.client_id ? await grants.getDynamicClient(params.client_id) : null
        if (!client) { res.status(400).send('Unknown client_id'); return null }
        if (!redirectUriAllowed(client, params.redirect_uri)) {
            res.status(400).send('redirect_uri is not registered for this client')
            return null
        }
        return client
    }

    function redirectWithError(res, redirectUri, state, error, description) {
        const url = new URL(redirectUri)
        url.searchParams.set('error', error)
        if (description) url.searchParams.set('error_description', description)
        if (state != null) url.searchParams.set('state', state)
        res.redirect(302, url.toString())
    }

    function checkRequest(params, res) {
        if (params.response_type !== 'code') {
            redirectWithError(res, params.redirect_uri, params.state, 'unsupported_response_type')
            return false
        }
        if (params.code_challenge_method !== 'S256' || !params.code_challenge) {
            redirectWithError(res, params.redirect_uri, params.state, 'invalid_request', 'PKCE (S256) is required')
            return false
        }
        return true
    }

    router.get('/authorize', async (req, res) => {
        const params = authParams(req.query)
        const client = await resolveClient(params, res)
        if (!client) return
        if (!checkRequest(params, res)) return
        res.type('html').send(loginPage({ params, client, appName: nameOf(req), logoUrl }))
    })

    router.post('/authorize', async (req, res) => {
        const params = authParams(req.body)
        const client = await resolveClient(params, res)
        if (!client) return
        if (!checkRequest(params, res)) return

        const { store } = ready()
        const principal = await store.authenticate(req.body.username, req.body.password)
        if (!principal) {
            logger?.warn?.('auth: sign-in refused for %j (ip=%s)', req.body.username, req.ip)
            // Re-render rather than redirect. WhiteBox redirects an
            // access_denied back to the client so its own branded form can
            // show the message; mikser's form IS this page, and bouncing the
            // browser out to the client just to be sent back loses what the
            // person typed and reads like a crash.
            return res.status(401).type('html').send(loginPage({
                params, client, appName: nameOf(req), logoUrl,
                error: 'Incorrect username or password',
            }))
        }

        // params.scope is what the CLIENT asked for. It is recorded and never
        // trusted: the token's real scope is recomputed from the files at
        // issue time, so a forged request cannot mint itself more access.
        const code = await grants.createCode({
            clientId: client.clientId, subject: principal.subject,
            redirectUri: params.redirect_uri, codeChallenge: params.code_challenge,
            scope: params.scope, ttlSec: CODE_TTL_SEC,
        })
        // Marks the registration as live, so pruning can tell a client
        // somebody actually uses from one left behind by a reinstall.
        await grants.touchClient(client.clientId)
        logger?.info?.('auth: authorization granted to %j for %j', client.clientId, principal.subject)

        const url = new URL(params.redirect_uri)
        url.searchParams.set('code', code)
        if (params.state != null) url.searchParams.set('state', params.state)
        res.redirect(302, url.toString())
    })

    // ── /token ───────────────────────────────────────────────────────────
    //
    // The ONE place a token's capabilities and row scope are decided, always
    // recomputed from the identity files. Nothing a client sends can influence
    // what goes in here.
    //
    // The token also carries a STAMP of the identity it was minted from. A
    // gate still reads capabilities from the token — no per-request file read
    // — but it compares that stamp against the current one, so a user who has
    // since been deleted, moved group, or had their group narrowed stops being
    // accepted immediately rather than when the token ages out. Only the users
    // whose own identity changed are affected.
    async function issueTokens(res, { clientId, subject, withRefresh }) {
        const { store, key } = ready()
        const capabilities = await store.capabilitiesOf(subject)
        const scope        = await store.scopeOf(subject)
        const roles        = await store.groupsOf(subject)
        const stamp        = await store.stampOf(subject)
        const issuer       = issuerFor(res.req)

        const accessToken = await issueToken({
            key, issuer, audience: audienceFor(res.req),
            subject, capabilities, scope, roles, ttl, stamp,
        })

        const body = {
            access_token: accessToken,
            token_type:   'Bearer',
            expires_in:   typeof ttl === 'number' ? ttl : 3600,
            scope:        capabilities.join(' '),
        }
        if (withRefresh) {
            body.refresh_token = await grants.createRefreshToken({
                clientId, subject, ttlSec: REFRESH_TTL_SEC,
            })
            // Say that unattended renewal was granted, not just hand over the
            // means to do it. Per RFC 6749 §5.1 the response scope is what the
            // client was actually granted; returning the capability list alone
            // told a client that asked for offline_access that it had been
            // REFUSED, so a conforming one would not use the refresh token it
            // had just been given. Measured symptom: a fixed one-hour window
            // that never renewed, and a human re-authorizing by hand.
            body.scope = [...capabilities, OFFLINE_ACCESS].join(' ')
        }
        res.json(body)
    }

    async function authorizationCodeGrant(req, res) {
        const { code, redirect_uri: redirectUri, code_verifier: verifier, client_id: clientId } = req.body
        const row = code && await grants.getCode(code)
        if (!row) return res.status(400).json({ error: 'invalid_grant' })
        if (row.used_at || row.expires_at < Date.now()) {
            return res.status(400).json({ error: 'invalid_grant' })
        }
        // Both must match what /authorize was called with (RFC 6749 §4.1.3):
        // a code minted for one client or redirect cannot be redeemed against
        // another.
        if (row.client_id !== clientId || row.redirect_uri !== redirectUri) {
            return res.status(400).json({ error: 'invalid_grant' })
        }
        if (!verifyPkce(verifier, row.code_challenge)) {
            return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' })
        }
        // Single-use, decided by the UPDATE itself — two simultaneous
        // redemptions both pass every check above, and only one wins here.
        if (!await grants.redeemCode(code)) return res.status(400).json({ error: 'invalid_grant' })

        return issueTokens(res, { clientId: row.client_id, subject: row.subject, withRefresh: true })
    }

    async function refreshGrant(req, res) {
        const { refresh_token: token, client_id: clientId } = req.body
        const row = token && await grants.getRefreshToken(token)
        if (!row) return res.status(400).json({ error: 'invalid_grant' })
        if (row.revoked_at || row.expires_at < Date.now()) {
            return res.status(400).json({ error: 'invalid_grant' })
        }
        if (row.client_id !== clientId) return res.status(400).json({ error: 'invalid_grant' })

        // Revoke BEFORE minting the replacement: losing this race means
        // having created nothing, rather than leaving a valid token that
        // nobody holds.
        if (!await grants.revokeRefreshToken(token)) return res.status(400).json({ error: 'invalid_grant' })

        // Recomputed from the files, not carried over from the old token —
        // this is what makes an htgroup edit take effect on the next refresh
        // rather than only on the next full sign-in.
        return issueTokens(res, { clientId: row.client_id, subject: row.subject, withRefresh: true })
    }

    // Credentials straight to a token: for a script or a CLI, where there is
    // no browser to open and no callback to receive. No refresh token — a
    // caller that can replay the password does not need one.
    async function passwordGrant(req, res) {
        const { store } = ready()
        let username = req.body?.username
        let password = req.body?.password
        const header = req.get('authorization')
        if (!username && header?.startsWith('Basic ')) {
            const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8')
            const i = decoded.indexOf(':')
            if (i >= 0) { username = decoded.slice(0, i); password = decoded.slice(i + 1) }
        }
        if (!username || typeof password !== 'string') {
            return res.status(400).json({ error: 'invalid_request' })
        }
        const principal = await store.authenticate(username, password)
        if (!principal) {
            logger?.warn?.('auth: token request refused for %j (ip=%s)', username, req.ip)
            res.set('WWW-Authenticate', `Basic realm="${ctx.realm}", charset="UTF-8"`)
            return res.status(401).json({ error: 'invalid_grant' })
        }
        return issueTokens(res, { clientId: req.body?.client_id ?? 'password', subject: principal.subject, withRefresh: false })
    }

    router.post('/token', async (req, res) => {
        const grantType = req.body?.grant_type
        if (grantType === 'authorization_code') return authorizationCodeGrant(req, res)
        if (grantType === 'refresh_token')      return refreshGrant(req, res)
        if (grantType === 'password' || !grantType) return passwordGrant(req, res)
        return res.status(400).json({ error: 'unsupported_grant_type' })
    })

    // ── Dynamic Client Registration (RFC 7591) ───────────────────────────
    //
    // The only way a client exists. There is no operator-maintained list,
    // because a list makes the set of agents that can connect equal to the
    // set somebody wrote down — and an agent whose UI takes a URL and
    // nothing else has no field to type a client_id into anyway.
    {
        const recent = new Map()   // ip -> timestamps[]

        router.post('/register', async (req, res) => {
            const now = Date.now()
            const ip = req.ip || 'unknown'
            const hits = (recent.get(ip) || []).filter(t => now - t < windowMs)
            if (hits.length >= maxPerIp) {
                logger?.warn?.('auth: registration rate-limited (ip=%s)', ip)
                return res.status(429).json({
                    error: 'invalid_client_metadata',
                    error_description: 'too many registrations from this address — try again later',
                })
            }
            // Counts every REQUEST, not every success — a rejected attempt
            // still spends budget. Fail-closed for an unauthenticated
            // endpoint: otherwise an invalid payload repeats for free. The
            // cost is that a client with broken metadata locks itself out
            // until the window rolls, which is recoverable and logged.
            hits.push(now)
            recent.set(ip, hits)
            if (recent.size > 10_000) {
                for (const [k, v] of recent) if (!v.some(t => now - t < windowMs)) recent.delete(k)
            }

            try {
                const row = await registerDynamicClient({
                    name:         req.body?.client_name,
                    redirectUris: req.body?.redirect_uris,
                    maxClients,
                    store:        grants,
                })
                logger?.info?.('auth: client self-registered — %j (%s) from %s',
                    row.name, row.clientId, ip)
                // RFC 7591 §3.2.1: 201, echoing the metadata AS REGISTERED,
                // which may differ from what was sent (a missing name became
                // a placeholder) so a client can see what it actually got.
                res.status(201).json({
                    client_id:                  row.clientId,
                    client_id_issued_at:        Math.floor(row.createdAt / 1000),
                    client_name:                row.name,
                    redirect_uris:              row.redirectUris,
                    grant_types:                ['authorization_code', 'refresh_token'],
                    response_types:             ['code'],
                    // Stated in the response itself: every client here is
                    // public, and PKCE is what proves possession.
                    token_endpoint_auth_method: 'none',
                })
            } catch (err) {
                if (err instanceof RegistrationError) {
                    return res.status(400).json({ error: err.code, error_description: err.message })
                }
                logger?.error?.('auth: registration failed — %s', err.message)
                res.status(500).json({ error: 'invalid_client_metadata' })
            }
        })
    }
}
