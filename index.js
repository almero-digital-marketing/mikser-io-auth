import path from 'node:path'
import { registerRoute, anyOf } from 'mikser-io'

import { createIdentityStore, parseHtpasswd, parseHtgroup, verifyPassword } from './lib/htpasswd.js'
import { loadOrCreateKey, jwks, ALG } from './lib/keys.js'
import { issueToken, createTokenVerifier } from './lib/tokens.js'
import { basic, jwt } from './lib/verifiers.js'
import { redirectUriAllowed, validateRedirectUri, registerDynamicClient } from './lib/clients.js'
import { challengeFromVerifier, verifyPkce, opaqueToken } from './lib/pkce.js'
import { loginPage } from './lib/login-page.js'
import { mountRoutes, metadataHandler } from './lib/routes.js'
import * as grants from './lib/grants.js'

export { parseHtpasswd, parseHtgroup, verifyPassword, createIdentityStore }
export { loadOrCreateKey, jwks, ALG }
export { issueToken, createTokenVerifier }
export { redirectUriAllowed, validateRedirectUri, registerDynamicClient }
export { challengeFromVerifier, verifyPkce, opaqueToken }
export { loginPage }
export { grants }

/**
 * Authentication for mikser (ADR-0012).
 *
 * Returns a value that is BOTH the lifecycle plugin and the factory for the
 * verifiers other plugins gate on — because config is evaluated before the
 * runtime exists, and a verifier has to be nameable at config time while its
 * store can only be opened once the working folder is known:
 *
 *     const identity = auth({
 *         capabilities: { editors: ['api:update', 'mcp:use'] },
 *         issuer: 'https://cms.example.com',
 *     })
 *
 *     export default async () => ({
 *         plugins: [
 *             identity,
 *             api({ endpoints: { admin: { auth: identity.basic() } } }),
 *             mcp({ endpoints: { remote: { auth: identity.jwt() } } }),
 *         ],
 *     })
 *
 * Verifiers are created eagerly and resolve their store lazily, so the order
 * of `plugins:` doesn't matter and a config-time typo still surfaces at boot.
 */
export function auth(options = {}) {
    const {
        users        = 'users.htpasswd',
        groups       = 'groups.htgroup',
        key          = 'auth.key',
        capabilities = {},
        scopes       = {},
        issuer,
        audience     = issuer,
        base         = '/auth',
        ttl          = '1h',
        realm        = 'mikser',
        dcr          = {},
        pruneClientsAfterDays = 30,
        logo,
    } = options

    // Filled in at onLoad, read by the verifiers at request time.
    let state = null
    const ready = () => {
        if (!state) {
            throw new Error(
                'mikser-io-auth: a verifier was used before the auth plugin loaded. ' +
                'Add the value returned by auth() to your `plugins:` array.'
            )
        }
        return state
    }

    // A lazy façade over the store, so basic() can be constructed at config
    // time and still read files that only exist once mikser has a working folder.
    const lazyStore = {
        authenticate:    (u, p) => ready().store.authenticate(u, p),
        groupsOf:        (u)    => ready().store.groupsOf(u),
        capabilitiesOf:  (u)    => ready().store.capabilitiesOf(u),
        reload:          ()     => ready().store.reload(),
    }

    // Captured on first invocation so the surfaces defined below — which are
    // built at config time, before any hook runs — can reach the engine.
    let engine = null

    const plugin = ({ runtime, onLoad, onLoaded, useLogger }) => {
        engine = runtime
        // Published here rather than after the factory, because `runtime` is
        // only in scope once the plugin has been invoked. mikser-io-webdav
        // mints through this without importing this package.
        runtime.options.auth = {
            mint:         (...args) => plugin.mint(...args),
            revokeMinted: (jti) => plugin.revokeMinted(jti),
            listMinted:   (subject) => plugin.listMinted(subject),
        }
        onLoad(async () => {
            const logger = useLogger()
            const workingFolder = runtime.options.workingFolder
            const resolve = (f) => (path.isAbsolute(f) ? f : path.join(workingFolder, f))

            const store = createIdentityStore({
                usersFile:  resolve(users),
                groupsFile: resolve(groups),
                groups:     capabilities,
                scopes,
                logger,
            })
            const signingKey = await loadOrCreateKey({ keyFile: resolve(key), logger })

            state = {
                store,
                key: signingKey,
                verifyToken: createTokenVerifier({
                    key: signingKey,
                    issuer:   issuer ?? runtime.options.url,
                    audience: audience ?? runtime.options.url,
                    // Minted tokens are revokable; session tokens carry no jti
                    // and never reach this, so it costs a lookup only for the
                    // credentials that need one.
                    mintedTokenUsable: grants.mintedTokenUsable,
                }),
                logger,
            }
        })

        onLoaded(async () => {
            const app = runtime.options.app
            if (!app) return   // no server this run — verifiers still work in-process

            const logger = useLogger()
            // Express comes from the host, not from our own node_modules —
            // same instance as runtime.options.app, same pattern as the
            // forms plugin uses.
            const { default: express } = await import('express').catch(() => {
                throw new Error('mikser-io-auth: express is required — npm install express')
            })
            const router = express.Router()
            router.use(express.urlencoded({ extended: false, limit: '8kb' }))
            router.use(express.json({ limit: '8kb' }))

            // The deployment's identity, and it must be the SAME string the
            // verifier was built with — a token minted for one issuer and
            // checked against another fails verification, which from the
            // outside is indistinguishable from an expired token. The
            // verifier is pinned to `issuer ?? runtime.options.url` at load,
            // so this resolves in that order too and only falls back to the
            // request when neither is configured (a dev box with no --url).
            //
            // RFC 8414 §2 wants a stable issuer besides: clients cache the
            // metadata document keyed by it, so deriving it per-request makes
            // one deployment look like several.
            const originOf = (req) =>
                issuer ?? runtime.options.url ?? `${req.protocol}://${req.get('host')}`

            // What the sign-in page calls this deployment. Not a config
            // option: mikser already knows its external URL, and failing
            // that, the host in the address bar is the most honest name
            // there is — it IS the thing you connected to, so it cannot
            // name a different deployment than the one in front of you.
            const nameOf = (req) => {
                try {
                    if (runtime.options.url) return new URL(runtime.options.url).host
                } catch { /* not a URL — fall through */ }
                return req.get('host')
            }

            mountRoutes(router, {
                base,
                nameOf,
                logoUrl:  logo ?? `${base}/logo.svg`,
                realm,
                ttl,
                ready,
                issuerFor:   originOf,
                audienceFor: (req) => audience ?? originOf(req),
                dcr,
                scopes: [...new Set(Object.values(capabilities).flat())],
                logger,
            })

            app.use(base, router)

            // RFC 8414 §3.1: an issuer with no path component publishes its
            // metadata at <origin>/.well-known/oauth-authorization-server.
            // `issuerFor` is the origin, so that is where a conforming client
            // looks — including every MCP client, which is sent here by the
            // resource's RFC 9728 document naming this issuer. Mounted under
            // `base` alone, the document exists but at an address nothing
            // following the spec will ask for, and dynamic client
            // registration fails with the metadata sitting right there.
            //
            // The copy under `base` stays: clients that append to the issuer
            // rather than insert the well-known segment find it there.
            if (base && base !== '/') {
                app.get('/.well-known/oauth-authorization-server',
                    metadataHandler({ base, issuerFor: originOf,
                        scopes: [...new Set(Object.values(capabilities).flat())] }))
            }

            // Codes are 60s and refresh tokens 30d; without a sweep the rows
            // accumulate for the life of the database. Once at boot is enough
            // for a build tool — the checks that matter (expiry, single use)
            // are enforced on read, not by the sweep.
            try {
                const swept = grants.sweepExpired()
                if (swept.codes || swept.refresh) {
                    logger?.debug?.('auth: swept %d expired code(s), %d refresh token(s)',
                        swept.codes, swept.refresh)
                }
                // Every registration mints a NEW client_id — there is no
                // "get or create" in RFC 7591 — so a reinstall or a second
                // machine leaves another row behind. Only ones nobody ever
                // signed in with are dropped; a config-declared client is
                // never touched, because it lives in config, not this table.
                if (pruneClientsAfterDays) {
                    const pruned = grants.pruneUnusedClients({
                        olderThanMs: pruneClientsAfterDays * 24 * 60 * 60 * 1000,
                    })
                    if (pruned) logger?.info?.('auth: pruned %d unused client registration(s)', pruned)
                }
            } catch (err) {
                logger?.debug?.('auth: could not sweep expired grants — %s', err.message)
            }

            registerRoute({
                path:         base,
                plugin:       'auth',
                reachability: 'public',
                streaming:    false,
                label:        'Auth',
                detail:       `(authorize, token, register, jwks; alg=${ALG})`,
                authLabel:    'public',
            })
            logger?.info?.('Auth mounted at %s (users=%s, groups=%s)', base, users, groups)
        })
    }

    // Verifier factories. Both close over the lazy store/state, so they can
    // be handed to another plugin's `auth:` option at config time.
    plugin.basic = (opts = {}) => basic({ store: lazyStore, realm, ...opts })

    plugin.jwt = (opts = {}) => jwt({
        verifyToken: (token) => ready().verifyToken(token),
        issuer,
        scopes: [...new Set(Object.values(capabilities).flat())],
        ...opts,
    })

    plugin.store = lazyStore

    // Mint a token narrower than the caller's own, for one job.
    //
    // Everything about this is deliberately small. The scopes are whatever the
    // caller asks for INTERSECTED with what they already hold — this can never
    // widen anyone's reach, only narrow it, which is the property that makes it
    // safe to expose to an agent at all. It is short-lived, it is revokable by
    // jti, and it is not refreshable: expiry IS the revocation mechanism, so a
    // caller whose transfer outlives it mints another rather than renewing one
    // that has been sitting in a transcript.
    //
    // Returns `{ token, jti, scopes, expiresAt, ttl }`, or throws with the
    // missing scope named when the caller is asking for more than it holds.
    plugin.mint = async ({ subject, capabilities: held, request, ttlSec, purpose, audience: aud }) => {
        const { key } = ready()
        const wanted = [...new Set(request ?? [])]
        if (!wanted.length) throw new Error('mint: no scopes requested')
        // `capabilities: null` means "not capability-scoped" — a static token.
        // Such a caller cannot delegate what it cannot enumerate, so refuse
        // rather than mint something unbounded.
        if (!Array.isArray(held)) {
            throw new Error('mint: the caller holds no enumerable capabilities, so nothing can be delegated from them')
        }
        const missing = wanted.filter(scope => !held.includes(scope))
        if (missing.length) {
            const err = new Error(`mint refused: you do not hold ${missing.join(', ')}`)
            err.missing = missing
            throw err
        }
        const jti = opaqueToken()
        const token = await issueToken({
            key,
            issuer:   issuer ?? engine?.options?.url,
            audience: aud ?? audience ?? engine?.options?.url,
            subject,
            capabilities: wanted,
            ttl: `${ttlSec}s`,
            jti,
        })
        const { expiresAt } = grants.recordMintedToken({ jti, subject, purpose, scopes: wanted, ttlSec })
        // Every mint is logged: who, what for, how wide, how long. A
        // credential handed to a machine that no one can account for later is
        // the thing that makes short expiry necessary in the first place.
        engine?.engine?.logger?.info?.('auth: minted %ds token for %j — %s [%s]',
            ttlSec, subject, purpose ?? 'unspecified', wanted.join(' '))
        return { token, jti, scopes: wanted, ttl: ttlSec, expiresAt: new Date(expiresAt).toISOString() }
    }

    plugin.revokeMinted = (jti) => grants.revokeMintedToken(jti)
    plugin.listMinted   = (subject) => grants.listMintedTokens(subject)


    // The plugin IS a verifier, accepting either credential:
    //
    //     api({ endpoints: { admin: { auth: identity } } })
    //
    // rather than making every call site pick basic() or jwt() when the
    // honest answer is "whichever the caller has". A browser sends Basic, an
    // agent sends its Bearer, and the two never collide — each verifier
    // reports "not mine" for the other's scheme, so the composite reaches the
    // right one. Reach for .basic() or .jwt() only to deliberately EXCLUDE
    // one, which is rare.
    const composite = anyOf(plugin.basic(), plugin.jwt())
    plugin.verify    = (req) => composite.verify(req)
    // Both forwarded WITH their arguments. Dropping either is silent: the
    // endpoint still denies correctly, it just stops saying which denial it
    // was — so an expiry a refresh token would have fixed reads as a fresh
    // sign-in, which is the whole failure this vocabulary exists to prevent.
    // `auth: identity` is the documented shape, so a gap here bypasses the
    // signal in the configuration almost everyone uses.
    plugin.rejectionFor = (req) => composite.rejectionFor?.(req)
    plugin.challenge = (req, res, outcome) => composite.challenge(req, res, outcome)
    Object.defineProperties(plugin, {
        // A function's own `name` is non-writable, so plain assignment
        // throws in a module. defineProperty is the only way to give the
        // verifier the name that shows up in route logs.
        name:                 { value: 'auth', configurable: true },
        authorizationServers: { get: () => composite.authorizationServers },
        resource:             { get: () => composite.resource },
        scopesSupported:      { get: () => composite.scopesSupported },
    })

    return plugin
}

export default auth
