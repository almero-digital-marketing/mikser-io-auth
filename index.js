import path from 'node:path'
import { registerRoute } from 'mikser-io'

import { createIdentityStore, parseHtpasswd, parseHtgroup, verifyPassword } from './lib/htpasswd.js'
import { loadOrCreateKey, jwks, ALG } from './lib/keys.js'
import { issueToken, createTokenVerifier } from './lib/tokens.js'
import { basic, jwt } from './lib/verifiers.js'
import { resolveClients, redirectUriAllowed } from './lib/clients.js'
import { challengeFromVerifier, verifyPkce, opaqueToken } from './lib/pkce.js'
import { loginPage } from './lib/login-page.js'
import { mountRoutes } from './lib/routes.js'
import * as grants from './lib/grants.js'

export { parseHtpasswd, parseHtgroup, verifyPassword, createIdentityStore }
export { loadOrCreateKey, jwks, ALG }
export { issueToken, createTokenVerifier }
export { resolveClients, redirectUriAllowed }
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
        clients      = {},
        appName,
        logo,
    } = options

    // Fail at config time, not at the first sign-in attempt.
    const registeredClients = resolveClients(clients)

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

    const plugin = ({ runtime, onLoad, onLoaded, useLogger }) => {
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

            const originOf = (req) => issuer ?? `${req.protocol}://${req.get('host')}`

            mountRoutes(router, {
                base,
                clients:  registeredClients,
                appName:  appName ?? runtime.config?.name,
                logoUrl:  logo ?? `${base}/logo.svg`,
                realm,
                ttl,
                ready,
                issuerFor:   originOf,
                audienceFor: (req) => audience ?? originOf(req),
                logger,
            })

            app.use(base, router)

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
            } catch (err) {
                logger?.debug?.('auth: could not sweep expired grants — %s', err.message)
            }

            registerRoute({
                path:         base,
                plugin:       'auth',
                reachability: 'public',
                streaming:    false,
                label:        'Auth',
                detail:       `(authorize, token, jwks; alg=${ALG}, clients=${registeredClients.size})`,
                authLabel:    'public',
            })
            logger?.info?.('Auth mounted at %s (users=%s, groups=%s, clients=%d)',
                base, users, groups, registeredClients.size)
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

    return plugin
}

export default auth
