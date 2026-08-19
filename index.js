import path from 'node:path'
import { registerRoute } from 'mikser-io'

import { createIdentityStore, parseHtpasswd, parseHtgroup, verifyPassword } from './lib/htpasswd.js'
import { loadOrCreateKey, jwks, ALG } from './lib/keys.js'
import { issueToken, createTokenVerifier } from './lib/tokens.js'
import { basic, jwt } from './lib/verifiers.js'

export { parseHtpasswd, parseHtgroup, verifyPassword, createIdentityStore }
export { loadOrCreateKey, jwks, ALG }
export { issueToken, createTokenVerifier }

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

            // JWKS — the public half of the working folder's key, so any
            // client (or a second mikser) can verify a token we minted.
            router.get('/jwks.json', (req, res) => {
                res.json(jwks({ publicJwk: ready().key.publicJwk }))
            })

            // RFC 8414 authorization-server metadata.
            router.get('/.well-known/oauth-authorization-server', (req, res) => {
                const origin = issuer ?? `${req.protocol}://${req.get('host')}`
                res.json({
                    issuer:                                 origin,
                    jwks_uri:                               `${origin}${base}/jwks.json`,
                    token_endpoint:                         `${origin}${base}/token`,
                    grant_types_supported:                  ['password'],
                    token_endpoint_auth_methods_supported:  ['client_secret_basic', 'none'],
                    response_types_supported:               [],
                    id_token_signing_alg_values_supported:  [ALG],
                })
            })

            // Exchange htpasswd credentials for a JWT.
            //
            // This is the credentials grant only — enough for a script, a
            // CLI, or an MCP client configured with a token out of band. The
            // browser-facing authorization-code + PKCE flow is deliberately
            // NOT here yet; see the README.
            router.post('/token', async (req, res) => {
                const { store, key, logger: log } = ready()

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
                    log?.warn?.('auth: token request refused for %j (ip=%s)', username, req.ip)
                    // RFC 6749 §5.2 — invalid_grant, and deliberately no hint
                    // about which half was wrong.
                    res.set('WWW-Authenticate', `Basic realm="${realm}", charset="UTF-8"`)
                    return res.status(401).json({ error: 'invalid_grant' })
                }

                const origin = issuer ?? `${req.protocol}://${req.get('host')}`
                const token = await issueToken({
                    key,
                    issuer:   origin,
                    audience: audience ?? origin,
                    subject:  principal.subject,
                    // Always from the files, never from the request — the
                    // invariant the whole scope-only enforcement rests on.
                    // The row filter rides along for the same reason: a
                    // caller must not be able to widen it.
                    capabilities: principal.capabilities,
                    scope:        principal.scope,
                    ttl,
                })

                res.json({
                    access_token: token,
                    token_type:   'Bearer',
                    expires_in:   typeof ttl === 'number' ? ttl : 3600,
                    scope:        principal.capabilities.join(' '),
                })
            })

            app.use(base, router)

            registerRoute({
                path:         base,
                plugin:       'auth',
                reachability: 'public',
                streaming:    false,
                label:        'Auth',
                detail:       `(token, jwks; alg=${ALG})`,
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

    return plugin
}

export default auth
