// The two verifiers, both implementing the ADR-0012 contract:
//
//   { name, verify(req) → null | false | { subject, capabilities }, challenge? }
//
// null  = no credential presented  (loopback may still apply)
// false = presented and rejected   (never falls back to anything)

// Build a Bearer challenge, appending the RFC 6750 §3.1 error parameters
// when the request actually presented something.
//
// Omission is meaningful and is why `outcome` is consulted rather than
// always writing an error: a challenge to a request that carried NO
// credential must not claim the token was invalid — that is how a client
// distinguishes "sign in" from "your token went stale".
export function challengeHeader({ params = {}, outcome } = {}) {
    const parts = Object.entries(params).map(([k, v]) => `${k}="${v}"`)
    if (outcome?.code) {
        parts.push(`error="${outcome.code}"`)
        if (outcome.description) parts.push(`error_description="${outcome.description}"`)
        if (outcome.scope) parts.push(`scope="${outcome.scope}"`)
    }
    return parts.length ? `Bearer, ${parts.join(', ')}` : 'Bearer'
}

// HTTP Basic against the htpasswd file. Browser-native, no flow, no tokens —
// the right tool for the api/forms/decap surfaces, where the caller is a
// person with a browser or a script with curl. Not for MCP: an MCP client
// expects Bearer and a discovery document.
export function basic({ store, realm = 'mikser', logger } = {}) {
    if (!store) throw new Error('basic({ store }) requires an identity store')

    return {
        name: 'basic',

        async verify(req) {
            const header = req.headers?.authorization ?? req.get?.('authorization')
            if (!header) return null

            const [scheme, encoded] = header.split(' ')
            // A Bearer on a Basic-only endpoint is a presented credential we
            // cannot accept — false, not null. Treating it as "nothing
            // presented" would let it fall through to a loopback bypass.
            if (!/^basic$/i.test(scheme ?? '') || !encoded) return false

            let decoded
            try {
                decoded = Buffer.from(encoded, 'base64').toString('utf8')
            } catch {
                return false
            }

            const i = decoded.indexOf(':')
            if (i < 0) return false
            const username = decoded.slice(0, i)
            const password = decoded.slice(i + 1)

            const principal = await store.authenticate(username, password)
            if (!principal) {
                logger?.debug?.('auth: basic rejected for %j', username)
                return false
            }
            return principal
        },

        challenge(req, res) {
            // charset="UTF-8" per RFC 7617 §2.1 — without it a browser may
            // send latin-1 for a non-ASCII password and the hash won't match.
            res.set('WWW-Authenticate', `Basic realm="${realm}", charset="UTF-8"`)
        },
    }
}

// Bearer JWT, for MCP and any other client that runs an OAuth flow. The
// discovery fields are what make an MCP client able to log in unattended:
// mikser-io-mcp reads them to publish RFC 9728 metadata and to point its
// 401 challenge at that document.
export function jwt({ verifyToken, issuer, audience, resource, scopes = [], requiredCapability, logger } = {}) {
    if (!verifyToken) throw new Error('jwt({ verifyToken }) requires a token verifier')

    // Why the last verify() on THIS request said no.
    //
    // The ADR-0012 contract is three-valued on purpose and `false` is all of
    // it — but "expired" and "you are not allowed" are opposite instructions
    // to a client, and only this function ever looked at the token. Kept on
    // the request rather than in the closure because a verifier instance is
    // shared across every concurrent request and a module-level slot would
    // hand one request's reason to another.
    const REASON = Symbol.for('mikser-io-auth.rejection')

    const reject = (req, rejection, detail) => {
        if (req) req[REASON] = rejection
        logger?.debug?.('auth: jwt rejected — %s%s', rejection.code, detail ? ` (${detail})` : '')
        return false
    }

    return {
        name: 'jwt',
        authorizationServers: [issuer],
        resource,
        scopesSupported: scopes,

        async verify(req) {
            const header = req.headers?.authorization ?? req.get?.('authorization')
            if (!header) return null
            if (req) delete req[REASON]

            const match = /^Bearer\s+(.+)$/i.exec(header)
            if (!match) {
                return reject(req, { status: 401, code: 'invalid_token',
                                     description: 'Authorization header is not a Bearer token' })
            }

            let principal
            try {
                principal = await verifyToken(match[1])
            } catch (err) {
                // An expired or malformed token is a rejection, not an error:
                // failing loudly here would turn a routine token expiry into
                // a 500 and mask it from the client's refresh logic.
                //
                // jose throws ERR_JWT_EXPIRED for the one case a client can
                // fix by itself, so it is named. Everything else is a token
                // this server will never accept, and saying "expired" there
                // would send a client to burn its refresh token for nothing.
                const expired = err.code === 'ERR_JWT_EXPIRED'
                return reject(req, {
                    status: 401,
                    code: 'invalid_token',
                    description: expired
                        ? 'The access token expired'
                        : 'The access token is not valid',
                    expired,
                }, err.code ?? err.message)
            }

            if (requiredCapability && !principal.capabilities.includes(requiredCapability)) {
                // 403, not 401: the token is perfectly good and a fresh one
                // for the same subject would be refused identically. A client
                // that reads this as an expiry refreshes in a loop.
                return reject(req, {
                    status: 403,
                    code: 'insufficient_scope',
                    description: `This token does not carry ${requiredCapability}`,
                    scope: requiredCapability,
                }, `${principal.subject} lacks ${requiredCapability}`)
            }
            return principal
        },

        rejectionFor(req) {
            return req?.[REASON]
        },

        // Only used when a surface has no better idea; mikser-io-mcp
        // overrides this with a resource_metadata pointer of its own.
        //
        // `error` is the field a client's refresh logic reads (RFC 6750
        // §3.1). Without it every denial looks the same from outside, and an
        // expiry that a refresh token would have fixed silently becomes a
        // fresh authorization flow — a human, a browser, mid-task.
        challenge(req, res, outcome) {
            res.set('WWW-Authenticate', challengeHeader({
                params: issuer ? { authorization_uri: issuer } : {},
                outcome,
            }))
        },
    }
}
