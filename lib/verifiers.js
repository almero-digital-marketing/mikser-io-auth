// The two verifiers, both implementing the ADR-0012 contract:
//
//   { name, verify(req) → null | false | { subject, capabilities }, challenge? }
//
// null  = no credential presented  (loopback may still apply)
// false = presented and rejected   (never falls back to anything)

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

    return {
        name: 'jwt',
        authorizationServers: [issuer],
        resource,
        scopesSupported: scopes,

        async verify(req) {
            const header = req.headers?.authorization ?? req.get?.('authorization')
            if (!header) return null

            const match = /^Bearer\s+(.+)$/i.exec(header)
            if (!match) return false

            let principal
            try {
                principal = await verifyToken(match[1])
            } catch (err) {
                // An expired or malformed token is a rejection, not an error:
                // failing loudly here would turn a routine token expiry into
                // a 500 and mask it from the client's refresh logic.
                logger?.debug?.('auth: jwt rejected — %s', err.code ?? err.message)
                return false
            }

            if (requiredCapability && !principal.capabilities.includes(requiredCapability)) {
                logger?.debug?.('auth: %j lacks %j', principal.subject, requiredCapability)
                return false
            }
            return principal
        },

        // Only used when a surface has no better idea; mikser-io-mcp
        // overrides this with a resource_metadata pointer of its own.
        challenge(req, res) {
            res.set('WWW-Authenticate', `Bearer${issuer ? `, authorization_uri="${issuer}"` : ''}`)
        },
    }
}
