import { randomUUID } from 'node:crypto'

// Clients register themselves (RFC 7591). There is no operator-maintained
// list, and no way to declare one.
//
// The alternative was a `clients:` config map, which sounds harmless and
// isn't: it makes the set of agents that can connect equal to the set
// somebody thought to write down, so every new agent is a config change and
// a deploy. Worse, an agent whose UI takes a URL and nothing else has no
// field to type a client_id into — it registers or it cannot connect at all.
// A server whose whole purpose is that agents connect to it should not ship
// a default where they can't.
//
// Public clients only: PKCE is required and there is no client_secret,
// because a browser or a native agent cannot keep one.

const MAX_REDIRECT_URIS = 10
const MAX_CLIENT_NAME   = 80

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', '[::1]', 'localhost'])

const isLoopbackUrl = (url) =>
    url.hostname === '127.0.0.1' || url.hostname === '[::1]' || url.hostname === '::1' ||
    url.hostname === 'localhost'

// Exact match, with ONE exception: RFC 8252 §7.3 requires an authorization
// server to ignore the port of a loopback redirect, because a native client
// binds an ephemeral port it cannot know in advance. Every MCP client that
// opens a browser depends on this. Everything else about the URI — scheme,
// host, path, query, fragment — must still match exactly.
export function redirectUriAllowed(client, redirectUri) {
    if (!redirectUri) return false
    if (client.redirectUris.includes(redirectUri)) return true

    let asked
    try { asked = new URL(redirectUri) } catch { return false }
    if (!isLoopbackUrl(asked)) return false

    return client.redirectUris.some(registered => {
        let reg
        try { reg = new URL(registered) } catch { return false }
        return isLoopbackUrl(reg)
            && reg.protocol === asked.protocol
            && reg.hostname === asked.hostname
            && reg.pathname === asked.pathname
            && reg.search   === asked.search
            && reg.hash     === asked.hash
    })
}

// Throws with an RFC 7591 error code, which the route maps onto the body.
export class RegistrationError extends Error {
    constructor(code, description) {
        super(description)
        this.code = code
    }
}

// What a self-registering client may ask to be redirected to. Stricter than
// what an operator may write in config, because nobody reviewed this one.
export function validateRedirectUri(value) {
    if (typeof value !== 'string' || !value) return 'must be a string'
    let url
    try { url = new URL(value) } catch { return 'is not an absolute URI' }
    if (url.hash) return 'must not contain a fragment'
    if (url.protocol === 'https:') return null
    if (url.protocol === 'http:') {
        return LOOPBACK_HOSTS.has(url.hostname) ? null : 'must use https, except on loopback'
    }
    return `scheme ${url.protocol} is not allowed — use https, or http on loopback`
}

// Register a client that named itself.
//
// Unauthenticated by necessity: you need a client_id BEFORE you can
// authenticate, so requiring a token here would make the endpoint useless to
// the only callers that need it. That is safe because a registered client can
// do NOTHING on its own — it holds no tokens and represents no person, and
// cannot act until someone signs in on the page, where what they can do comes
// from their groups rather than from anything the client asked for.
//
// What is at risk is table volume, not access. `maxClients` bounds it in the
// durable place — a rate limiter lives in process memory and does not survive
// a restart, while rows do.
export async function registerDynamicClient({ name, redirectUris, maxClients, store }) {
    if (!Array.isArray(redirectUris) || !redirectUris.length) {
        throw new RegistrationError('invalid_redirect_uri', 'redirect_uris must be a non-empty array')
    }
    if (redirectUris.length > MAX_REDIRECT_URIS) {
        throw new RegistrationError('invalid_redirect_uri', `at most ${MAX_REDIRECT_URIS} redirect_uris`)
    }
    for (const uri of redirectUris) {
        const problem = validateRedirectUri(uri)
        if (problem) {
            throw new RegistrationError('invalid_redirect_uri', `redirect_uri ${JSON.stringify(uri)} ${problem}`)
        }
    }

    if (maxClients != null && await store.countDynamicClients() >= maxClients) {
        throw new RegistrationError('invalid_client_metadata',
            'this server is not accepting new client registrations right now')
    }

    // The name is client-supplied and ends up on the sign-in page, so it is
    // length-capped here and HTML-escaped at render. A client that sends no
    // name gets a neutral one rather than a blank line where the agent's
    // identity should be — which would make the page's whole point moot.
    const clientName = (typeof name === 'string' && name.trim())
        ? name.trim().slice(0, MAX_CLIENT_NAME)
        : 'Unnamed client'

    return store.insertDynamicClient({
        clientId: randomUUID(),
        name: clientName,
        redirectUris,
    })
}
