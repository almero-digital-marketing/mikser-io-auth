// OAuth clients are declared in config — not registered through an API.
//
// Dynamic Client Registration is convenient for a multi-tenant SaaS and is a
// real attack surface for a self-hosted single-tenant build server. Public
// clients only, PKCE required, no client_secret: an MCP client or a browser
// cannot keep a secret, and pretending otherwise buys nothing.
//
//   clients: {
//       'claude': {
//           name: 'Claude',
//           redirectUris: ['http://127.0.0.1/callback', 'https://claude.ai/api/mcp/auth_callback'],
//       },
//   }

export function resolveClients(declared = {}) {
    const clients = new Map()
    for (const [clientId, config] of Object.entries(declared)) {
        const redirectUris = config.redirectUris ?? config.redirect_uris ?? []
        if (!Array.isArray(redirectUris) || !redirectUris.length) {
            throw new Error(`auth: client ${JSON.stringify(clientId)} declares no redirectUris`)
        }
        clients.set(clientId, { clientId, name: config.name ?? clientId, redirectUris })
    }
    return clients
}

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
