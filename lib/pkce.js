import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

// PKCE (RFC 7636), S256 only. `plain` exists in the spec for clients that
// cannot compute SHA-256, which describes nothing that will ever talk to a
// mikser build server — and accepting it would let anyone who captured the
// authorization request replay the code without ever holding the verifier.

const base64url = (buf) => buf.toString('base64url')

export function challengeFromVerifier(verifier) {
    return base64url(createHash('sha256').update(verifier).digest())
}

export function verifyPkce(verifier, challenge) {
    if (!verifier || !challenge) return false
    const a = Buffer.from(challengeFromVerifier(verifier), 'utf8')
    const b = Buffer.from(challenge, 'utf8')
    return a.length === b.length && timingSafeEqual(a, b)
}

// Opaque, unguessable, and URL-safe: authorization codes and refresh tokens
// are bearer strings, so entropy is the only thing protecting them.
export const opaqueToken = () => base64url(randomBytes(32))
