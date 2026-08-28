import { SignJWT, jwtVerify, createLocalJWKSet } from 'jose'
import { ALG } from './keys.js'

// Access tokens are JWTs signed with the working folder's key.
//
// The load-bearing invariant, inherited from WhiteBox: `scope` is ALWAYS
// computed here from the identity files, never taken from whatever a client
// asked for at /authorize. Enforcement downstream is scope-only with no
// per-request re-read, which is safe precisely because a client cannot
// influence what goes in.
export async function issueToken({ key, issuer, audience, subject, capabilities = [], scope = null, ttl = '1h', jti = null }) {
    // `scope` is already taken: in OAuth it is the space-separated capability
    // list, and a client library will parse it as one. The row filter travels
    // as a private claim so the two never collide. It is signed, so a client
    // cannot widen its own reach by editing it.
    const signer = new SignJWT({
        scope: capabilities.join(' '),
        ...(scope ? { mks_scope: scope } : {}),
    })
        .setProtectedHeader({ alg: ALG, kid: key.kid })
        .setIssuedAt()
        .setIssuer(issuer)
        .setAudience(audience)
        .setSubject(subject)
        .setExpirationTime(ttl)
    // A jti makes the token REVOKABLE. A session token has none and is
    // unrevokable before expiry, which is fine for an hour a human owns; a
    // token minted for a machine and returned in output that gets logged needs
    // to be killable before its clock runs out.
    if (jti) signer.setJti(jti)
    return signer.sign(key.privateKey)
}

// Verify a token minted by this server. `audience` is checked because a
// token issued for one endpoint must not be replayable against another.
export function createTokenVerifier({ key, issuer, audience, mintedTokenUsable }) {
    const keySet = createLocalJWKSet({ keys: [key.publicJwk] })
    return async function verifyToken(token) {
        const { payload } = await jwtVerify(token, keySet, {
            issuer,
            audience,
            algorithms: [ALG],
        })
        // A token carrying a jti was minted for one narrow job and is only
        // usable while the server still says so. FAIL CLOSED: no checker
        // wired, or no row, means not usable — losing the record must revoke,
        // never un-revoke.
        if (payload.jti) {
            if (typeof mintedTokenUsable !== 'function' || !mintedTokenUsable(payload.jti)) {
                const err = new Error('This token has been revoked or is no longer on record')
                err.code = 'ERR_JWT_REVOKED'
                throw err
            }
        }
        return {
            subject:      payload.sub,
            capabilities: payload.scope ? payload.scope.split(' ') : [],
            scope:        payload.mks_scope ?? null,
            claims:       payload,
        }
    }
}
