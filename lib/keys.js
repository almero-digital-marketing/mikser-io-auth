import { readFile, writeFile, chmod, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { generateKeyPair, exportJWK, importJWK, calculateJwkThumbprint } from 'jose'

// The signing key lives in a file in the working folder, alongside the
// identity it signs for (ADR-0012). ES256 — the most broadly interoperable
// asymmetric alg for OAuth clients, and small enough that the key file
// stays readable.
//
// A key file rather than a generated-on-boot key because tokens have to
// survive a restart: regenerating on boot silently invalidates every token
// the moment the process cycles, which looks exactly like an intermittent
// auth bug and is miserable to diagnose.
export const ALG = 'ES256'

export async function loadOrCreateKey({ keyFile, logger }) {
    let stored
    try {
        stored = JSON.parse(await readFile(keyFile, 'utf8'))
    } catch (err) {
        if (err.code !== 'ENOENT') {
            throw new Error(`auth: key file ${keyFile} is unreadable or not JSON — ${err.message}`)
        }
    }

    if (stored) {
        const privateKey = await importJWK(stored.privateJwk, ALG)
        const publicKey  = await importJWK(stored.publicJwk, ALG)
        return { privateKey, publicKey, publicJwk: stored.publicJwk, kid: stored.kid }
    }

    const { publicKey, privateKey } = await generateKeyPair(ALG, { extractable: true })
    const privateJwk = await exportJWK(privateKey)
    const publicJwk  = await exportJWK(publicKey)
    const kid = await calculateJwkThumbprint(publicJwk)
    publicJwk.kid = kid
    publicJwk.alg = ALG
    publicJwk.use = 'sig'

    await mkdir(path.dirname(keyFile), { recursive: true })
    await writeFile(keyFile, JSON.stringify({ kid, alg: ALG, privateJwk, publicJwk }, null, 2), { mode: 0o600 })
    // writeFile's mode is only applied on create; be explicit for the case
    // where an empty file already existed with looser permissions.
    await chmod(keyFile, 0o600).catch(() => {})

    logger?.warn?.(
        'auth: generated a new signing key at %s (kid=%s). Back it up and keep it out of version control — ' +
        'losing it invalidates every issued token; leaking it lets anyone mint one.',
        keyFile, kid)

    return { privateKey, publicKey, publicJwk, kid }
}

// The JWKS document an OAuth client fetches to verify our tokens. Public
// half only — if a private component ever appears here, that is the whole
// system compromised, so it is asserted rather than trusted.
export function jwks({ publicJwk }) {
    for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
        if (secret in publicJwk) {
            throw new Error(`auth: refusing to publish a JWKS containing the private component "${secret}"`)
        }
    }
    return { keys: [publicJwk] }
}
