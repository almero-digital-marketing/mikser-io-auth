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
//
// Deliberately NOT added to .gitignore, unlike the engine's durable database.
// That file is rewritten on every write, so committing it means a binary diff
// and a conflict every time — a reason that holds whatever it contains. This
// one is written once and never again, so there is no such reason, and what
// would be left is a guess about the operator's threat model that the engine
// is in no position to make. Committing it to a private repo is a legitimate
// choice and a real backup; keeping it out is also legitimate. What is not
// legitimate is mikser editing a .gitignore to enforce either.
//
// Losing it is the failure that actually happens — a rebuilt container, an
// `rm -rf` — and checkKeyContinuity below is what makes that sayable.
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

// Has the signing key changed since last time?
//
// Creating a key logs a warning either way, and on a first run that is routine
// — so the alarming case and the normal one produce the same line, and the
// difference only shows up later as every agent being asked to authorise
// again. That is the shape of failure this whole codebase keeps finding: two
// states, one output.
//
// The kid is recorded in the durable store, which survives the cache wipe that
// the key file survives, so the two stay in step. A recorded kid that no
// longer matches means the file was replaced or lost — and every access and
// refresh token ever issued under the old one is now unverifiable.
//
// Returns null when there is nothing to compare against, which is not the same
// as "unchanged" and must not be reported as such.
export async function checkKeyContinuity({ kid, db, logger }) {
    if (!db || !kid) return null
    try {
        const [previous] = await db(SIGNING_KEY_TABLE).orderBy('recorded_at', 'desc').limit(1)

        if (!previous) {
            // First run, or the first boot after this check was added. Either
            // way there is no prior claim to contradict.
            await db(SIGNING_KEY_TABLE).insert({ kid, alg: ALG, recorded_at: Date.now() })
            return { recorded: true }
        }
        if (previous.kid === kid) return { unchanged: true }

        await db(SIGNING_KEY_TABLE).insert({ kid, alg: ALG, recorded_at: Date.now() })
        logger?.error?.({ code: 'auth-signing-key-changed' },
            'The signing key changed (was %s, now %s). Every access and refresh token issued under the old key '
            + 'is unverifiable, so everyone who was signed in must authorise again. If %s was not replaced on '
            + 'purpose it was LOST — restoring it from backup is what brings those sessions back; leaving it '
            + 'means every client re-registers.',
            previous.kid, kid, 'auth.key')
        return { changed: true, previous: previous.kid }
    } catch (err) {
        logger?.error?.({ code: 'auth-signing-key-changed' },
            'Could not check whether the signing key changed: %s. A silently replaced key looks exactly like '
            + 'tokens expiring at random, so this check not running is worth knowing about.', err.message)
        return null
    }
}

export const SIGNING_KEY_TABLE = 'mikser_auth_signing_key'

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
