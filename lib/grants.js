import { registerMigrations, useDurableDatabase } from 'mikser-io'
import { opaqueToken } from './pkce.js'

// Authorization codes and refresh tokens — the only server-side state this
// package keeps. Identity stays in files (ADR-0012); this is session
// bookkeeping.
//
// DURABLE, which since 9.56 means a database of its own rather than a flag on
// a table in the cache. A registered OAuth client and its refresh token exist
// only because a human completed a sign-in once, and no file can reproduce
// them — so they live in `mikser.data.sqlite`, which the cache wipe cannot
// reach and `--clear` does not touch. Upgrading mikser no longer signs
// everyone out.
//
// Migrations rather than an idempotent CREATE, because a durable table is the
// only kind that is never recreated: `CREATE TABLE IF NOT EXISTS` can never
// give it a column it has grown, and it goes stale silently.
//
// Table prefix follows the cross-repo convention: `mikser-io-auth` →
// `mikser_auth_*`.
registerMigrations('auth', [
    {
        name: '001-grants',
        up: async (knex) => {
            await knex.schema.createTable('mikser_auth_codes', (table) => {
                table.string('code').primary()
                table.string('client_id').notNullable()
                table.string('subject').notNullable()
                table.text('redirect_uri').notNullable()
                table.text('code_challenge').notNullable()
                table.text('scope').notNullable().defaultTo('')
                table.bigInteger('expires_at').notNullable()
                table.bigInteger('used_at')
                table.index(['expires_at'], 'idx_mikser_auth_codes_expiry')
            })

            await knex.schema.createTable('mikser_auth_refresh', (table) => {
                table.string('token').primary()
                table.string('client_id').notNullable()
                table.string('subject').notNullable()
                table.bigInteger('expires_at').notNullable()
                table.bigInteger('revoked_at')
                table.index(['subject'], 'idx_mikser_auth_refresh_subject')
            })

            // Self-registered clients (RFC 7591). Config-declared clients are
            // NOT here: they live in config, are not prunable, and always win
            // a lookup. Keeping the two apart is what makes pruning safe — an
            // operator's client that has not been used yet is not garbage.
            await knex.schema.createTable('mikser_auth_clients', (table) => {
                table.string('client_id').primary()
                table.string('name').notNullable()
                table.text('redirect_uris').notNullable()
                table.bigInteger('created_at').notNullable()
                table.bigInteger('last_used_at')
            })
        },
    },
    {
        // Which signing key was in force. A history rather than one row: when
        // it changes, the useful sentence names both, and "was X, now Y" is
        // what tells an operator whether they replaced it on purpose.
        //
        // Appended as its own migration rather than edited into 001 — a
        // migration that has run is permanent, and changing it would mean it
        // never runs against the databases that already applied it.
        name: '002-signing-key',
        up: async (knex) => {
            await knex.schema.createTable('mikser_auth_signing_key', (table) => {
                table.string('kid').primary()
                table.string('alg').notNullable()
                table.bigInteger('recorded_at').notNullable()
                table.index(['recorded_at'], 'idx_mikser_auth_signing_key_recorded')
            })
        },
    },
])

const db = () => useDurableDatabase()

export async function createCode({ clientId, subject, redirectUri, codeChallenge, scope, ttlSec = 60 }) {
    const code = opaqueToken()
    await db()('mikser_auth_codes').insert({
        code, client_id: clientId, subject, redirect_uri: redirectUri,
        code_challenge: codeChallenge, scope: scope ?? '', expires_at: Date.now() + ttlSec * 1000,
    })
    return code
}

export async function getCode(code) {
    return db()('mikser_auth_codes').where({ code }).first()
}

// Single-use, enforced by the UPDATE's own WHERE rather than by a read
// followed by a write: two simultaneous redemptions of the same code both
// pass a prior SELECT, and only one can win this.
export async function redeemCode(code) {
    const changed = await db()('mikser_auth_codes')
        .where({ code }).whereNull('used_at').update({ used_at: Date.now() })
    return changed === 1
}

export async function createRefreshToken({ clientId, subject, ttlSec }) {
    const token = opaqueToken()
    await db()('mikser_auth_refresh').insert({
        token, client_id: clientId, subject, expires_at: Date.now() + ttlSec * 1000,
    })
    return token
}

export async function getRefreshToken(token) {
    return db()('mikser_auth_refresh').where({ token }).first()
}

// Same race-safe shape as redeemCode. Rotation revokes BEFORE minting the
// replacement, so losing the race means creating nothing at all rather than
// leaving a valid token nobody holds.
export async function revokeRefreshToken(token) {
    const changed = await db()('mikser_auth_refresh')
        .where({ token }).whereNull('revoked_at').update({ revoked_at: Date.now() })
    return changed === 1
}

// Everything a subject holds, for a sign-out-everywhere. Also what an
// operator gets implicitly by deleting the user from users.htpasswd —
// except that revoking here is immediate, where an htpasswd edit only
// stops the NEXT login and leaves live access tokens valid until they
// expire.
export async function revokeAllForSubject(subject) {
    return db()('mikser_auth_refresh')
        .where({ subject }).whereNull('revoked_at').update({ revoked_at: Date.now() })
}

export async function sweepExpired() {
    const now = Date.now()
    const codes = await db()('mikser_auth_codes').where('expires_at', '<', now - 60_000).delete()
    const refresh = await db()('mikser_auth_refresh').where('expires_at', '<', now).delete()
    return { codes, refresh }
}

// ── self-registered clients ─────────────────────────────────────────────

export async function countDynamicClients() {
    const [{ n }] = await db()('mikser_auth_clients').count({ n: '*' })
    return Number(n)
}

export async function insertDynamicClient({ clientId, name, redirectUris }) {
    const createdAt = Date.now()
    await db()('mikser_auth_clients').insert({
        client_id: clientId, name, redirect_uris: JSON.stringify(redirectUris), created_at: createdAt,
    })
    return { clientId, name, redirectUris, createdAt }
}

export async function getDynamicClient(clientId) {
    const row = await db()('mikser_auth_clients').where({ client_id: clientId }).first()
    if (!row) return null
    return {
        clientId:     row.client_id,
        name:         row.name,
        redirectUris: JSON.parse(row.redirect_uris),
        createdAt:    row.created_at,
        lastUsedAt:   row.last_used_at,
        dynamic:      true,
    }
}

export async function touchClient(clientId) {
    await db()('mikser_auth_clients').where({ client_id: clientId }).update({ last_used_at: Date.now() })
}

// DCR has no "get or create" — every registration mints a NEW client_id, so
// a reinstall, a cleared cache or a second machine each leave another row
// behind. Prune the ones nobody ever signed in with.
export async function pruneUnusedClients({ olderThanMs }) {
    return db()('mikser_auth_clients')
        .whereNull('last_used_at').where('created_at', '<', Date.now() - olderThanMs).delete()
}
