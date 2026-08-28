import { registerSchema, useDatabase } from 'mikser-io'
import { opaqueToken } from './pkce.js'

// Authorization codes and refresh tokens — the only server-side state this
// package keeps. Identity stays in files (ADR-0012); this is session
// bookkeeping, which is exactly what the engine's sqlite substrate is for
// (ADR-0009).
//
// Table prefix follows the cross-repo convention: `mikser-io-auth` →
// `mikser_auth_*`.
//
// One consequence worth knowing: the engine wipes this database when its
// schema stamp changes, so upgrading mikser signs everyone out. Codes live
// 60 seconds so they are irrelevant; refresh tokens are the real cost, and
// re-authenticating after an engine upgrade is a fair price for not
// inventing a second persistence story.
registerSchema('auth', `
    CREATE TABLE IF NOT EXISTS mikser_auth_codes (
        code           TEXT PRIMARY KEY,
        client_id      TEXT NOT NULL,
        subject        TEXT NOT NULL,
        redirect_uri   TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        scope          TEXT,
        expires_at     INTEGER NOT NULL,
        used_at        INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_mikser_auth_codes_expiry
        ON mikser_auth_codes (expires_at);

    CREATE TABLE IF NOT EXISTS mikser_auth_refresh (
        token      TEXT PRIMARY KEY,
        client_id  TEXT NOT NULL,
        subject    TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_mikser_auth_refresh_subject
        ON mikser_auth_refresh (subject);

    -- Short-lived tokens minted for one narrow job — a WebDAV upload, say —
    -- rather than for a session. A JWT is normally unrevokable before its
    -- expiry, which is exactly the property you do not want in a credential
    -- handed to something that logs its own output. So a minted token carries
    -- a jti and is only usable while its row here says so.
    --
    -- The verifier FAILS CLOSED on a missing row: no row, not usable. That
    -- makes this table load-bearing for validity rather than merely advisory,
    -- which is the safe direction — losing it revokes, it never un-revokes.
    CREATE TABLE IF NOT EXISTS mikser_auth_minted (
        jti        TEXT PRIMARY KEY,
        subject    TEXT NOT NULL,
        purpose    TEXT,
        scopes     TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_mikser_auth_minted_subject
        ON mikser_auth_minted (subject);

    -- Self-registered clients (RFC 7591). Config-declared clients are NOT
    -- here: they live in config, are not prunable, and always win a lookup.
    -- Keeping the two apart is what makes pruning safe — an operator's
    -- client that has not been used yet is not garbage.
    CREATE TABLE IF NOT EXISTS mikser_auth_clients (
        client_id     TEXT PRIMARY KEY,
        name          TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        last_used_at  INTEGER
    );
`, {
    // Durable: these tables are not derived from anything on disk.
    //
    // The engine wipes its database whenever the schema version or the
    // config checksum changes — an upgrade, or any deploy that edits
    // mikser.config.js. That is correct for a cache the files can rebuild,
    // and wrong here: a registered OAuth client and its refresh token exist
    // only because a human completed a sign-in once. Losing them logs every
    // connected agent out, and the operator's first sign of it is being
    // asked to authorize again after an unrelated deploy.
    //
    // Codes are 60s and swept anyway; they ride along because they share the
    // schema, and a stale one is rejected on expiry rather than trusted.
    durable: true,
})

const db = () => useDatabase().handle

export function createCode({ clientId, subject, redirectUri, codeChallenge, scope, ttlSec = 60 }) {
    const code = opaqueToken()
    db().prepare(`
        INSERT INTO mikser_auth_codes
            (code, client_id, subject, redirect_uri, code_challenge, scope, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(code, clientId, subject, redirectUri, codeChallenge, scope ?? '', Date.now() + ttlSec * 1000)
    return code
}

export function getCode(code) {
    return db().prepare('SELECT * FROM mikser_auth_codes WHERE code = ?').get(code)
}

// Single-use, enforced by the UPDATE's own WHERE rather than by a read
// followed by a write: two simultaneous redemptions of the same code both
// pass a prior SELECT, and only one can win this.
export function redeemCode(code) {
    const result = db()
        .prepare('UPDATE mikser_auth_codes SET used_at = ? WHERE code = ? AND used_at IS NULL')
        .run(Date.now(), code)
    return result.changes === 1
}

export function createRefreshToken({ clientId, subject, ttlSec }) {
    const token = opaqueToken()
    db().prepare(`
        INSERT INTO mikser_auth_refresh (token, client_id, subject, expires_at)
        VALUES (?, ?, ?, ?)
    `).run(token, clientId, subject, Date.now() + ttlSec * 1000)
    return token
}

export function getRefreshToken(token) {
    return db().prepare('SELECT * FROM mikser_auth_refresh WHERE token = ?').get(token)
}

// Same race-safe shape as redeemCode. Rotation revokes BEFORE minting the
// replacement, so losing the race means creating nothing at all rather than
// leaving a valid token nobody holds.
export function revokeRefreshToken(token) {
    const result = db()
        .prepare('UPDATE mikser_auth_refresh SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL')
        .run(Date.now(), token)
    return result.changes === 1
}

// Everything a subject holds, for a sign-out-everywhere. Also what an
// operator gets implicitly by deleting the user from users.htpasswd —
// except that revoking here is immediate, where an htpasswd edit only
// stops the NEXT login and leaves live access tokens valid until they
// expire.
export function revokeAllForSubject(subject) {
    return db()
        .prepare('UPDATE mikser_auth_refresh SET revoked_at = ? WHERE subject = ? AND revoked_at IS NULL')
        .run(Date.now(), subject).changes
}

export function sweepExpired() {
    const now = Date.now()
    const codes = db().prepare('DELETE FROM mikser_auth_codes WHERE expires_at < ?').run(now - 60_000).changes
    const refresh = db().prepare('DELETE FROM mikser_auth_refresh WHERE expires_at < ?').run(now).changes
    // A minted row past its expiry can no longer authorise anything — the JWT
    // has expired on its own — so keeping it buys nothing. Swept a minute late
    // so a token expiring mid-request is rejected by the clock rather than by
    // a missing row, which reads as revoked and is a different answer.
    const minted = db().prepare('DELETE FROM mikser_auth_minted WHERE expires_at < ?').run(now - 60_000).changes
    return { codes, refresh, minted }
}

// ── minted tokens ───────────────────────────────────────────────────────

export function recordMintedToken({ jti, subject, purpose, scopes, ttlSec }) {
    const now = Date.now()
    db().prepare(`
        INSERT INTO mikser_auth_minted (jti, subject, purpose, scopes, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(jti, subject, purpose ?? null, scopes.join(' '), now, now + ttlSec * 1000)
    return { jti, expiresAt: now + ttlSec * 1000 }
}

// Is this jti still usable? Missing means NO — see the schema comment.
export function mintedTokenUsable(jti) {
    const row = db().prepare('SELECT revoked_at, expires_at FROM mikser_auth_minted WHERE jti = ?').get(jti)
    if (!row) return false
    if (row.revoked_at) return false
    return row.expires_at > Date.now()
}

export function revokeMintedToken(jti) {
    return db()
        .prepare('UPDATE mikser_auth_minted SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL')
        .run(Date.now(), jti).changes > 0
}

export function listMintedTokens(subject) {
    const rows = subject
        ? db().prepare('SELECT * FROM mikser_auth_minted WHERE subject = ? ORDER BY created_at DESC').all(subject)
        : db().prepare('SELECT * FROM mikser_auth_minted ORDER BY created_at DESC').all()
    return rows.map(r => ({
        jti: r.jti, subject: r.subject, purpose: r.purpose,
        scopes: r.scopes.split(' '),
        createdAt: new Date(r.created_at).toISOString(),
        expiresAt: new Date(r.expires_at).toISOString(),
        revokedAt: r.revoked_at ? new Date(r.revoked_at).toISOString() : null,
        usable: !r.revoked_at && r.expires_at > Date.now(),
    }))
}

// ── self-registered clients ─────────────────────────────────────────────

export function countDynamicClients() {
    return db().prepare('SELECT COUNT(*) AS n FROM mikser_auth_clients').get().n
}

export function insertDynamicClient({ clientId, name, redirectUris }) {
    const createdAt = Date.now()
    db().prepare(`
        INSERT INTO mikser_auth_clients (client_id, name, redirect_uris, created_at)
        VALUES (?, ?, ?, ?)
    `).run(clientId, name, JSON.stringify(redirectUris), createdAt)
    return { clientId, name, redirectUris, createdAt }
}

export function getDynamicClient(clientId) {
    const row = db().prepare('SELECT * FROM mikser_auth_clients WHERE client_id = ?').get(clientId)
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

export function touchClient(clientId) {
    db().prepare('UPDATE mikser_auth_clients SET last_used_at = ? WHERE client_id = ?')
        .run(Date.now(), clientId)
}

// DCR has no "get or create" — every registration mints a NEW client_id, so
// a reinstall, a cleared cache or a second machine each leave another row
// behind. Prune the ones nobody ever signed in with.
export function pruneUnusedClients({ olderThanMs }) {
    return db().prepare(`
        DELETE FROM mikser_auth_clients
        WHERE last_used_at IS NULL AND created_at < ?
    `).run(Date.now() - olderThanMs).changes
}
