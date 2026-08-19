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
`)

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
    return { codes, refresh }
}
