import { createHash, timingSafeEqual, randomBytes } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import bcrypt from 'bcryptjs'

// Apache-format identity, per ADR-0012.
//
//   users.htpasswd    alice:$2y$10$…
//   groups.htgroup    editors: alice bob
//
// Read-only, always. Mikser provisions these files; it never writes them.
// The moment a running server writes an htpasswd file it has a locking
// problem and a database it won't admit to.

// One `user:hash` per line. `#` comments and blank lines are skipped, and a
// hash containing `:` (crypt output never does, but be exact) survives
// because only the FIRST colon separates.
export function parseHtpasswd(text) {
    const users = new Map()
    for (const raw of text.split('\n')) {
        const line = raw.trim()
        if (!line || line.startsWith('#')) continue
        const i = line.indexOf(':')
        if (i < 1) continue
        users.set(line.slice(0, i), line.slice(i + 1))
    }
    return users
}

// `groupname: user1 user2`. Apache allows a group to be repeated across
// lines, so members accumulate rather than replace.
export function parseHtgroup(text) {
    const groups = new Map()
    for (const raw of text.split('\n')) {
        const line = raw.trim()
        if (!line || line.startsWith('#')) continue
        const i = line.indexOf(':')
        if (i < 1) continue
        const name = line.slice(0, i).trim()
        const members = line.slice(i + 1).trim().split(/\s+/).filter(Boolean)
        const set = groups.get(name) ?? new Set()
        for (const m of members) set.add(m)
        groups.set(name, set)
    }
    return groups
}

// Apache's own MD5 variant ($apr1$). Supported because `htpasswd` emits it
// by default on some platforms and an operator shouldn't have to care —
// but it is MD5-based and weak. Prefer bcrypt (`htpasswd -B`).
function apr1(password, salt) {
    const pw = Buffer.from(password, 'utf8')
    const sa = Buffer.from(salt, 'utf8')

    // The inner digest, folded into the outer one password-length bytes at
    // a time, then one bit per bit of the password length: NUL for a 1-bit,
    // the password's first byte for a 0-bit. That last step is the part
    // every reimplementation gets backwards.
    const inner = createHash('md5').update(pw).update(sa).update(pw).digest()

    const ctx = createHash('md5').update(pw).update('$apr1$').update(sa)
    for (let i = pw.length; i > 0; i -= 16) ctx.update(inner.subarray(0, Math.min(16, i)))
    for (let i = pw.length; i !== 0; i >>= 1) {
        ctx.update(i & 1 ? Buffer.from([0]) : pw.subarray(0, 1))
    }
    let final = ctx.digest()

    // 1000 rounds of deliberate slowness — by 2026 standards, not nearly
    // enough. This format is here for compatibility, not because it's good.
    for (let i = 0; i < 1000; i++) {
        const round = createHash('md5')
        round.update(i & 1 ? pw : final)
        if (i % 3) round.update(sa)
        if (i % 7) round.update(pw)
        round.update(i & 1 ? final : pw)
        final = round.digest()
    }

    // Apache's own base64 alphabet, and its own byte order.
    const ITOA = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    let out = ''
    for (const [a, b, c] of [[0, 6, 12], [1, 7, 13], [2, 8, 14], [3, 9, 15], [4, 10, 5]]) {
        let v = (final[a] << 16) | (final[b] << 8) | final[c]
        for (let i = 0; i < 4; i++) { out += ITOA[v & 0x3f]; v >>= 6 }
    }
    let v = final[11]
    for (let i = 0; i < 2; i++) { out += ITOA[v & 0x3f]; v >>= 6 }
    return `$apr1$${salt}$${out}`
}

function safeEqual(a, b) {
    const ba = Buffer.from(a, 'utf8')
    const bb = Buffer.from(b, 'utf8')
    return ba.length === bb.length && timingSafeEqual(ba, bb)
}

// Verify a plaintext password against one htpasswd hash.
//
// bcrypt ($2a/$2b/$2y) is the only format here worth trusting; the others
// exist because `htpasswd` can produce them and an operator's existing file
// should keep working. $2y is PHP's prefix for a hash that is byte-identical
// to $2a — bcryptjs doesn't know it, so it's rewritten before comparison.
export function verifyPassword(hash, password) {
    if (!hash || typeof password !== 'string') return false

    if (/^\$2[aby]\$/.test(hash)) {
        try {
            return bcrypt.compareSync(password, hash.replace(/^\$2y\$/, '$2a$'))
        } catch {
            return false
        }
    }

    if (hash.startsWith('$apr1$')) {
        const salt = hash.split('$')[2] ?? ''
        return safeEqual(hash, apr1(password, salt))
    }

    if (hash.startsWith('{SHA}')) {
        const digest = createHash('sha1').update(password, 'utf8').digest('base64')
        return safeEqual(hash, `{SHA}${digest}`)
    }

    if (hash.startsWith('$2') || hash.startsWith('$1$') || hash.length === 13) {
        // MD5-crypt and DES-crypt. Deliberately unsupported rather than
        // half-supported: both are broken, and silently rejecting is safer
        // than a subtly wrong implementation that accepts something.
        return false
    }

    // A plaintext htpasswd file (Windows/Netware Apache) — compared in
    // constant time, still a terrible idea, still someone's existing file.
    return safeEqual(hash, password)
}

// What a token asserts about a user, reduced to one short string.
//
// A JWT carries the capabilities it was minted with, and verification checks
// the signature and the expiry — not the files. So deleting a user, or moving
// them out of a group, left their existing token working until it aged out.
//
// A single global generation counter would fix that by logging EVERYONE out
// whenever anyone's group changed. This is per user: their token carries the
// stamp of the identity it was minted from, and verification compares it
// against the current one. One person's change touches one person.
//
// The DERIVED identity, not the raw row, because that is what the token
// asserts. If the token says drive:styles:write and the current derivation
// says otherwise, it should fail — whether that is because the user moved
// group, the group's capability list changed, or the row is gone.
//
// The password hash is in it deliberately: rotating a password ends that
// user's other sessions, which is what "change the password to lock them
// out" is supposed to mean.
//
// No storage anywhere. The token carries the stamp it was minted with, so
// there is no revocation list to keep, replicate, or expire.
export function identityStamp({ hash, roles = [], capabilities = null, scope = null }) {
    const canonical = JSON.stringify({
        h: hash ?? null,
        r: [...roles].sort(),
        // null (not capability-scoped) and [] (scoped, holds nothing) are
        // different answers and must not collide.
        c: capabilities === null ? null : [...capabilities].sort(),
        s: scope ?? null,
    })
    return createHash('sha256').update(canonical).digest('base64url').slice(0, 22)
}

// The store. Identity lives in files so an operator can edit them and have it
// take effect now rather than on the next deploy — so the question is how
// quickly a change is noticed, and how much it costs to keep noticing.
//
// It used to stat both files on every read. That is two syscalls, ~75µs with
// promise overhead, on every authenticated request, to detect a change that
// happens about monthly.
//
// So: a watcher invalidates the cache when the files move, and a timestamp
// backstops it. Within `recheckAfterMs` of the last verification the cache is
// trusted outright and the hot path does no I/O at all. Past that, one stat
// pair confirms it.
//
// The backstop is not belt-and-braces, it is the design. A watch that stops
// working stops silently — write-then-rename replaces the inode a file watch
// is holding, inotify does not cross NFS, a watcher can die under EMFILE —
// and a silent watch here means REVOCATION silently stops working, which is
// discovered on the day someone needs removing now. Bounded staleness that
// self-heals beats unbounded staleness that does not.
export function createIdentityStore({
    usersFile, groupsFile, groups = {}, scopes = {}, logger,
    watchFolder,
    recheckAfterMs = 30_000,
} = {}) {
    let cache = { users: new Map(), members: new Map(), stamp: null, stamps: new Map() }
    // When the cache was last known to match the files. 0 forces a check.
    let verifiedAt = 0
    // Set by the watcher. Distinct from verifiedAt because a watch event is
    // TESTIMONY that the bytes changed, and must not then be second-guessed by
    // comparing mtimes: mtime has millisecond granularity, so a write-then-
    // rename inside one millisecond leaves it identical and the reload never
    // happens. The timed backstop compares; a watch event does not.
    let dirty = false
    let watchers = []

    async function mtime(file) {
        if (!file) return null
        try {
            return (await stat(file)).mtimeMs
        } catch {
            return null
        }
    }

    // A change event only says "look again" — it never parses. The next read
    // does the work, so a burst of writes costs one reload rather than one per
    // event, and a watcher firing on an unrelated file in the folder is
    // harmless.
    if (watchFolder && usersFile) {
        const folders = [...new Set([usersFile, groupsFile].filter(Boolean).map(f => path.dirname(f)))]
        const names = new Set([usersFile, groupsFile].filter(Boolean).map(f => path.basename(f)))
        for (const folder of folders) {
            try {
                watchers.push(watchFolder(folder, (_event, fullPath) => {
                    if (fullPath && !names.has(path.basename(fullPath))) return
                    dirty = true
                }))
            } catch (err) {
                // Not fatal: the backstop still bounds staleness at
                // recheckAfterMs. Said out loud because the operator asked for
                // immediate propagation and is now getting delayed.
                logger?.warn?.('auth: could not watch %s — identity changes will be picked up within %dms instead of immediately (%s)',
                    folder, recheckAfterMs, err.message)
            }
        }
    }

    async function load() {
        // The hot path: recently verified and no event since, nothing to do.
        if (!dirty && cache.stamp !== null && Date.now() - verifiedAt < recheckAfterMs) return cache

        const wasDirty = dirty
        dirty = false
        const stamp = `${await mtime(usersFile)}:${await mtime(groupsFile)}`
        verifiedAt = Date.now()
        // Only the timed path trusts the comparison. See `dirty` above.
        if (!wasDirty && stamp === cache.stamp) return cache

        let users = new Map()
        try {
            users = parseHtpasswd(await readFile(usersFile, 'utf8'))
        } catch (err) {
            if (err.code !== 'ENOENT') throw err
            logger?.warn?.('auth: no users file at %s — every login will be refused', usersFile)
        }

        let members = new Map()
        if (groupsFile) {
            try {
                members = parseHtgroup(await readFile(groupsFile, 'utf8'))
            } catch (err) {
                if (err.code !== 'ENOENT') throw err
            }
        }

        const stamps = stampAll(users, members)
        const changed = cache.stamp === null ? null : diffStamps(cache.stamps, stamps)
        cache = { users, members, stamp, stamps }
        if (changed) {
            logger?.info?.('auth: identity changed for %d of %d user(s): %s',
                changed.length, stamps.size, changed.slice(0, 8).join(', ') + (changed.length > 8 ? ' …' : ''))
        }
        logger?.debug?.('auth: loaded %d user(s), %d group(s)', users.size, members.size)
        return cache
    }

    // Every user's stamp, computed once per reload rather than per request.
    function stampAll(users, members) {
        const out = new Map()
        for (const [username, hash] of users) {
            out.set(username, identityStamp({
                hash,
                roles:        [...members].filter(([, u]) => u.has(username)).map(([g]) => g),
                capabilities: capabilitiesFor(username, members),
                scope:        scopeFor(username, members),
            }))
        }
        return out
    }

    // Who actually changed. A deleted user counts: their tokens must stop
    // working, and nothing else names them again.
    function diffStamps(before, after) {
        const changed = []
        for (const [username, stamp] of after) {
            if (before.get(username) !== stamp) changed.push(username)
        }
        for (const username of before.keys()) {
            if (!after.has(username)) changed.push(username)
        }
        return changed.length ? changed : null
    }

    // Is this deployment using capabilities at all?
    const capabilitiesConfigured = Object.keys(groups).length > 0

    // Which capabilities does this user hold, via group membership?
    //
    // With NO capability map configured the answer is null — "not
    // capability-scoped" — which is exactly what a bare static token
    // reports, and means the endpoint's own `operations` list is the only
    // limit. Returning [] instead would grant nothing to anybody, so the
    // simplest possible setup (a users file and nothing else) would
    // authenticate people and then refuse them everything.
    //
    // Once a map EXISTS, a user whose groups grant nothing gets [] — an
    // explicit "no verbs", because at that point the operator is using
    // capabilities and silence means denial rather than absence.
    function capabilitiesFor(username, members) {
        if (!capabilitiesConfigured) return null
        const caps = new Set()
        for (const [group, users] of members) {
            if (!users.has(username)) continue
            for (const cap of groups[group] ?? []) caps.add(cap)
        }
        return [...caps]
    }

    // Which ROWS may this user see? A per-group sift filter, combined with
    // $or across the groups they belong to — capabilities union, and so does
    // reach: being in two groups shows you the union of what each group
    // sees, not the intersection (which would make every extra group make a
    // user LESS able, and is never what an operator means).
    //
    // No matching group with a scope → null, meaning "unscoped": the
    // endpoint's own query is the only limit. That is the pre-existing
    // behaviour for every credential that carries no scope.
    function scopeFor(username, members) {
        const filters = []
        for (const [group, users] of members) {
            if (!users.has(username)) continue
            const filter = scopes[group]
            if (filter) filters.push(filter)
        }
        if (!filters.length) return null
        return filters.length === 1 ? filters[0] : { $or: filters }
    }

    return {
        async authenticate(username, password) {
            const { users, members } = await load()
            const hash = users.get(username)
            if (!hash) {
                // Spend the time anyway: returning early on an unknown user
                // makes username enumeration a timing measurement.
                verifyPassword('$2a$10$' + randomBytes(16).toString('base64url').slice(0, 53), password)
                return null
            }
            if (!verifyPassword(hash, password)) return null
            return {
                subject:      username,
                groups:       [...members].filter(([, u]) => u.has(username)).map(([g]) => g),
                capabilities: capabilitiesFor(username, members),
                scope:        scopeFor(username, members),
            }
        },
        async groupsOf(username) {
            const { members } = await load()
            return [...members].filter(([, u]) => u.has(username)).map(([g]) => g)
        },
        async capabilitiesOf(username) {
            const { members } = await load()
            return capabilitiesFor(username, members)
        },
        async scopeOf(username) {
            const { members } = await load()
            return scopeFor(username, members)
        },
        // The stamp for a user right now, or null if they no longer exist.
        // The jwt verifier compares a token's claim against this.
        async stampOf(username) {
            const { stamps } = await load()
            return stamps.get(username) ?? null
        },
        async reload() { dirty = true; verifiedAt = 0; cache = { ...cache, stamp: null }; return load() },
        // Release the watchers. Without this a server that recreates its
        // identity store leaks one chokidar instance per reload.
        async close() {
            for (const w of watchers) { try { await w?.close?.() } catch { /* already gone */ } }
            watchers = []
        },
    }
}
