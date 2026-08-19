import { createHash, timingSafeEqual, randomBytes } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'
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

// The store. Files are re-read when their mtime moves, so an operator who
// edits users.htpasswd sees it take effect on the next request rather than
// on the next deploy — which is the whole reason identity lives in files.
export function createIdentityStore({ usersFile, groupsFile, groups = {}, scopes = {}, logger } = {}) {
    let cache = { users: new Map(), members: new Map(), stamp: null }

    async function mtime(file) {
        if (!file) return null
        try {
            return (await stat(file)).mtimeMs
        } catch {
            return null
        }
    }

    async function load() {
        const stamp = `${await mtime(usersFile)}:${await mtime(groupsFile)}`
        if (stamp === cache.stamp) return cache

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

        cache = { users, members, stamp }
        logger?.debug?.('auth: loaded %d user(s), %d group(s)', users.size, members.size)
        return cache
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
        async reload() { cache = { ...cache, stamp: null }; return load() },
    }
}
