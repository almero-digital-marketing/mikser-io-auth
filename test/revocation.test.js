// Does a change to the identity files reach a token that was already issued?
//
// Before this, no. A JWT carries the capabilities it was minted with, and
// verification checked the signature, the issuer, the audience and the expiry
// — never the files. So deleting a user left their token working for the rest
// of its life, an hour by default, with everything it was granted.
//
// The fix is a per-user stamp of the DERIVED identity, carried in the token
// and compared on each request. Per user rather than one global counter,
// because a global counter answers "someone changed" by logging everybody out.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { createIdentityStore, identityStamp } from '../lib/htpasswd.js'

// bcrypt hash of 'pw', reused so the tests are not spending 100ms each.
const PW_HASH = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'

const project = async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'auth-rev-'))
    return {
        dir,
        users: (lines) => writeFile(path.join(dir, 'users.htpasswd'), lines.join('\n') + '\n'),
        groups: (lines) => writeFile(path.join(dir, 'groups'), lines.join('\n') + '\n'),
        cleanup: () => rm(dir, { recursive: true, force: true }),
    }
}

const storeFor = (p, extra = {}) => createIdentityStore({
    usersFile:  path.join(p.dir, 'users.htpasswd'),
    groupsFile: path.join(p.dir, 'groups'),
    groups: { editors: ['drive:styles:write'], viewers: ['drive:styles'] },
    // No watcher and no grace, so each read reflects the files as they are.
    recheckAfterMs: 0,
    ...extra,
})

describe('a stamp changes exactly when the identity does', () => {
    let p
    before(async () => { p = await project() })
    after(async () => { await p.cleanup() })

    it('is stable across reads when nothing moved', async () => {
        await p.users([`alice:${PW_HASH}`, `bob:${PW_HASH}`])
        await p.groups(['editors: alice'])
        const store = storeFor(p)
        const first = await store.stampOf('alice')
        assert.ok(first, 'a known user has a stamp')
        assert.equal(await store.stampOf('alice'), first)
    })

    it('is null for a user who does not exist', async () => {
        const store = storeFor(p)
        assert.equal(await store.stampOf('nobody'), null)
    })

    it('changes when the user is removed from the file', async () => {
        // The case that started this: deleting a line must make the token
        // issued from it stop working.
        await p.users([`alice:${PW_HASH}`, `bob:${PW_HASH}`])
        await p.groups(['editors: alice'])
        const store = storeFor(p)
        assert.ok(await store.stampOf('bob'))
        await p.users([`alice:${PW_HASH}`])
        assert.equal(await store.stampOf('bob'), null)
    })

    it('changes when the user moves group', async () => {
        await p.users([`alice:${PW_HASH}`])
        await p.groups(['editors: alice'])
        const store = storeFor(p)
        const asEditor = await store.stampOf('alice')
        await p.groups(['viewers: alice'])
        assert.notEqual(await store.stampOf('alice'), asEditor)
    })

    it('changes when the password changes', async () => {
        // Deliberate: rotating a password ends that user's other sessions,
        // which is what "change the password to lock them out" means.
        await p.users([`alice:${PW_HASH}`])
        await p.groups(['editors: alice'])
        const store = storeFor(p)
        const before = await store.stampOf('alice')
        await p.users([`alice:${PW_HASH.slice(0, -1)}X`])
        assert.notEqual(await store.stampOf('alice'), before)
    })

    it('does NOT change for everyone else when one user moves', async () => {
        // The whole reason this is per user. A global counter would end
        // every session in the system whenever anyone's group changed.
        await p.users([`alice:${PW_HASH}`, `bob:${PW_HASH}`, `carol:${PW_HASH}`])
        await p.groups(['editors: alice bob', 'viewers: carol'])
        const store = storeFor(p)
        const aliceBefore = await store.stampOf('alice')
        const bobBefore   = await store.stampOf('bob')
        const carolBefore = await store.stampOf('carol')

        // Alice loses her group but remains a user — so she still has a
        // stamp, a different one. Her sessions end; nobody else's do.
        await p.groups(['editors: bob', 'viewers: carol'])
        assert.notEqual(await store.stampOf('alice'), aliceBefore, 'alice lost her group')
        assert.equal(await store.stampOf('bob'), bobBefore, 'bob is untouched')
        assert.equal(await store.stampOf('carol'), carolBefore, 'carol is untouched')

        // And deleting her row entirely removes the stamp altogether.
        await p.users([`bob:${PW_HASH}`, `carol:${PW_HASH}`])
        assert.equal(await store.stampOf('alice'), null, 'alice is gone')
        assert.equal(await store.stampOf('bob'), bobBefore, 'bob still untouched')
    })

    it('changes for a group whose capabilities were narrowed', async () => {
        // Not a file change at all — the capability map. The stamp covers the
        // DERIVED identity, which is what the token actually asserts.
        await p.users([`alice:${PW_HASH}`])
        await p.groups(['editors: alice'])
        const wide   = storeFor(p, { groups: { editors: ['drive:styles:write', 'drive:styles'] } })
        const narrow = storeFor(p, { groups: { editors: ['drive:styles'] } })
        assert.notEqual(await wide.stampOf('alice'), await narrow.stampOf('alice'))
    })
})

describe('the stamp function itself', () => {
    it('does not confuse "not capability-scoped" with "scoped to nothing"', () => {
        // null and [] are different answers in this codebase — one means the
        // endpoint's own limits apply, the other means no verbs at all.
        // Colliding them would let a token minted under one be accepted under
        // the other.
        assert.notEqual(
            identityStamp({ hash: 'h', capabilities: null }),
            identityStamp({ hash: 'h', capabilities: [] }),
        )
    })

    it('ignores the order groups and capabilities happen to be listed in', () => {
        // Otherwise reordering a line in the groups file would log everyone
        // in it out, for no change in what they can do.
        assert.equal(
            identityStamp({ hash: 'h', roles: ['a', 'b'], capabilities: ['x', 'y'] }),
            identityStamp({ hash: 'h', roles: ['b', 'a'], capabilities: ['y', 'x'] }),
        )
    })

    it('separates users with the same groups but different passwords', () => {
        assert.notEqual(
            identityStamp({ hash: 'one', roles: ['editors'] }),
            identityStamp({ hash: 'two', roles: ['editors'] }),
        )
    })
})
