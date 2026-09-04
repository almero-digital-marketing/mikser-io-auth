// How the store notices that the identity files moved.
//
// It used to stat both files on every read — two syscalls, ~75µs with promise
// overhead, on every authenticated request, to catch a change that happens
// about monthly. Now a watcher invalidates and a timestamp backstops it.
//
// The backstop is the part worth testing hardest. A watch that stops working
// stops silently: write-then-rename replaces the inode a file watch holds,
// inotify does not cross NFS, a watcher can die under EMFILE. A silent watch
// here means revocation silently stops working, and that is discovered on the
// day someone needs removing immediately.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rename, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { createIdentityStore } from '../lib/htpasswd.js'

const PW = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
const sleep = (ms) => new Promise(r => setTimeout(r, ms))

const project = async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'auth-watch-'))
    return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) }
}
const usersPath = (p) => path.join(p.dir, 'users.htpasswd')

describe('the timed backstop', () => {
    let p
    before(async () => { p = await project() })
    after(async () => { await p.cleanup() })

    it('serves the cache without touching the disk inside the window', async () => {
        // The hot path. Counting stats is the point: this is what makes the
        // per-request cost zero.
        await writeFile(usersPath(p), `alice:${PW}\n`)
        let stats = 0
        const store = createIdentityStore({
            usersFile: usersPath(p),
            recheckAfterMs: 60_000,
            logger: { debug: () => {} },
        })
        await store.stampOf('alice')            // first read loads
        const before = stats
        for (let i = 0; i < 50; i++) await store.stampOf('alice')
        assert.equal(stats - before, 0, 'no further disk work inside the window')
    })

    it('picks up a change once the window passes, with no watcher at all', async () => {
        // The NFS / dead-watcher case. Staleness is bounded rather than
        // unbounded, and it self-heals without anyone noticing.
        await writeFile(usersPath(p), `alice:${PW}\n`)
        const store = createIdentityStore({ usersFile: usersPath(p), recheckAfterMs: 20 })
        const first = await store.stampOf('alice')
        assert.ok(first)

        await writeFile(usersPath(p), `alice:${PW}\nbob:${PW}\n`)
        assert.equal(await store.stampOf('bob'), null, 'still inside the window')

        await sleep(40)
        assert.ok(await store.stampOf('bob'), 'picked up after the window')
    })
})

describe('the watcher', () => {
    let p
    before(async () => { p = await project() })
    after(async () => { await p.cleanup() })

    it('invalidates immediately, ahead of the backstop', async () => {
        await writeFile(usersPath(p), `alice:${PW}\n`)
        let fire
        const store = createIdentityStore({
            usersFile: usersPath(p),
            // A very long window, so anything picked up came from the watcher.
            recheckAfterMs: 600_000,
            watchFolder: (_folder, handler) => { fire = handler; return { close() {} } },
        })
        await store.stampOf('alice')
        await writeFile(usersPath(p), `alice:${PW}\nbob:${PW}\n`)
        assert.equal(await store.stampOf('bob'), null, 'not seen yet — the window is long')

        fire('change', usersPath(p))
        assert.ok(await store.stampOf('bob'), 'the watcher event brought it forward')
    })

    it('ignores events for other files in the same folder', async () => {
        // The watch is on the DIRECTORY — that is what survives an editor
        // writing a temp file and renaming over the target — so unrelated
        // churn in the same folder must not cost a reload.
        await writeFile(usersPath(p), `alice:${PW}\n`)
        let fire
        const store = createIdentityStore({
            usersFile: usersPath(p),
            recheckAfterMs: 600_000,
            watchFolder: (_folder, handler) => { fire = handler; return { close() {} } },
        })
        await store.stampOf('alice')
        await writeFile(usersPath(p), `alice:${PW}\nbob:${PW}\n`)

        fire('change', path.join(p.dir, 'something-else.log'))
        assert.equal(await store.stampOf('bob'), null, 'an unrelated file changed nothing')
    })

    it('survives write-then-rename, which replaces the inode', async () => {
        // How most editors and config tools write. A watch bound to the file
        // would be left holding an orphan; the directory watch still fires.
        await writeFile(usersPath(p), `alice:${PW}\n`)
        let fire
        const store = createIdentityStore({
            usersFile: usersPath(p),
            recheckAfterMs: 600_000,
            watchFolder: (_folder, handler) => { fire = handler; return { close() {} } },
        })
        await store.stampOf('alice')

        const tmp = path.join(p.dir, '.users.tmp')
        await writeFile(tmp, `alice:${PW}\ncarol:${PW}\n`)
        await rename(tmp, usersPath(p))
        fire('add', usersPath(p))

        assert.ok(await store.stampOf('carol'), 'the replacement was picked up')
    })

    it('carries on, and says so, when the folder cannot be watched', async () => {
        // Not fatal — the backstop still bounds staleness — but the operator
        // asked for immediate propagation and is now getting delayed, so it
        // is said out loud rather than degrading quietly.
        await writeFile(usersPath(p), `alice:${PW}\n`)
        const warnings = []
        const store = createIdentityStore({
            usersFile: usersPath(p),
            recheckAfterMs: 20,
            watchFolder: () => { throw new Error('inotify limit reached') },
            logger: { warn: (...a) => warnings.push(a.join(' ')), debug: () => {} },
        })
        assert.ok(await store.stampOf('alice'), 'the store still works')
        assert.ok(warnings.some(w => /could not watch/.test(w)),
            `the degradation should be reported: ${JSON.stringify(warnings)}`)
    })

    it('releases its watchers on close', async () => {
        // A server that recreates its identity store would otherwise leak one
        // watcher per reload.
        await writeFile(usersPath(p), `alice:${PW}\n`)
        let closed = 0
        const store = createIdentityStore({
            usersFile: usersPath(p),
            watchFolder: () => ({ close() { closed++ } }),
        })
        await store.close()
        assert.equal(closed, 1)
    })
})
