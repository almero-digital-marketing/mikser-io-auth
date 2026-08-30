// The signing key: kept out of the repo, and never replaced quietly.
//
// It is ONE key for the whole deployment — every token for every user is
// signed with it. Losing it invalidates all of them at once; leaking it lets
// anyone mint one for any subject. Both failures are silent by default, which
// is what these two guards are for.

import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, mkdir, readFile, writeFile, stat } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import knexFactory from 'knex'

import { runMigrations } from 'mikser-io'
import { loadOrCreateKey, checkKeyContinuity } from '../lib/keys.js'
import '../lib/grants.js'   // registers the auth migrations

let dir, db
const quiet = { warn() {}, info() {}, notice() {}, error() {} }
const loud = () => { const seen = []; return { warn() {}, info() {}, notice() {}, error: (o) => seen.push(o), seen } }

beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'mikser-key-'))
    db = knexFactory({ client: 'better-sqlite3', connection: { filename: path.join(dir, 'd.sqlite') }, useNullAsDefault: true })
    await runMigrations(db, quiet)
})
afterEach(async () => {
    await db.destroy()
    await rm(dir, { recursive: true, force: true })
})

const keyFile = () => path.join(dir, 'auth.key')
const gitignore = () => path.join(dir, '.gitignore')

describe('keeping the signing key out of the repository', () => {
    it('gitignores the key it creates', async () => {
        await mkdir(path.join(dir, '.git'), { recursive: true })
        await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        assert.match(await readFile(gitignore(), 'utf8'), /^auth\.key\*$/m)
    })

    it('gitignores a key that already existed', async () => {
        // A deployment whose key predates this guard is exactly as exposed as
        // a new one — the file is already sitting there unignored.
        await mkdir(path.join(dir, '.git'), { recursive: true })
        await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        await rm(gitignore())
        await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        assert.match(await readFile(gitignore(), 'utf8'), /^auth\.key\*$/m)
    })

    it('still writes the key 0600', async () => {
        await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        assert.equal((await stat(keyFile())).mode & 0o777, 0o600)
    })
})

describe('noticing that the key changed', () => {
    it('records the kid on a first run without complaining', async () => {
        const key = await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        const logger = loud()
        const result = await checkKeyContinuity({ kid: key.kid, db, logger })
        assert.deepEqual(result, { recorded: true })
        assert.deepEqual(logger.seen, [], 'a first run is routine and must be silent')
    })

    it('says nothing on a restart with the same key', async () => {
        const key = await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        await checkKeyContinuity({ kid: key.kid, db, logger: quiet })
        const logger = loud()
        assert.deepEqual(await checkKeyContinuity({ kid: key.kid, db, logger }), { unchanged: true })
        assert.deepEqual(logger.seen, [])
    })

    it('raises a fault when the key was replaced', async () => {
        // The case that matters: auth.key deleted, regenerated on the next
        // boot. Every token anyone holds is now unverifiable, and the creation
        // warning alone reads exactly like a first run.
        const first = await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        await checkKeyContinuity({ kid: first.kid, db, logger: quiet })

        await rm(keyFile())
        const second = await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        assert.notEqual(second.kid, first.kid, 'a regenerated key is a different key')

        const logger = loud()
        const result = await checkKeyContinuity({ kid: second.kid, db, logger })
        assert.equal(result.changed, true)
        assert.equal(result.previous, first.kid)
        assert.equal(logger.seen[0]?.code, 'auth-signing-key-changed',
            'it has to be a fault, or ping cannot say why everyone was signed out')
    })

    it('reports null rather than "unchanged" with no store to compare against', async () => {
        // Absence of a comparison is not evidence the key is the same, and
        // returning `unchanged` here would be inventing the reassurance.
        const key = await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        assert.equal(await checkKeyContinuity({ kid: key.kid, db: null, logger: quiet }), null)
    })

    it('is a fault when the check itself cannot run', async () => {
        const key = await loadOrCreateKey({ keyFile: keyFile(), logger: quiet })
        await db.schema.dropTable('mikser_auth_signing_key')
        const logger = loud()
        assert.equal(await checkKeyContinuity({ kid: key.kid, db, logger }), null)
        assert.equal(logger.seen[0]?.code, 'auth-signing-key-changed')
    })
})
