import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import bcrypt from 'bcryptjs'

import { parseHtpasswd, parseHtgroup, verifyPassword, createIdentityStore } from '../lib/htpasswd.js'

describe('parseHtpasswd', () => {
    it('reads user:hash, skipping comments and blank lines', () => {
        const users = parseHtpasswd('# a comment\n\nalice:$2a$10$abc\nbob:{SHA}xyz\n')
        assert.deepEqual([...users.keys()], ['alice', 'bob'])
        assert.equal(users.get('alice'), '$2a$10$abc')
    })

    it('splits on the FIRST colon only, so a hash keeps any it contains', () => {
        const users = parseHtpasswd('alice:$apr1$a:b$c\n')
        assert.equal(users.get('alice'), '$apr1$a:b$c')
    })

    it('ignores malformed lines rather than throwing', () => {
        const users = parseHtpasswd('nocolon\n:noname\nalice:hash\n')
        assert.deepEqual([...users.keys()], ['alice'])
    })
})

describe('parseHtgroup', () => {
    it('reads "group: members", split on any whitespace', () => {
        const groups = parseHtgroup('editors: alice   bob\nviewers: carol\n')
        assert.deepEqual([...groups.get('editors')], ['alice', 'bob'])
        assert.deepEqual([...groups.get('viewers')], ['carol'])
    })

    it('accumulates a group repeated across lines, as Apache does', () => {
        const groups = parseHtgroup('editors: alice\neditors: bob\n')
        assert.deepEqual([...groups.get('editors')], ['alice', 'bob'])
    })

    it('tolerates an empty group', () => {
        const groups = parseHtgroup('empty:\n')
        assert.deepEqual([...groups.get('empty')], [])
    })
})

describe('verifyPassword', () => {
    it('accepts bcrypt, including the $2y$ prefix htpasswd -B emits', () => {
        const hash = bcrypt.hashSync('s3cret', 10)
        assert.equal(verifyPassword(hash, 's3cret'), true)
        assert.equal(verifyPassword(hash, 'wrong'), false)
        assert.equal(verifyPassword(hash.replace(/^\$2[ab]\$/, '$2y$'), 's3cret'), true)
    })

    it('matches openssl for $apr1$, empty password included', () => {
        // Generated with: openssl passwd -apr1 -salt Xy3Zq8Lm <password>
        assert.equal(verifyPassword('$apr1$Xy3Zq8Lm$.f38Fzaj.hL2hlw7nUzyU0', 'secret'), true)
        assert.equal(verifyPassword('$apr1$Xy3Zq8Lm$S/NLPnpu5C6dtylCJZrAE.', 'password'), true)
        assert.equal(verifyPassword('$apr1$Xy3Zq8Lm$6AX7I0yPbQ0CvK/8r.ZfL0', ''), true)
        assert.equal(verifyPassword('$apr1$Xy3Zq8Lm$QxwZvfxeHTo8vpjS3o5fy1', 'a-much-longer-passphrase-here'), true)
        assert.equal(verifyPassword('$apr1$Xy3Zq8Lm$.f38Fzaj.hL2hlw7nUzyU0', 'secre'), false)
    })

    it('accepts {SHA}', () => {
        assert.equal(verifyPassword('{SHA}/vNB+F2HQ559kaLUZbmHHvZrXpg=', 's3cret'), true)
        assert.equal(verifyPassword('{SHA}/vNB+F2HQ559kaLUZbmHHvZrXpg=', 'nope'), false)
    })

    it('refuses DES-crypt and MD5-crypt rather than half-supporting them', () => {
        assert.equal(verifyPassword('abJnggxhB/yWI', 's3cret'), false)
        assert.equal(verifyPassword('$1$salt$dGVzdA', 's3cret'), false)
    })

    it('never throws on junk', () => {
        assert.equal(verifyPassword(null, 'x'), false)
        assert.equal(verifyPassword('', 'x'), false)
        assert.equal(verifyPassword('$2a$notavalidhash', 'x'), false)
        assert.equal(verifyPassword('$2a$10$abc', 12345), false)
    })
})

describe('createIdentityStore', () => {
    let dir, usersFile, groupsFile

    before(async () => {
        dir = await mkdtemp(path.join(tmpdir(), 'mikser-auth-'))
        usersFile  = path.join(dir, 'users.htpasswd')
        groupsFile = path.join(dir, 'groups.htgroup')
        await writeFile(usersFile, [
            `alice:${bcrypt.hashSync('alice-pw', 10)}`,
            `bob:${bcrypt.hashSync('bob-pw', 10)}`,
            `carol:${bcrypt.hashSync('carol-pw', 10)}`,
        ].join('\n') + '\n')
        await writeFile(groupsFile, 'editors: alice bob\nadmins: alice\n')
    })

    after(async () => { await rm(dir, { recursive: true, force: true }) })

    const store = () => createIdentityStore({
        usersFile, groupsFile,
        groups: { editors: ['api:update', 'mcp:use'], admins: ['api:delete'] },
    })

    it('authenticates and unions capabilities across every group', async () => {
        const p = await store().authenticate('alice', 'alice-pw')
        assert.equal(p.subject, 'alice')
        assert.deepEqual(p.groups.sort(), ['admins', 'editors'])
        assert.deepEqual(p.capabilities.sort(), ['api:delete', 'api:update', 'mcp:use'])
    })

    it('gives a user only their own groups capabilities', async () => {
        const p = await store().authenticate('bob', 'bob-pw')
        assert.deepEqual(p.capabilities.sort(), ['api:update', 'mcp:use'])
    })

    it('authenticates a user in no group, with no capabilities', async () => {
        const p = await store().authenticate('carol', 'carol-pw')
        assert.equal(p.subject, 'carol')
        assert.deepEqual(p.capabilities, [])
    })

    it('rejects a wrong password and an unknown user identically', async () => {
        assert.equal(await store().authenticate('alice', 'nope'), null)
        assert.equal(await store().authenticate('nobody', 'nope'), null)
    })

    it('ignores a group naming a user who does not exist', async () => {
        const s = createIdentityStore({
            usersFile, groupsFile,
            groups: { ghosts: ['api:delete'] },
        })
        const p = await s.authenticate('alice', 'alice-pw')
        assert.deepEqual(p.capabilities, [])
    })

    it('picks up an edit to the users file without a restart', async () => {
        const s = store()
        assert.equal(await s.authenticate('dave', 'dave-pw'), null)
        await writeFile(usersFile, `dave:${bcrypt.hashSync('dave-pw', 10)}\n`, { flag: 'a' })
        // mtime granularity can collapse two writes in the same millisecond.
        await new Promise(r => setTimeout(r, 12))
        await s.reload()
        const p = await s.authenticate('dave', 'dave-pw')
        assert.equal(p?.subject, 'dave')
    })

    it('refuses everyone when the users file is missing, without throwing', async () => {
        const s = createIdentityStore({ usersFile: path.join(dir, 'nope.htpasswd') })
        assert.equal(await s.authenticate('alice', 'alice-pw'), null)
    })

    it('works with no groups file at all', async () => {
        const s = createIdentityStore({ usersFile })
        const p = await s.authenticate('alice', 'alice-pw')
        assert.equal(p.subject, 'alice')
        assert.deepEqual(p.capabilities, [])
    })
})

describe('group → row scope (principal-bound scope)', () => {
    let dir, usersFile, groupsFile

    before(async () => {
        dir = await mkdtemp(path.join(tmpdir(), 'mikser-auth-scope-'))
        usersFile  = path.join(dir, 'users.htpasswd')
        groupsFile = path.join(dir, 'groups.htgroup')
        await writeFile(usersFile, ['alice', 'bob', 'carol', 'dan'].map(
            u => `${u}:${bcrypt.hashSync(`${u}-pw`, 10)}`).join('\n') + '\n')
        await writeFile(groupsFile, [
            'web-editors: alice dan',
            'franchise-editors: bob dan',
            'staff: carol',            // a group with capabilities but no scope
        ].join('\n') + '\n')
    })

    after(async () => { await rm(dir, { recursive: true, force: true }) })

    const store = () => createIdentityStore({
        usersFile, groupsFile,
        groups: {
            'web-editors':       ['api:list', 'api:update'],
            'franchise-editors': ['api:list', 'api:update'],
            'staff':             ['api:list'],
        },
        scopes: {
            'web-editors':       { 'meta.href': { $regex: '^/web' } },
            'franchise-editors': { 'meta.href': { $regex: '^/franchise' } },
        },
    })

    it('gives a single-group user that group\'s filter verbatim', async () => {
        const p = await store().authenticate('alice', 'alice-pw')
        assert.deepEqual(p.scope, { 'meta.href': { $regex: '^/web' } })
    })

    it('unions across groups with $or — more groups means MORE reach, not less', async () => {
        // Intersecting would make every extra group make a user less able,
        // which is never what an operator means by adding one.
        const p = await store().authenticate('dan', 'dan-pw')
        assert.deepEqual(p.scope, {
            $or: [
                { 'meta.href': { $regex: '^/web' } },
                { 'meta.href': { $regex: '^/franchise' } },
            ],
        })
    })

    it('leaves a user in no scoped group unscoped — the endpoint is their only limit', async () => {
        const p = await store().authenticate('carol', 'carol-pw')
        assert.equal(p.scope, null)
        assert.deepEqual(p.capabilities, ['api:list'])
    })

    it('is null when no scopes are configured at all', async () => {
        const s = createIdentityStore({ usersFile, groupsFile, groups: { 'web-editors': ['api:list'] } })
        assert.equal((await s.authenticate('alice', 'alice-pw')).scope, null)
    })

    it('picks up a group-membership edit without a restart', async () => {
        const s = store()
        assert.equal((await s.authenticate('carol', 'carol-pw')).scope, null)
        await writeFile(groupsFile, 'web-editors: carol\n', { flag: 'a' })
        await new Promise(r => setTimeout(r, 12))
        await s.reload()
        assert.deepEqual((await s.authenticate('carol', 'carol-pw')).scope,
                         { 'meta.href': { $regex: '^/web' } })
    })
})
