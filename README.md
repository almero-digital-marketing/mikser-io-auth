# mikser-io-auth

> Authentication for mikser — HTTP Basic and JWT over Apache-format
> `htpasswd` / `htgroup` files in the working folder.

## What it is

Mikser's engine ships an authentication *seam* (ADR-0012): a verifier
contract, a constant-time static-token verifier, and the loopback policy
that used to be hand-copied into every plugin that mounted a route. It ships
no identity — no users, no groups, no login.

This package is the identity half. It plugs in wherever a static token
plugs in, because it implements the same contract:

```js
{ name, async verify(req), challenge?(req, res) }
```

**Design choices, and why:**

- **Users and groups are files, not a database.** `users.htpasswd` and
  `groups.htgroup` sit in the working folder next to the content they
  govern. That is ADR-0002 applied to identity: reviewable in a pull
  request, diffable, deployable by copying a directory, editable with
  `htpasswd(1)` — a tool that predates every framework this project will
  outlive. The format is not ours to version or migrate.

- **The files are provisioned, never written at runtime.** No signup, no
  password reset, no "create user" tool. A build tool has operators, not
  members. The moment mikser writes an htpasswd file it has a locking
  problem and a database it won't admit to. Edits *are* picked up without a
  restart — the files are re-read when their mtime moves.

- **bcrypt is the format worth trusting.** `$apr1$` and `{SHA}` are
  supported because `htpasswd` emits them and an operator's existing file
  should keep working; both are weak. DES-crypt and MD5-crypt are refused
  outright rather than half-supported — silently rejecting is safer than a
  subtly wrong implementation that accepts something. Use `htpasswd -B`.

- **The signing key is a file, not a boot-time secret.** Regenerating a key
  on boot silently invalidates every live token whenever the process
  cycles, which presents as an intermittent auth bug and is miserable to
  diagnose. `auth.key` is written `0600` on first run and reused after.

- **Scope is computed from the files, never from the request.** A client
  cannot ask for capabilities it doesn't hold. Downstream enforcement is
  scope-only with no per-request re-read, which is safe *because* of this
  invariant — it is the load-bearing piece, not optional hardening.

- **Basic for people, JWT for clients.** HTTP Basic is browser-native and
  needs no flow, which makes it right for `api` / `forms` / `decap`. MCP
  clients expect Bearer and a discovery document, so they get JWT.

## Use

The whole thing, minimally:

```js
import { auth } from 'mikser-io-auth'
import { api }  from 'mikser-io'
import { mcp }  from 'mikser-io-mcp'

const identity = auth()

export default async () => ({
    plugins: [
        identity,
        api({ endpoints: { admin:  { auth: identity } } }),
        mcp({ endpoints: { remote: { auth: identity } } }),
    ],
})
```

That is a working setup. `htpasswd -B -c users.htpasswd alice` and you can
sign in; an agent can self-register and connect. Everything below is
optional and narrows what you already have.

`identity` is both the plugin and the verifier, so `auth: identity` accepts
whichever credential the caller has — Basic from a browser, Bearer from an
agent. Use `identity.basic()` or `identity.jwt()` only to deliberately
exclude one.

With no capability map configured, an authenticated user is **unscoped**:
the endpoint's own `operations` list is the only limit, exactly as for a
static token. Add capabilities when you want them to mean something:

```js
const identity = auth({
    // paths are relative to the working folder; these are the defaults
    users:  'users.htpasswd',
    groups: 'groups.htgroup',
    key:    'auth.key',

    // groups → capabilities. The files stay pure identity; this decides
    // what a group is allowed to do. Once this exists, a user whose groups
    // grant nothing can do nothing.
    capabilities: {
        editors: ['api:update', 'mcp:use'],
        admins:  ['api:update', 'api:delete', 'mcp:use'],
    },

    // groups → rows, ANDed with the endpoint's own query
    scopes: {
        editors: { 'meta.href': { $regex: '^/web' } },
    },

    issuer: 'https://cms.example.com',
})
```

The sign-in page names the deployment from mikser's own external URL
(`runtime.options.url`), falling back to the host you connected to. It is
not a config option — the host in the address bar is the most honest name
there is, because it *is* the thing in front of you and so cannot name a
different deployment.

`auth()` returns a value that is both the lifecycle plugin and the factory
for the verifiers — because config is evaluated before the runtime exists,
so a verifier has to be nameable at config time while its store can only be
opened once the working folder is known. Verifiers resolve their store
lazily; plugin order doesn't matter, and forgetting to add `identity` to
`plugins:` fails with a message saying so.

### The files

```
<workingFolder>/
    users.htpasswd      alice:$2y$10$…          htpasswd -B -c users.htpasswd alice
    groups.htgroup      editors: alice bob
    auth.key            {"kid":…,"privateJwk":…}   generated on first run, 0600
```

Keep `auth.key` out of version control — losing it invalidates every issued
token; leaking it lets anyone mint one.

### Endpoints

Mounted at `base` (default `/auth`) when mikser runs with `--server`:

| | |
| --- | --- |
| `GET /auth/authorize` | the sign-in page |
| `POST /auth/authorize` | verify against `users.htpasswd`, redirect back with a code |
| `POST /auth/token` | `authorization_code`, `refresh_token`, or `password` |
| `POST /auth/register` | RFC 7591 self-registration — the only way a client exists |
| `GET /auth/jwks.json` | the public half of the signing key |
| `GET /auth/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `GET /auth/logo.svg` | the mark on the sign-in page |

For a script or CLI, skip the browser entirely:

```bash
curl -u alice:alice-pw -X POST https://cms.example.com/auth/token
```

### Clients — there is no client config

Agents register themselves (RFC 7591). There is no list to maintain, no
per-agent redirect to write down, and no way to declare one.

A `clients:` map sounds harmless and isn't: it makes the set of agents that
can connect equal to the set somebody thought to write down, so every new
agent becomes a config change and a deploy. And an agent whose UI takes a
URL and nothing else has no field to type a `client_id` into — it registers
or it cannot connect at all.

Tune the bounds if you need to:

```js
auth({ dcr: { maxPerIp: 5, windowMs: 3600_000, maxClients: 1000 } })
```

Public clients either way: PKCE (S256) required, no `client_secret`, because
a browser or a native agent cannot keep one.

`POST /auth/register` is **unauthenticated by necessity** — you need a
`client_id` before you can authenticate, so a token requirement would make the
endpoint useless to the only callers that need it. That is safe because a
registered client can do nothing on its own: it holds no tokens and represents
no person, and cannot act until someone signs in on the page, where what they
can do comes from their groups rather than from anything the client asked for.
What is at risk is table volume, not access — hence `maxPerIp` (in-process,
counts every request including rejected ones) and `maxClients` (a row count,
the bound that survives a restart).

Registration names are attacker-controlled, so they are length-capped and
HTML-escaped where they render.

Every registration mints a **new** `client_id` — RFC 7591 has no get-or-create
— so a reinstall or a second machine leaves another row behind. Registrations
nobody ever signed in with are pruned after `pruneClientsAfterDays` (30).

### Redirect URIs

Matched exactly, with one exception: RFC 8252 §7.3 requires the **port of a
loopback URI to be ignored**, because a native client binds an ephemeral port
it cannot know in advance. Every MCP client that opens a browser depends on
this. Scheme, host, path, query and fragment still match exactly.

A self-registering client is held to a stricter rule than an operator writing
config, because nobody reviewed it: `https` anywhere, `http` only on loopback,
and never a fragment.

### The sign-in page

Deliberately identical to WhiteBox's — same layout, type scale, tokens and
pending state — because mikser and WhiteBox are the same company's products
and someone who administers both should not have to wonder which one they are
looking at. The mark is the only difference, and `logo:` overrides it.

The page names two things, and the second is the one that matters: **which**
deployment (`appName`), and **who** is asking for access (the client). Without
the second, signing in to your own site and handing an agent your permissions
look identical.

### Grants

Authorization codes (60s, single-use) and refresh tokens (30d, rotated on
every use) live in the engine's sqlite (ADR-0009), under `mikser_auth_*`.
Identity stays in files; this is session bookkeeping.

The engine wipes that database when its schema stamp or config checksum
changes — an upgrade, or any deploy that edits `mikser.config.js`. These
tables are registered `durable: true`, so the wipe drops table by table and
keeps them: a registered client and its refresh token exist only because a
human completed a sign-in once, and they are not something the working folder
can rebuild.

### When an access token expires

Access tokens are short (`ttl`, default `1h`) and refresh tokens are long, so
a client is expected to notice the expiry and exchange quietly. It can only do
that if the resource server *says* which failure it hit, and the vocabulary is
RFC 6750 §3.1:

| Situation | Status | `WWW-Authenticate` | What a client should do |
| --- | --- | --- | --- |
| no credential presented | 401 | no `error` — the omission is the signal | start a sign-in |
| access token expired | 401 | `error="invalid_token"`, `error_description="The access token expired"` | exchange the refresh token, retry |
| token malformed, wrong audience, wrong key | 401 | `error="invalid_token"` | sign in again; refreshing will not help |
| token valid, subject lacks the capability | 403 | `error="insufficient_scope"`, `scope="<capability>"` | do NOT refresh — a fresh token is refused identically |

All four used to be one byte-identical 401. A client cannot tell "your token
went stale" from "you have never authenticated here" in that state, so it does
the safe thing and starts a whole new authorization flow — a human, a browser,
mid-task, with a perfectly good refresh token in hand.

The verifier reports which one it hit through `rejectionFor(req)`, an optional
method on the engine's ADR-0012 verifier contract. It can only *narrow* a
denial that has already happened; there is nothing it can return that turns a
rejection into an acceptance.

## Not implemented

Deliberately out of scope: self-service registration, password reset, invites,
and any cross-plugin permission catalog. A build server has operators, not
members.

## Auth on a mikser endpoint

Reachability is unchanged from the engine's rule, with one difference that
matters:

| config | behaviour |
| --- | --- |
| nothing | loopback only, unless `allowRemote` |
| `token: '…'` | valid token from anywhere; loopback still reaches it *without* the token |
| `auth: identity.basic()` | the verifier gates every request — **no loopback bypass** |
| `auth: identity.jwt()` | same, plus RFC 9728 discovery on MCP endpoints |

A static token keeps the internet out, not the developer running the build.
A real verifier gets no bypass: if you wired it up, an unauthenticated
loopback caller — another process on a shared box, an SSRF hop — is exactly
what you were buying protection from.
