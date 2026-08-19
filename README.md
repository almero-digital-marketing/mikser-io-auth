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

```js
import { auth }   from 'mikser-io-auth'
import { api }    from 'mikser-io'
import { mcp }    from 'mikser-io-mcp'

const identity = auth({
    // paths are relative to the working folder
    users:  'users.htpasswd',
    groups: 'groups.htgroup',
    key:    'auth.key',

    // groups → capabilities. The files stay pure identity; this decides
    // what a group is allowed to do.
    capabilities: {
        editors: ['api:update', 'mcp:use'],
        admins:  ['api:update', 'api:delete', 'mcp:use'],
    },

    issuer: 'https://cms.example.com',
})

export default async () => ({
    plugins: [
        identity,
        api({ endpoints: { admin:  { auth: identity.basic() } } }),
        mcp({ endpoints: { remote: { auth: identity.jwt() } } }),
    ],
})
```

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
| `GET /auth/jwks.json` | the public half of the signing key |
| `GET /auth/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `GET /auth/logo.svg` | the mark on the sign-in page |

For a script or CLI, skip the browser entirely:

```bash
curl -u alice:alice-pw -X POST https://cms.example.com/auth/token
```

### Clients

Declared in config — no Dynamic Client Registration. DCR is convenient for a
multi-tenant SaaS and a real attack surface for a self-hosted build server.
Public clients only: PKCE (S256) is required and there is no `client_secret`,
because a browser or an MCP client cannot keep one.

```js
auth({
    appName: 'GPoint CMS',       // shown on the sign-in page
    clients: {
        claude: {
            name: 'Claude',      // shown as "to give Claude access"
            redirectUris: ['http://127.0.0.1/callback'],
        },
    },
})
```

Redirect URIs match exactly, with one exception: RFC 8252 §7.3 requires the
**port of a loopback URI to be ignored**, because a native client binds an
ephemeral port it cannot know in advance. Every MCP client that opens a
browser depends on this. Scheme, host, path, query and fragment still match
exactly.

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

The engine wipes that database when its schema stamp changes, so **upgrading
mikser signs everyone out**. Codes are irrelevant at 60 seconds; re-issuing
refresh tokens after an engine upgrade is the price of not inventing a second
persistence story.

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
