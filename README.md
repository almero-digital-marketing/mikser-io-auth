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
| `POST /auth/token` | htpasswd credentials → a JWT. Accepts form/JSON `username`+`password`, or HTTP Basic. |
| `GET /auth/jwks.json` | the public half of the signing key |
| `GET /auth/.well-known/oauth-authorization-server` | RFC 8414 metadata |

```bash
curl -u alice:alice-pw -X POST https://cms.example.com/auth/token
```

## Not implemented yet

**The browser-facing authorization-code + PKCE flow.** What's here is the
credentials grant: enough for a script, a CLI, or an MCP client configured
with a token out of band. An MCP client that expects to open a browser and
log in unattended needs the full authorization server — an `/authorize`
endpoint, a login form, a code store, and refresh rotation. That's most of
what WhiteBox's `server-plugin-oauth` is, and it is a deliberate decision
still open rather than an oversight.

Also out of scope, deliberately: self-service registration, password reset,
invites, and any cross-plugin permission catalog.

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
