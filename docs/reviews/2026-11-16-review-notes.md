# go-iam review (read-only)

Repo: `~/src/go-iam` @ `eb0824a` (branch `main`, clean tree)
Reviewer: review-agent, 2026-11-16

## Summary

go-iam is a small Fiber + MongoDB IAM server: OAuth2/OIDC login (Google, Microsoft,
GitHub, generic OIDC), JWT access tokens, clients/service accounts, and an
RBAC-shaped data model (projects → users → roles → resources → policies).

Toolchain results (Go 1.26.10):

| command | result |
|---|---|
| `go build ./...` | pass (exit 0) |
| `go vet ./...` | pass (exit 0) |
| `go test ./... -count=1` | pass, all packages |
| `go test ./... -cover` | 89–100% per package (`utils/test*`, `main`, `syncuser`, `utils/server` untested) |

The build is healthy, but **the security model is not**: the server authenticates
users and then trusts the caller for authorization. There is no admin/role check on
the management API, the tenant scope is taken from a client-controlled header, and
several parts of the OAuth2 token exchange do not actually verify the client. On top
of that, two reachable panics crash the process (no recover middleware), so a single
authenticated request can take down the IAM service.

Tests are broad but almost entirely mock-based: they prove handler wiring, not Mongo
query construction, real auth flows, or concurrency. High coverage here is not
evidence of correctness.

Note: no Mongo/Redis was available, so DB-semantics claims (`$in: null`, index
behaviour) are from reading the code, not execution.

---

## P1 — fix before this is exposed to anything

### 1. Tenant isolation is controlled by the client via `X-Project-Ids`
`utils/server/server.go:28`, `middlewares/projects/projects.go:44-58`,
`middlewares/auth/auth.go:145-150`

`prv.PM.Projects` is registered globally and does
`projectIds = strings.Split(headers["X-Project-Ids"][0], ",")` with no check against
the authenticated user. `middlewares.GetProjects(ctx)` is the *only* thing every
service uses to scope queries
(`services/user/store_impl.go:110`, `services/client/service_impl.go:36`,
`services/role/service_impl.go:42`, `services/resource/service_impl.go:23`,
`services/authprovider/service_impl.go:30`), and create/update paths check
membership against the same value (`services/client/service_impl.go:67,106`,
`services/authprovider/service_impl.go:49-70`). So any authenticated user can send
`X-Project-Ids: <victim project id>` and list/create/update/delete that tenant's
users, clients, roles, resources and auth providers. `auth.GetUser` only fills in
the token's project **when the header is absent**, which makes the header strictly
more powerful than the token.

Fix: derive the project scope from the authenticated principal only. If
multi-project switching is wanted, validate the requested ids against the user's
memberships/policies and reject anything else. Never let an unauthenticated header
widen `GetProjects`.

Related: `middlewares/auth/auth.go:145-150` is dead code — when the header is present
it neither sets a scope nor uses `projectIdsCsv`, so the variable is unused and a
request with the header ends up with a nil project list (Mongo queries then build
`{project_id: {$in: null}}`). Same file, same fix.

### 2. No authorization on the management API — authentication only
`routes/routes.go:24` and every `routes/*/router.go`

`RegisterAuthRoutes` applies `prv.AM.User` (who are you?) and nothing else. There is
no role/policy check anywhere in `routes/` or `middlewares/` — grep for
`PolicyCheck` finds it only inside `services/policy/system/*`, used by event
handlers, never by a request path. Any user who can log in through *any* client
(e.g. any Google account on a public client, or any user in a shared tenant) can:

- `PUT /client/:id` — change redirect URLs, `GoIamClient`, `LinkedUserId`, `Enabled`
- `PUT /client/:id/regenerate-secret` — and read the new plaintext secret
- create/update/delete users, roles, resources, projects, auth providers
- read every other user in the project, including their roles and policies

Combined with #1 this becomes cross-tenant takeover; on its own it is already a
complete authorization bypass relative to the product's promise.

Fix: define an admin policy/role and enforce it per route (or per route group) before
the handler. Given `RegenerateSecret` (`services/client/service_impl.go:137-158`)
calls `s.Get(ctx, id, true)` — skipping the project check — it should also require
the strongest permission.

### 3. `ClientCallback` issues tokens with no client authentication at all
`services/auth/service_impl.go:132-181`, `routes/auth/auth.go:214-226`

```go
isPublicClient  := len(codeChallenge) != 0
isPrivateClient := len(clientSecret) != 0
token, err := s.getAuthTokenFromCache(ctx, code)
if isPrivateClient { ...verify secret... }
if isPublicClient  { ...verify PKCE...  }
// no else: token is cached and a JWT is minted
```

If both values are empty, no verification runs. The route only requires that a
`Basic` header *parses* (`routes/auth/auth.go:333-352` splits `id:secret`), so
`Authorization: Basic base64(<any client id>:)` yields `clientSecret == ""` and the
auth code is exchanged for a full JWT. Auth codes travel in redirect URLs, so they
leak via browser history, referrer headers and proxy logs; a 60-second window with no
client authentication is enough.

Also: nothing verifies the caller-supplied `clientId` matches `token.ClientId` on the
private-client branch, so **any client with a valid secret can redeem another
client's code** and receive a token for that client's user (RFC 6749 §4.1.3 requires
this binding). `ClientCallback` also never checks `cl.Enabled` or that the client
still exists.

Fix: require exactly one of PKCE or client secret; reject an empty secret; compare
`token.ClientId == clientId`; load the client and check `Enabled` before minting.

### 4. Client-secret rotation never revokes the old secret
`services/auth/helpers.go:15-33`, `services/client/service_impl.go:137-158`

`handlePrivateClient` reads `client-<id>` from the cache first, and that key is
written with a **365-day TTL** (`time.Hour*24*365`). `RegenerateSecret` writes the DB
directly via `s.s.Update` (not the service `Update`), so no `EventClientUpdated` is
emitted, and the cache entry is neither deleted nor refreshed. Result: after
`PUT /client/:id/regenerate-secret` the **old secret keeps authenticating for up to a
year** on every instance, while the new secret may not work at all on instances whose
cache was never populated. This defeats the main reason to rotate a leaked secret.

Fix: invalidate `client-<id>` on create/update/regenerate/delete, keep the TTL short
(minutes), store the hash rather than the plaintext, and make rotation an event that
all instances handle.

### 5. `PUT /client/:id` destroys the stored secret (and mass-assigns privilege fields)
`services/client/store_impl.go:99-121`, `services/client/service_impl.go:104-120`,
`routes/client/client.go:210-250`

`store.Update` does `d := fromSdkToModel(*client); $set: d`. `Secret` is not
preserved from the existing document and is not re-hashed, unlike `Create`
(`store_impl.go:84-92`). A normal rename payload omits `secret`, so the stored hash
is overwritten with `""` — `VerifySecret` then rejects every login for that client,
permanently. If the caller echoes the value returned by `GET` (the SHA-256 hash) it is
stored as-is and happens to keep working; if the caller sends the plaintext it is
stored in plaintext and `VerifySecret` (which hashes the input) fails. On top of that
the same payload lets any authenticated user set `GoIamClient`, `LinkedUserId`
(impersonate any user via the client-credentials flow), `Enabled`, and `ProjectId`.

`Update` also emits `EventClientUpdated` with that payload secret, and
`services/auth/events.go:24-26` caches it for a year — so an empty/plaintext secret is
propagated to `client-<id>` and breaks or weakens the cache path (#4).

Fix: never accept `Secret` on update; load the existing document and only overwrite
fields explicitly present in a dedicated update DTO; never put secrets in event
payloads; require admin permission for the privileged fields.

### 6. Any authenticated user can crash the whole process (no panic recovery)
`services/policy/store_impl.go:28-49`; no `recover` middleware anywhere
(`utils/server/server.go`)

```go
if skip+limit > int64(len(policies)) { limit = int64(len(policies)) - skip }
...
result := pls[skip : limit+skip]
```

`GET /policy/v1/?skip=5` (3 built-in policies → `limit` clamped to 0, then
`pls[5:5]`) panics with slice bounds out of range. Filtering makes it worse:
`len(pls)` can be smaller than `len(policies)`, so the clamp is computed against the
wrong length. Fiber does not recover panics by default and no `recover.New()`
middleware is registered, so the process exits. Any authenticated user can therefore
take down the IAM service for everyone, including all login paths.

Two more panic paths to fix in the same pass:
- `services/encrypt/service_impl.go:49` — `by[:nonceSuze]` on a short/empty cache
  value panics instead of returning an error.
- `services/user/service_impl.go:225` — `newOwner.Resources[k].PolicyIds[id] = ...`
  panics when the target's `PolicyIds` map is nil (decoded `null`), reachable via
  `PUT /user/:id/transfer-ownership/...`.

Fix: register `recover.New()` as the first middleware (log + 500, don't leak), add
length/bounds validation, and convert the slice arithmetic into a helper that clamps
against `len(pls)`.

### 7. Auth-provider secrets are returned in plaintext by the API
`services/authprovider/store_impl.go:28-44,47-80`, `routes/authprovider/authprovider.go:85,124`

`decryptSecrets` is applied on every read, and the route serialises the whole
`sdk.AuthProvider`, including `params[].value` for `is_secret: true` — i.e. Google /
Microsoft / GitHub / OIDC client secrets in clear text. The endpoint is reachable by
any authenticated user (see #2), and those are the credentials go-iam uses to fetch
identities: leaking them lets an attacker impersonate the tenant's IdP client.

Fix: keep secrets write-only. Return a masked placeholder (or omit secret params) on
read, never log them, and combine with the authorization fix.

---

## P2 — correctness, security hardening, data integrity

1. **Token refresh is broken.** `services/auth/service_impl.go:332-341` caches the
   **old** token (`s.cacheAccessToken(ctx, token, accessToken)`) and returns the new
   one, which is only assigned to a local copy (`:310`). The new access/refresh token
   is never persisted, so every request re-refreshes from the expired token; with
   providers that rotate refresh tokens, auth breaks after the first refresh.
   Fix: `s.cacheAccessToken(ctx, *tk, accessToken)`.

2. **PKCE does not follow RFC 7636 and proves nothing.** Login stores the
   client-supplied `code_challenge`; `getRedirectUrl` (`service_impl.go:592-622`)
   appends `S256(stored)` to the callback URL; `handlePublicClient`
   (`services/auth/helpers.go:50-63`) compares `S256(stored)` with the value the
   client sends back. The "verifier" is never sent by the client and the challenge
   travels in the same URL as the code, so a leaked redirect URL is enough. Fix:
   store the challenge, require the client to send the original verifier at the token
   endpoint, compare `S256(verifier)` with the stored challenge.

3. **Auth code replay.** `ClientCallback` reads the code (`:144`), mints a token, and
   only deletes it afterwards (`:174`). Two concurrent verifies of the same code both
   succeed. Fix: atomic get-and-delete (`GETDEL`) before minting.

4. **Email-domain allowlist is checked once, too late, and case-sensitively.**
   `routes/auth/auth.go:240-249` calls `GetIdentity(..., force, client.AllowedEmailDomains)`
   *after* the access token was minted and the auth code consumed; on failure the token
   is not revoked, and later requests use `middlewares/auth/auth.go:141` with
   `emailDomains = nil`, so they are never re-checked. Matching uses
   `strings.HasSuffix(email, "@"+domain)` (`service_impl.go:226-241`) — `Alice@Example.COM`
   is rejected — and `AllowedEmailDomains` is only enforced for the non-service-account
   branch. Fix: normalise to lower case, enforce on every `GetIdentity`, and revoke the
   token (delete `access-token-<id>`) when the check fails.

5. **JWT tokens: hardcoded lifetime, no standard claims, no revocation.**
   `service_impl.go:169` and `:676` use `time.Now().AddDate(0,0,1)` — `TOKEN_CACHE_TTL_IN_MINUTES`
   and the `ServiceAccount` TTL config are ignored. Tokens carry only `{id, exp}`:
   no `iat`/`nbf`, `iss`, `aud`, or `jti`, and the HS256 secret has no length or
   strength validation (`config/config.go:276-280`); `sample.env` ships
   `JWT_SECRET=abcd`. A leaked token cannot be revoked except by deleting the cache
   entry (which also logs the user out of identity lookups). Fix: sign with a
   configured TTL, add `iss`/`aud`/`iat`/`jti`, validate the secret's strength at
   startup, and define a revocation path.

6. **Plaintext client secrets in Redis + a public default encryption key.**
   `services/auth/helpers.go:16,31` cache the plaintext client secret for 365 days;
   `config/config.go:219-226` silently falls back to an all-zero AES-256 key when
   `ENCRYPTER_KEY` is empty (it is empty in `sample.env`), and that key encrypts
   `AuthToken`s and cached user records in Redis. Anyone who can read Redis or an old
   backup can decrypt provider access/refresh tokens. Fix: fail fast when
   `ENCRYPTER_KEY` is unset/default, don't cache plaintext secrets, and rotate the key
   with a version tag.

7. **Login does not validate the client or the provider's tenant.**
   `GetLoginUrl` (`service_impl.go:41-70`) never checks `client.Enabled`, and when
   `auth_provider` is supplied it is looked up with `dontCheckProjects=true` — no check
   that the provider belongs to the client's project. A client can therefore run its
   login through another tenant's IdP credentials, and the resulting identity is
   created in *that* provider's project (`getAuthProivderIdentity:300`), which is how
   cross-tenant identity confusion happens. Fix: load the client with the project
   check, require `Enabled`, and require `provider.ProjectId == client.ProjectId`.

8. **Mass assignment and lost updates on `PUT /user/:id`.**
   `routes/user/user.go:236-274` bind the full `sdk.User`; `services/user/store_impl.go:46-64`
   then `$set`s the whole document (preserving only `CreatedAt`/`CreatedBy`). Callers
   can move a user to another project (`project_id`), flip `enabled`/`expiry`, and
   replace `roles`/`resources`/`policies` wholesale, and any field omitted from the
   payload is silently cleared. The read-modify-write is also racy: two concurrent
   updates (e.g. the policy event handlers write users from request goroutines) lose
   one another. Fix: dedicated update DTOs, project check, and `$set` only the changed
   fields (or add a version/`updated_at` precondition).

9. **By-ID reads/writes skip the tenant check.**
   `services/user/store_impl.go:81` (`GetById`), `services/role/service_impl.go:28,37`,
   `services/resource/store_impl.go:87,101,142`, `services/project/store_impl.go:26`.
   With ids obtained from logs/emails/previous tenants, any authenticated user can
   read or modify another tenant's records. `resource.Create` also accepts an
   arbitrary `project_id` from the body (`store_impl.go:101-110`). Fix: every store
   operation should take the caller's scope and filter on it; validate
   `project_id` on create.

10. **Auth middleware fails open.** `middlewares/auth/auth.go:65-79` (and
    `:97-107`) `return c.Next()` when `AuthClient == nil`. If the Go IAM client is
    deleted or never created (the README calls this "insecure mode"), every
    management endpoint is open to the world. Fix: fail closed and require an explicit
    `INSECURE_MODE=true` (logged loudly) for the bootstrap case.

11. **Data races on shared state.** `utils/events.go:27-39` keeps a plain
    `map`/slice with no mutex while `Emit` runs in request goroutines, and
    `providers/providers.go:172-186` assigns `p.AuthClient` / `p.AM.AuthClient` from
    the event handler while the auth middleware reads `m.AuthClient` on other
    goroutines. Fix: `sync.RWMutex` (or `atomic.Pointer`) and snapshot subscribers
    under a read lock.

12. **No database indexes.** `db/models/*.go` define field maps only; there is no
    `CreateIndexes` anywhere. Every `find`/`lookup` is a collection scan, and there is
    no unique constraint on `(project_id, email)` — two concurrent first logins can
    create duplicate users (`getOrCreateUser`, `service_impl.go:244-276`; no
    transaction/upsert). Fix: create indexes during startup/migration, including a
    unique compound index on `(project_id, email)`.

13. **Auth `state` handling is fragile and injectable.**
    `service_impl.go:530-565` joins six fields with `:` and splits on `:`, so a
    client `state` containing `:` makes every login fail; `getRedirectUrl`
    (`:614-616`) interpolates `state`/`code` into the callback URL without escaping,
    so `state=a&code=...` injects parameters into the client's callback. Fix: store
    the state as structured data keyed by an opaque id (no string packing) or at
    minimum `url.QueryEscape` every component.

14. **Health check is a DB amplifier.** `routes/health/health.go:75-90` calls
    `Projects.GetAll()` — a full, unscoped collection read — on every unauthenticated
    request. Fix: a real `Ping` with a short timeout, cached/throttled, and no data
    returned beyond up/down.

---

## P3 — maintainability, hygiene, tests

1. **Duplicate route registration.** `routes/me/router.go:18` registers
   `GET /me/v1/dashboard` without any auth middleware, after the protected version
   (`me.RegisterOpenRoutes`). It is currently unreachable because the first matching
   route wins, but it is an unauthenticated `DashboardMe` waiting for a reorder. Delete
   it.

2. **No server timeouts / body limits / rate limits.** `main.go:14-16` sets only
   `ReadBufferSize`; `utils/server/server.go:26` uses default CORS (`*`). For an auth
   server add `ReadTimeout`/`WriteTimeout`/`IdleTimeout`, `BodyLimit`, a login/token
   rate limit, and an explicit CORS allowlist.

3. **Error detail leaks to clients.** e.g. `routes/client/client.go` and
   `routes/auth/auth.go:283-296` return `err.Error()` (DB and provider messages) and
   distinguish 404 for unknown client ids from 401 for bad secrets, which enumerates
   clients. Log details, return generic messages.

4. **Broken format verbs.** `main.go:30` `log.Fatal("failed to create OpenAPI doc: %w", err)`
   (Fiber's `log.Fatal` is not `fmt.Errorf`), `services/auth/helpers.go:17,32`
   `log.Errorf(... %w ...)`. Use `%v` or `fmt.Errorf` before logging.

5. **Startup depends on docs generation.** `main.go:28-31` exits if
   `docs/goiam.yaml` cannot be written (read-only FS, wrong cwd). Make it best-effort.

6. **Config gaps.** `SERVER_HOST` is loaded but ignored — `app.Listen(":"+port)`
   binds all interfaces (`main.go:34`). `REDIS_DB` is loaded but
   `services/cache/service_impl.go:16` hardcodes DB 0. Redis is never pinged, so a
   wrong host surfaces as per-request errors. `LoadEncrypterConfig` panics on bad hex
   (acceptable) but silently accepts an empty key (#P2-6).

7. **Migration hygiene.** `db/migrations/001_update_user_policies.go:70,142` uses
   `defer cursor.Close(...)` inside the pagination loop, so every batch's cursor is
   held until the function returns; skip-based pagination while writing to the same
   collection is also fragile. Close cursors per iteration and page by `_id`.

8. **`force_fetch` is client-controlled.** `middlewares/auth/auth.go:141` lets any
   request bypass the identity cache (`?force_fetch=true`) and hit the IdP/DB, which
   is a cheap amplification vector; restrict it to trusted callers or rate-limit it.

9. **Stub policy store.** `services/policy/store_impl.go:17-60` returns three
   hard-coded policies and does no persistence; `PolicyCheck` exists but nothing
   evaluates policies at request time. The product advertises fine-grained
   authorization, yet there is no decision endpoint and no enforcement — consumers
   can only read raw user documents (see P1-2/P2-9). Worth deciding what the contract
   is before users rely on it.

10. **Event bus runs handlers synchronously in the request path.**
    `utils/events.go:30-36` — `user.Update` fans out to `syncuser`, which calls the
    IdP over HTTP while the API request waits. `syncuser` also usually fails: it looks
    up `user-token-<id>` (`service_impl.go:365,376`), which is written with a
    `refetchTTL` (default 1 minute) TTL, so most updates log
    `failed to synchronize identity`. Make events async with a bounded queue, and give
    the reverse mapping the token's own TTL.

11. **`getUserFromCache` ignores account state.** `service_impl.go:383-406` returns
    the cached user without re-checking `Enabled`/`Expiry`, so a disabled user keeps
    working for up to `refetchTTL`. Acceptable if TTL is small (it is 1 min by
    default), but it is a second, implicit source of truth — document it or check.

12. **Cache mock is fragile.** `services/cache/mock.go:47-57` manually
    `RUnlock`/`Lock`/`RUnlock` inside a deferred unlock; correct today, easy to break.
    It is also the default when Redis is disabled, so it masks production behaviour.
    Note that `cache.NewMockService` is used in `providers.go` when `ENABLE_REDIS` is
    false — multi-instance deployments silently lose all token state.

13. **Tests: broad but shallow.** There are no tests for `main`, `services/auth/syncuser`,
    `utils/server`, and almost all service/store tests use hand-written mocks, so
    Mongo query construction, cache-key semantics and the OAuth flows are unverified.
    `middlewares/auth` has no test touching `X-Project-Ids`; `routes` tests never
    exercise the project-scope path. CI lowered the coverage gate from 90% to 89%
    (`d669723`). Google/Microsoft provider tests hit the network (`google` 3–11 s,
    `microsoft` 30 s), which is slow and flaky. Add: a testcontainers-style Mongo
    integration suite for stores, an end-to-end login→verify→authenticated-request
    test, table tests for `GetProjects` authorization, and `-race` runs that actually
    exercise concurrent client/user updates.

14. **Duplicated wiring.** `GetGoIamClient` + middleware construction is repeated in
    `providers.InjectDefaultProviders` and `utils/test/server/setup.go`, and
    `NewAccessToCreatedResource(nil)` is used as an ID/name accessor in
    `services/policy/system/default_policies_on_user.go:32` and the migration — a
    nil-service object that panics if anyone calls its handler. Give the policy
    definitions standalone constructors.

---

## Suggested order of work

1. Fail closed + admin authorization + project scope from the token (P1-1, P1-2, P2-10).
   These are one design change and unblock everything else.
2. Fix the token endpoint: empty secret, client binding, code atomicity, PKCE, secret
   rotation/cache (P1-3, P1-4, P2-2, P2-3, P2-5).
3. Stop leaking secrets: provider params, client `secret` on GET, plaintext cache,
   default encrypter key (P1-7, P2-6).
4. Crash-proofing: `recover`, bounds checks, nil maps (P1-6), then timeouts/limits.
5. Fix `PUT /client` and `PUT /user` update semantics + indexes (P1-5, P2-8, P2-12).
6. Tests that actually exercise Mongo and the auth flow (P3-13).
