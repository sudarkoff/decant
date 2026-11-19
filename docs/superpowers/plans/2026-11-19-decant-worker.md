# decant Worker (v1, plan 1 of 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A deployable Cloudflare Worker that serves npm and Go packages through a per-project policy (cooldown, allow list, global blocks), keeps everything it serves in R2, and exposes the admin API the GitHub Action (plan 2) will call.

**Architecture:** One Worker, `src/index.ts`, routes to the npm, Go and admin handlers. Raw upstream data (npm documents, Go lists and `.info` files) is cached in R2 with a 5-minute freshness window and served stale when upstream fails. Policy is applied at request time from D1, so blocks and allows take effect on the next request. Handlers receive injected `Deps` (`fetch`, `now`), so tests are deterministic and never touch the network.

**Tech Stack:** TypeScript, Cloudflare Workers, R2, D1, Cron Triggers, vitest + `@cloudflare/vitest-pool-workers`. No runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-11-19-decant-design.md`

## Global Constraints

- **No runtime dependencies.** `dependencies` in `package.json` stays empty. Dev dependencies are limited to `wrangler`, `typescript`, `vitest`, `@cloudflare/vitest-pool-workers` and `@cloudflare/workers-types`, each pinned exactly. Install with `npm install --save-exact --before=<today−7d>` so decant obeys its own cooldown.
- **Scripts are off for all installs:** `.npmrc` has `ignore-scripts=true`, and CI runs `npm ci --ignore-scripts`.
- **Package bytes are never modified.** npm `integrity`/`shasum` and Go `.mod`/`.zip` are served exactly as fetched.
- **Fail closed.** An unknown publish time hides the version. A publish time that changes upstream blocks it. An unverifiable advisory rejects the sync.
- **Freshness:** raw upstream metadata is considered fresh for 300 s. The filtered output is never cached (`Cache-Control: no-store`).
- **Defaults:** cooldown 7 days. `autoShip` defaults to critical and high `auto`, moderate and low `approve`. Overlays expire 14 days after their last sync. Lazy Go `.info` fetches are capped at 10 per request.
- **Upstreams:** `https://registry.npmjs.org`, `https://proxy.golang.org`, `https://api.osv.dev`.
- **Tokens:** never logged, stored as SHA-256 hex. Format `dk_<kind>_<43 chars base64url of 32 random bytes>`, where kind is `read`, `ci` or `op`.
- **Commits are signed** (git is already configured). Work happens on a branch; nothing is pushed to `main`.
- **No deploy** until George names the Cloudflare account and domain.

## Review Focus

1. **Scoped npm names in every encoding:** `@scope%2fname`, `@scope%2Fname` and `@scope/name` must resolve on both metadata and tarball routes. Owned by Task 8.
2. **A package whose versions are all still in cooldown** returns 200 with `versions: {}` and `dist-tags: {}`, never a 500 or an unfiltered document. Owned by Task 7.
3. **Upstream down with nothing cached** returns 502 with a plain message. With a cached copy it serves stale and sets `X-Decant-Stale: 1`. Owned by Task 6.
4. **Go modules with uppercase letters** (e.g. `github.com/Azure/azure-sdk-for-go`) round-trip through `!`-escaping on every route. Owned by Task 9.
5. **Isolation:** a token for project A can't read with B's overlay, can't sync B's policy, and main-ref reads never see overlay allows. Owned by Tasks 3 and 5.

---

## File Structure

```
package.json, tsconfig.json, wrangler.jsonc, vitest.config.ts, .npmrc
.github/workflows/ci.yml          decant's own CI (SHA-pinned)
migrations/0001_init.sql          D1 schema
schema/policy.json                JSON Schema for decant.json
src/index.ts                      fetch + scheduled entry, router
src/types.ts                      Env, Deps, Ecosystem, PackageRef, ids
src/http.ts                       json(), error(), noStore helpers
src/auth.ts                       token generation/hashing, request → AuthCtx
src/semver.ts                     parse/compare for npm and Go versions
src/policy/schema.ts              decant.json validation
src/policy/decide.ts              pure version decision
src/policy/store.ts               D1: policies, allows, blocks, version times, verdicts, serve log
src/osv.ts                        OSV client: advisory verification, MAL lookup
src/upstream.ts                   R2-backed cached fetch, single-flight, stale-serve
src/npm/filter.ts                 pure document filtering
src/npm/handler.ts                npm routes
src/go/escape.ts                  module path escaping
src/go/handler.ts                 GOPROXY routes
src/admin/handler.ts              /api/* routes
src/cron.ts                       MAL re-check, overlay expiry
scripts/decant.ts                 operator CLI (Node ≥ 23.6, no deps)
docs/deploy.md                    deploy guide
test/helpers.ts                   fake upstream, seeding, fixed clock
test/*.test.ts                    one file per src module
```

## Shared types (`src/types.ts`, created in Task 1, referenced everywhere)

```ts
export type Ecosystem = 'npm' | 'go';
export interface PackageRef { eco: Ecosystem; name: string; version: string }
export interface Env { DB: D1Database; BUCKET: R2Bucket; OPERATOR_TOKEN_HASH: string }
export interface Deps { fetch: typeof fetch; now: () => Date }
export function formatPackageId(p: PackageRef): string;      // "npm:@s/n@1.2.3", "go:github.com/x/y@v1.2.3"
export function parsePackageId(id: string): PackageRef | null; // splits on the LAST '@'; name may start with '@'
```

---

### Task 1: Scaffold, schema, CI

**Files:** Create everything in the file structure above except `src/**` beyond `index.ts`, `types.ts` and `http.ts`. Also create `test/types.test.ts` and `test/health.test.ts`.

**Interfaces:**
- Produces: `src/types.ts` (above). `handle(req: Request, env: Env, deps: Deps, ctx: ExecutionContext): Promise<Response>` exported from `src/index.ts`, with `export default { fetch, scheduled }` built on top of it. `test/helpers.ts`:
  - `fixedClock(iso: string): () => Date`
  - `fakeFetch(routes: Record<string, Response | ((req: Request) => Response | Promise<Response>)>): typeof fetch & { calls: string[] }`. Unknown URLs throw.
  - `seedProject(env: Env, id: string): Promise<{ read: string; ci: string }>`. Filled in during Task 3.

- [ ] **Step 1: Write failing tests.** In `test/types.test.ts`:
  - `parsePackageId('npm:@a/b@1.0.0')` → `{eco:'npm',name:'@a/b',version:'1.0.0'}`;
  - `parsePackageId('go:github.com/x/y@v1.2.3')` → go ref;
  - `parsePackageId('pypi:x@1')` → `null`;
  - `formatPackageId` round-trips both.

  In `test/health.test.ts`, `GET /healthz` → 200 body `ok`.
- [ ] **Step 2:** `npx vitest run` → FAIL (modules missing).
- [ ] **Step 3: Scaffold.**
  - `wrangler.jsonc`: name `decant`, `main: src/index.ts`, `compatibility_date: "2026-11-01"`, R2 binding `BUCKET` (bucket `decant`), D1 binding `DB` (database `decant`, placeholder id), `triggers.crons: ["17 4 * * *"]`.
  - `migrations/0001_init.sql` creates the tables below.
  - Configure the vitest pool per the installed version's README, applying `migrations/` before tests.
  - CI runs `npm ci --ignore-scripts`, `npx tsc --noEmit` and `npx vitest run`. Pin `actions/checkout` and `actions/setup-node` to the commit SHA of their latest release tag (resolve with `gh api repos/<o>/<r>/git/ref/tags/<tag>`), with the tag in a trailing comment. Set `permissions: contents: read`.

```sql
CREATE TABLE projects (id TEXT PRIMARY KEY, main_ref TEXT NOT NULL DEFAULT 'main', created_at TEXT NOT NULL);
CREATE TABLE tokens (hash TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), kind TEXT NOT NULL CHECK (kind IN ('read','ci')), created_at TEXT NOT NULL);
CREATE TABLE policies (project_id TEXT NOT NULL, ref TEXT NOT NULL, json TEXT NOT NULL, sha TEXT NOT NULL, synced_at TEXT NOT NULL, PRIMARY KEY (project_id, ref));
CREATE TABLE allows (project_id TEXT NOT NULL, ref TEXT NOT NULL, eco TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, advisory TEXT, reason TEXT NOT NULL, verified_at TEXT, PRIMARY KEY (project_id, ref, eco, name, version));
CREATE TABLE versions (eco TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, publish_time TEXT NOT NULL, first_seen TEXT NOT NULL, conflict INTEGER NOT NULL DEFAULT 0, stored_at TEXT, osv_checked_at TEXT, PRIMARY KEY (eco, name, version));
CREATE TABLE global_blocks (eco TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY (eco, name, version, source));
CREATE TABLE verdicts (eco TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, scanner TEXT NOT NULL, scanner_version TEXT NOT NULL, result TEXT NOT NULL CHECK (result IN ('clean','flagged','malicious')), details TEXT, scanned_at TEXT NOT NULL, PRIMARY KEY (eco, name, version, scanner));
CREATE TABLE serve_log (project_id TEXT NOT NULL, eco TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, day TEXT NOT NULL, PRIMARY KEY (project_id, eco, name, version, day));
CREATE INDEX idx_blocks_pkg ON global_blocks (eco, name);
CREATE INDEX idx_versions_stored ON versions (stored_at, osv_checked_at);
```

- [ ] **Step 4:** `npx vitest run && npx tsc --noEmit` → PASS.
- [ ] **Step 5:** Commit `chore: scaffold worker, schema, CI`.

### Task 2: Version ordering (`src/semver.ts`)

**Interfaces:**
- Produces:
  - `parseVersion(v: string, eco: Ecosystem): Parsed | null`
  - `compareVersions(a: string, b: string, eco: Ecosystem): number` (negative when a < b; unparseable sorts lowest)
  - `isPrerelease(v: string, eco: Ecosystem): boolean`

  Go versions carry a leading `v`. `+incompatible` and build metadata are ignored for ordering. Go pseudo-versions (`v0.0.0-20240101000000-abcdef123456`, `vX.Y.(Z+1)-0.<ts>-<hash>`) count as prereleases.

- [ ] **Step 1: Write failing tests** (`test/semver.test.ts`):
  - npm ascending order: `1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0 < 1.0.1 < 1.10.0`;
  - `compareVersions('1.0.0+build','1.0.0','npm') === 0`;
  - Go: `v2.0.0+incompatible > v1.9.9`;
  - `isPrerelease('v0.0.0-20240101000000-abcdef123456','go')` and `isPrerelease('v1.2.4-0.20240101000000-abcdef123456','go')` are both true;
  - `parseVersion('latest','npm') === null`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement per SemVer 2.0.0 §11. Numeric identifiers compare numerically and rank below alphanumeric ones.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: semver ordering for npm and go`.

### Task 3: Auth and request context (`src/auth.ts`, router in `src/index.ts`)

**Interfaces:**
- Consumes: `Env`, `test/helpers.ts`.
- Produces:
  - `newToken(kind: 'read'|'ci'|'op'): string`
  - `hashToken(t: string): Promise<string>`
  - `type AuthCtx = { kind: 'operator' } | { kind: 'read'|'ci'; projectId: string }`
  - `authenticate(req: Request, env: Env): Promise<AuthCtx | null>`. Reads `Authorization: Bearer <t>`, or `Basic` with the token as the password and any username. The operator check compares hashes in constant time against `OPERATOR_TOKEN_HASH`.
  - Router contract in `handle`:
    - `/healthz` is public;
    - `/api/*` goes to the admin handler;
    - `/(r/<ref>/)?(npm|go)/*` needs a `read` or `ci` token, with `ref` matching `^[A-Za-z0-9._-]{1,64}$`. The handler gets `RequestCtx = { projectId: string; ref: string | null; base: string }`, where `base` is origin plus prefix, e.g. `https://h/r/pr-12`;
    - anything else is 404.
  - `seedProject` in helpers inserts a project plus read and ci tokens.

- [ ] **Step 1: Write failing tests** (`test/auth.test.ts`):
  - no header → 401 with `WWW-Authenticate: Basic realm="decant"`;
  - unknown token → 401;
  - a read token over Bearer reaches `/npm/` (mock the handler with a 200 stub);
  - a read token as the Basic password reaches `/go/`;
  - the operator token on `/npm/` → 403;
  - an invalid ref `/r/../npm/x` → 404;
  - `hashToken` is 64 hex chars, and `newToken('ci')` matches `^dk_ci_[A-Za-z0-9_-]{43}$`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Use `crypto.subtle.digest('SHA-256')` and `crypto.getRandomValues`. Never log headers.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: token auth and request routing`.

### Task 4: Policy schema and decision (`src/policy/schema.ts`, `src/policy/decide.ts`, `schema/policy.json`)

**Interfaces:**
- Produces:
  - `type Severity = 'critical'|'high'|'moderate'|'low'`
  - `interface AllowEntry { package: string; reason: string; advisory?: string; added: string }`
  - `interface BlockEntry { package: string; reason: string; advisory?: string }`
  - `interface Policy { project: string; cooldownDays: number; autoShip: Record<Severity,'auto'|'approve'>; allow: AllowEntry[]; block: BlockEntry[] }`
  - `parsePolicy(input: unknown): { ok: true; policy: Policy } | { ok: false; errors: string[] }`. Applies the defaults. `cooldownDays` is an integer from 0 to 365. Every package ID must parse. `added` is `YYYY-MM-DD`. Advisories match `^(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,}|[A-Z]+-\d{4}-[A-Za-z0-9-]+)$`. Unknown top-level keys other than `$schema` are errors.
  - `type Decision = 'allow' | 'hidden' | 'blocked'`
  - `decide(i: { publishTime: Date | null; conflict: boolean; blocked: boolean; allowed: boolean; cooldownDays: number; now: Date }): Decision`. The order is: `blocked || conflict` → `'blocked'`; then `allowed` → `'allow'`; then `publishTime === null` → `'hidden'`; then age ≥ cooldown → `'allow'`; otherwise `'hidden'`.
  - `schema/policy.json` is the JSON Schema mirroring this.

- [ ] **Step 1: Write failing tests** (`test/policy.test.ts`):
  - a minimal `{project:'t'}` gets defaults `cooldownDays 7` and `autoShip.critical 'auto'`, `moderate 'approve'`;
  - `cooldownDays: -1` gives an error mentioning `cooldownDays`;
  - an unknown key `foo` is an error;
  - a bad advisory `GHSA-1` is an error;
  - `decide`, with `now=2026-11-19T00:00Z` and cooldown 7:
    - published `2026-11-12T00:00Z` → allow (exactly 7 days);
    - `2026-11-12T00:00:01Z` → hidden;
    - null → hidden;
    - null + allowed → allow;
    - blocked + allowed → blocked;
    - conflict → blocked;
    - cooldown 0 + published now → allow.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: policy schema and version decision`.

### Task 5: Policy store, OSV, admin API (`src/policy/store.ts`, `src/osv.ts`, `src/admin/handler.ts`)

**Interfaces:**
- Consumes: `parsePolicy`, `authenticate`, `Deps`.
- Produces (store):
  - `loadPolicyView(env: Env, projectId: string, ref: string | null): Promise<{ cooldownDays: number; allowedFor(eco: Ecosystem, name: string): Set<string> /* versions */ }>`. Allowed is the main-ref allows, plus the ref's allows when a ref is given. Advisory rows count only if `verified_at` is set.
  - `blockedVersions(env, eco, name): Promise<Set<string>>`
  - `pinPublishTimes(env, eco, name, times: Map<string, Date>, now: Date): Promise<Map<string, { publishTime: Date; conflict: boolean }>>`. Does `INSERT OR IGNORE`, then reads back. A differing upstream time sets `conflict=1`, and the stored time is kept.
  - `getPinnedTimes(env, eco, name, versions: string[]): Promise<Map<string, { publishTime: Date; conflict: boolean }>>`
  - `markStored(env, ref: PackageRef, now)`
  - `logServe(env, projectId, ref: PackageRef, now)`
  - `addGlobalBlock(env, ref, source: string, reason: string, now)`
- Produces (OSV):
  - `verifyAdvisoryFix(deps, advisory: string, ref: PackageRef): Promise<'verified'|'not-fixed'|'unknown-advisory'|'unavailable'>`. It does `GET /v1/vulns/<id>`, which must list `ref.name` in that ecosystem (OSV calls them `npm` and `Go`). Then `POST /v1/query` with the version must return no vuln whose `id` or `aliases` equals the advisory. A network or 5xx failure returns `'unavailable'`.
  - `maliciousIds(deps, refs: PackageRef[]): Promise<Map<string /* packageId */, string[]> | null>`. It calls `POST /v1/querybatch`, keeps IDs starting with `MAL-`, and returns `null` if OSV is unavailable.
- Produces (admin routes; all JSON, all `no-store`):
  - `POST /api/projects {id}` (operator) → 201, or 409 if it exists;
  - `POST /api/projects/:id/tokens {kind}` (operator) → 201 `{token}`;
  - `PUT /api/projects/:id/policy {policy, sha, ref}` (the project's own ci token):
    - validate the policy and require `policy.project === :id`;
    - when `ref === main_ref`, replace the main policy and its allows. Replace the `global_blocks` rows with source `policy:<id>` with this policy's block list;
    - for any other ref, it's an overlay. Reject with 422 `overlay may only add allow entries` if `cooldownDays` or `autoShip` differ from main, or if any main block entry is missing. Store only its allows under that ref;
    - verify advisory allows via `verifyAdvisoryFix`. Any `unavailable` result → 503 and nothing is written. `not-fixed` or `unknown-advisory` → 422 naming the entry;
    - success → 200 `{ref, allows, blocks}`;
  - `PUT /api/verdicts {package, scanner, scannerVersion, result, details?}` (any ci token) → 204. A `malicious` result also calls `addGlobalBlock(source 'verdict:<scanner>')`;
  - `GET /api/verdicts?package=<id>` (any ci token) → `{verdicts: [...]}`;
  - `GET /api/projects/:id/status` (own ci token) → `{mainSha, syncedAt, overlays: [{ref, syncedAt}], globalBlocks: n}`.

- [ ] **Step 1: Write failing tests** (`test/admin.test.ts`, `test/osv.test.ts`, `test/store.test.ts`), using `fakeFetch` for OSV:
  - **Projects and tokens:**
    - operator creates a project and then a token;
    - a ci token can't create projects (403);
    - project A's ci token on B's policy → 403;
    - a read token on any `/api` route → 403.
  - **Policy sync:**
    - a main sync with `block: [npm:evil@1.0.0]` makes `blockedVersions(npm, evil)` equal `{1.0.0}`;
    - re-syncing without that entry clears it;
    - an overlay `pr-1` with a different `cooldownDays` → 422;
    - an overlay with an extra plain allow `npm:x@2.0.0` puts `x@2.0.0` in `loadPolicyView(A,'pr-1')`, but not in `loadPolicyView(A,null)` and not in project B's view;
    - an advisory allow with OSV mocked to list the version as still affected → 422;
    - OSV returning 500 → 503 with no rows written;
    - a verified advisory → `verified_at` set.
  - **Publish-time pinning:** pinning `1.0.0` at T1 and then again at T2 → `conflict: true`, `publishTime` T1.
  - **Verdicts:** a `malicious` verdict → the version shows up in `blockedVersions`.
  - **OSV:** `maliciousIds` maps an ID `MAL-2025-1` to its package.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Use D1 `batch()` for multi-row writes, so each sync is atomic.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: policy store, OSV verification, admin API`.

### Task 6: Cached upstream fetch (`src/upstream.ts`)

**Interfaces:**
- Produces: `cachedFetch(env, deps, opts: { key: string; url: string; accept?: string; maxAgeSec?: number /* default 300 */; immutable?: boolean }): Promise<{ status: 'ok'; body: ArrayBuffer; stale: boolean } | { status: 'not-found' } | { status: 'unavailable' }>`.
  - The R2 object at `key` stores the body, with `customMetadata.fetchedAt`.
  - It's fresh if `immutable` is set, or if it's younger than `maxAgeSec`.
  - A stale or missing copy is refetched. An upstream 404 returns `not-found`, but the stored copy is kept and also returned when upstream later deletes the item (stale: true): a deleted package keeps serving.
  - A network error or 5xx serves the stored copy with `stale: true`, or `unavailable` if there's nothing stored.
  - Concurrent calls for the same key in one isolate share one in-flight promise.
- The callers map `unavailable` to a 502 `upstream unavailable and nothing cached`, and set `X-Decant-Stale: 1` when stale.

- [ ] **Step 1: Write failing tests** (`test/upstream.test.ts`):
  - first call fetches;
  - a second call within 300 s makes no fetch (`calls.length === 1`);
  - at 301 s it refetches;
  - upstream 500 with a stored copy → `ok`, stale;
  - upstream 500 with nothing stored → `unavailable`;
  - upstream 404 with a stored copy → `ok`, stale;
  - two concurrent calls → one fetch;
  - `immutable: true` never refetches.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: R2-backed upstream cache with stale-serve`.

### Task 7: npm document filter (`src/npm/filter.ts`)

**Interfaces:**
- Consumes: `compareVersions`, `isPrerelease`.
- Produces: `filterPackument(doc: Packument, allowed: Set<string> /* versions */, tarballBase: string /* e.g. https://h/r/pr-1/npm */): Packument`. It's pure and works on both the full and the abbreviated format. `Packument` is a loose type (`{ name: string; versions: Record<string, any>; 'dist-tags'?: Record<string,string>; time?: Record<string,string>; modified?: string; [k: string]: unknown }`).
- Rules (verbatim from spec):
  - hidden versions are removed from `versions`, from `time` (`created` and `modified` are kept, and `modified` is set to the newest allowed version's time), and from every dist-tag;
  - `latest` is the highest-semver non-prerelease allowed version, else the highest allowed prerelease, else it is omitted;
  - other dist-tags are kept only if their target is allowed;
  - `dist.tarball` is set to `${tarballBase}/${name}/-/${basename}-${version}.tgz`, where `basename` is the unscoped name. `integrity` and `shasum` are untouched;
  - the input is not mutated.

- [ ] **Step 1: Write failing tests** (`test/npm-filter.test.ts`), with fixture versions `1.0.0` (time T0), `2.0.0` (T2), `1.0.1` (T3, a backport published after 2.0.0) and `3.0.0-beta.1` (T4):
  - allowed {1.0.0, 2.0.0, 1.0.1}, upstream `latest: '3.0.0-beta.1'` → `latest` is `2.0.0`;
  - `next: '3.0.0-beta.1'` is dropped;
  - `time` has no `3.0.0-beta.1` but keeps `created`, and `modified === T3`;
  - with allowed {} → `versions` is `{}` and `dist-tags` is `{}` (Review Focus 2);
  - with only the prerelease allowed → `latest === '3.0.0-beta.1'`;
  - the scoped `@s/pkg` tarball becomes `https://h/npm/@s/pkg/-/pkg-1.0.0.tgz`;
  - `integrity` is unchanged;
  - an abbreviated doc (no `time`) filters without error;
  - the input is deep-equal to a pre-call clone.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: npm document filter`.

### Task 8: npm handler (`src/npm/handler.ts`)

**Interfaces:**
- Consumes: `cachedFetch`, `filterPackument`, `decide`, the store functions, `maliciousIds`, `RequestCtx`.
- Produces: `handleNpm(req: Request, env: Env, deps: Deps, ctx: ExecutionContext, rc: RequestCtx, path: string /* after /npm */): Promise<Response>`.

**Routes:**
- `GET /<name>` and `GET /<name>/-/<file>.tgz`. The name is `@scope%2fname` (any case of `%2f`), `@scope/name` or `name`. The version is parsed by stripping `<basename>-` and `.tgz` from the file.
- `POST /-/npm/v1/security/advisories/bulk` and `POST /-/npm/v1/security/audits/quick` pass through to the registry with the request body, so `npm audit` works.
- `PUT` or `DELETE` on anything → 405. Anything else → 404.

**Metadata:**
- R2 keys are `npm/meta/full/<name>.json` and `npm/meta/abbrev/<name>.json`. The format is picked by `Accept` containing `application/vnd.npm.install-v1+json`.
- Publish times always come from the full document's `time`. For an abbreviated request, the full document is fetched only when some listed version has no pinned time.
- Pin the times, read the blocks and policy view, and run `decide` per version. Filter, then respond with `Content-Type` matching the format, `Vary: Accept` and `Cache-Control: no-store`.

**Tarballs:**
- Decide first: hidden or blocked → 404 `{"error":"<id> is not available: in cooldown|blocked"}`.
- If `npm/tar/<name>/<file>` is in R2, stream it.
- Otherwise:
  1. If the version has `osv_checked_at` null, call `maliciousIds` for it. A hit → `addGlobalBlock(source 'osv')` and a 404. `null` (OSV down) → continue; the cron re-checks it.
  2. Fetch the upstream `dist.tarball` URL from the raw document.
  3. `tee()` the body. One branch goes to the client. The other goes through `crypto.DigestStream('SHA-512')` and into `BUCKET.put` with `FixedLengthStream(content-length)`.
  4. In `ctx.waitUntil`, compare the digest to `integrity`. A mismatch deletes the object and logs `integrity mismatch <id>`.
  5. Call `markStored` on success.
- Every allowed tarball serve calls `logServe` via `waitUntil`.

- [ ] **Step 1: Write failing tests** (`test/npm.test.ts`), with `fakeFetch` serving a fixture document and tarball, and the clock fixed:
  - Review Focus 1: `@s/pkg`, `@s%2fpkg` and `@s%2Fpkg` all return the same filtered doc, and the scoped tarball route works;
  - an abbreviated `Accept` → `Content-Type: application/vnd.npm.install-v1+json` and `Vary: Accept`;
  - a cooldown-hidden version's tarball → 404 with `in cooldown`;
  - a blocked one → 404 with `blocked`, even when it's already in R2;
  - with overlay ref `pr-1` allowing a young version, `/r/pr-1/npm/x` lists it and its tarball URL starts with `https://h/r/pr-1/npm/`, while `/npm/x` doesn't list it;
  - the second tarball request is served from R2 with no upstream call;
  - a tarball whose sha512 mismatches → the R2 object is gone after `waitUntil`;
  - `maliciousIds` hit → 404, and the version is now in `blockedVersions`;
  - audit POST passes through, and its body reaches upstream;
  - `PUT /npm/x` → 405;
  - the serve log has a row for (project, npm, x, 1.0.0, 2026-11-19).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: npm registry routes`.

### Task 9: Go module proxy (`src/go/escape.ts`, `src/go/handler.ts`)

**Interfaces:**
- Produces:
  - `escapeModulePath(p: string): string` (uppercase → `!` + lowercase);
  - `unescapeModulePath(p: string): string | null` (invalid → null);
  - `handleGo(req, env, deps, ctx, rc: RequestCtx, path: string /* after /go */): Promise<Response>`.

**Routes:** `<escaped>/@v/list`, `<escaped>/@v/<ver>.info|.mod|.zip`, `<escaped>/@latest`, all passed upstream escaped and unchanged.

**R2 keys:**
- `go/<escaped>/@v/list.raw` uses the 300 s window;
- `.info`, `.mod` and `.zip` are `immutable`.

**Publish times:**
- The time is the `.info` `Time`, pinned via `pinPublishTimes`.
- `list` keeps versions whose pinned decision is `allow`. For unpinned versions, it fetches at most 10 `.info` files per request, highest version first. Versions still unpinned are omitted.
- `.info`, `.mod` and `.zip` decide first (fetching `.info` if unpinned): hidden or blocked → 404 with a plain-text reason.
- `@latest`: if the upstream `@latest` version is allowed, return its info. Otherwise return the highest allowed non-prerelease from the filtered list, and 404 if there is none.

**Storing:** `.zip` streams into R2 the same way as tarballs, but with no digest check (the go client verifies against sumdb). Call `markStored` on success. The OSV MAL check works the same as for npm. `logServe` runs on `.zip` serves.

**Other:** `/sumdb/*` → 404. Decant does not proxy sumdb.

- [ ] **Step 1: Write failing tests** (`test/go.test.ts`):
  - Review Focus 4: `escapeModulePath('github.com/Azure/azure-sdk-for-go') === 'github.com/!azure/azure-sdk-for-go'`, the round-trip works, and a request for `github.com/!azure/x/@v/list` hits the upstream URL with `!azure`;
  - `unescapeModulePath('github.com/Azure')` → null (uppercase isn't allowed in escaped form);
  - `list`, with versions v1.0.0 (old), v1.1.0 (2 days old) and v1.2.0 (unpinned, `.info` old) → returns `v1.0.0\nv1.2.0\n`;
  - with 15 unpinned versions → at most 10 `.info` fetches;
  - `@latest` when upstream latest is young → returns the info of the highest allowed;
  - `.zip` for a hidden version → 404;
  - a second `.zip` comes from R2;
  - `.info` time changing upstream → the version is blocked;
  - a pseudo-version `v0.0.0-20240101000000-abcdef123456` with an old `.info` is allowed and served;
  - `/go/sumdb/sum.golang.org/latest` → 404.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: GOPROXY routes`.

### Task 10: Scheduled jobs (`src/cron.ts`)

**Interfaces:**
- Consumes: `maliciousIds`, `addGlobalBlock`.
- Produces: `runScheduled(env, deps): Promise<{ checked: number; blocked: number; overlaysExpired: number }>`, wired to `scheduled` in `src/index.ts`.
  1. Select versions with `stored_at` set, ordering by `osv_checked_at` nulls first, then oldest. Take up to 20 batches of 1,000 and call `maliciousIds` per batch. Hits → `addGlobalBlock(source 'osv')`. Set `osv_checked_at` on success. Stop early if OSV returns `null`.
  2. Delete overlay `policies` and `allows` rows whose ref isn't `main_ref` and whose `synced_at` is more than 14 days old.

- [ ] **Step 1: Write failing tests** (`test/cron.test.ts`):
  - 3 stored versions with OSV mocked to flag one → `{checked:3, blocked:1}`, and it's in `blockedVersions`;
  - OSV 500 → `checked: 0` and nothing marked;
  - an overlay synced 15 days ago is removed, one synced 13 days ago is kept, and main is never removed.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: daily malicious re-check and overlay expiry`.

### Task 11: Operator CLI and deploy guide (`scripts/decant.ts`, `docs/deploy.md`, `README.md`)

**Interfaces:**
- Consumes: the admin API (Task 5).
- Produces:
  - `node scripts/decant.ts project create <id>`, `node scripts/decant.ts token create <project> <read|ci>` and `node scripts/decant.ts op-token`. The last one prints a new operator token and the `wrangler secret put OPERATOR_TOKEN_HASH` value to set.
  - The CLI reads `DECANT_URL` and `DECANT_OPERATOR_TOKEN` from the environment and uses only Node built-ins. `package.json` gets the script `"decant": "node scripts/decant.ts"`.
  - `docs/deploy.md` covers creating the R2 bucket and D1 database, `wrangler d1 migrations apply`, setting the secret, a custom domain, `wrangler deploy`, and creating the first project and tokens. Every command is copy-pasteable.
  - `README.md` gets a Status line ("Worker usable; GitHub Action coming") and links.

- [ ] **Step 1: Write failing tests** (`test/cli.test.ts`). The CLI's request builder is exported as `buildRequest(argv: string[], env: Record<string,string>): Request | { error: string }`:
  - `project create twocal` → `POST <url>/api/projects` with body `{id:'twocal'}` and operator Bearer;
  - a missing `DECANT_URL` → an error message;
  - `token create twocal admin` → error `kind must be read or ci`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement, and write the docs.
- [ ] **Step 4:** `npx vitest run && npx tsc --noEmit` → PASS. Also run `npx wrangler deploy --dry-run --outdir dist-check`, which must bundle with no errors and no external imports.
- [ ] **Step 5:** Commit `feat: operator CLI and deploy guide`.

### Task 12: Deploy (gated on George)

- [ ] **Step 1:** Ask George which Cloudflare account and domain to use. Stop until he answers.
- [ ] **Step 2:** Follow `docs/deploy.md` exactly, fixing the doc where reality differs.
- [ ] **Step 3: Smoke test:**
  - `npm view lodash version --registry https://<host>/npm/` with a read token returns the version;
  - `GOPROXY=https://decant:<token>@<host>/go GOFLAGS=-mod=mod go list -m -versions golang.org/x/text` lists versions;
  - a version younger than 7 days is absent from both.
- [ ] **Step 4:** Commit any doc fixes. Report the URL to George.

---

Plan 2 (next): the GitHub Action (`scan`, `audit`, `sync`), lockfile parsers, `decant adopt`, the adoption and hardening docs, signed release tags and the `dist/` reproducibility check.
