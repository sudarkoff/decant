# decant Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A private, live dashboard at `<host>/dashboard` (behind Cloudflare Access) showing "Needs attention" first, then per-project Activity, Security, Freshness, Uptime, Policy, Packages and Recently resolved.

**Architecture:**
- The Worker records one daily counter per package request into D1, notes each package's latest version whenever it refetches upstream metadata, and the daily cron stores every known vulnerability (not only `MAL-`) for stored versions.
- `/dashboard*` is gated by verifying the Cloudflare Access JWT.
- The Worker serves JSON endpoints that read aggregates, plus one dependency-free HTML page (inline JS/CSS, hand-drawn SVG) that renders them.

**Tech Stack:** TypeScript, Cloudflare Workers, D1, R2, vitest (workers pool for the Worker, Node config for `action/`). No runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-11-20-dashboard-design.md` (including "Calls made after the builder check"). Layout approved from the mockups: "Needs attention" on top, then the one-page sections with a project switcher.

## Global Constraints

- **No runtime dependencies, no frontend build step.** The page is a TS module exporting an HTML string.
- **Recording never affects installs.** It runs only via `ctx.waitUntil`, and every recording error is caught and logged with no tokens or URLs.
- **One `request_counts` upsert per counted request.** The `packages` upsert happens only when upstream metadata is actually refetched.
- **Outcomes** ∈ `served | cooldown | blocked | stale | failed`; **kinds** ∈ `metadata | download`. Requests without a valid token are not counted.
- **Dashboard config:** the vars `ACCESS_TEAM_DOMAIN` (e.g. `myteam.cloudflareaccess.com`) and `ACCESS_AUD`. With either unset, every `/dashboard*` path returns 404.
- **JWT rules:**
  - RS256 only, verified against `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs`, with the JWKS cached in memory and refetched once on an unknown `kid`;
  - `aud` must include `ACCESS_AUD`, and `iss` must be `https://<ACCESS_TEAM_DOMAIN>`;
  - `exp`/`nbf` are checked with 60 s leeway;
  - any failure → 403 with no body detail.
- **Ranges** are 7, 30 or 90 days (default 30); `project` is a project id or `all`.
- **Severity order and fallback** are the same as the Action: GHSA `database_specific.severity`, then CVSS v3.1 base score (≥9 critical, ≥7 high, ≥4 moderate, >0 low), else `unknown`, which counts as moderate.
- **Page:** AA contrast, phone width works, light/dark via `prefers-color-scheme`, no external requests except same-origin `/dashboard/api/*`. Served with `Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'` and `Cache-Control: no-store`.
- **Commits:** signed, on branch `dashboard`; never push to main.

## Review Focus

1. **A forged or wrong Access token** (wrong `aud`, expired, unknown `kid`, `alg: none`, HS256) gets 403 and never any data. Owned by Task 4.
2. **A recording failure** (D1 throws) never changes an install response. Owned by Task 1.
3. **Package search input** with `%`, `_` or quotes is matched literally (escaped LIKE, bound parameters). Owned by Task 5.
4. **Empty states:** no projects, a project with no requests, or `project=all` with nothing return 200 with zeros or empty arrays, never 500. Owned by Tasks 5–6.
5. **An unknown `project` or `range`** returns 400, never a cross-project leak. Owned by Task 5.

---

## File Structure

```
migrations/0004_dashboard.sql        request_counts, packages, vulns, alerts_state; allows.first_synced_at, advisory_published
src/stats/record.ts                  recordRequest(), notePackageLatest()
src/npm/handler.ts, src/go/handler.ts  call the recorders at each outcome
src/vuln-severity.ts                 pure: cvss31BaseScore, severityOf(record), maxSeverity (moved from action/src/osv.ts)
action/src/osv.ts                    imports the moved helpers (no behavior change)
src/osv.ts                           verifyAdvisoryFix also returns advisory `published`; vulnsFor()
src/admin/handler.ts                 allows.first_synced_at carry-over, advisory_published
src/cron.ts                          store all vulns for stored versions
src/dashboard/access.ts              verifyAccess()
src/dashboard/api.ts                 JSON endpoints
src/dashboard/attention.ts           attention items + alerts_state diff
src/dashboard/page.ts                DASHBOARD_HTML
src/index.ts                         /dashboard routing
docs/deploy.md, README.md            Dashboard section
test/stats.test.ts, test/access.test.ts, test/dashboard-api.test.ts, test/attention.test.ts, test/dashboard-page.test.ts, test/vuln-severity.test.ts
```

---

### Task 1: Schema and request recording

**Files:**
- Create `migrations/0004_dashboard.sql` and `src/stats/record.ts`.
- Modify `src/npm/handler.ts` and `src/go/handler.ts`.
- Test: `test/stats.test.ts`.

**Interfaces:**
- Produces:
  - `type Kind = 'metadata' | 'download'`; `type Outcome = 'served' | 'cooldown' | 'blocked' | 'stale' | 'failed'`.
  - `recordRequest(env: Env, ctx: ExecutionContext, projectId: string, eco: Ecosystem, kind: Kind, outcome: Outcome, now: Date): void`. It schedules via `ctx.waitUntil` one `INSERT INTO request_counts … ON CONFLICT(project_id, day, eco, kind, outcome) DO UPDATE SET n = n + 1`, where `day` = UTC `YYYY-MM-DD`, and catches errors.
  - `notePackageLatest(env: Env, ctx: ExecutionContext, eco: Ecosystem, name: string, latest: string, latestTime: string | null, now: Date): void`, an upsert into `packages`.
- Migration:
  - `request_counts(project_id TEXT, day TEXT, eco TEXT, kind TEXT, outcome TEXT, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(project_id, day, eco, kind, outcome))`;
  - `packages(eco, name, latest, latest_time, checked_at, PRIMARY KEY(eco, name))`;
  - `vulns(eco, name, version, id, severity, summary, published, checked_at, PRIMARY KEY(eco, name, version, id))`;
  - `alerts_state(key TEXT PRIMARY KEY, project_id TEXT, first_seen TEXT NOT NULL, resolved_at TEXT)`;
  - `ALTER TABLE allows ADD COLUMN advisory_published TEXT` and `ADD COLUMN first_synced_at TEXT`;
  - `CREATE INDEX idx_serve_log_day ON serve_log(project_id, day)`.
- Handler mapping:
  - **npm metadata:** 200 → `served`, or `stale` when cachedFetch was stale. 502/5xx → `failed`.
  - **npm tarball:** served → `served`; refused for cooldown → `cooldown`; blocked → `blocked`; 5xx → `failed`.
  - **Go:** `list`/`.info`/`@latest` count as metadata, and `.mod`/`.zip` as download, with the same mapping.
  - **Not counted:** 404 for an unknown package or route, 405, and 401/403.
  - On every successful upstream (non-cached) metadata refetch, call `notePackageLatest`. npm uses `dist-tags.latest` and `time[latest]`; Go uses the `@latest` Version and Time.

- [ ] **Step 1: Write failing tests.**
  - A served npm metadata request increments `(proj, today, npm, metadata, served)` to 1, and a second one to 2.
  - A cooldown-refused tarball increments `download/cooldown`; a blocked one increments `download/blocked`.
  - Upstream down with a stored copy gives `metadata/stale`; with nothing stored, `metadata/failed`.
  - A Go `.zip` serve increments `go/download/served`.
  - An unknown route and a 401 record nothing.
  - **Review Focus 2:** a DB proxy whose `request_counts` insert throws still yields the normal 200 tarball response.
  - A fresh upstream packument upserts `packages` (npm, name) with latest; a cached hit does not write `packages`.
- [ ] **Step 2:** `npx vitest run test/stats.test.ts` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `npm test && npm run typecheck` → PASS. The existing `d1-reads` budgets still pass; raise a budget only by ≤5 rows if needed and say so.
- [ ] **Step 5:** Commit `feat: record package request counts and latest versions`.

### Task 2: Shared severity and fast-lane timing

**Files:**
- Create `src/vuln-severity.ts`.
- Modify `action/src/osv.ts` (import from it), `src/osv.ts` and `src/admin/handler.ts`.
- Test: `test/vuln-severity.test.ts`, `test/admin.test.ts`.

**Interfaces:**
- Produces:
  - `cvss31BaseScore(vector: string): number | null` and `maxSeverity(...)`, moved verbatim from `action/src/osv.ts`;
  - `severityOf(record: { database_specific?: { severity?: string }; severity?: { type: string; score: string }[] }): Severity | 'unknown'`;
  - `verifyAdvisoryFix` now returns `{ result: AdvisoryCheck; published: string | null }`. Update callers.
- Policy sync on the main ref:
  - each advisory allow row gets `advisory_published` from the verified record;
  - `first_synced_at` = the existing row's value for the same (project, eco, name, version, advisory) if present, else now. The batch must read the old values before deleting.

- [ ] **Step 1: Write failing tests:**
  - `cvss31BaseScore` gives 9.8, 10.0 and 1.8 for the vectors `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` and `CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N`;
  - `severityOf` prefers GHSA `HIGH` over CVSS;
  - the action suite still passes unchanged;
  - re-syncing main keeps `first_synced_at` from the first sync, and a new entry gets now;
  - `advisory_published` is stored.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `npm test && npm run typecheck && npm run build:action` with `git diff --exit-code action/dist` clean after committing dist → PASS.
- [ ] **Step 5:** Commit `feat: shared severity helpers; record advisory publish and first sync`.

### Task 3: Cron stores known vulnerabilities

**Files:** modify `src/cron.ts` and `src/osv.ts`. Test: `test/cron.test.ts`.

**Interfaces:**
- Produces `vulnIds(deps, refs): Promise<Map<string /* packageId */, string[]> | null>`, which returns all ids. `maliciousIds` becomes a filter over it.
- Also produces `vulnDetails(deps, id): Promise<{ severity: Severity | 'unknown'; summary: string; published: string | null } | null>`, cached per run.
- The cron batch stores one `vulns` row per (version, id) via `INSERT OR REPLACE`, then removes `vulns` rows for checked versions whose id no longer appears. MAL handling is unchanged. Detail fetches are capped at 200 new ids per run; the rest are filled on later runs.

- [ ] **Step 1: Write failing tests:**
  - stored version with ids GHSA-a (HIGH) and MAL-1 → two `vulns` rows with severities, and the global block still added for MAL;
  - an id gone on the next run → its row deleted;
  - OSV down → no rows changed.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `npm test` → PASS.
- [ ] **Step 5:** Commit `feat: cron records known vulnerabilities for stored versions`.

### Task 4: Access gate and routing

**Files:**
- Create `src/dashboard/access.ts`.
- Modify `src/index.ts` and `src/types.ts` (`Env.ACCESS_TEAM_DOMAIN?`, `Env.ACCESS_AUD?`).
- Test: `test/access.test.ts`.

**Interfaces:**
- Produces `verifyAccess(req: Request, env: Env, deps: Deps): Promise<{ email: string | null } | null>`. Null means deny.
- Router:
  - `/dashboard` and `/dashboard/` serve the page (Task 7; a placeholder 200 until then);
  - `/dashboard/api/*` goes to `handleDashboardApi(req, env, deps, path)` (Task 5; a 404 stub until then);
  - config unset → 404; verification fails → 403.
  - Registry and `/api/*` are untouched.

- [ ] **Step 1: Write failing tests.** Generate an RSA keypair with `crypto.subtle` in the test and serve the JWKS via fakeFetch.
  - A valid token passes.
  - **Review Focus 1:** wrong `aud`, wrong `iss`, expired, future `nbf` beyond leeway, unknown `kid` after one refetch, `alg: "none"`, `alg: "HS256"`, a bad signature and a missing header each give 403.
  - Config unset gives 404.
  - `/npm/x` with a read token is unaffected.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement with Web Crypto (`RSASSA-PKCS1-v1_5`, SHA-256).
- [ ] **Step 4:** `npm test && npm run typecheck` → PASS.
- [ ] **Step 5:** Commit `feat: Cloudflare Access gate for /dashboard`.

### Task 5: Dashboard JSON endpoints

**Files:** create `src/dashboard/api.ts`. Test: `test/dashboard-api.test.ts`.

**Interfaces:**
- Produces `handleDashboardApi(req, env, deps, path): Promise<Response>` with these GET routes (JSON, `no-store`):
  - `projects` → `{projects: [{id}]}`;
  - `activity?project&range` → `{days: [{day, served, cooldown, blocked, stale, failed}], distinctPackages, distinctVersions}` (zero-filled days);
  - `security?…` → `{blocksHit, maliciousHits, flagged: [...], vulnsBySeverity: {critical, high, moderate, low, unknown}, fastLane: [{package, advisory, hoursToFix}]}`;
  - `freshness?…` → `{medianAgeDays, majorBehind: [...], minorAvailable}`. It uses each project's most recently served version per package, compared with `packages.latest` via `src/semver.ts`;
  - `uptime?…` → `{outageDays: [day], staleServed, failed}`;
  - `policy?project` → `{policies: [{project, cooldownDays, autoShip, allows, blocks, syncedAt, sha}]}`;
  - `packages?project&q&page` → 50 per page, `[{project, eco, name, version, published, latest, lastServed}]`.
- Validation: `range` ∉ {7, 30, 90} or an unknown project → 400 `{error}`. `all` aggregates.

- [ ] **Step 1: Write failing tests.** Seed two projects across `serve_log`, `request_counts`, `versions`, `packages`, `vulns`, `verdicts`, `global_blocks`, `allows` and `policies`, then cover:
  - every endpoint's shape and numbers for `project=twocal` and `all`;
  - **Review Focus 3:** `q=%` matches only names containing `%`;
  - **Review Focus 4:** a fresh DB returns zeros or empty arrays with 200;
  - **Review Focus 5:** `project=nope` and `range=8` → 400;
  - project B's packages never appear for `project=A`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement with bounded queries (`serve_log` by `(project_id, day)`, `request_counts` by primary key prefix).
- [ ] **Step 4:** `npm test && npm run typecheck` → PASS.
- [ ] **Step 5:** Commit `feat: dashboard data endpoints`.

### Task 6: Needs attention and recently resolved

**Files:** create `src/dashboard/attention.ts` and add the `attention` route in `api.ts`. Test: `test/attention.test.ts`.

**Interfaces:**
- Produces `attention(env, project: string | 'all', range: 7 | 30 | 90, now: Date): Promise<{ open: Item[]; resolved: Item[] }>`, where `Item = { key, project: string | null, kind, title, detail, firstSeen, resolvedAt?: string }`.
- Item kinds, with keys (spec's Goals 1 and the calls):
  - `blocked:<pkgId>:<project>`: a version installed in the last 30 days that is now in `global_blocks` or blocked by the main policy;
  - `malicious:<pkgId>:<project>`;
  - `vuln:<id>:<pkgId>:<project>`: severity high or critical;
  - `flagged:<pkgId>:<project>`: a `flagged` verdict;
  - `conflict:<pkgId>`: a `versions.conflict = 1` row, listed under `all` only;
  - `silent:<project>`: no request or serve in 14 days, using the latest of `serve_log.day` and `request_counts.day`.
- Each call diffs against `alerts_state`: new keys are inserted with `first_seen` = now, missing open keys get `resolved_at` = now, and a reappearing key gets `resolved_at` = NULL.
- `resolved` = rows resolved within the range, filtered to the project.

- [ ] **Step 1: Write failing tests:**
  - each kind appears when seeded;
  - removing the block resolves the item, and it shows in `resolved`;
  - re-adding it reopens the same key, with no duplicate row;
  - project A's items don't show for project B;
  - `silent` doesn't fire for a project with a serve 3 days ago.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `npm test` → PASS.
- [ ] **Step 5:** Commit `feat: needs-attention items with resolve tracking`.

### Task 7: Dashboard page

**Files:** create `src/dashboard/page.ts` and wire it in `src/index.ts`. Test: `test/dashboard-page.test.ts`.

**Interfaces:**
- Produces `DASHBOARD_HTML: string`, served by `/dashboard` with the CSP and `no-store` headers from Global Constraints.
- **Layout** (approved: attention on top, then sections):
  - a header with "decant", a project `<select>` (from `projects`, plus "All projects") and a range group (7/30/90 as buttons, `aria-pressed`);
  - "Needs attention (N)", a list of items each with a severity-coloured left label word (not a border-only cue) and detail. An empty state reads "Nothing needs attention";
  - Activity: a stacked bar SVG per day with a legend and the totals line;
  - a two-column grid (stacking below 720px) of Security, Freshness, Uptime and Policy;
  - Packages: a search input and table, scrollable on narrow screens, with Prev/Next pagination;
  - Recently resolved.
- **Behavior:** state lives in the URL query (`?project=&range=`); on change it fetches every endpoint in parallel; errors show inline per section.
- **Style:** light and dark palettes, AA contrast, system font stack.

- [ ] **Step 1: Write failing tests:**
  - `/dashboard` with valid Access returns 200 `text/html` with the exact CSP header and `no-store`;
  - the HTML contains no `http://` or `https://` URLs and no `<script src`;
  - it contains the section headings "Needs attention", "Activity", "Security", "Freshness", "Uptime", "Policy", "Packages" and "Recently resolved".
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `npm test && npm run typecheck` → PASS. Also render once locally with `wrangler dev` and seeded data, take a phone-width and a desktop screenshot with any available headless browser, and describe them in the report. If none is available, say so.
- [ ] **Step 5:** Commit `feat: dashboard page`.

### Task 8: Docs

- [ ] **Step 1:** `docs/deploy.md` gains a "Dashboard" section:
  - create a Cloudflare Zero Trust Access application of type self-hosted on `<host>/dashboard*` only (never the bare host, which would break installs);
  - a policy allowing the operator's email;
  - copy the Application Audience (AUD) tag;
  - set the vars `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` in the wrangler config;
  - apply migration 0004 and deploy.

  `README.md` gets one line and a link.
- [ ] **Step 2:** Commit `docs: dashboard setup`.

### Task 9: Deploy (controller, gated on George for the Access application)

- [ ] **Step 1:** After merge: `npx wrangler d1 migrations apply decant --remote -c wrangler.local.jsonc`, then deploy. `/dashboard` returns 404 until configured.
- [ ] **Step 2:** George creates the Access application. He shares the team domain and AUD, or sets them himself.
- [ ] **Step 3:** Set the vars, redeploy, and confirm the page loads through Access and that `/npm/left-pad` with the read token is unaffected.
