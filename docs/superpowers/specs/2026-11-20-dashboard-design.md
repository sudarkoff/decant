# decant dashboard: design

Status: draft for approval, 2026-11-20.

## Why

decant now sees every dependency install for every adopting project. George wants a live, private dashboard that answers "is anything wrong?" first, then shows per-project stats. It is for him alone today. It ships as part of open-source decant, so every deployment gets it.

## Goals

1. **Needs attention**, at the top. Actionable items, newest first:
   - a version installed in the last 30 days that is now blocked (globally or by policy);
   - an installed version with an OSV `MAL-` advisory;
   - an installed version with a known vulnerability at or above high severity;
   - a GuardDog `flagged` verdict on an installed version;
   - a publish-time conflict (upstream republished a version decant had already pinned);
   - a project with no package requests in 14 days (stale config or a broken token).
2. **Per-project stats** below, with a project switcher that includes "All projects" and a time range of 7, 30 or 90 days:
   - **Activity:** package requests per day, split by outcome (served, held by cooldown, blocked, served stale during an upstream outage, failed). Also distinct packages and versions.
   - **Security:** blocks hit; malicious hits; flagged verdicts; known vulnerabilities in installed versions by severity; fast-lane allow entries used, with time-to-fix (advisory published → allow entry synced to main).
   - **Freshness:** median age of installed versions, the number a major version behind latest, and minor updates available.
   - **Uptime:** days with stale serves or upstream failures, plus requests served stale.
   - **Policy:** cooldown, auto-ship settings, allow and block counts, last main sync and its commit.
   - **Packages:** a searchable table of name, version, published date, latest, and last served.
   - **Recently resolved:** items that left "Needs attention" in the selected range.
3. **Private:** reachable only through Cloudflare Access. The Worker also verifies the Access token itself, so a misconfigured Access app fails closed.
4. **Cheap:** at most one extra D1 write per package request. The dashboard reads aggregates, never raw scans of large tables.

## Non-goals

- Counting builds (George: count package requests instead).
- Alerts, notifications or email.
- Multi-user roles; a public or shared view.
- Showing fix-PR state from GitHub. "Needs attention" links to the repo's decant issues instead.
- Charts libraries or a frontend build step.

## Anti-goals

- Anything that slows the install path or makes it depend on something other than Cloudflare. Recording happens through `ctx.waitUntil`, and a recording failure never fails a request.
- Putting the registry routes behind Access, which would break every install.
- Leaking tokens or per-request IPs into stored data.

## Constraints

- Worker, R2 and D1 on Workers Paid. No new services.
- No runtime dependencies. The dashboard is one static HTML page with inline JS and CSS, served by the Worker, with hand-drawn SVG charts.
- Access setup (a Zero Trust application on `<host>/dashboard*`) is done by the operator in the Cloudflare dashboard. decant only needs the team domain and the application's AUD tag.

## Approaches considered

- **Data source:**
  - **A. Daily counters in D1. Chosen** by George. One upsert per request into `request_counts`, plus the existing tables.
  - B. Workers Analytics Engine. Rejected: it needs an extra API token, keeps data only 3 months, and is a second system.
- **Serving:** the Worker serves `/dashboard` (HTML) and `/dashboard/api/*` (JSON). No separate app, which would mean a second deployment for every adopter.
- **Layout: "Needs attention" first, then one page of sections with a project switcher.** Chosen by George from three mockups (overview-then-project-pages, one-page switcher, attention-first). The mockups are in the artifact "decant dashboard layouts".

## Data

**New migration `0004_dashboard.sql`:**
- `request_counts(project_id, day, eco, kind, outcome, n, PRIMARY KEY(project_id, day, eco, kind, outcome))`.
  - `kind` ∈ `metadata | download`. npm metadata and Go list/info/@latest are `metadata`; npm tarballs and Go `.mod`/`.zip` are `download`.
  - `outcome` ∈ `served | cooldown | blocked | stale | failed`.
  - Written with `INSERT … ON CONFLICT DO UPDATE SET n = n + 1` via `waitUntil`.
- `packages(eco, name, latest, latest_time, checked_at, PRIMARY KEY(eco, name))`: the newest stable version, updated whenever decant parses fresh upstream metadata (npm `dist-tags.latest`; Go `@latest`). No extra upstream calls.
- `vulns(eco, name, version, id, severity, summary, published, checked_at, PRIMARY KEY(eco, name, version, id))`: known vulnerabilities for stored versions, written by the daily cron. It already queries OSV for every stored version; it now keeps all ids, not only `MAL-`, and fetches severity per new id, cached.
- `allows.advisory_published TEXT`: filled at policy sync from the OSV record already fetched during verification.
- `alerts_state(key PRIMARY KEY, first_seen, resolved_at)`: lets "Needs attention" show "recently resolved" and keep order stable. The key is a stable string per item, such as `blocked:npm:x@1.0.0:twocal`.

The existing `serve_log` (project, package, version, day) remains the source for "what was installed when".

## Auth

- `/dashboard*` requires a valid `Cf-Access-Jwt-Assertion`:
  - an RS256 JWT verified against `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs` (JWKS cached in memory and refreshed on an unknown `kid`);
  - `aud` must contain `ACCESS_AUD`, and `iss` must be the team domain;
  - `exp`/`nbf` must be valid.
- With either variable unset, `/dashboard*` returns 404, so the dashboard is off by default.
- Registry and `/api/*` routes are unchanged (tokens).

## API (JSON, all GET, under `/dashboard/api/`)

- `projects` → the list.
- `attention?project=&range=` → open items plus recently resolved.
- `activity?project=&range=` → daily series by outcome, plus distinct package and version counts.
- `security?…`, `freshness?…`, `uptime?…`, `policy?project=`, `packages?project=&q=&page=`.
- `project=all` aggregates across projects. `range` is one of 7, 30 or 90 days.

## UI

- One HTML page at `/dashboard`: a header with a project select and range buttons; then "Needs attention"; then Activity (stacked bar SVG), Security, Freshness, Uptime and Policy in a two-column grid; then Packages (a table with search); then Recently resolved.
- It works at phone width (columns stack, the table scrolls), meets AA contrast, uses the system font stack plus Inter if available, and has a light theme with dark via `prefers-color-scheme`.
- It shows no tokens and no IPs.

## Left to the builder

- SQL for each endpoint, as long as each query is bounded by indexes on `(project_id, day)` or `(eco, name)`.
- How "major behind" is computed: semver major for npm, `vN` path or major for Go, using `src/semver.ts`.
- Chart drawing details.
- Pagination size for packages.

## Calls made after the builder check (Claude's, not George's; correct any)

1. **No backfill.** `request_counts` starts empty at deploy, and the charts show data from then on. Freshness, security and package views use the existing `serve_log` and tables, so they have history immediately. The "no requests in 14 days" alert uses the latest of `serve_log.day` and `request_counts.day`, so active projects don't trigger it at deploy.
2. **Attention rules:**
   - "Installed" means a `download` served, which is a `serve_log` row.
   - "Blocked by policy" uses the main-ref policy only.
   - Vulnerability severity follows the Action (GHSA, then CVSS v3.1, else `unknown`). `unknown` counts as moderate, so it is not alerted, but it is listed in Security.
   - A `malicious` verdict falls under the malicious rule. The `flagged` rule is for `flagged` verdicts only.
   - Items attach to a project through that project's `serve_log` (global facts × that project's installs). Conflicts and blocks with no installs show under "All projects" only.
3. **`alerts_state`** is maintained lazily by the `attention` endpoint: each call diffs the current items against open rows, inserts new ones and stamps `resolved_at` on vanished ones. A resolved item that reappears clears its `resolved_at`, so the same key is reused and no duplicate appears. Writing on a GET is acceptable here, because the endpoint is Access-only and idempotent.
4. **Outcome classification:**
   - Metadata 200 is `served`, or `stale` when served from the stored copy because upstream failed.
   - A download refused for cooldown is `cooldown`, and one refused for a block is `blocked`.
   - Upstream-unavailable 502s, and any 5xx, are `failed`.
   - Versions hidden inside a 200 metadata response are not counted, so `cooldown` and `blocked` count refused downloads.
   - Requests without a valid token aren't counted, because they have no project.
5. **Write budget:** one `request_counts` upsert per request. A `packages` upsert happens only when upstream metadata is actually refetched (at most once per 5 minutes per package), and the dashboard's JWKS cache lives in memory. "At most one extra write per request" holds for cached traffic.
6. **Time-to-fix:** a new column, `allows.first_synced_at`. It is set when an advisory allow entry first appears in a main sync, and carried over when re-syncs rewrite the allows. Time-to-fix = `first_synced_at − advisory_published`.
7. **"All projects":**
   - Activity, security, freshness and uptime aggregate across projects.
   - Policy shows one compact row per project.
   - Packages gains a project column.
   - Attention lists every project's items, tagged with the project.
8. **Config:**
   - Wrangler vars `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD`. The AUD isn't secret, but setting it as a secret also works.
   - `docs/deploy.md` gains a "Dashboard" section: create the Access application for `<host>/dashboard*` only (never the bare host), copy its AUD, and set the vars.
   - Operator docs are part of the deliverable.
