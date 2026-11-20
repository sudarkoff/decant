# decant: design

Status: draft for approval, 2026-11-19.

## Why

Malicious releases on public registries, npm especially, are now routine. Most are caught and pulled within days. decant sits between our builds and npm and Go's public registries, and it:

- holds every new version back for a cooldown (default 7 days);
- scans what we're about to install;
- keeps the versions we depend on even if they're deleted upstream;
- keeps builds working when the public registries are down;
- lets a security fix through in hours, still scanned and tested, but without the cooldown.

It's an independent open-source project (`sudarkoff/decant`) that anyone can deploy to their own Cloudflare account with `wrangler deploy`. twocal is the first adopter, and the other projects (TIC, Unleash) will follow.

## Goals

1. **Cooldown.** A version can be installed only once it is N days old (per project, default 7).
2. **Scan.** Every version a dependency change adds, direct or transitive, is scanned in CI before it can merge.
3. **Keep.** Any version decant has served is kept in R2 forever and served even after an upstream deletion.
4. **Survive outages.** Cached metadata and files are served when npm or the Go proxy are down.
5. **Fast lane.** Any version can skip the cooldown through an `allow` entry in the policy, approved by merging a PR. It is never exempt from the scan or the tests. Security fixes cite an advisory ID (GHSA/OSV/CVE) and are created automatically, so they can ship within hours of the advisory. Other entries only need a written reason: George's call is that scanning, tests and PR review make skipping the wait acceptable whenever we choose.
6. **Blocklist.** Listed versions are refused immediately, even if already cached.
7. **Policy as code.** Each project's policy is a file in its repo. Approval is a merged PR, and git history is the audit trail.
8. **No install scripts.** Docs and the Action make `--ignore-scripts` the default.
9. **Clean supply chain of its own.** No runtime dependencies in the Worker, few build dependencies, pinned Actions, signed release tags, and a reproducible build.

## Non-goals (v1)

- Ecosystems other than npm and Go. The code keeps an ecosystem interface so PyPI and crates can be added later.
- Scanning at the registry, where a never-seen version is withheld until scanned. This is gate B, issue #1. v1 stores scan verdicts so that B can be added without rework.
- Mirroring whole registries. Only versions that are actually requested get cached.
- Private or internal packages. npm scopes pointing elsewhere and Go `GOPRIVATE` modules bypass decant.
- Publishing. decant is read-only to clients, and `npm publish` against it is refused.
- A web UI.

## Anti-goals (failure even if it "works")

- **A silent fail-open path.** Any client config that falls back to the public registry when decant refuses (`GOPROXY=...,direct`, a missing `.npmrc` line) defeats the tool. The documented configs must fail closed.
- **decant itself as the attack path,** through a compromised dependency or Action in its own build.
- **Changing package bytes.** Lockfile integrity hashes and Go's sumdb must keep verifying.
- **Blocks or fast-lane approvals that take minutes to take effect** because of caching.
- **Policy changes made outside git.** The only exception is automatic blocks for known-malicious advisories, which are logged (see Global blocks).

## Constraints

- Cloudflare Workers + R2 + D1. Deploys with `wrangler deploy`.
- Assumes Workers Paid ($5/mo) for the CPU and subrequest limits. Large npm documents, like `@types/node`, run to tens of MB of JSON.
- Worker memory is 128 MB, so tarballs and Go zips are streamed, never buffered.
- GitHub Actions minutes are billed, so the Action runs only on dependency changes, on a daily schedule and on merge to main.
- George has more than one Cloudflare account. Ask which account and domain before any deploy.

## Approaches considered

- **Where the scan happens.**
  - A: in CI, over the lockfile diff. **Chosen for v1.**
  - B: in the registry, before first serve. It's stronger but needs Containers to run Python scanners. Ticketed as #1, and it stacks on A.
  - C: direct deps only, which was the brief's original. Rejected because most real attacks arrive transitively.
- **Language.**
  - TypeScript Worker and Action. **Chosen**, because it's native to Workers, streams easily into R2 and needs no runtime deps.
  - Go compiled to Wasm. Rejected for large binaries, slow cold starts and awkward streaming.
  - A Go server on Fly. Rejected because it gives up Cloudflare.
- **Tenancy.**
  - One shared deployment serving many projects, each with its own policy, picked by token. **Chosen** by George, because all projects will use it, and adding it later would mean migrating storage.
  - One deployment per repo. Rejected.
- **Policy state.**
  - D1. **Chosen** because changes are visible immediately.
  - KV. Rejected because a change can take up to 60s to show up, which is too slow for a blocklist.

## Architecture

Three pieces live in one repo: the **Worker** (registry + admin API), the **Action** (scan, audit, sync) and the **docs** (adoption guide + hardening guide).

```
 npm / go client ──token──▶ Worker ──▶ R2  (tarballs, zips, raw upstream metadata, scan verdicts)
                              │   └──▶ D1  (projects, tokens, policies, first-seen times, global blocks, serve log)
                              └──▶ registry.npmjs.org / proxy.golang.org / api.osv.dev
 GitHub Action ──admin token──▶ Worker admin API (policy sync, verdict writes)
```

### Projects and tokens

- A **project** is one adopting repo (e.g. `twocal`). Each has its own policy.
- **Read tokens:** clients authenticate with a per-project token. npm sends it as `Authorization: Bearer` (`_authToken` in `.npmrc`). Go sends it as HTTP basic auth (`https://decant:<token>@host/go`, or `.netrc`). The project is resolved from the token. Every read requires a token.
- **CI tokens:** a per-project token with write access to that project's policy and to scan verdicts.
- **Operator token:** creates projects and tokens. It's set as a Worker secret and used from a small CLI script (`npm run decant -- project create twocal`).
- Tokens are stored as SHA-256 hashes in D1 and never logged.
- **Trust model:** all projects on one deployment belong to one organization and trust each other. This matters because a block issued by one project applies to all.

### Policy file

The policy file is `decant.json` at the root of the adopting repo. It's JSON so the Action needs no parser dependency, and a JSON Schema ships for editor validation.

```json
{
  "$schema": "https://raw.githubusercontent.com/sudarkoff/decant/main/schema/policy.json",
  "project": "twocal",
  "cooldownDays": 7,
  "autoShip": { "critical": "auto", "high": "auto", "moderate": "approve", "low": "approve" },
  "allow": [
    { "package": "npm:lodash@4.17.22", "advisory": "GHSA-xxxx-xxxx-xxxx", "reason": "security fix", "added": "2026-11-19" },
    { "package": "npm:astro@5.4.2", "reason": "fixes build regression we hit", "added": "2026-11-19" }
  ],
  "block": [
    { "package": "npm:chalk@5.6.1", "reason": "compromised release", "advisory": "MAL-2025-0001" }
  ]
}
```

- Package IDs are `<ecosystem>:<name>@<version>`, e.g. `npm:@scope/name@1.2.3` or `go:github.com/x/y@v1.2.3`.
- `autoShip` applies only to security PRs that the Action opens. Hand-made `allow` PRs follow the repo's normal review. It sets, per severity, whether a security PR merges itself once the scans and CI pass (`auto`) or waits for a human (`approve`). twocal uses `auto` for all severities. The schema default is critical/high `auto` and the rest `approve`.
- `cooldownDays` is set per project. The default is 7, and 0 turns the cooldown off.
- Each `allow` entry needs a `reason`. `advisory` is optional. Entries with an advisory are the security fast lane, and the `audit` mode creates them. Entries without one are added by hand.
- An entry with an `advisory` is only honored if OSV confirms that the advisory lists that version as fixed (or later than the last affected version). This guards against a typo or a lazy entry turning into a general bypass. The Action prunes all `allow` entries once their version has aged past the cooldown.
- **Adoption:** the CLI (`decant adopt`) reads the current lockfiles and writes `allow` entries, with reason `adopted`, for any pinned version still inside the cooldown. Installs work from the first day, and the entries prune themselves.
- **Verification happens at sync time (my call).** The Worker calls OSV when a policy or overlay is synced and stores the verified advisory entries in D1 (`advisory`, fixed range, `verifiedAt`). The read path never calls OSV. If OSV is down at sync time, the unverified entries are rejected and the sync fails, which fails closed and is visible in CI; a re-run retries. Overlays are re-verified on every sync.

### Version decision (applied per request, per project)

For version `v` of package `p`, in order:

1. **Blocked:** if `p@v` is in the global block set, it is hidden from metadata and returns 404 on download.
2. **Allow:** if `p@v` is in this project's `allow` list, it is allowed. An entry with an advisory counts only once OSV has verified it.
3. **Cooldown:** if `now − publishTime(p@v) ≥ cooldownDays`, it is allowed. Otherwise it is hidden and the download returns 404.

`publishTime` comes from npm's `time[v]`, or the `Time` field in Go's `.info`. The first value seen is recorded in D1 and pinned. If upstream later reports a different time for that version, it is treated as blocked and flagged, which fails closed.

Downloads enforce the same decision as metadata, because lockfiles pin download URLs directly.

### Global blocks

A version is in the global block set if any of these hold:
- it appears in any project's synced `block` list;
- it has an OSV `MAL-` (known malicious) advisory. The Worker checks this when it first stores a version, and a daily Worker cron re-checks every stored version in batches through OSV's querybatch API. Hits are written to D1 with their source and time, and they surface in the Action's daily run as an issue on each affected repo;
- a scan verdict stored for it is `malicious`. A heuristics `flagged` verdict does not block; it fails the PR check for a human to review.

### npm registry (Worker)

- **Routes:** `/npm/<name>` for package metadata, accepting `@scope%2fname` and `@scope/name`, and `/npm/<name>/-/<file>.tgz` for tarballs. The version is parsed from the file name from the right. `/-/npm/v1/security/*` passes through, so `npm audit` keeps working. Every other route, including publish, returns 404/405.
- **Metadata:** the raw upstream document is stored in R2 and refetched when it's older than 5 minutes. Concurrent cold fetches are collapsed into one. If upstream fails, the stored copy is served regardless of age. Policy is applied at request time to a copy:
  - hidden versions are removed from `versions`, from `time` (`created` and `modified` are kept, and `modified` is set to the newest allowed time), and from every dist-tag;
  - `latest` is set to the highest semver non-prerelease allowed version. If there is none, it's the highest allowed prerelease, and if nothing is allowed the dist-tag is omitted;
  - other dist-tags are kept only if their target is allowed;
  - `dist.tarball` is rewritten structurally to point at decant. `integrity` and `shasum` are never touched.

  Both the full and the abbreviated (`application/vnd.npm.install-v1+json`) formats are supported and cached separately (`Vary: Accept`). The filtered output is never cached at the edge; the raw upstream cache is what makes it cheap.
- **Tarballs:** the version decision is checked first. If the tarball is in R2, it's served from there. Otherwise it's fetched upstream and streamed to both the client and R2 while its sha512 is computed. If the hash doesn't match the upstream `integrity`, the R2 object is deleted and the error logged.

### Go module proxy (Worker)

- **Routes:** the GOPROXY protocol under `/go/`: `<module>/@v/list`, `@v/<ver>.info`, `.mod`, `.zip` and `@latest`. Module paths use Go's `!`-lowercase escaping. Upstream is `proxy.golang.org`.
- `.info` gives the publish time. It is stored per version in D1 the first time it's seen, so `@v/list` can be filtered without fetching `.info` for every version. Versions with no stored time get fetched lazily, a bounded number per request. The rest are left out of `list` until they have a time, which fails closed.
- `@latest` and `list` reflect only allowed versions. Pseudo-versions and `+incompatible` versions follow the same rules, using the `.info` time and not the commit time embedded in the pseudo-version.
- `.mod` and `.zip` are stored in R2 and served byte-for-byte. `GOSUMDB` stays at its default (`sum.golang.org`), and decant does not proxy sumdb. Docs say never to set `GONOSUMDB`/`GOFLAGS=-insecure` and to use `GOPROXY=https://…/go` with no `,direct` fallback.

### Storage layout

- **R2:**
  - `npm/meta/<name>.json` for the raw upstream metadata (full and abbreviated stored separately);
  - `npm/tar/<name>/<file>.tgz`;
  - `go/<module>/@v/<ver>.{info,mod,zip}` and `go/<module>/@v/list.raw`;
  - `verdicts/<eco>/<name>@<ver>.json`, holding `{scanner, version, result, details, scannedAt}`.
- **D1:** `projects`, `tokens`, `policies` (the current synced policy per project, with commit SHA and sync time), `versions` (eco, name, version, publishTime, firstSeen), `global_blocks` (package, source, reason, at), and `serve_log` (project, eco, name, version, day). The serve log records one row per project, version and day, which answers "what did prod install on day X" next to the lockfiles in git.

### Admin API

- `PUT /api/projects/<id>/policy` (CI token): body is `decant.json`, the commit SHA and the ref. Only `main` (configurable) becomes the project's policy. See "PR previews" below for other refs.
- `PUT /api/verdicts/<eco>/<name>@<ver>` (CI token).
- `GET /api/projects/<id>/status` (CI token): the current policy SHA, global blocks hitting this project's lockfiles, and pending items.

### Lockfile URLs and who installs through decant (my call)

- **Lockfiles keep `registry.npmjs.org` URLs.** npm's default `replace-registry-host=npmjs` rewrites them to the configured registry at install time. Lockfiles stay portable, and decant's domain never gets baked into them. *Correction (2026-11-19, tested):* npm writes the URL it actually downloaded from into `resolved`, so an install through decant puts decant URLs into the lockfile. The Action therefore normalizes lockfiles: any `resolved` URL under `<decant>/npm/` or `<decant>/r/<ref>/npm/` is rewritten to `https://registry.npmjs.org/` (the paths below that prefix are identical). `scan` fails a PR whose lockfile contains decant URLs and prints the one-line fix, and `audit` and `adopt` normalize what they write. The Worker builds `dist.tarball` URLs under the prefix of the request, whether that's `/npm/` or `/r/pr-<n>/npm/`, so previews work too. The Action's lockfile differ keys on name and version, never on URL.
- **Every install goes through decant:** CI, Docker builds (the token is passed as a BuildKit secret, never as a build arg or layer) and local dev (each developer's `~/.npmrc` and `.netrc` hold a read token). A local `npm install` is an attack path too.

### PR previews

A PR that adds an `allow` entry needs CI on that PR to install the new version before the entry is merged.

- On a PR, the Action syncs the PR's `decant.json` as an overlay for ref `pr-<n>`.
- An overlay may only add `allow` entries, and entries with an advisory are still OSV-verified. It cannot change the cooldown, remove blocks or change `autoShip`.
- CI installs through `/r/pr-<n>/npm/` and `/r/pr-<n>/go/`. Overlays expire 14 days after their last sync.
- Builds from `main` never see overlays.

### GitHub Action (`sudarkoff/decant/action@<sha>`)

It's a single TypeScript action, bundled and committed as `dist/` (the standard JS-action layout), and it runs in one of three modes:

1. **`scan`** (on PRs that touch lockfiles or `decant.json`):
   - diffs lockfiles (`package-lock.json` v2/v3 and `go.sum`) between base and head, giving every added `pkg@version`;
   - downloads each through decant, so the bytes scanned are the bytes served;
   - checks OSV for known vulnerabilities and malicious advisories, and runs GuardDog (pinned version, installed with hashes) for malware heuristics. GuardDog's Go support needs checking; if it's lacking, Go gets OSV only in v1;
   - writes verdicts to decant;
   - fails the check on a `malicious` result or a vulnerability at or above the configured severity, and posts a summary comment.

   Verdicts are cached by `pkg@version`, so a version scanned for one project isn't rescanned for another.
2. **`audit`** (daily cron, plus manual dispatch):
   - checks all lockfiles against OSV/GHSA;
   - for each vulnerable package that has a fix, opens one PR per run (see plan-2 additions) that raises each package to the highest fixed release its advisories need (lockfile update with `--ignore-scripts --package-lock-only`, or `go get` + `go mod tidy`), adds the `allow` entry with its advisory, and labels the severity;
   - if `autoShip` is `auto` for that severity, enables GitHub auto-merge, so the PR merges itself when required checks pass;
   - also reports global blocks that hit the lockfiles and prunes `allow` entries whose versions have aged past the cooldown.
3. **`sync`** (on push to main): sends `decant.json` to decant and fails the run if decant rejects it.

**GitHub constraint:** PRs opened with the default `GITHUB_TOKEN` don't trigger other workflows, so CI wouldn't run on them. The `audit` mode needs a GitHub App installation token (recommended) or a fine-grained PAT. The docs cover creating the App. Commits are created through the GitHub API, so they show as verified, which matters for repos that require signed commits.

### decant's own supply chain

- The Worker has no runtime dependencies. It uses the Workers runtime only and includes its own small semver comparator and a tar reader if one is needed.
- Dev and build dependencies are minimal and pinned: `wrangler`, `typescript`, `vitest` with `@cloudflare/vitest-pool-workers`, and `esbuild` to bundle the Action. Lockfile committed, `npm ci --ignore-scripts`.
- All Actions in decant's own workflows are pinned to commit SHAs. Releases are signed tags, and `dist/` is rebuilt in CI and must match what's committed, which keeps the build reproducible.
- License: Apache-2.0. Its explicit patent grant is the norm for security infrastructure.

### Docs that ship in v1

- **Deploy:** wrangler, R2 bucket, D1, secrets, custom domain, creating projects and tokens.
- **Adopt:** `.npmrc` (`registry=`, `_authToken`, `ignore-scripts=true`), `GOPROXY`/`.netrc`, the policy file, and wiring the Action (scan, audit, sync) with the GitHub App.
- **Hardening:** pin third-party Actions to SHAs, Docker base images to digests, `npm ci --ignore-scripts`, no `,direct` in GOPROXY, and setting any Renovate/Dependabot `minimumReleaseAge` to match the cooldown.

## Lessons from prior art (Thinkst package-proxy, escrow)

**Borrowed:**
- serve stale on upstream failure;
- collapse concurrent cold fetches into one;
- re-check already-served versions;
- enforce at the download route;
- pass `npm audit` through.

**Avoided:**
- Picking `latest` by insertion order or by newest publish time. Both promote backports or prereleases to `latest`.
- Rewriting tarball URLs with a string replace.
- Iterating `created`/`modified` as if they were versions.
- Ignoring the abbreviated metadata format.
- Caching filtered output for 30 minutes, which delays blocks.
- Keeping config in KV outside git.
- Not rewriting `dist.tarball`, which sends clients straight to npm.

## twocal adoption (separate PR, after v1)

- **Surfaces:** `apps/web` and `apps/site` (npm, `package-lock.json`) and `apps/api` (Go). There's no root `package.json`.
- **The adoption PR adds:**
  - `.npmrc` in both apps;
  - `GOPROXY` in CI and the Dockerfiles;
  - `decant.json`;
  - the three Action modes in `.github/workflows/`;
  - SHA-pinning of existing Actions;
  - Docker base image digests.

  It follows twocal's PR + squash-merge flow.

## Left to the builder

- Module layout, the ecosystem interface shape and test structure (TDD, using `vitest-pool-workers` against local R2/D1).
- Exact D1 schema and migrations.
- How lazy Go `.info` fetches are bounded per request.
- How the semver comparator handles edge cases. It must order prereleases per the npm spec.
- Whether verdict JSON lives in R2 or D1, provided lookup is by `pkg@version`.
- CLI ergonomics for the operator script.

## Additions for plan 2 (2026-11-19)

These came out of building and reviewing the Worker. George approved the direction in conversation.

- **Three token kinds: `read`, `ci` and `sync`.**
  - A `sync` token can only sync the main-ref policy.
  - A `ci` token can sync overlays (any ref except main), write and read verdicts, read status and read blocks. A `ci` token on the main ref gets 403.
  - Adopters keep the `sync` token in a GitHub Environment restricted to the default branch. A workflow on another branch then can't loosen the main policy, even though it can read the repo's other secrets.
  - Migration `0003` widens the `tokens.kind` check.
- **`GET /api/blocks` (`ci` token):** returns every global block (`package`, `source`, `reason`, `at`). The Action intersects these with the lockfiles.
- **Emergency bypass (George: last resort, deliberate manual steps only, never automatic).**
  - The Action's `setup` mode writes the npm and Go client config. With the inputs `bypass: true` and a non-empty `bypass-reason`, it points at the public registries instead.
  - It emits a warning annotation and a step-summary banner naming the actor and the reason.
  - The example workflow exposes this only as a `workflow_dispatch` input that defaults to `false`.
  - Because lockfiles are normalized (above), npm and Go still verify the locked hashes during a bypass.
- **Reviewing a flagged scan result:** a heuristics `flagged` result fails the check until a user with write access adds the label `decant:reviewed` to the PR. Security PRs carrying a `flagged` result are never auto-merged.
- **Fixed versions inside `audit`:** a fixed version can still be in its cooldown. `audit` therefore first syncs one overlay for ref `audit`: the main policy plus one verified allow entry per fixed package version (citing the highest-severity advisory, the rest listed in `reason`). If decant rejects some entries, those packages are dropped and the sync is retried once; a second rejection fails the run. All upgrades resolve through `/r/audit/`, and the PR gets its own `pr-<n>` overlay as usual.
- **One security PR per audit run (George, 2026-11-19).** Per-advisory PRs flooded repos (one adopter got 15 PRs for 7 packages). `audit` now groups advisories by package, targets the highest fix each locked copy needs, applies every fix in one working tree, and commits them to one branch `decant/security-fixes` with one PR (`decant: security fixes (N packages, M advisories)`, labels `decant:security` + `decant:<max severity>`). An open PR is refreshed in place; a closed-unmerged PR covering the same package@target set (a hidden hash marker in the body) is not reopened. Auto-merge needs every severity at `autoShip: auto` and no major-line crossing. Unresolvable packages are reverted and listed in the unfixed-advisories issue.
- **`adopt` is an Action mode (`workflow_dispatch`).** It reads the lockfiles and writes `decant.json` with `allow` entries (reason `adopted`) for pinned versions still in their cooldown, using publish times from the public registries. It opens a PR, so adoption is also approved in git.
- **Unscannable sources:** lockfile entries resolved from git, file or non-npm URLs can't be gated. `scan` reports them as warnings, and they don't fail the check.
