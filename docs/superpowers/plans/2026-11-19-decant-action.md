# decant GitHub Action (v1, plan 2 of 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A dependency-free GitHub Action (`sudarkoff/decant/action@<sha>`) with five modes: `setup`, `sync`, `scan`, `audit` and `adopt`. It wires an adopting repo to the deployed Worker. The Worker also gains the `sync` token kind and `GET /api/blocks`, and the release hygiene and adoption docs ship.

**Architecture:**
- The Action is a Node 24 JavaScript action. TypeScript lives in `action/src/` and is bundled by esbuild into the committed `action/dist/index.js`. It uses only Node built-ins: `fetch` for decant, OSV, the GitHub REST and GraphQL APIs and the public registries, and `child_process` for `npm`, `go`, `git` and GuardDog.
- A single entry point dispatches on the `mode` input.
- GitHub I/O (inputs, outputs, annotations, step summary) goes through a tiny local module, not `@actions/*`.
- Tests run in a separate vitest config with the Node environment. All network access goes through an injected `fetch`, and all commands through an injected `exec`.

**Tech Stack:** TypeScript, Node 24 (`runs.using: node24`), esbuild and vitest. GuardDog (Python) is installed at runtime from a hash-pinned requirements file.

**Spec:** `docs/superpowers/specs/2026-11-19-decant-design.md`. Read the "GitHub Action", "Lockfile URLs", "PR previews" and "Additions for plan 2" sections.

## Global Constraints

- **No runtime dependencies,** in the Worker or the Action. Dev dependencies may be added only from this list: `esbuild`, `@types/node`. Each is pinned exactly and installed with `npm install --save-exact --before=<today−7d>`.
- **Scripts off:** every `npm` command the Action runs passes `--ignore-scripts`.
- **Secrets:**
  - Tokens are never printed. Every token input is registered with `::add-mask::` before use.
  - Tokens are never put in a URL that gets logged. For Go, write a `.netrc` file (mode 600) instead of embedding `user:token@` in `GOPROXY`.
- **Lockfiles:** `resolved` URLs are normalized to `https://registry.npmjs.org/`, which rewrites both `<decant>/npm/` and `<decant>/r/<ref>/npm/`. Only `package-lock.json` versions 2 and 3 are supported. Version 1 fails with `regenerate package-lock.json with npm 7 or newer`.
- **Severity order:** `critical > high > moderate > low > unknown`. `fail-on` defaults to `high`. `unknown` counts as `moderate`.
- **Labels:** `decant:security`, `decant:<severity>`, `decant:reviewed`, `decant:prune`, `decant:adopt`.
- **Refs:** overlays use `pr-<number>` for PRs and `audit-<advisory>` (lowercased) for audit. Main uses the repo's default branch name.
- **Commits** made by the Action go through GraphQL `createCommitOnBranch`, so they show as verified.
- **Commits** in this repo are signed. Work happens on branch `action`; nothing is pushed to `main`.
- **Gated on George:** the public release tag (Task 11).

## Review Focus

1. **A lockfile entry under `node_modules/a/node_modules/b`** resolves to package `b`. Entries with `link: true` or `inBundle: true` are skipped. Non-registry `resolved` URLs are reported, not scanned. Owned by Task 3.
2. **`decant.json` missing** from the repo makes `sync`, `scan` and `audit` fail with `decant.json not found at <path>` (exit 1). Only `adopt` creates it. Owned by Task 5.
3. **A PR from a fork has no secrets.** `scan` must detect the missing token and exit 0 with a notice saying the decant check was skipped because a fork has no secrets. A missing token must never make it scan unauthenticated against public registries. Owned by Task 6.
4. **An advisory with no fixed version** produces no PR. It is listed in the run summary and in one tracking issue titled `decant: unfixed advisories`, which is updated rather than duplicated. Owned by Task 8.
5. **Re-running `audit`** never opens a duplicate PR or branch for an advisory that already has an open PR, and never re-creates an issue. Owned by Task 8.

---

## File Structure

```
src/auth.ts, src/admin/handler.ts, migrations/0003_sync_token.sql, scripts/cli-lib.ts   (Task 1)
action/action.yml                    inputs, runs.using node24, main dist/index.js
action/tsconfig.json                 Node types, strict
action/build.mjs                     esbuild bundle → action/dist/index.js (deterministic)
action/dist/index.js                 committed bundle
action/src/main.ts                   read inputs, dispatch mode, exit code
action/src/gh-io.ts                  inputs, outputs, mask, annotations, summary
action/src/exec.ts                   injectable command runner
action/src/lockfiles.ts              find + parse package-lock / go.sum, diff, normalize
action/src/policy-file.ts            read/write decant.json (reuses src/policy/schema.ts)
action/src/decant-client.ts          Worker API + package downloads via overlay ref
action/src/registries.ts             public npm / Go publish times
action/src/osv.ts                    vulns + MAL lookups, severity, fixed-version math
action/src/github.ts                 REST + GraphQL client
action/src/guarddog.ts               venv install with hashes, scan, parse
action/src/modes/setup.ts, sync.ts, scan.ts, audit.ts, adopt.ts
action/guarddog-requirements.txt     hash-pinned
action/test/*.test.ts                one per module/mode
vitest.action.config.ts              Node environment, include action/test
examples/workflows/decant-pr.yml, decant-main.yml, decant-audit.yml, decant-adopt.yml
docs/adopt.md, docs/hardening.md, docs/release.md
```

---

### Task 1: Worker — `sync` token kind and `GET /api/blocks`

**Files:** `migrations/0003_sync_token.sql`, `src/auth.ts`, `src/admin/handler.ts`, `scripts/cli-lib.ts`, plus tests in `test/auth.test.ts`, `test/admin.test.ts` and `test/cli.test.ts`.

**Interfaces:**
- Produces:
  - `AuthCtx` kinds `'read' | 'ci' | 'sync'`, with `newToken('sync')` → `dk_sync_…`.
  - Policy sync authz: `sync` tokens of the project only when `ref === main_ref`; `ci` tokens of the project only when `ref !== main_ref`; anything else 403 `use the sync token for <main_ref>` or `sync tokens may only sync <main_ref>`.
  - Verdicts, status and blocks accept `ci` tokens only. `sync` gets 403 there.
  - On npm and Go registry routes, `sync` tokens get 403. They are not install credentials.
  - `GET /api/blocks` (`ci`) → `{ blocks: [{ package, source, reason, at }] }`, ordered by `at` desc.
  - CLI: `token create <project> <read|ci|sync>`.
  - Migration: rebuild `tokens` with `CHECK (kind IN ('read','ci','sync'))`, copying rows (SQLite can't alter a CHECK in place).

- [ ] **Step 1: Write failing tests.**
  - A `sync` token on a main-ref sync → 200, and on ref `pr-1` → 403.
  - A `ci` token on a main-ref sync → 403, and on `pr-1` → 200.
  - A `sync` token on `/npm/x` → 403.
  - A `sync` token on `GET /api/blocks` → 403.
  - A `ci` token on `GET /api/blocks` → 200 and lists a block added via a main sync.
  - Existing `read`/`ci` rows survive the migration (seed, then apply 0003, then authenticate).
  - CLI: `token create twocal sync` builds a POST with `{kind:'sync'}`, and `admin` still errors with `kind must be read, ci or sync`.
- [ ] **Step 2:** `npx vitest run` → FAIL.
- [ ] **Step 3:** Implement. Update `seedProject` to also return a `sync` token.
- [ ] **Step 4:** `npx vitest run && npx tsc --noEmit` → PASS.
- [ ] **Step 5:** Commit `feat: sync token kind and blocks endpoint`.

### Task 2: Action scaffold, I/O, build and CI

**Files:**
- `action/action.yml`, `action/tsconfig.json`, `action/build.mjs`
- `action/src/main.ts`, `gh-io.ts`, `exec.ts`, `action/dist/index.js`
- `vitest.action.config.ts`, `package.json` (scripts), `.github/workflows/ci.yml`
- `action/test/gh-io.test.ts`, `action/test/main.test.ts`

**Interfaces:**
- `action.yml` inputs, all strings:
  - `mode` (required): `setup|sync|scan|audit|adopt`
  - `decant-url` (required)
  - `token`: read for setup, ci for scan/audit/adopt, sync for sync on main
  - `sync-token`
  - `github-token`, defaulting to `${{ github.token }}`
  - `policy-path`, default `decant.json`
  - `fail-on`, default `high`
  - `working-directory`, default `.`
  - `bypass`, default `false`
  - `bypass-reason`, default empty
- `gh-io.ts`:
  - `getInput(name, env = process.env): string`, reading `INPUT_<NAME>` with `-` → `_`, uppercased and trimmed;
  - `mask(v)`;
  - `notice|warning|error(msg, file?)`, writing `::<level>[ file=…]::` with `%`, `\r` and `\n` escaped;
  - `setOutput(k, v)` and `appendSummary(md)`, which append to the `GITHUB_OUTPUT` and `GITHUB_STEP_SUMMARY` files;
  - `exportVar(k, v)` → `GITHUB_ENV`, using the multiline-safe delimiter form.
- `exec.ts`: `type Exec = (cmd: string, args: string[], opts?: { cwd?: string; env?: Record<string,string>; input?: string }) => Promise<{ code: number; stdout: string; stderr: string }>`, with a default implementation built on `child_process.spawn` and no shell.
- `main.ts`: `run(deps: { env; fetch; exec; now; fs }): Promise<number>`, which returns the exit code. An unknown mode exits 1 with `unknown mode <m>`. Each mode module exports `run(ctx): Promise<number>`; until each mode's task lands, its stub returns 1 with `not implemented`.
- **Build:** `node action/build.mjs` runs esbuild with `platform: 'node'`, `target: 'node24'`, `format: 'esm'`, `bundle: true`, `minify: false` and `legalComments: 'none'`, and no banner timestamp, so output is byte-stable.
- **CI:** a new job builds and runs `git diff --exit-code action/dist`. Tests run both configs: `"test": "vitest run && vitest run -c vitest.action.config.ts"`.

- [ ] **Step 1: Write failing tests.**
  - `getInput('policy-path', {INPUT_POLICY_PATH:' x '}) === 'x'`.
  - `error('a\nb')` writes `::error::a%0Ab`.
  - `exportVar` uses the `name<<delim` form.
  - `run` with mode `nope` → 1, and stderr has `unknown mode nope`.
  - Building twice yields identical bytes (hash compare).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement, and add the dev dependencies `esbuild` and `@types/node`.
- [ ] **Step 4:** `npm test && npx tsc --noEmit -p action && node action/build.mjs && git diff --exit-code action/dist` → PASS (after committing dist once).
- [ ] **Step 5:** Commit `feat(action): scaffold, I/O and reproducible build`.

### Task 3: Lockfiles (`action/src/lockfiles.ts`)

**Interfaces:**
- `type Dep = { eco: 'npm'|'go'; name: string; version: string; file: string; source: 'registry'|'other'; resolved?: string }`
- `findLockfiles(root, fs): Promise<string[]>`: finds `package-lock.json` and `go.sum`, skipping `node_modules`, `.git` and `vendor`. Paths are relative and sorted.
- `parsePackageLock(text, file): Dep[]`:
  - for v2 and v3 it reads `packages`;
  - it skips `""`, `link: true` and `inBundle: true`;
  - the name is `entry.name ??` whatever follows the last `node_modules/`;
  - `source` is `'registry'` iff `resolved` is absent or starts with `https://registry.npmjs.org/` or a decant npm prefix passed in. Otherwise it's `'other'`;
  - v1 throws the constraint message.
- `parseGoSum(text, file): Dep[]`: only lines whose version has no `/go.mod` suffix (module zips), deduplicated.
- `diffDeps(base: Dep[], head: Dep[]): Dep[]`: entries in head whose `eco:name@version` isn't in base.
- `normalizeLockfile(text, decantUrl): { text: string; changed: number }`: rewrites `resolved` values matching `^<decantUrl>(/r/[A-Za-z0-9._-]{1,64})?/npm/` to `https://registry.npmjs.org/`. It is a string-level rewrite of `"resolved": "<url>"` values only, so formatting is preserved.
- `containsDecantUrls(text, decantUrl): boolean`

- [ ] **Step 1: Write failing tests** (fixtures in `action/test/fixtures/`):
  - nested `node_modules/a/node_modules/b@1.0.0` → name `b` (Review Focus 1);
  - `link` and `inBundle` are skipped;
  - `git+https://…` → source `other`;
  - lockfile v1 throws;
  - the scoped `node_modules/@s/p` → `@s/p`;
  - go.sum with both `v1.2.3 h1:` and `v1.2.3/go.mod h1:` lines → one dep;
  - diff returns only the new entries;
  - normalize turns `https://d.example/r/pr-3/npm/left-pad/-/left-pad-1.3.0.tgz` into `https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz` with `changed === 1` and the surrounding whitespace byte-identical;
  - `findLockfiles` ignores `node_modules/x/package-lock.json`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(action): lockfile parsing, diff and normalization`.

### Task 4: Clients — decant, registries, OSV, GitHub

**Files:** `action/src/decant-client.ts`, `registries.ts`, `osv.ts`, `github.ts` and one test each.

**Interfaces:**
- **decant client:** `decant(fetch, url, token)` →
  - `syncPolicy(project, policyJson, sha, ref)`, which returns `{status, body}`;
  - `getVerdicts(pkgId)` and `putVerdict(v)`;
  - `blocks()`;
  - `downloadNpm(name, version, ref?)`, which reads `/r/<ref>/npm/<name>` metadata, then fetches the version's `dist.tarball`, and returns `{status: 'ok', bytes: Uint8Array} | {status: 'cooldown'|'blocked'|'missing'}`. A 404 body containing `in cooldown` maps to `cooldown`, and `blocked` maps to `blocked`;
  - `downloadGo(module, version, ref?)`, the same shape for the `.zip`, using Basic auth `decant:<token>`.

  All calls use Bearer auth, a 30 s timeout, and never include the token in thrown messages.
- **registries:**
  - `npmPublishTime(fetch, name, version): Promise<Date|null>` reads `registry.npmjs.org` `time[version]`;
  - `goPublishTime(fetch, module, version)` reads `proxy.golang.org/<escaped>/@v/<v>.info` `Time`. Reuse `src/go/escape.ts`.
- **OSV:**
  - `queryVulns(fetch, deps: Dep[]): Promise<Map<depKey, Vuln[]>>` uses `querybatch` in chunks of 1000, then `GET /v1/vulns/<id>` for details, cached per run;
  - `Vuln = { id; aliases; severity: Severity|'unknown'; summary; fixedFor(eco, name, version): string|null; malicious: boolean }`;
  - severity comes from `database_specific.severity` (GHSA: `CRITICAL|HIGH|MODERATE|LOW`), else `unknown`;
  - `fixedFor` finds the `affected` entry for the package, then the `ranges` event pair where `introduced ≤ version < fixed`, and returns that `fixed` (Go versions are compared with a leading `v`). It returns null if no range covers the version or there is no `fixed`;
  - `malicious` is `id.startsWith('MAL-')`.
- **GitHub:** `github(fetch, token, repo /* owner/name */)` →
  - `getPr(n)`, `prLabels(n)`, `labelAddedByWriter(n, label)` (timeline events plus collaborator permission ∈ admin, maintain or write);
  - `upsertComment(n, marker, body)`, `findOpenPr(head)`;
  - `createBranch(name, fromSha)`;
  - `commitFiles(branch, expectedHeadOid, message, files: {path, contents}[])` (GraphQL `createCommitOnBranch`);
  - `openPr({head, base, title, body, labels})`, `enableAutoMerge(prNodeId, 'SQUASH')`;
  - `upsertIssue(title, body, labels)` (searches open issues by exact title);
  - `defaultBranch()`.

  REST uses `Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2022-11-28`.

- [ ] **Step 1: Write failing tests,** all with fake fetch:
  - `downloadNpm` maps a 404 `in cooldown` → `cooldown`;
  - the token never appears in a thrown error;
  - `fixedFor` for a range `introduced 0, fixed 1.2.4` at `1.2.3` → `1.2.4`, at `1.2.4` → null;
  - for two ranges, it picks the one covering the version;
  - GHSA `MODERATE` → `moderate`;
  - `MAL-2025-1` → malicious;
  - `upsertComment` edits an existing comment that contains the marker instead of posting a new one;
  - `upsertIssue` updates by exact title (Review Focus 5);
  - `commitFiles` sends `expectedHeadOid` and base64 contents.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(action): decant, registry, OSV and GitHub clients`.

### Task 5: Modes `setup` and `sync`

**Interfaces:**
- **`setup`** (read token):
  - writes `~/.npmrc` lines `registry=<url>/npm/`, `//<host>/npm/:_authToken=<token>` and `ignore-scripts=true`;
  - writes `~/.netrc` (`machine <host> login decant password <token>`, mode 600) and exports only `GOPROXY=<url>/go`. It leaves `GOSUMDB`, `GONOSUMDB` and `GOFLAGS` untouched;
  - with `bypass=true`, `bypass-reason` must be non-empty, else exit 1 with `bypass requires bypass-reason`. It then writes `registry=https://registry.npmjs.org/` and `ignore-scripts=true` and exports `GOPROXY=https://proxy.golang.org`. It emits `::warning::decant BYPASSED by <GITHUB_ACTOR>: <reason>` and a summary banner `## ⚠️ decant bypassed`. No token is written.
- **`sync`:**
  - reads and validates `policy-path` with `parsePolicy` from `src/policy/schema.ts`, imported and bundled. Invalid → exit 1 listing errors. Missing → Review Focus 2;
  - picks the ref from `GITHUB_EVENT_NAME`: `pull_request` → `pr-<n>` (from the event payload) using `token` (ci); `push` to the default branch → the branch name using `sync-token`;
  - posts `{policy, sha: GITHUB_SHA, ref}`. Non-2xx → exit 1 with the server's error;
  - outputs `ref`.

- [ ] **Step 1: Write failing tests** (temp HOME and temp GITHUB_* files):
  - `setup` writes all three npmrc lines and a `.netrc` with mode 600, and `GOPROXY` has no `,direct` and no token;
  - bypass without a reason → 1;
  - bypass with a reason → public registries, a warning line containing the actor, and no token anywhere in the written files;
  - `sync` on `pull_request` #7 → `ref` `pr-7` using the ci token;
  - `push` to main → sync-token;
  - a missing policy file → 1 with the exact message;
  - a server 422 → 1 and its error is printed.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(action): setup (with bypass) and sync modes`.

### Task 6: GuardDog runner and mode `scan`

**Interfaces:**
- **`guarddog.ts`:**
  - `installGuardDog(exec, dir)` creates a venv in `RUNNER_TEMP/decant-guarddog`, then runs `pip install --require-hashes --no-deps -r action/guarddog-requirements.txt`, resolving the path from `GITHUB_ACTION_PATH`;
  - `scanNpm(exec, tgzPath)` and `scanGo(exec, dirOrZip)` return `{ result: 'clean'|'flagged'; details: string[] }`, parsed from `--output-format json`. Any rule with findings means `flagged`;
  - if GuardDog lacks Go support in the pinned version, `scanGo` returns `null` and the report says `go: OSV only`;
  - `guarddog-requirements.txt` is generated with `uv pip compile --generate-hashes --exclude-newer <today−7d>` for a pinned `guarddog==<latest ≥7 days old>`, with the command in a header comment.
- **`scan`** (on `pull_request`; token = ci):
  - if the token is empty → notice plus exit 0 (Review Focus 3);
  - read the base files via `git show <base_sha>:<path>`. The workflow uses `fetch-depth: 0`;
  - fail if any changed `package-lock.json` contains decant URLs, printing `run: sed -i.bak -E 's#<url>(/r/[^/]+)?/npm/#https://registry.npmjs.org/#g' <file> && rm <file>.bak`;
  - for each added registry dep:
    - look up cached verdicts;
    - otherwise download via ref `pr-<n>`. `cooldown` → listed as "waiting for cooldown until <publish+cooldownDays>", and the check fails, because CI can't install it. `blocked` → fail;
    - run OSV (vulns and MAL) and GuardDog;
    - `putVerdict` for each scanner. OSV MAL means `malicious`. Known vulns are recorded in the report, not as verdicts;
  - the result fails if any of these holds:
    - a `malicious` verdict;
    - a vuln at or above `fail-on`;
    - a `flagged` verdict, unless `labelAddedByWriter(n, 'decant:reviewed')`;
    - a cooldown or blocked package;
  - `other`-source deps are warnings only;
  - the report is a markdown table (package, scanner results, vulns, status), written to the step summary and `upsertComment` with marker `<!-- decant-scan -->`;
  - outputs `result` (`pass|fail`) and `flagged` (`true|false`), which `audit` reads for auto-merge.

- [ ] **Step 1: Write failing tests** (fake exec and fetch):
  - an empty token → 0 plus a notice and no network calls;
  - a lockfile with decant URLs → 1 and the sed hint;
  - added `left-pad@1.3.0` with clean OSV and GuardDog → 0, two verdicts put, and a comment upserted once;
  - a cached clean verdict → no download;
  - OSV `MAL-` → 1;
  - a `high` vuln with `fail-on high` → 1, and with `fail-on critical` → 0;
  - GuardDog flagged → 1, but 0 when the `decant:reviewed` label was added by a writer, and still 1 when added by a reader;
  - cooldown → 1 and the report shows the date;
  - a git-sourced dep → a warning and doesn't fail;
  - GuardDog install is invoked with `--require-hashes`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Verify the GuardDog CLI flags against the pinned version's `--help` and record them in the report.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(action): scan mode with OSV and GuardDog`.

### Task 7: Mode `adopt`

**Interfaces:** `adopt` (`workflow_dispatch`; token = ci; github-token needs `contents: write` and `pull-requests: write`).
- If `decant.json` exists and is valid, it keeps the existing entries and adds only missing young versions. Otherwise it creates `{ "$schema": "...", "project": <input or repo name>, "cooldownDays": 7, "allow": [], "block": [] }`.
- For every registry dep across all lockfiles, it looks up the publish time on the public registry. Deps younger than `cooldownDays` get `{package, reason: 'adopted', added: <today>}`.
- It normalizes every `package-lock.json`.
- On branch `decant/adopt`, it commits `decant.json` and the changed lockfiles, then opens a PR titled `decant: adopt` with label `decant:adopt`. The body lists the entries and when each will age out.
- If an open PR already exists for that head, it updates the branch instead of opening a new one.

- [ ] **Step 1: Write failing tests:**
  - 3 deps (old, 2 days, 6 days) → 2 allow entries with reason `adopted`;
  - an existing valid policy keeps its entries;
  - lockfiles with decant URLs are normalized in the same commit;
  - a second run with an open PR → no new PR;
  - a publish-time lookup failure → exit 1 naming the package (fail closed: don't silently skip).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(action): adopt mode`.

### Task 8: Mode `audit`

**Interfaces:** `audit` (daily `schedule` plus `workflow_dispatch`; token = ci; github-token from the GitHub App).
1. Parse all lockfiles, then `queryVulns`.
2. Group by advisory id and package. For each group with `fixedFor` non-null:
   - **Skip it** if an open PR exists with head `decant/fix-<advisory-lower>-<sanitized-name>` (Review Focus 5).
   - **Sync overlay** ref `audit-<advisory-lower>` with the main policy plus one allow `{package: <eco>:<name>@<fixed>, advisory, reason: 'security fix', added: today}`. If the sync is rejected (e.g. OSV can't verify the fix), record it under `unverified` and continue.
   - **npm:**
     - In the lockfile's directory, write a temp userconfig with `registry=<url>/r/audit-<id>/npm/`, the auth line for that prefix and `ignore-scripts=true`.
     - If the package is a direct dependency in `package.json`, run `npm install <name>@<fixed> --package-lock-only --ignore-scripts`.
     - Otherwise run `npm update <name> --package-lock-only --ignore-scripts`. If any locked copy is still `< fixed`, set `overrides[<name>] = <fixed>` in `package.json` and run `npm install --package-lock-only --ignore-scripts`.
     - Then normalize the lockfile.
     - If copies `< fixed` remain, record it under `unresolvable` and open no PR.
   - **Go:** `GOPROXY=<url>/r/audit-<id>/go` (`.netrc` auth), then `go get <module>@<fixed>` and `go mod tidy` in the module directory.
   - **Commit** the changed files plus `decant.json` (with the new allow entry appended) to branch `decant/fix-…`, created from the default branch head.
   - **Open the PR** with title `decant: <package> <old> → <fixed> (<advisory>)` and labels `decant:security` and `decant:<severity>`. The body has the summary, advisory link and the cooldown-skip notice.
   - **Auto-merge:** if `autoShip[severity] === 'auto'`, call `enableAutoMerge`. GitHub merges the PR only after the required checks, including `scan`, pass. A flagged scan fails, so it blocks auto-merge without extra logic.
3. Advisories with no fix go to one issue, `decant: unfixed advisories`, via `upsertIssue` (Review Focus 4). It is closed by the run that finds none.
4. **Blocks:** `blocks()` ∩ lockfile deps, upserted to issue `decant: blocked versions in lockfiles`.
5. **Prune:** `allow` entries whose version is now older than `cooldownDays` (public registry time) are removed in a PR `decant: prune allow entries` with label `decant:prune`, which is never auto-merged. One PR at a time.
6. Write the run summary: fixes opened, skipped, unverified, unresolvable, blocks, prune.

- [ ] **Step 1: Write failing tests** (fake fetch, exec and github):
  - one direct-dependency high vuln with a fix → overlay sync to `audit-ghsa-…`, npm install via the overlay registry, normalization run, PR opened with both labels, and auto-merge enabled under `autoShip.high = 'auto'`;
  - the same under `approve` → no auto-merge;
  - a re-run with the PR open → no new branch or PR;
  - no fix → issue upserted, no PR;
  - a transitive dep that `npm update` can't lift → override added and install rerun;
  - still unresolved → no PR and recorded;
  - overlay sync 422 → recorded as unverified, no PR;
  - the Go path runs `go get` with GOPROXY pointing at the audit overlay and no token in the env;
  - a block hitting a lockfile → issue upserted;
  - an expired allow entry → prune PR without auto-merge.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(action): audit mode`.

### Task 9: Example workflows and docs

**Files:**
- `examples/workflows/*.yml`
- `docs/adopt.md`, `docs/hardening.md`, `docs/release.md`
- `README.md` (status line, links), `docs/deploy.md` (`sync` token)

**Content (no code; every command copy-pasteable):**
- **`decant-pr.yml`:**
  - triggers on `pull_request` with paths on lockfiles and `decant.json`;
  - `permissions: contents: read, pull-requests: write`;
  - runs checkout (`fetch-depth: 0`), then `sync` (ci), then `scan`.
- **`decant-main.yml`:** `push` to the default branch, `environment: decant-sync`, `sync` with `sync-token`.
- **`decant-audit.yml`:** cron `23 5 * * *` plus `workflow_dispatch`. It takes a GitHub App token via `actions/create-github-app-token` (SHA-pinned), then sets up Go and Node and runs `audit`.
- **`decant-adopt.yml`:** `workflow_dispatch`.
- **Install job snippet:** `setup` plus `workflow_dispatch` inputs `bypass` (boolean, default false) and `bypass_reason` (string).
- All `uses:` are pinned to full SHAs with tag comments.
- **`adopt.md`:**
  - creating the three tokens;
  - the `decant-sync` environment restricted to the default branch;
  - creating the GitHub App (permissions: contents, pull requests and issues write; metadata read) and storing `DECANT_APP_ID`/`DECANT_APP_KEY`;
  - enabling "Allow auto-merge" and requiring the `decant scan` check in branch protection;
  - local dev (`~/.npmrc`, `~/.netrc`, `GOPROXY`, and the normalization one-liner);
  - Docker (`RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --ignore-scripts`; for Go, `--mount=type=secret,id=netrc,target=/root/.netrc`);
  - the **emergency bypass** section: when to use it, how to run it, and what it skips and keeps (lockfile and sumdb hashes still verified);
  - Renovate/Dependabot `minimumReleaseAge` set equal to the cooldown.
- **`hardening.md`:** pin Actions to SHAs, Docker base images to digests, `npm ci --ignore-scripts`, no `,direct`, never set `GONOSUMDB`/`GOFLAGS=-insecure`, least-privilege `permissions:`.
- **`release.md`:**
  - signed tags (`git tag -s vX.Y.Z`);
  - CI verifies `action/dist` is reproducible;
  - adopters pin `sudarkoff/decant/action@<commit-sha> # vX.Y.Z`.

- [ ] **Step 1:** Write the files.
- [ ] **Step 2:** Lint the YAML with `node -e` using a tiny parse check (no new dependency). If none is possible, do a careful manual read, and have the reviewer check every `uses:` SHA via `gh api`.
- [ ] **Step 3:** Commit `docs: adoption, hardening, release and example workflows`.

### Task 10: Deploy the Worker change

- [ ] **Step 1:** `npx wrangler d1 migrations apply decant --remote -c wrangler.local.jsonc`, then `npx wrangler deploy -c wrangler.local.jsonc`.
- [ ] **Step 2: Smoke test:**
  - existing read token still installs;
  - `token create twocal sync` works;
  - `GET /api/blocks` with a new ci token → 200;
  - the sync token on `/npm/left-pad` → 403.
- [ ] **Step 3:** Save the new tokens to `~/.config/decant/` (mode 600) and report to George.

### Task 11: First release (gated on George)

- [ ] **Step 1:** Ask George to approve tagging `v0.1.0`. Stop until he answers.
- [ ] **Step 2:** `git tag -s v0.1.0 -m "decant v0.1.0"` on main after merge, push the tag, and create a GitHub release with notes from the README.

---

twocal adoption is a separate PR in the twocal repo after this plan. It follows twocal's squash-merge flow.
