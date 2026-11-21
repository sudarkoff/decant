# Adopting decant in a repo

You need a deployed Worker ([deploy.md](deploy.md)) and its project's `read`, `ci` and `sync` tokens. The finished workflows are in [`examples/workflows/`](../examples/workflows/).

Every example pins `sudarkoff/decant/action@<release-sha> # v0.1.0`. Replace `<release-sha>` with the commit SHA of the decant release you trust (see [release.md](release.md)). Never use a tag or branch.

## 1. Tokens, secrets and the environment

| Token | Used by | Where to store it |
| --- | --- | --- |
| `read` | installs: `setup` mode, developers, Docker builds | repo secret `DECANT_READ_TOKEN` |
| `ci` | PR policy sync, scan, audit, adopt | repo secret `DECANT_CI_TOKEN` |
| `sync` | main-branch policy sync only | **environment** secret `DECANT_SYNC_TOKEN` in `decant-sync` |

```sh
npm run decant -- token create <project> read
npm run decant -- token create <project> ci
npm run decant -- token create <project> sync
```

Also set a repo variable `DECANT_URL` (your Worker's URL).

Create the `decant-sync` environment (Settings, Environments) and restrict it to the default branch only (Deployment branches and tags: Selected branches and tags, add a **branch** rule for `main`, and add no tag rules). A PR build or a tag (even one named `main`) can then never read the sync token or rewrite the main policy. The sync step also checks the full ref (`refs/heads/<default>`), so a tag never syncs main.

Fork PRs get no secrets. Sync skips them with a notice. Scan still diffs the lockfiles (that needs no token): a fork PR that changes no lockfile passes with a notice, and one that changes a lockfile fails with `fork changes lockfiles; push the branch to this repo to scan it`. A maintainer pushes the branch to this repo (a same-repo PR) to get it scanned.

## 2. GitHub App

`audit` and `adopt` open PRs and issues. PRs opened with the default `GITHUB_TOKEN` do not trigger workflows, so your required checks would never run. Use a GitHub App token instead.

1. Settings, Developer settings, GitHub Apps, New GitHub App. No webhook.
2. Repository permissions: **Contents** read and write, **Pull requests** read and write, **Issues** read and write, **Metadata** read.
3. Create it, generate a private key, and install it on the repo.
4. Store the App ID as repo secret `DECANT_APP_ID` and the private key (the whole PEM) as `DECANT_APP_KEY`.

The audit and adopt workflows mint a short-lived token with `actions/create-github-app-token` and set `DECANT_GITHUB_LOGIN` to `<app-slug>[bot]`, so decant recognises its own issues and PRs. Leave that env var in place or you will get duplicate daily issues.

## 3. Repo settings

- Settings, General: turn **Allow auto-merge** on. Auto-shipped fix PRs use it.
- Branch protection (or a ruleset) on the default branch: require pull requests and require the status check **`decant scan`**. That is the name of the job in `decant-pr.yml`; keep it.

## 4. Workflows

Copy these to `.github/workflows/`:

- `decant-pr.yml`: on every PR, syncs the PR overlay policy then scans. Needs `contents: read`, `pull-requests: write`, `issues: write` (labels and comments) and a full checkout (`fetch-depth: 0`, `persist-credentials: false`) so it can read the base branch's lockfile and policy. It runs on `edited` too, so changing a PR's base resets review state, and on `labeled`/`unlabeled`, so adding `decant:reviewed` re-runs the check.
  The overlay is built from the **base branch's** `decant.json` plus the PR's new `allow` entries and any `block` entries it adds. Other policy edits in a PR (`cooldownDays`, `autoShip`, removing a block) are not applied to the PR: the run posts the notice `policy changes in decant.json take effect after merge`. There is deliberately no `paths:` filter: a required check that never runs on a PR stays "Expected" and blocks the merge. When no lockfile changed, scan exits quickly and does not install GuardDog (it is installed lazily, only when a new package needs scanning).
  Python: GuardDog's hash-pinned wheels exist for Python 3.12 and 3.13 only, and a hosted runner's `python3` may be newer. Keep the example's `actions/setup-python` step (`python-version: '3.12'`) before the scan step. Scan uses `$DECANT_PYTHON` if set, else the Python setup-python installed (`$pythonLocation`), else `python3`; any other version fails the scan with that hint before installing anything.
  Runner cost: every decant check run takes a runner, and a busy PR (pushes, label changes, edits) starts several. The example sets `concurrency` with `cancel-in-progress`, so a newer run cancels the superseded one. Each audit PR also runs your repo's full CI; audit opens at most one PR per run.
- `decant-main.yml`: on pushes to the default branch that change `decant.json`, weekly (Mondays 06:41 UTC), and on demand (`workflow_dispatch`), syncs the main policy using the environment's sync token. PR overlays are rejected until main has been synced once, so add this workflow first (see [step 5](#5-sync-main-then-run-adopt)). The same run also sends a dependency summary of the lockfiles (package names and versions, whether each is a direct dependency, and which direct dependencies pull it in; no URLs, hashes or secrets) so the dashboard's Freshness card can split direct dependencies from transitive ones. The summary refreshes whenever this workflow runs: a `decant.json` change, the weekly run, or a manual run. If sending it fails, the run warns and still passes. PR syncs never send it.
- `decant-audit.yml`: daily at 05:23 UTC and on demand. **It runs on the default branch only**, and the job is guarded to refuse any other ref. It needs Node and Go on the runner (the example installs both) because it runs `npm` and `go` to prepare fixes. For an npm-only repo, delete the setup-go step (or use `go-version: stable` instead of `go-version-file`).
  Each run opens **at most one security PR**, on branch `decant/security-fixes`, titled `decant: security fixes (N packages, M advisories)`. It groups advisories by package and raises each package to the highest fixed version its advisories need (per major line; direct dependencies are bumped, transitive ones get `overrides`), resolved through the overlay ref `audit`. The PR body lists every package, its advisories and severity, and anything left out. `decant.json` gains one advisory-cited `allow` entry per fixed version, so the fixes skip the cooldown.
  - If that PR is still open, the next run rebuilds its branch on the default head and refreshes it; it never opens a second one.
  - If you close it without merging, decant does not reopen the same set of fixes. A new advisory (a different set) opens a new PR. Only the most recently closed unmerged PR is compared: if you decline set A, then decline set B, a later run that finds set A again opens a PR for it.
  - decant reuses an open PR's branch only if it is still exactly decant's own single commit on the current default branch; anything else (a pushed commit, a moved default branch) is force-reset and recommitted. Auto-merge is turned off before that push when the batch doesn't qualify, and is only turned on for content the run itself just wrote.
  - Auto-merge is on only if every advisory's severity has `autoShip: auto` and no upgrade crosses a major (or 0.x minor) line; otherwise the body says why it is off.
  - Packages with no fix, a fix decant cannot verify, or an upgrade npm/go cannot resolve stay out of the PR and are listed in the `decant: unfixed advisories` issue.
- `decant-adopt.yml`: manual, one time. Also default branch only.
- The install job: add it to your build workflow ([install-snippet.yml](../examples/workflows/install-snippet.yml)).

On a PR, `setup` installs through the PR's overlay (`/r/pr-<n>/npm/` and `/r/pr-<n>/go`), so an allow entry the PR adds (for example a security fix still inside the cooldown) works in that PR's own build. The overlay only has the entry after the PR's sync has run, so the install job must run **after** a sync job (`needs: decant`). `needs` cannot reach a job in another workflow, so the build workflow runs its own sync on PRs (syncing twice is harmless):

```yaml
on:
  push:
  pull_request:
  workflow_dispatch:
    inputs:
      bypass:
        type: boolean
        default: false
      bypass_reason:
        type: string
jobs:
  decant:
    if: github.event_name == 'pull_request'
    concurrency:
      group: decant-build-sync-${{ github.event.pull_request.number }}
      cancel-in-progress: true
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: sudarkoff/decant/action@<release-sha> # v0.1.0
        with:
          mode: sync
          decant-url: ${{ vars.DECANT_URL }}
          token: ${{ secrets.DECANT_CI_TOKEN }}
  install:
    needs: decant
    if: ${{ !cancelled() && (needs.decant.result == 'success' || needs.decant.result == 'skipped') }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: sudarkoff/decant/action@<release-sha> # v0.1.0
        with:
          mode: setup
          decant-url: ${{ vars.DECANT_URL }}
          token: ${{ secrets.DECANT_READ_TOKEN }}
          bypass: ${{ inputs.bypass || 'false' }}
          bypass-reason: ${{ inputs.bypass_reason }}
      - run: npm ci --ignore-scripts
```

`setup` writes `~/.npmrc` and `~/.netrc` (mode 600) and exports `GOPROXY`, `npm_config_registry` and `npm_config_ignore_scripts` (no token in any exported variable). For Go, run `go` after it with no `,direct` anywhere. On other events (push, workflow_dispatch) and on fork PRs it uses the main paths.

After a PR that adds allow entries merges, a build on the merge commit can start before `decant-main.yml` has synced them to main, and fail to install the new version. Re-run the failed build once the **decant main** run is green (or trigger the build from it with `on: workflow_run: workflows: [decant main]`).

## 5. Sync main, then run adopt

Order matters: the Worker refuses PR overlays (`sync main first`) until the main policy has been synced once.

1. Merge `decant-main.yml` (and `decant-adopt.yml`) first, before the adopt PR and before `decant-pr.yml`. If `decant.json` already exists on the default branch, run **decant main** once from the Actions tab (it has a `workflow_dispatch` trigger) so main is synced now.
2. Run the **decant adopt** workflow once. It opens a PR (label `decant:adopt`) that:
   - creates `decant.json` if you have none (project name defaults to the repo name, lowercased; 7-day cooldown), and adds an allow entry for every version in your lockfiles that is still inside the cooldown, so installs keep working on day one;
   - rewrites lockfile `resolved` URLs to `https://registry.npmjs.org/`, so lockfiles stay portable.
3. Review and merge it. Merging changes `decant.json` on the default branch, so `decant-main.yml` syncs main.
4. Then merge `decant-pr.yml` and the install job, and require the `decant scan` check.

The project name defaults to the repo name lowercased; it must match `^[a-z0-9][a-z0-9._-]{0,63}$` (the Worker's project id rule). If your repo name does not, set the action's `project` input to your decant project. Lockfiles must be package-lock v2 or v3; for v1, regenerate with npm 7 or newer.

## 6. Local development

npm: commit a per-app `.npmrc` (the token stays in your environment, never in the file):

```ini
registry=https://<your-domain>/npm/
//<your-domain>/npm/:_authToken=${DECANT_READ_TOKEN}
ignore-scripts=true
```

Export `DECANT_READ_TOKEN` locally. In CI, the `setup` step also exports `npm_config_registry` (and `npm_config_ignore_scripts=true`), which beats the project `.npmrc`. That is how PR builds install through the PR overlay (`/r/pr-<n>/npm/`) and how an emergency bypass reaches `registry.npmjs.org` even though the committed `.npmrc` points at decant.

Go, in `~/.netrc` (mode 600):

```
machine <your-domain> login decant password <read-token>
```

```sh
chmod 600 ~/.netrc
export GOPROXY=https://<your-domain>/go
```

No `,direct` on `GOPROXY`: it would let Go fall back to the public proxy and skip the gate.

npm writes your decant URL into `package-lock.json` as `resolved`. Normalize before committing (the PR scan fails lockfiles that still contain decant URLs):

```sh
sed -i.bak -E 's#https://<host>(/r/[^/]+)?/npm/#https://registry.npmjs.org/#g' package-lock.json && rm package-lock.json.bak
```

`<host>` is your Worker's hostname, for example `decant.example.com`.

## 7. Docker

Pass the files as BuildKit secrets so the token never lands in an image layer.

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --ignore-scripts
# Go:
RUN --mount=type=secret,id=netrc,target=/root/.netrc go mod download
```

```sh
docker build --secret id=npmrc,src=$HOME/.npmrc --secret id=netrc,src=$HOME/.netrc .
```

In CI, run the `setup` step first, then the same command; it reads the files `setup` wrote. Set `GOPROXY` in the Dockerfile with `ENV GOPROXY=https://<your-domain>/go`.

### Pin base images by digest

The PR scan gates base images too. Every `FROM` (and a `# syntax=` frontend, which is code BuildKit runs) in a changed `Dockerfile`, `*.Dockerfile` or `Dockerfile.*` must be `scratch`, an earlier stage, or pinned by digest. The tag stays as documentation:

```dockerfile
# syntax=docker/dockerfile:1@sha256:<digest>
FROM node:22-alpine@sha256:<digest> AS build
FROM build AS test
FROM scratch
```

Find a tag's current digest with `docker buildx imagetools inspect node:22-alpine` (the `Digest:` line), or let the scan tell you: an unpinned `FROM` fails with a fix-it naming the digest the tag resolves to now. Use the index (multi-arch) digest, the one `imagetools inspect` prints first.

What the scan checks for each digest that is new in the PR:

- **Cooldown.** A digest's age counts from when decant first verified it in the registry (never the image's own `created` time, which the publisher controls). Main-branch sync reports the digests in use, so adopting decant does not block images you already build from. An `allow` entry skips the cooldown, as for npm and Go: `{ "package": "docker:docker.io/library/node@sha256:<digest>", "reason": "…", "added": "2026-11-20" }`. Names are fully qualified (`docker.io/library/node`, `ghcr.io/org/app`).
- **Blocks.** `block` entries with `docker:` ids work like any other.
- **Vulnerabilities.** Grype (pinned) scans the image straight from the registry. High or Critical findings with a fixed version fail the PR; findings with no fix are reported and pass. The daily audit re-scans every image in use and, once the tag points at a newer digest that has cleared the cooldown and removes a High or Critical finding, bumps the digest in the same security PR as npm and Go fixes.
- **Registries.** decant resolves and scans public images on Docker Hub and ghcr.io. Images on other or private registries have a per-project cooldown clock and cannot be scanned, so they fail unless an `allow` entry names the digest.
- **What fails closed.** An `ARG` in `FROM` without a default, a line decant cannot parse (it accepts only Dockerfile instructions, `#` comments and `RUN`/`COPY`/`ADD` heredocs it can read unambiguously), a digest the registry does not have, or a Grype or Grype database error.

Images referenced outside Dockerfiles (compose files, `fly.toml`) are noted in the report but not gated.

## 8. Renovate and Dependabot

Set their minimum release age equal to your `cooldownDays` so they stop proposing versions decant would still hide.

Renovate (`renovate.json`, for a 7-day cooldown):

```json
{ "minimumReleaseAge": "7 days" }
```

Dependabot PRs get **no Actions secrets**: workflows triggered by Dependabot read only Dependabot secrets. Store `DECANT_CI_TOKEN` (and `DECANT_READ_TOKEN`, for the install job) as **Dependabot secrets** too (Settings, Secrets and variables, Dependabot), with the same values. Without them, the PR check fails on every Dependabot PR (`token is required on pull requests`).

Dependabot: use `cooldown` in `dependabot.yml`:

```yaml
updates:
  - package-ecosystem: npm
    directory: /
    schedule: { interval: daily }
    cooldown: { default-days: 7 }
```

## How the scan behaves

- A flagged GuardDog result can be cleared by a repo writer adding the **`decant:reviewed`** label. Adding it re-runs the check (the workflow listens for `labeled`). A label added by anyone without write access is ignored. decant removes the label on new commits, when the PR is reopened and when its base changes, so each of those needs a fresh review.
- The report lists, under **GuardDog findings**, each rule that fired for a flagged package with GuardDog's message and up to five file:line locations. When GuardDog refuses an archive it cannot enumerate unambiguously (an "archive parser anomaly", e.g. a Go module zip that contains zip test fixtures), the package is flagged with the rule `archive-anomaly` rather than failing as a scan error, so the same `decant:reviewed` review clears it. Any other GuardDog failure is a scan error and fails the check.
- **An `archive-anomaly` flag is not a normal review.** The package's contents were NOT scanned by GuardDog (archive anomaly; can be deliberate scan evasion: a package can craft its archive to trigger it). Inspect the archive manually before adding `decant:reviewed`; the report and annotation say so next to the finding.
- A flagged dependency on a `decant:security` PR (an audit fix) turns auto-merge off and says so in the report. `decant:reviewed` can still make the check green, but a person must merge it.
- Lockfiles or directories that are symlinks fail the scan. decant does not follow them.
- GuardDog runs in its sandbox. A runner that cannot run it fails closed: the scan fails instead of passing unchecked.
- Fork PRs have no secrets: one that changes no lockfile or Dockerfile passes; one that changes either fails until the branch is pushed to this repo.
- Base images: see [Pin base images by digest](#pin-base-images-by-digest). The report has a **Base images** table with each new digest's cooldown and Grype result.

## Emergency bypass

**Last resort.** Use it only when decant itself is down or blocking an urgent fix, and a build cannot wait. It is a deliberate manual run, never automatic.

To use it, run your build workflow from the Actions tab with **bypass** ticked and a **bypass_reason** (required; the run fails without one).

It **skips**: the cooldown, the vulnerability and malware scans, and blocks. npm and Go install straight from the public registry and proxy.

It **still holds**: lockfile integrity hashes (npm verifies `integrity`) and `go.sum` and sumdb hashes (Go verifies against `sum.golang.org`). A tampered tarball or module still fails.

The run leaves a visible warning (`decant BYPASSED by <actor>: <reason>`) and a job summary naming who ran it, why, and the run URL. Afterwards, run audit, and review the versions installed during the bypass by hand (the PR scan only checks lockfile diffs).
