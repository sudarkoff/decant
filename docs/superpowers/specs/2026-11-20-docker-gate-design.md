# Docker base image gate

George chose the CI gate over a registry mirror on 2026-11-20 ("go straight to the CI gate").

## Why

decant gates npm and Go dependencies, but not the base images in `FROM` lines. Base images are
dependencies too. A floating tag (`node:22`) can change under a build, and a compromised publisher
can push a malicious digest that the next build pulls without anyone noticing. Dependabot no longer
watches them: George turned off its security PRs on twocal and theinsightcrew (alerts stay on).

## Goals

- Every base image is pinned by digest, the same way a lockfile pins a package.
- A new digest waits out the project's cooldown (default 7 days), unless an `allow` entry names an
  advisory or reason. This is the same fast lane npm and Go use.
- New digests are scanned for OS-package vulnerabilities in the PR, and High or Critical findings
  fail it.
- The daily audit proposes digest bumps that have cleared the cooldown and fix a High or Critical
  finding. They go in the same single security PR.
- Everything fails closed, like the rest of the scan.

## Non-goals

- A registry mirror or pull-through cache. There's no outage resilience for image pulls; that's a
  later, separate project if Docker Hub outages bite.
- GitHub Actions pinning (George: "I don't care about GitHub Actions").
- Images referenced outside Dockerfiles (compose files, fly.toml `image =`, Kubernetes manifests).
  The scan notes where these exist but doesn't gate them.

## Approach

Approaches considered:
- **CI gate (chosen):** pin plus cooldown plus scan in the Action, with decant's Worker as the
  first-seen clock. Small and consistent with how npm and Go work.
- **Registry mirror:** a Worker implementing the OCI distribution API, with blobs in R2. This adds
  outage resilience, but it's a large project with large storage. Deferred.
- **Trust the image's own `created` timestamp for cooldown:** rejected. The publisher controls it, and
  a compromised publisher can backdate it. Reproducible images even set it to 1970.

### Cooldown clock

A digest's age is measured from when decant first saw it, recorded server-side, never from image
metadata. decant records first-seen in three cases:
- when a PR scan meets a new digest;
- when the main-branch sync reports the digests in use, which grandfathers them so adopting decant
  doesn't block existing images;
- when the daily audit resolves the current digest of each tag in use (candidate bumps).

A digest that the audit has watched for at least the cooldown becomes eligible for a bump PR.

### Identity

An image is identified by its fully qualified repository: `docker.io/library/node`, `ghcr.io/org/x`,
and so on. Docker Hub short names are normalized. The version is the manifest digest
(`sha256:…`). For multi-arch images that's the index digest, the one written in `FROM`. Policy
entries use ecosystem `docker`, with `name` set to the repository and `version` to the digest.
Blocklist and allow entries work the same as for npm and Go.

### Dockerfile rules (scan)

- Look at `Dockerfile`, `*.Dockerfile` and `Dockerfile.*` across the repo, skipping vendored,
  node_modules and testdata directories.
- Each `FROM` is one of the following:
  - **`scratch`:** exempt.
  - **A reference to an earlier stage name:** exempt.
  - **An image pinned by digest:** gated. `image:tag@sha256:…` is fine and the tag is documentation.
  - **Anything else fails the PR,** with a fix-it message naming the digest it currently resolves to.
- `ARG` substitution in `FROM`: resolve from `ARG` defaults. If the value can't be resolved
  statically, fail the PR with a clear message.
- `--platform` is allowed.

### Scanning

- Grype is a single binary, version- and checksum-pinned like GuardDog. It scans
  `registry:<repo>@<digest>` without a Docker daemon.
- High or Critical findings with a fix available fail the PR. Findings with no fix are reported but
  don't fail it. The same no-fix advisory can't block forever: the audit re-checks daily.
- Verdicts are stored in decant like other scan verdicts, keyed `docker`/repo/digest, shared across
  projects and never downgraded.
- If Grype or its database is unavailable, that's a scan error and the scan fails closed.

### Surfacing

- The PR summary and annotations show each image's verdict and cooldown status.
- The Needs-attention items for vulns and flags cover `docker` too. The package-page link for `docker`
  points to Docker Hub or the registry when the host is known; otherwise there's no link.

## Left to the builder

The exact Worker API shape (reuse the existing verdict and deps endpoints where possible), the Grype
version, output parsing, and how the audit resolves tag → digest (registry HTTP API: anonymous token
for Docker Hub and ghcr.io public images).
