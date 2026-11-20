# Hardening your pipeline

decant gates what your clients fetch. These habits stop anything from going around it.

- **Pin Actions to full commit SHAs**, with the tag in a trailing comment: `uses: actions/checkout@<40-hex-sha> # v7.0.1`. Tags can be moved; SHAs cannot. Let Dependabot or Renovate bump them.
- **Pin Docker base images to digests**: `FROM node:24@sha256:<digest>`.
- **Install with `npm ci --ignore-scripts`.** `npm ci` installs exactly the lockfile; `--ignore-scripts` stops install scripts running. Keep `ignore-scripts=true` in `.npmrc` too.
- **No `,direct` in `GOPROXY`.** `https://<your-domain>/go,direct` lets Go fall back to the public proxy for anything decant hides.
- **Never set `GONOSUMDB`, `GOSUMDB=off` or `GOFLAGS=-insecure`.** They disable the checksum database, which is what catches a tampered module.
- **Understand `GOPRIVATE` and `GOINSECURE` before setting them.** `GOPRIVATE` makes Go fetch matching modules directly and skip the checksum database; `GOINSECURE` allows plain HTTP. Either sends those modules around decant's gate.
- **Least-privilege `permissions:`.** Set `permissions: contents: read` at the workflow level and add only what a job needs (the PR scan adds `pull-requests: write` and `issues: write`).
- **Keep the sync token out of PRs.** Store it in the `decant-sync` environment, restricted to the default branch.
- **Require the `decant scan` check** in branch protection, and require review for `decant.json` changes (a CODEOWNERS entry works): a merged `decant.json` is how a version is approved.
- **Don't use `pull_request_target`** with decant or with any job that builds PR code and has secrets.
- **Rotate tokens** if one leaks: create a new one with `npm run decant -- token create` and update the secret (see [deploy.md](deploy.md)).

## How fast changes take effect

Each Worker instance caches what it needs to decide, so a cached install costs almost no D1 queries. The bounds:

- **Blocks, allows, cooldown changes and publish-time conflicts** reach every instance within **30 seconds**. The instance that handled the policy sync or verdict applies it at once. A version decant has never stored is always checked against the current block list before its first serve.
- **A deleted token** keeps working for up to **60 seconds**. A new token works at once.
- **If decant can't read the policy or block list** (D1 overloaded, after two retries), it refuses the request with a 502. It never serves on a guess.
