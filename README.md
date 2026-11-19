# decant

A self-hosted package cache and supply-chain gate for npm and Go, running on Cloudflare Workers and R2.

New releases rest before they're poured: decant serves a version only after it has aged past a cooldown, been scanned, and cleared your policy. Versions you depend on stay cached even if they vanish upstream, and your builds keep working when the public registries don't.

**Status:** design phase. Nothing to install yet.

## Goals

- **Cooldown.** A new version becomes installable only after it is N days old (default 7).
- **Scan.** New versions are checked for known vulnerabilities and malware heuristics before use.
- **Keep.** Versions in use are kept in R2, so rollbacks work even after an upstream deletion.
- **Survive outages.** Cached packages are served when npm, GitHub or the Go proxy are down.
- **Security fast lane.** A fix for a known advisory can skip the cooldown (never the scan) via a policy entry that cites the advisory ID.
- **Policy as code.** One policy file in your repo; approval is a merged PR, and git history is the audit trail.
- **Cheap to self-host.** `wrangler deploy` into your own Cloudflare account.

v1 supports npm and Go.
