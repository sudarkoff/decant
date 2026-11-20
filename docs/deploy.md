# Deploying decant

decant runs in your own Cloudflare account: one Worker, one R2 bucket, one D1 database.

## Before you start

- A Cloudflare account on the **Workers Paid plan** (the free plan's per-request subrequest and query limits are too low for a package proxy).
- A domain on Cloudflare for the Worker (e.g. `decant.example.com`).
- Node 22.18 or newer, and a clone of this repo.

```sh
npm ci --ignore-scripts
npx wrangler login
```

## 1. Create the R2 bucket and D1 database

```sh
npx wrangler r2 bucket create decant
npx wrangler d1 create decant
```

`d1 create` prints a `database_id`. Paste it into `wrangler.jsonc`, replacing the all-zeros placeholder. (If you deploy from a fork you also push publicly, copy `wrangler.jsonc` to `wrangler.local.jsonc`, which is gitignored, edit that instead, and add `-c wrangler.local.jsonc` to every `wrangler` command below.)

```jsonc
"d1_databases": [
  {
    "binding": "DB",
    "database_name": "decant",
    "database_id": "<your-d1-id>",
    "migrations_dir": "migrations"
  }
]
```

Create the tables:

```sh
npx wrangler d1 migrations apply decant --remote
```

## 2. Expire orphaned temp objects

Uploads are staged under `npm/tmp/` and `go/tmp/` before being verified and moved. A failed upload can leave a temp object behind. Delete anything older than one day:

```sh
npx wrangler r2 bucket lifecycle add decant tmp-npm npm/tmp/ --expire-days 1
npx wrangler r2 bucket lifecycle add decant tmp-go go/tmp/ --expire-days 1
```

## 3. Create the operator token

The operator token lets you create projects and tokens. Only its SHA-256 hash is stored on the Worker.

```sh
npm run decant -- op-token
```

This prints the token and its hash. Save the token somewhere safe (a password manager), then store the hash as a Worker secret and paste the hash when prompted:

```sh
npx wrangler secret put OPERATOR_TOKEN_HASH
```

## 4. Custom domain

Add a route to `wrangler.jsonc` (top level, next to `triggers`):

```jsonc
"routes": [{ "pattern": "<your-domain>", "custom_domain": true }]
```

The hostname's zone must be on your Cloudflare account. Wrangler creates the DNS record and certificate on deploy.

## 5. Deploy

```sh
npx wrangler deploy
curl https://<your-domain>/healthz
```

The health check should answer `ok`. The Worker's cron runs daily at 04:17 UTC: it re-checks stored versions against OSV for malicious-package advisories and expires PR overlays 14 days after their last sync.

`wrangler.jsonc` turns on Workers Logs (`"observability": { "enabled": true }`), so exceptions and decant's own warnings are kept and searchable in the dashboard. If you deploy from your own config (`wrangler.local.jsonc` or another), add the same line to it: without it, nothing is retained to diagnose a failure after the fact. Decant logs error names and package ids, never tokens.

### Upgrading an existing deployment

Migrations 0004 and 0005 are required for every deploy of this version: policy sync writes the new `allows` columns. Run them BEFORE `npx wrangler deploy` (add `-c <config>` if you use a local config):

```sh
npx wrangler d1 migrations apply decant --remote
npx wrangler deploy
```

## 6. Create a project and tokens

Point the CLI at your deployment:

```sh
export DECANT_URL=https://<your-domain>
export DECANT_OPERATOR_TOKEN=<operator-token-from-step-3>
```

Create a project (lowercase letters, digits, `.`, `_`, `-`):

```sh
npm run decant -- project create <project>
```

Create three tokens: read, ci and sync:

```sh
npm run decant -- token create <project> read
npm run decant -- token create <project> ci
npm run decant -- token create <project> sync
```

Each prints `{"token":"dk_..."}`. The token is shown once; only its hash is stored.

- `read`: installs (developers, build machines).
- `ci`: PR overlay policy syncs, scanner verdicts, status and blocks.
- `sync`: main-branch policy sync only. Keep it in a GitHub Environment restricted to the default branch, so a PR build can never rewrite the main policy.

Existing deployments: a `ci` token on a main-branch policy sync now gets 403. After upgrading, create a `sync` token before the next main sync.

## 7. Check a client

npm. In the project's `.npmrc`:

```ini
registry=https://<your-domain>/npm/
//<your-domain>/npm/:_authToken=<read-token>
ignore-scripts=true
```

```sh
npm view left-pad version
```

Go. Do not add `,direct`: that would bypass the gate.

```sh
export GOPROXY=https://decant:<read-token>@<your-domain>/go
go list -m -versions github.com/google/uuid
```

A version younger than the cooldown (7 days by default) is hidden until it ages in, unless the project's policy allows it. Policy files are synced by the GitHub Action; see [adopt.md](adopt.md).

## Dashboard (optional)

A private page at `https://<your-domain>/dashboard`: needs-attention items, request activity, vulnerabilities in cached versions, package freshness, uptime, policy and recently resolved items. It is protected by Cloudflare Access. Request counts start at deploy (no backfill). They are best-effort: each Worker instance buffers them and writes them every 10 seconds or 200 requests, so a few counts can be lost when an instance shuts down.

1. In Cloudflare, go to Zero Trust → Access → Applications (newer dashboards: Access controls → Applications) and add a Self-hosted application.
2. Add two paths on your hostname: `/dashboard` and `/dashboard/*`. Never protect the bare host: that would put Access in front of installs and break them.
3. Add a policy with action Allow and your email as the include rule.
4. Copy the Application Audience (AUD) tag from the application's overview. The team domain is under Zero Trust → Settings (your team domain, `<team>.cloudflareaccess.com`).
5. Add both to `wrangler.jsonc`:

```jsonc
"vars": {
  "ACCESS_TEAM_DOMAIN": "<team>.cloudflareaccess.com",
  "ACCESS_AUD": "<aud-tag>"
}
```

6. Apply the migrations (0004 and 0005) and deploy:

```sh
npx wrangler d1 migrations apply decant --remote
npx wrangler deploy
```

Open `https://<your-domain>/dashboard`. The Worker checks the `Cf-Access-Jwt-Assertion` header Access adds. If either var is unset or invalid, `/dashboard` answers 404; a missing or bad token answers 403.

## Rotating the operator token

Run `npm run decant -- op-token` again, then `npx wrangler secret put OPERATOR_TOKEN_HASH` with the new hash. The old token stops working immediately.
