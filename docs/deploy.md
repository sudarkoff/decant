# Deploying decant

decant runs in your own Cloudflare account: one Worker, one R2 bucket, one D1 database. Setup takes about ten minutes.

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

`d1 create` prints a `database_id`. Paste it into `wrangler.jsonc`, replacing the all-zeros placeholder:

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

Create a read token for installs (developers, build machines) and a CI token for the policy sync and scanner verdicts:

```sh
npm run decant -- token create <project> read
npm run decant -- token create <project> ci
```

Each prints `{"token":"dk_..."}`. The token is shown once; only its hash is stored. Keep the CI token for the GitHub Action (coming in the GitHub Action, plan 2). Syncing a policy file and CI verdicts depend on it.

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

A version younger than the cooldown (7 days by default) is hidden until it ages in, unless the project's policy allows it. Policy files are synced by the GitHub Action (coming in the GitHub Action, plan 2).

## Rotating the operator token

Run `npm run decant -- op-token` again, then `npx wrangler secret put OPERATOR_TOKEN_HASH` with the new hash. The old token stops working immediately.
