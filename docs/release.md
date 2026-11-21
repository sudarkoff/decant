# Releasing the Action

Adopters pin a commit SHA, so a release is a signed tag plus a reproducible `action/dist`.

0. Upgrade the Worker first. The Action needs `sync` tokens, so apply migration `0003_sync_token` and redeploy before tagging:

   ```sh
   npx wrangler d1 migrations apply decant --remote
   npx wrangler deploy
   ```

   From then on a `ci` token gets 403 on a main-branch policy sync. Tell adopters in the release notes: create a `sync` token (`npm run decant -- token create <project> sync`), store it as `DECANT_SYNC_TOKEN` in the `decant-sync` environment, and switch `decant-main.yml` to `sync-token` ([adopt.md](adopt.md)).

   **Docker base image gate (migration `0008_project_images`)**: apply it and redeploy before tagging the release that adds the gate (same commands). It adds `project_images`, `project_image_seen` and `verdict_details`, and the Worker's `POST /api/images`. An Action from before it gets a 404 there only if it calls it, so an older Action keeps working against the new Worker.

   **Breaking for adopters (audit):** the Worker now reserves the overlay refs `audit` and `audit-images` for the `sync` token, so a `ci` token gets 403 syncing them. Release notes must say: in `decant-audit.yml`, add `environment: decant-sync` to the job and `sync-token: ${{ secrets.DECANT_SYNC_TOKEN }}` to the audit step (see `examples/workflows/decant-audit.yml`). Without `sync-token` the audit fails at the start with a message naming it. Also add the Dockerfile globs to `decant-main.yml`'s push `paths:` so main sync reports base images when they change.

1. Build and commit the bundle:

   ```sh
   npm run build:action
   git add action/dist
   ```

2. CI verifies `action/dist` is reproducible: it rebuilds from source and fails if the result differs from what is committed. Do not tag until that check is green.

3. Tag with a signed tag and push it:

   ```sh
   git tag -s vX.Y.Z -m "decant vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. Find the commit SHA the tag points at:

   ```sh
   git rev-parse vX.Y.Z^{commit}
   ```

5. Tell adopters to pin it, with the tag as a comment:

   ```yaml
   - uses: sudarkoff/decant/action@<commit-sha> # vX.Y.Z
   ```

Adopters never use a tag or branch ref. The first release is v0.1.0.
