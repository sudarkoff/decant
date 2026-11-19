# Releasing the Action

Adopters pin a commit SHA, so a release is a signed tag plus a reproducible `action/dist`.

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
