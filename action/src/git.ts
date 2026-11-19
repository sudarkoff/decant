import type { ActionDeps } from './deps';

export const SHA_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/;

/** `git show <sha>:./<rel>` from directory `wd`; null when the file did not exist at that commit. */
export async function fileAtCommit(deps: ActionDeps, wd: string, sha: string, rel: string): Promise<string | null> {
  const r = await deps.exec('git', ['show', `${sha}:./${rel}`], { cwd: wd });
  if (r.code === 0) return r.stdout;
  if (/does not exist in|exists on disk, but not in/.test(r.stderr)) return null;
  throw new Error(
    `git show ${sha.slice(0, 12)}:${rel} failed: ${r.stderr.trim().slice(0, 300)} (actions/checkout needs fetch-depth: 0)`,
  );
}
