import { maliciousIds } from '../osv';
import { forgetDenied } from './decider';
import { formatPackageId, type Deps, type Env, type PackageRef } from '../types';
import { addGlobalBlock, markOsvChecked } from './store';

/** The stored artifact, or null if absent or R2 can't be read (the caller then goes upstream). */
export async function storedObject(env: Env, key: string): Promise<R2ObjectBody | null> {
  try {
    return await env.BUCKET.get(key);
  } catch {
    console.warn(`stored read failed ${key}`);
    return null;
  }
}

/**
 * The first-serve OSV check: true if OSV lists a MAL- advisory for `ref` (and records the block).
 * Fail-open by design, for ANY error (OSV down, malformed answer, anything vulnIds throws): the version
 * is served, osv_checked_at stays null, and the daily cron re-checks it. Recording is best-effort: a known-malicious version is refused whether or not its block row was
 * written, and it is marked checked only once the block is written, so the cron retries a lost block.
 */
export async function osvMalicious(env: Env, deps: Deps, ref: PackageRef, now: Date): Promise<boolean> {
  const id = formatPackageId(ref);
  let mal: Map<string, string[]> | null;
  try {
    mal = await maliciousIds(deps, [ref]);
  } catch {
    console.warn(`osv check failed ${id}`);
    return false;
  }
  if (mal === null) return false;
  const ids = mal.get(id) ?? [];
  try {
    if (ids.length > 0) {
      await addGlobalBlock(env, ref, 'osv', ids.join(', '), now);
      forgetDenied(ref.eco, ref.name); // this isolate sees the block at once
    }
    await markOsvChecked(env, [ref], now);
  } catch {
    console.warn(`osv result write failed ${id}`);
  }
  return ids.length > 0;
}
