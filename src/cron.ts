import { maliciousIds } from './osv';
import { addGlobalBlock, markOsvChecked } from './policy/store';
import { formatPackageId, type Deps, type Ecosystem, type Env, type PackageRef } from './types';

const BATCH = 1000;
const MAX_BATCHES = 20;
const OVERLAY_TTL_MS = 14 * 86400_000;

interface VersionRow { eco: Ecosystem; name: string; version: string }

async function osvRecheck(env: Env, deps: Deps): Promise<{ checked: number; blocked: number }> {
  const now = deps.now();
  const { results } = await env.DB.prepare(
    `SELECT eco, name, version FROM versions WHERE stored_at IS NOT NULL
     ORDER BY osv_checked_at IS NOT NULL, osv_checked_at, stored_at LIMIT ?`,
  ).bind(BATCH * MAX_BATCHES).all<VersionRow>();
  const refs: PackageRef[] = results.map((r) => ({ eco: r.eco, name: r.name, version: r.version }));

  let checked = 0;
  let blocked = 0;
  for (let i = 0; i < refs.length; i += BATCH) {
    const batch = refs.slice(i, i + BATCH);
    const hits = await maliciousIds(deps, batch);
    if (hits === null) break;
    for (const ref of batch) {
      const ids = hits.get(formatPackageId(ref));
      if (!ids) continue;
      const existing = await env.DB.prepare(
        "SELECT 1 AS x FROM global_blocks WHERE eco = ? AND name = ? AND version = ? AND source = 'osv'",
      ).bind(ref.eco, ref.name, ref.version).first();
      await addGlobalBlock(env, ref, 'osv', `OSV malicious-package advisory: ${ids.join(', ')}`, now);
      if (!existing) blocked++;
    }
    await markOsvChecked(env, batch, now);
    checked += batch.length;
  }
  return { checked, blocked };
}

/** Deletes non-main overlays (policies + their allows) last synced more than 14 days ago, in one batch. */
async function expireOverlays(env: Env, deps: Deps): Promise<number> {
  const cutoff = new Date(deps.now().getTime() - OVERLAY_TTL_MS).toISOString();
  const staleOverlay = `EXISTS (SELECT 1 FROM projects pr WHERE pr.id = policies.project_id
    AND policies.ref != pr.main_ref AND policies.synced_at < ?1)`;
  const out = await env.DB.batch([
    // allows first: they are located through the policies rows deleted next.
    env.DB.prepare(
      `DELETE FROM allows WHERE EXISTS (SELECT 1 FROM policies WHERE policies.project_id = allows.project_id
         AND policies.ref = allows.ref AND ${staleOverlay})`,
    ).bind(cutoff),
    env.DB.prepare(`DELETE FROM policies WHERE ${staleOverlay}`).bind(cutoff),
  ]);
  return out[1]!.meta.changes ?? 0;
}

export async function runScheduled(
  env: Env,
  deps: Deps,
): Promise<{ checked: number; blocked: number; overlaysExpired: number }> {
  let osv = { checked: 0, blocked: 0 };
  try {
    osv = await osvRecheck(env, deps);
  } catch (err) {
    console.error('cron: osv re-check failed', err instanceof Error ? err.name : 'error');
  }
  const overlaysExpired = await expireOverlays(env, deps);
  const result = { ...osv, overlaysExpired };
  console.log(`cron: checked=${result.checked} blocked=${result.blocked} overlaysExpired=${result.overlaysExpired}`);
  return result;
}
