import { vulnDetails, vulnIds, type VulnDetails } from './osv';
import { addGlobalBlock, markOsvChecked } from './policy/store';
import { formatPackageId, type Deps, type Ecosystem, type Env, type PackageRef } from './types';

const BATCH = 1000;
const MAX_BATCHES = 20;
const OVERLAY_TTL_MS = 14 * 86400_000;
const MAX_DETAIL_FETCHES = 200;

interface VersionRow { eco: Ecosystem; name: string; version: string }

type Details = Pick<VulnDetails, 'severity' | 'summary' | 'published'>;
const PLACEHOLDER: Details = { severity: 'unknown', summary: '', published: null };

/**
 * Details per advisory id for one batch: reuse what `vulns` already holds, then fetch the rest from OSV
 * (placeholders first, then new ids) until `budget.left` runs out. Ids left over get a placeholder row.
 */
async function detailsFor(
  env: Env,
  deps: Deps,
  ids: string[],
  cache: Map<string, VulnDetails>,
  budget: { left: number },
): Promise<Map<string, Details>> {
  const out = new Map<string, Details>();
  if (ids.length === 0) return out;
  const { results } = await env.DB.prepare(
    `SELECT id, severity, summary, published FROM vulns WHERE id IN (SELECT value FROM json_each(?))
       GROUP BY id HAVING MAX(NOT (severity = 'unknown' AND summary = ''))`,
  ).bind(JSON.stringify(ids)).all<{ id: string; severity: string; summary: string | null; published: string | null }>();
  for (const r of results) out.set(r.id, { severity: r.severity as Details['severity'], summary: r.summary ?? '', published: r.published });
  // Ids only ever stored as placeholders are refreshed before ids never seen at all.
  const { results: stale } = await env.DB.prepare(
    "SELECT DISTINCT id FROM vulns WHERE severity = 'unknown' AND summary = '' AND id IN (SELECT value FROM json_each(?))",
  ).bind(JSON.stringify(ids)).all<{ id: string }>();
  const staleIds = new Set(stale.map((r) => r.id));
  const todo = ids.filter((id) => !out.has(id)).sort((a, b) => Number(staleIds.has(b)) - Number(staleIds.has(a)));
  for (const id of todo) {
    const cached = cache.get(id);
    if (cached) { out.set(id, cached); continue; }
    if (budget.left <= 0) { out.set(id, PLACEHOLDER); continue; }
    budget.left--;
    out.set(id, (await vulnDetails(deps, id, cache)) ?? PLACEHOLDER);
  }
  return out;
}

/** Writes the vulns rows for a batch and drops rows of those versions whose id is gone, in one D1 batch. */
async function recordVulns(
  env: Env,
  batch: PackageRef[],
  hits: Map<string, string[]>,
  details: Map<string, Details>,
  now: Date,
): Promise<void> {
  const rows: (string | null)[][] = [];
  for (const ref of batch) {
    for (const id of hits.get(formatPackageId(ref)) ?? []) {
      const d = details.get(id) ?? PLACEHOLDER;
      rows.push([ref.eco, ref.name, ref.version, id, d.severity, d.summary, d.published]);
    }
  }
  const rowsJson = JSON.stringify(rows);
  const refsJson = JSON.stringify(batch.map((r) => [r.eco, r.name, r.version]));
  await env.DB.batch([
    env.DB.prepare(
      `INSERT OR REPLACE INTO vulns (eco, name, version, id, severity, summary, published, checked_at)
       SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]'), json_extract(value, '$[3]'),
              json_extract(value, '$[4]'), json_extract(value, '$[5]'), json_extract(value, '$[6]'), ?2
       FROM json_each(?1)`,
    ).bind(rowsJson, now.toISOString()),
    env.DB.prepare(
      `DELETE FROM vulns
       WHERE (eco, name, version) IN (
         SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]') FROM json_each(?1))
       AND (eco, name, version, id) NOT IN (
         SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]'), json_extract(value, '$[3]')
         FROM json_each(?2))`,
    ).bind(refsJson, rowsJson),
  ]);
}

async function osvRecheck(env: Env, deps: Deps): Promise<{ checked: number; blocked: number }> {
  const now = deps.now();
  const { results } = await env.DB.prepare(
    `SELECT eco, name, version FROM versions WHERE stored_at IS NOT NULL
     ORDER BY osv_checked_at IS NOT NULL, osv_checked_at, stored_at LIMIT ?`,
  ).bind(BATCH * MAX_BATCHES).all<VersionRow>();
  const refs: PackageRef[] = results.map((r) => ({ eco: r.eco, name: r.name, version: r.version }));

  let checked = 0;
  let blocked = 0;
  const cache = new Map<string, VulnDetails>(); // per run, never across requests
  const budget = { left: MAX_DETAIL_FETCHES };
  for (let i = 0; i < refs.length; i += BATCH) {
    const batch = refs.slice(i, i + BATCH);
    const hits = await vulnIds(deps, batch);
    if (hits === null) break;
    const details = await detailsFor(env, deps, [...new Set([...hits.values()].flat())], cache, budget);
    await recordVulns(env, batch, hits, details, now);
    for (const ref of batch) {
      const ids = hits.get(formatPackageId(ref))?.filter((id) => id.startsWith('MAL-'));
      if (!ids || ids.length === 0) continue;
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
