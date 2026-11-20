import { vulnDetails, vulnIds, type VulnDetails } from './osv';
import { addGlobalBlock, markOsvChecked } from './policy/store';
import { formatPackageId, type Deps, type Ecosystem, type Env, type PackageRef } from './types';

const BATCH = 1000;
const MAX_BATCHES = 20;
const OVERLAY_TTL_MS = 14 * 86400_000;
const MAX_DETAIL_FETCHES = 200;

interface VersionRow { eco: Ecosystem; name: string; version: string }

/**
 * `fixed`: fixed versions per package ("eco:name"). `fixedAll` is true when they came from the OSV record itself,
 * so a package missing from `fixed` has none; reused rows only know the packages they were stored for.
 */
type Details = Pick<VulnDetails, 'severity' | 'summary' | 'published'> & { pending?: true; fixed: Record<string, string[]>; fixedAll: boolean };
/** Stored with checked_at = '' so a later run knows its details were never fetched (as opposed to fetched-but-empty). */
const PLACEHOLDER: Details = { severity: 'unknown', summary: '', published: null, pending: true, fixed: {}, fixedAll: false };

const fromOsv = (d: VulnDetails): Details => ({ severity: d.severity, summary: d.summary, published: d.published, fixed: d.fixed, fixedAll: true });

/**
 * Details per advisory id for one batch: reuse what `vulns` already holds, then fetch the rest from OSV
 * (pending placeholders first, then new ids) until `budget.left` runs out. Ids left over get a pending placeholder.
 * With budget to spare, ids whose stored rows predate fixed versions (fixed_versions NULL) are re-fetched last.
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
    `SELECT id, eco, name, severity, summary, published, checked_at, fixed_versions FROM vulns
     WHERE id IN (SELECT value FROM json_each(?))`,
  ).bind(JSON.stringify(ids)).all<{
    id: string; eco: string; name: string; severity: string; summary: string | null; published: string | null; checked_at: string; fixed_versions: string | null;
  }>();
  const pending = new Set<string>();
  const stale = new Set<string>();
  for (const r of results) {
    if (r.checked_at === '') {
      pending.add(r.id);
      continue;
    }
    const d = out.get(r.id) ?? { severity: r.severity as Details['severity'], summary: r.summary ?? '', published: r.published, fixed: {}, fixedAll: false };
    let list: unknown = null;
    try {
      list = r.fixed_versions === null ? null : JSON.parse(r.fixed_versions);
    } catch {
      // treated as unknown
    }
    if (Array.isArray(list) && list.every((x) => typeof x === 'string')) d.fixed[`${r.eco}:${r.name}`] = list as string[];
    else stale.add(r.id);
    out.set(r.id, d);
  }
  const todo = ids.filter((id) => !out.has(id)).sort((a, b) => Number(pending.has(b)) - Number(pending.has(a)));
  for (const id of todo) {
    const cached = cache.get(id);
    if (cached) { out.set(id, fromOsv(cached)); continue; }
    if (budget.left <= 0) { out.set(id, PLACEHOLDER); continue; }
    budget.left--;
    const d = await vulnDetails(deps, id, cache);
    out.set(id, d ? fromOsv(d) : PLACEHOLDER);
  }
  for (const id of stale) {
    const cached = cache.get(id);
    if (cached) { out.set(id, fromOsv(cached)); continue; }
    if (budget.left <= 0) break;
    budget.left--;
    const d = await vulnDetails(deps, id, cache);
    if (d) out.set(id, fromOsv(d));
  }
  return out;
}

/** The JSON stored in vulns.fixed_versions for one row, or null when not known. */
function fixedJson(d: Details, ref: PackageRef): string[] | null {
  const list = d.fixed[`${ref.eco}:${ref.name}`];
  return list ?? (d.fixedAll ? [] : null);
}

const RECORD_CHUNK = 200;

/** Writes the vulns rows for a batch and drops rows of those versions whose id is gone, one D1 batch per 200 versions. */
async function recordVulns(
  env: Env,
  batch: PackageRef[],
  hits: Map<string, string[]>,
  details: Map<string, Details>,
  now: Date,
): Promise<void> {
  for (let i = 0; i < batch.length; i += RECORD_CHUNK) {
    const chunk = batch.slice(i, i + RECORD_CHUNK);
    const rows: (string | number | string[] | null)[][] = [];
    for (const ref of chunk) {
      for (const id of hits.get(formatPackageId(ref)) ?? []) {
        const d = details.get(id) ?? PLACEHOLDER;
        rows.push([ref.eco, ref.name, ref.version, id, d.severity, d.summary, d.published, d.pending ? 0 : 1, fixedJson(d, ref)]);
      }
    }
    const rowsJson = JSON.stringify(rows);
    const refsJson = JSON.stringify(chunk.map((r) => [r.eco, r.name, r.version]));
    await env.DB.batch([
      env.DB.prepare(
        `INSERT OR REPLACE INTO vulns (eco, name, version, id, severity, summary, published, checked_at, fixed_versions)
         SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]'), json_extract(value, '$[3]'),
                json_extract(value, '$[4]'), json_extract(value, '$[5]'), json_extract(value, '$[6]'),
                CASE WHEN json_extract(value, '$[7]') = 1 THEN ?2 ELSE '' END, json_extract(value, '$[8]')
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
  const done: { batch: PackageRef[]; hits: Map<string, string[]> }[] = [];
  for (let i = 0; i < refs.length; i += BATCH) {
    const batch = refs.slice(i, i + BATCH);
    const hits = await vulnIds(deps, batch);
    if (hits === null) break;
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
    done.push({ batch, hits });
    checked += batch.length;
  }
  // Best effort, and only after MAL blocking over ALL batches: detail fetches must never use up
  // subrequests that a later batch's OSV query needs.
  try {
    for (const { batch, hits } of done) {
      const details = await detailsFor(env, deps, [...new Set([...hits.values()].flat())], cache, budget);
      await recordVulns(env, batch, hits, details, now);
    }
  } catch (err) {
    console.error('cron: recording vulns failed', err instanceof Error ? err.name : 'error');
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
