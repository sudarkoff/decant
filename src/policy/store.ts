import type { Ecosystem, Env, PackageRef } from '../types';
import type { Policy } from './schema';

const DEFAULT_COOLDOWN_DAYS = 7;

export interface PinnedTime {
  publishTime: Date;
  conflict: boolean;
}

export interface PolicyView {
  cooldownDays: number;
  allowedFor(eco: Ecosystem, name: string): Set<string>;
}

/** Main-ref allows, plus `ref`'s allows when given. Advisory rows count only once verified. */
export async function loadPolicyView(env: Env, projectId: string, ref: string | null): Promise<PolicyView> {
  const [main, rows] = await env.DB.batch<Record<string, unknown>>([
    env.DB.prepare(
      'SELECT p.json AS json FROM policies p JOIN projects pr ON pr.id = p.project_id AND pr.main_ref = p.ref WHERE p.project_id = ?',
    ).bind(projectId),
    env.DB.prepare(
      `SELECT a.eco AS eco, a.name AS name, a.version AS version FROM allows a JOIN projects pr ON pr.id = a.project_id
       WHERE a.project_id = ?1 AND (a.ref = pr.main_ref OR a.ref = ?2)
         AND (a.advisory IS NULL OR a.verified_at IS NOT NULL)`,
    ).bind(projectId, ref),
  ]);
  const json = main!.results[0]?.json as string | undefined;
  const cooldownDays = json ? (JSON.parse(json) as Policy).cooldownDays : DEFAULT_COOLDOWN_DAYS;
  const allowed = new Map<string, Set<string>>();
  for (const r of rows!.results as { eco: string; name: string; version: string }[]) {
    const k = `${r.eco}:${r.name}`;
    let s = allowed.get(k);
    if (!s) allowed.set(k, (s = new Set()));
    s.add(r.version);
  }
  return {
    cooldownDays,
    allowedFor: (eco, name) => new Set(allowed.get(`${eco}:${name}`) ?? []),
  };
}

export async function blockedVersions(env: Env, eco: Ecosystem, name: string): Promise<Set<string>> {
  const r = await env.DB.prepare('SELECT DISTINCT version FROM global_blocks WHERE eco = ? AND name = ?')
    .bind(eco, name)
    .all<{ version: string }>();
  return new Set(r.results.map((x) => x.version));
}

type VersionRow = { version: string; publish_time: string; conflict: number };

function toPinned(rows: VersionRow[]): Map<string, PinnedTime> {
  return new Map(rows.map((r) => [r.version, { publishTime: new Date(r.publish_time), conflict: r.conflict === 1 }]));
}

const SELECT_PINNED =
  'SELECT version, publish_time, conflict FROM versions WHERE eco = ?1 AND name = ?2 AND version IN (SELECT value FROM json_each(?3))';

/**
 * First-seen publish times win. A later differing upstream time marks the version as conflicted
 * (stored time kept). One D1 batch; versions travel as a single JSON parameter.
 */
export async function pinPublishTimes(
  env: Env,
  eco: Ecosystem,
  name: string,
  times: Map<string, Date>,
  now: Date,
): Promise<Map<string, PinnedTime>> {
  if (times.size === 0) return new Map();
  const obj: Record<string, string> = {};
  for (const [v, t] of times) obj[v] = t.toISOString();
  const payload = JSON.stringify(obj);
  const versions = JSON.stringify([...times.keys()]);
  const res = await env.DB.batch<VersionRow>([
    env.DB.prepare(
      `INSERT OR IGNORE INTO versions (eco, name, version, publish_time, first_seen)
       SELECT ?1, ?2, j.key, j.value, ?3 FROM json_each(?4) j`,
    ).bind(eco, name, now.toISOString(), payload),
    env.DB.prepare(
      `UPDATE versions SET conflict = 1
       WHERE eco = ?1 AND name = ?2 AND conflict = 0
         AND EXISTS (SELECT 1 FROM json_each(?3) j WHERE j.key = versions.version AND j.value <> versions.publish_time)`,
    ).bind(eco, name, payload),
    env.DB.prepare(SELECT_PINNED).bind(eco, name, versions),
  ]);
  return toPinned(res[2]!.results);
}

export async function getPinnedTimes(env: Env, eco: Ecosystem, name: string, versions: string[]): Promise<Map<string, PinnedTime>> {
  if (versions.length === 0) return new Map();
  const r = await env.DB.prepare(SELECT_PINNED).bind(eco, name, JSON.stringify(versions)).all<VersionRow>();
  return toPinned(r.results);
}

export async function getVersionState(
  env: Env,
  ref: PackageRef,
): Promise<{ publishTime: Date; conflict: boolean; storedAt: string | null; osvCheckedAt: string | null } | null> {
  const r = await env.DB.prepare(
    'SELECT publish_time, conflict, stored_at, osv_checked_at FROM versions WHERE eco = ? AND name = ? AND version = ?',
  )
    .bind(ref.eco, ref.name, ref.version)
    .first<{ publish_time: string; conflict: number; stored_at: string | null; osv_checked_at: string | null }>();
  if (!r) return null;
  return { publishTime: new Date(r.publish_time), conflict: r.conflict === 1, storedAt: r.stored_at, osvCheckedAt: r.osv_checked_at };
}

export async function markOsvChecked(env: Env, refs: PackageRef[], now: Date): Promise<void> {
  if (refs.length === 0) return;
  await env.DB.prepare(
    `UPDATE versions SET osv_checked_at = ?1
     WHERE (eco, name, version) IN (
       SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]'), json_extract(value, '$[2]') FROM json_each(?2))`,
  )
    .bind(now.toISOString(), JSON.stringify(refs.map((r) => [r.eco, r.name, r.version])))
    .run();
}

/** Keeps the first stored_at. No-op if the version was never pinned. */
export async function markStored(env: Env, ref: PackageRef, now: Date): Promise<void> {
  await env.DB.prepare('UPDATE versions SET stored_at = COALESCE(stored_at, ?) WHERE eco = ? AND name = ? AND version = ?')
    .bind(now.toISOString(), ref.eco, ref.name, ref.version)
    .run();
}

export async function logServe(env: Env, projectId: string, ref: PackageRef, now: Date): Promise<void> {
  await env.DB.prepare('INSERT OR IGNORE INTO serve_log (project_id, eco, name, version, day) VALUES (?, ?, ?, ?, ?)')
    .bind(projectId, ref.eco, ref.name, ref.version, now.toISOString().slice(0, 10))
    .run();
}

/** Statement form so callers can include it in a batch. First (source, version) row wins. */
export function globalBlockStmt(env: Env, ref: PackageRef, source: string, reason: string, now: Date): D1PreparedStatement {
  return env.DB.prepare(
    'INSERT OR IGNORE INTO global_blocks (eco, name, version, source, reason, at) VALUES (?, ?, ?, ?, ?, ?)',
  ).bind(ref.eco, ref.name, ref.version, source, reason, now.toISOString());
}

export async function addGlobalBlock(env: Env, ref: PackageRef, source: string, reason: string, now: Date): Promise<void> {
  await globalBlockStmt(env, ref, source, reason, now).run();
}
