import type { Ecosystem, Env, PackageRef } from '../types';
import type { Policy } from './schema';

const DEFAULT_COOLDOWN_DAYS = 7;

export interface PinnedTime {
  publishTime: Date;
  conflict: boolean;
}

export interface PolicyView {
  cooldownDays: number;
  /** Allowed versions of the one package the view was loaded for. */
  allowed: Set<string>;
}

/**
 * Cooldown plus one package's allows: main-ref allows, plus `ref`'s allows when given.
 * Advisory rows count only once verified. Filtering by package in SQL keeps reads to that package's rows.
 */
export async function loadPolicyView(
  env: Env,
  projectId: string,
  ref: string | null,
  eco: Ecosystem,
  name: string,
): Promise<PolicyView> {
  const [main, rows] = await env.DB.batch<Record<string, unknown>>([
    env.DB.prepare(
      'SELECT p.json AS json FROM policies p JOIN projects pr ON pr.id = p.project_id AND pr.main_ref = p.ref WHERE p.project_id = ?',
    ).bind(projectId),
    env.DB.prepare(
      `SELECT a.version AS version FROM allows a JOIN projects pr ON pr.id = a.project_id
       WHERE a.project_id = ?1 AND a.ref IN (pr.main_ref, ?2) AND a.eco = ?3 AND a.name = ?4
         AND (a.advisory IS NULL OR a.verified_at IS NOT NULL)`,
    ).bind(projectId, ref, eco, name),
  ]);
  const json = main!.results[0]?.json as string | undefined;
  const cooldownDays = json ? (JSON.parse(json) as Policy).cooldownDays : DEFAULT_COOLDOWN_DAYS;
  return { cooldownDays, allowed: new Set((rows!.results as { version: string }[]).map((r) => r.version)) };
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

// D1 bills rows scanned. Short lists: one primary-key lookup per version via json_each.
// Longer lists: read the package's rows once and filter in JS.
const PINNED_LOOKUP_MAX = 10;
const SELECT_PACKAGE = 'SELECT version, publish_time, conflict FROM versions WHERE eco = ?1 AND name = ?2';

function selectPinnedStmt(env: Env, eco: Ecosystem, name: string, versions: string[]): D1PreparedStatement {
  return versions.length > PINNED_LOOKUP_MAX
    ? env.DB.prepare(SELECT_PACKAGE).bind(eco, name)
    : env.DB.prepare(`${SELECT_PACKAGE} AND version IN (SELECT value FROM json_each(?3))`).bind(eco, name, JSON.stringify(versions));
}

function onlyRequested(rows: VersionRow[], versions: Iterable<string>): VersionRow[] {
  const want = new Set(versions);
  return rows.filter((r) => want.has(r.version));
}

/**
 * First-seen publish times win. A later differing upstream time marks the version as conflicted
 * (stored time kept; the flag is sticky).
 *
 * Reads the package's pinned rows first, then writes only what changed: inserts for unseen versions and a
 * conflict update for versions whose time differs. A warm call is a single read. Never match json_each
 * against versions row by row: json_each has no index, so that reads O(N²) rows.
 */
export async function pinPublishTimes(
  env: Env,
  eco: Ecosystem,
  name: string,
  times: Map<string, Date>,
  now: Date,
): Promise<Map<string, PinnedTime>> {
  if (times.size === 0) return new Map();
  const requested = [...times.keys()];
  const current = await selectPinnedStmt(env, eco, name, requested).all<VersionRow>();
  const out = new Map(onlyRequested(current.results, requested).map((r) => [r.version, r]));
  const missing: Record<string, string> = {};
  const check: Record<string, string> = {}; // missing + differing: versions the conflict update must see
  for (const [v, t] of times) {
    const iso = t.toISOString();
    const row = out.get(v);
    if (!row) missing[v] = check[v] = iso;
    else if (row.conflict === 0 && row.publish_time !== iso) check[v] = iso;
  }
  const changed = Object.keys(check);
  if (changed.length === 0) return toPinned([...out.values()]);

  const stmts: D1PreparedStatement[] = [];
  if (Object.keys(missing).length > 0) {
    stmts.push(
      env.DB.prepare(
        `INSERT OR IGNORE INTO versions (eco, name, version, publish_time, first_seen)
         SELECT ?1, ?2, j.key, j.value, ?3 FROM json_each(?4) j`,
      ).bind(eco, name, now.toISOString(), JSON.stringify(missing)),
    );
  }
  // Missing versions are checked too: a concurrent request may have pinned a different time first.
  // CROSS JOIN pins json_each as the outer loop, so each element costs one primary-key lookup.
  stmts.push(
    env.DB.prepare(
      `UPDATE versions SET conflict = 1
       WHERE eco = ?1 AND name = ?2 AND conflict = 0
         AND version IN (SELECT j.key FROM json_each(?3) j CROSS JOIN versions v
                         WHERE v.eco = ?1 AND v.name = ?2 AND v.version = j.key AND j.value <> v.publish_time)`,
    ).bind(eco, name, JSON.stringify(check)),
    selectPinnedStmt(env, eco, name, changed),
  );
  const res = await env.DB.batch<VersionRow>(stmts);
  for (const r of onlyRequested(res[res.length - 1]!.results, changed)) out.set(r.version, r);
  return toPinned([...out.values()]);
}

export async function getPinnedTimes(env: Env, eco: Ecosystem, name: string, versions: string[]): Promise<Map<string, PinnedTime>> {
  if (versions.length === 0) return new Map();
  const r = await selectPinnedStmt(env, eco, name, versions).all<VersionRow>();
  return toPinned(onlyRequested(r.results, versions));
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
