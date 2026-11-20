import type { Ecosystem } from '../ids';
import { parsePolicy } from '../policy/schema';
import { compareVersions, parseVersion } from '../semver';

/**
 * Dashboard read queries. Every query is scoped with SCOPE, which binds ?1 to a project id or 'all'
 * and lets SQLite drive serve_log / request_counts by their (project_id, day) prefix per project.
 * Window queries bind ?2 to the first day (inclusive) of the range.
 */
export const SCOPE = "project_id IN (SELECT id FROM projects WHERE ?1 = 'all' OR id = ?1)";

const OUTCOMES = ['served', 'cooldown', 'blocked', 'stale', 'failed'] as const;
type Outcome = (typeof OUTCOMES)[number];
export type DayRow = { day: string } & Record<Outcome, number>;

const DAY_MS = 86_400_000;
const pkg = (eco: string, name: string, version?: string) => `${eco}:${name}${version === undefined ? '' : `@${version}`}`;

/** The last `range` UTC days ending today, oldest first. */
export function windowDays(now: Date, range: number): string[] {
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const out: string[] = [];
  for (let i = range - 1; i >= 0; i--) out.push(new Date(today - i * DAY_MS).toISOString().slice(0, 10));
  return out;
}

export async function listProjects(db: D1Database): Promise<string[]> {
  const r = await db.prepare('SELECT id FROM projects ORDER BY id').all<{ id: string }>();
  return r.results.map((x) => x.id);
}

async function dayOutcomes(db: D1Database, project: string, from: string): Promise<Map<string, Record<Outcome, number>>> {
  const r = await db
    .prepare(`SELECT day, outcome, SUM(n) AS n FROM request_counts WHERE ${SCOPE} AND day >= ?2 GROUP BY day, outcome`)
    .bind(project, from)
    .all<{ day: string; outcome: string; n: number }>();
  const m = new Map<string, Record<Outcome, number>>();
  for (const row of r.results) {
    if (!(OUTCOMES as readonly string[]).includes(row.outcome)) continue;
    let d = m.get(row.day);
    if (!d) m.set(row.day, (d = { served: 0, cooldown: 0, blocked: 0, stale: 0, failed: 0 }));
    d[row.outcome as Outcome] += row.n;
  }
  return m;
}

export async function activity(db: D1Database, project: string, days: string[]) {
  const [counts, distinct] = await Promise.all([
    dayOutcomes(db, project, days[0]!),
    db
      .prepare(
        `SELECT COUNT(DISTINCT eco || ':' || name) AS p, COUNT(*) AS v FROM (
           SELECT DISTINCT eco, name, version FROM serve_log WHERE ${SCOPE} AND day >= ?2)`,
      )
      .bind(project, days[0])
      .first<{ p: number; v: number }>(),
  ]);
  return {
    days: days.map((day): DayRow => ({ day, ...(counts.get(day) ?? { served: 0, cooldown: 0, blocked: 0, stale: 0, failed: 0 }) })),
    distinctPackages: distinct?.p ?? 0,
    distinctVersions: distinct?.v ?? 0,
  };
}

export async function uptime(db: D1Database, project: string, days: string[]) {
  const counts = await dayOutcomes(db, project, days[0]!);
  let staleServed = 0;
  let failed = 0;
  const outageDays: string[] = [];
  for (const day of days) {
    const c = counts.get(day);
    if (!c) continue;
    staleServed += c.stale;
    failed += c.failed;
    if (c.stale > 0 || c.failed > 0) outageDays.push(day);
  }
  return { outageDays, staleServed, failed };
}

/** Installed versions are passed to the per-version lookups as JSON, at most this many per statement. */
export const INSTALLED_CHUNK = 500;

type SecRow = { eco: string; name: string; version: string; blocked: number; malicious: number; flagged: string; sevs: string };

export async function security(db: D1Database, project: string, from: string) {
  // One pass over the serve_log window for the installed set; the global-fact tables are then probed
  // by primary key for each installed version (json_each), never scanned.
  const [installed, fast] = await db.batch([
    db.prepare(`SELECT DISTINCT eco, name, version FROM serve_log WHERE ${SCOPE} AND day >= ?2`).bind(project, from),
    db
      .prepare(
        `SELECT a.project_id, a.eco, a.name, a.version, a.advisory, a.advisory_published, a.first_synced_at
         FROM allows a JOIN projects p ON p.id = a.project_id AND a.ref = p.main_ref
         WHERE (?1 = 'all' OR a.project_id = ?1) AND a.advisory IS NOT NULL
           AND a.advisory_published IS NOT NULL AND a.first_synced_at IS NOT NULL
         ORDER BY a.project_id, a.eco, a.name, a.version`,
      )
      .bind(project),
  ]);
  const inst = (installed!.results as { eco: string; name: string; version: string }[]).map((r) => [r.eco, r.name, r.version]);
  const onInst = 'x.eco = i.eco AND x.name = i.name AND x.version = i.version';
  const lookup = db.prepare(
    `WITH i AS (SELECT json_extract(value, '$[0]') AS eco, json_extract(value, '$[1]') AS name, json_extract(value, '$[2]') AS version
                FROM json_each(?1))
     SELECT i.eco, i.name, i.version,
       EXISTS (SELECT 1 FROM global_blocks x WHERE ${onInst}) AS blocked,
       (EXISTS (SELECT 1 FROM vulns x WHERE ${onInst} AND x.id LIKE 'MAL-%')
        OR EXISTS (SELECT 1 FROM global_blocks x WHERE ${onInst} AND x.source = 'osv')
        OR EXISTS (SELECT 1 FROM verdicts x WHERE ${onInst} AND x.result = 'malicious')) AS malicious,
       (SELECT json_group_array(x.scanner) FROM verdicts x WHERE ${onInst} AND x.result = 'flagged') AS flagged,
       (SELECT json_group_array(x.severity) FROM vulns x WHERE ${onInst} AND x.id NOT LIKE 'MAL-%') AS sevs
     FROM i`,
  );
  const chunks: string[] = [];
  for (let k = 0; k < inst.length; k += INSTALLED_CHUNK) chunks.push(JSON.stringify(inst.slice(k, k + INSTALLED_CHUNK)));
  const results = chunks.length ? await db.batch(chunks.map((c) => lookup.bind(c))) : [];

  let blocksHit = 0;
  let maliciousHits = 0;
  const flagged: { key: string[]; package: string; scanner: string }[] = [];
  const vulnsBySeverity = { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
  for (const res of results) {
    for (const r of res.results as SecRow[]) {
      if (r.blocked) blocksHit++;
      if (r.malicious) maliciousHits++;
      for (const scanner of JSON.parse(r.flagged) as string[]) {
        flagged.push({ key: [r.eco, r.name, r.version, scanner], package: pkg(r.eco, r.name, r.version), scanner });
      }
      for (const sv of JSON.parse(r.sevs) as string[]) {
        const k = (sv in vulnsBySeverity ? sv : 'unknown') as keyof typeof vulnsBySeverity;
        vulnsBySeverity[k]++;
      }
    }
  }
  flagged.sort((a, b) => {
    for (let k = 0; k < 4; k++) if (a.key[k] !== b.key[k]) return a.key[k]! < b.key[k]! ? -1 : 1;
    return 0;
  });

  type FastRow = { project_id: string; eco: string; name: string; version: string; advisory: string; advisory_published: string; first_synced_at: string };
  const fastLane = [];
  for (const r of fast!.results as FastRow[]) {
    const ms = Date.parse(r.first_synced_at) - Date.parse(r.advisory_published);
    if (!Number.isFinite(ms)) continue;
    fastLane.push({ project: r.project_id, package: pkg(r.eco, r.name, r.version), advisory: r.advisory, hoursToFix: Math.round(ms / 360_000) / 10 });
  }
  return {
    blocksHit,
    maliciousHits,
    flagged: flagged.map(({ package: p, scanner }) => ({ package: p, scanner })),
    vulnsBySeverity,
    fastLane,
  };
}

const GO_MAJOR_SUFFIX = /\/v([2-9]|[1-9]\d+)$/;

function majorOf(eco: Ecosystem, name: string, version: string): number | null {
  const p = parseVersion(version, eco);
  if (!p) return null;
  if (eco === 'go') {
    const m = GO_MAJOR_SUFFIX.exec(name);
    if (m) return Math.max(p.major, Number(m[1]));
  }
  return p.major;
}

type FreshRow = {
  project_id: string;
  eco: Ecosystem;
  name: string;
  version: string;
  day: string;
  publish_time: string | null;
  latest: string | null;
};

export async function freshness(db: D1Database, project: string, from: string, now: Date) {
  const r = await db
    .prepare(
      `WITH s AS (SELECT project_id, eco, name, version, MAX(day) AS day FROM serve_log
                  WHERE ${SCOPE} AND day >= ?2 GROUP BY project_id, eco, name, version)
       SELECT s.project_id, s.eco, s.name, s.version, s.day, v.publish_time, p.latest
       FROM s LEFT JOIN versions v ON v.eco = s.eco AND v.name = s.name AND v.version = s.version
              LEFT JOIN packages p ON p.eco = s.eco AND p.name = s.name`,
    )
    .bind(project, from)
    .all<FreshRow>();

  // Most recently served version per (project, eco, name): latest day, tie → highest semver.
  const chosen = new Map<string, FreshRow>();
  for (const row of r.results) {
    const key = `${row.project_id}\0${row.eco}\0${row.name}`;
    const cur = chosen.get(key);
    if (!cur || row.day > cur.day || (row.day === cur.day && compareVersions(row.version, cur.version, row.eco) > 0)) {
      chosen.set(key, row);
    }
  }
  // Packages with no `packages` row (latest never fetched) are skipped entirely, including from the median.
  // Go majors come from the version and a `/vN` path suffix only; gopkg.in-style `.vN` paths are not handled.
  const rows = [...chosen.values()].filter((x) => x.latest !== null);

  // Go: a newer major lives at a different module path (<base>/vN). Look up the known siblings in one
  // query: a primary-key range scan of packages per base, driven by json_each.
  const goBases = [...new Set(rows.filter((x) => x.eco === 'go').map((x) => x.name.replace(GO_MAJOR_SUFFIX, '')))];
  const siblings = new Map<string, { name: string; latest: string }[]>();
  if (goBases.length > 0) {
    const res = await db
      .prepare(
        `SELECT j.value AS base, p.name, p.latest FROM json_each(?1) j
         JOIN packages p ON p.eco = 'go' AND p.name >= j.value || '/v' AND p.name < j.value || '/w'`,
      )
      .bind(JSON.stringify(goBases))
      .all<{ base: string; name: string; latest: string }>();
    for (const r of res.results) {
      if (!GO_MAJOR_SUFFIX.test(r.name) || r.name.replace(GO_MAJOR_SUFFIX, '') !== r.base) continue;
      const list = siblings.get(r.base) ?? [];
      list.push({ name: r.name, latest: r.latest });
      siblings.set(r.base, list);
    }
  }

  const ages: number[] = [];
  const majorBehind: MajorBehind[] = [];
  let minorAvailable = 0;
  for (const x of rows) {
    if (x.publish_time !== null) {
      const t = Date.parse(x.publish_time);
      if (Number.isFinite(t)) ages.push((now.getTime() - t) / DAY_MS);
    }
    const instMajor = majorOf(x.eco, x.name, x.version);
    if (instMajor === null) continue;
    let latest = x.latest!;
    let latestMajor = majorOf(x.eco, x.name, latest);
    if (x.eco === 'go') {
      for (const s of siblings.get(x.name.replace(GO_MAJOR_SUFFIX, '')) ?? []) {
        const m = majorOf('go', s.name, s.latest);
        if (m !== null && (latestMajor === null || m > latestMajor)) {
          latestMajor = m;
          latest = s.latest;
        }
      }
    }
    if (latestMajor === null) continue;
    if (latestMajor > instMajor) majorBehind.push({ project: x.project_id, package: pkg(x.eco, x.name), version: x.version, latest });
    else if (latestMajor === instMajor && compareVersions(latest, x.version, x.eco) > 0) minorAvailable++;
  }
  majorBehind.sort((a, b) => (a.package < b.package ? -1 : a.package > b.package ? 1 : a.project < b.project ? -1 : a.project > b.project ? 1 : 0));

  // Split by each project's synced dependency summary (version-insensitive). A project without one keeps
  // every entry in `direct`, marked classified: false.
  const summaries = await depSummaries(db, [...new Set(majorBehind.map((x) => x.project))]);
  const direct: (MajorBehind & { classified: boolean })[] = [];
  const transitive: (MajorBehind & { via: string[] })[] = [];
  for (const x of majorBehind) {
    const s = summaries.get(x.project);
    if (!s) {
      direct.push({ ...x, classified: false });
      continue;
    }
    const info = s.get(x.package);
    if (info?.direct) direct.push({ ...x, classified: true });
    else transitive.push({ ...x, via: [...(info?.via ?? [])].sort().slice(0, MAX_VIA) });
  }
  return { medianAgeDays: median(ages), majorBehind: { direct, transitive }, transitiveMajorBehindCount: transitive.length, minorAvailable };
}

type MajorBehind = { project: string; package: string; version: string; latest: string };
const MAX_VIA = 5;

/** project → (eco:name → direct anywhere in the summary, union of via). Missing or corrupt rows are absent. */
async function depSummaries(db: D1Database, projects: string[]): Promise<Map<string, Map<string, { direct: boolean; via: Set<string> }>>> {
  const out = new Map<string, Map<string, { direct: boolean; via: Set<string> }>>();
  if (projects.length === 0) return out;
  const r = await db
    .prepare('SELECT project_id, json FROM project_deps WHERE project_id IN (SELECT value FROM json_each(?1))')
    .bind(JSON.stringify(projects))
    .all<{ project_id: string; json: string }>();
  for (const row of r.results) {
    let list: unknown;
    try {
      list = JSON.parse(row.json);
    } catch {
      continue;
    }
    if (!Array.isArray(list)) continue;
    const m = new Map<string, { direct: boolean; via: Set<string> }>();
    for (const d of list as { eco: string; name: string; direct: boolean; via: string[] }[]) {
      const k = pkg(d.eco, d.name);
      let cur = m.get(k);
      if (!cur) m.set(k, (cur = { direct: false, via: new Set() }));
      cur.direct ||= d.direct === true;
      if (Array.isArray(d.via)) for (const v of d.via) cur.via.add(v);
    }
    out.set(row.project_id, m);
  }
  return out;
}

function median(xs: number[]): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return Math.round(s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2);
}

export async function policies(db: D1Database, project: string) {
  const r = await db
    .prepare(
      `SELECT pol.project_id, pol.json, pol.sha, pol.synced_at FROM policies pol
       JOIN projects p ON p.id = pol.project_id AND pol.ref = p.main_ref
       WHERE ?1 = 'all' OR pol.project_id = ?1 ORDER BY pol.project_id`,
    )
    .bind(project)
    .all<{ project_id: string; json: string; sha: string; synced_at: string }>();
  const out = [];
  for (const row of r.results) {
    let raw: unknown;
    try {
      raw = JSON.parse(row.json);
    } catch {
      continue;
    }
    const parsed = parsePolicy(raw);
    if (!parsed.ok) continue;
    const p = parsed.policy;
    out.push({
      project: row.project_id,
      cooldownDays: p.cooldownDays,
      autoShip: p.autoShip,
      allows: p.allow.length,
      blocks: p.block.length,
      syncedAt: row.synced_at,
      sha: row.sha,
    });
  }
  return { policies: out };
}

export const PAGE_SIZE = 50;

/** Escape LIKE metacharacters so `q` matches literally (used with ESCAPE '\'). */
export function likeLiteral(q: string): string {
  return q.replace(/[\\%_]/g, (c) => `\\${c}`);
}

export async function packageList(db: D1Database, project: string, from: string, q: string, page: number) {
  const r = await db
    .prepare(
      `WITH s AS (SELECT project_id, eco, name, version, MAX(day) AS last FROM serve_log
                  WHERE ${SCOPE} AND day >= ?5 AND (?2 = '' OR name LIKE '%' || ?2 || '%' ESCAPE '\\')
                  GROUP BY project_id, eco, name, version)
       SELECT s.project_id, s.eco, s.name, s.version, v.publish_time, p.latest, s.last
       FROM s LEFT JOIN versions v ON v.eco = s.eco AND v.name = s.name AND v.version = s.version
              LEFT JOIN packages p ON p.eco = s.eco AND p.name = s.name
       ORDER BY s.name, s.version, s.project_id, s.eco
       LIMIT ?3 OFFSET ?4`,
    )
    .bind(project, likeLiteral(q), PAGE_SIZE + 1, (page - 1) * PAGE_SIZE, from)
    .all<{ project_id: string; eco: string; name: string; version: string; publish_time: string | null; latest: string | null; last: string }>();
  const rows = r.results;
  return {
    items: rows.slice(0, PAGE_SIZE).map((x) => ({
      project: x.project_id,
      eco: x.eco,
      name: x.name,
      version: x.version,
      published: x.publish_time,
      latest: x.latest,
      lastServed: x.last,
    })),
    page,
    hasMore: rows.length > PAGE_SIZE,
  };
}
