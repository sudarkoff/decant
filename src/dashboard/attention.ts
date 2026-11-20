import type { Env } from '../types';
import { parsePolicy } from '../policy/schema';
import { INSTALLED_CHUNK, SCOPE, windowDays } from './queries';

export type Kind = 'malicious' | 'blocked' | 'vuln' | 'flagged' | 'conflict' | 'silent';
export interface Item {
  key: string;
  project: string | null;
  kind: Kind;
  title: string;
  detail: string;
  firstSeen: string;
  resolvedAt?: string;
}

/** Installs in this many days count as "installed", whatever range the dashboard shows. */
const INSTALLED_DAYS = 30;
const SILENT_DAYS = 14;
const RESOLVED_LIMIT = 50;
const DETAIL_MAX = 200;

/** Sort rank: malicious, blocked, vuln critical, vuln high, flagged, conflict, silent. */
const RANK = { malicious: 0, blocked: 1, critical: 2, high: 3, flagged: 4, conflict: 5, silent: 6 } as const;

type Current = { key: string; project: string | null; kind: Kind; detail: string; rank: number };

const clip = (s: string) => (s.length > DETAIL_MAX ? `${s.slice(0, DETAIL_MAX - 1)}…` : s);
/** A malicious-package block, which the malicious rule reports instead of the blocked rule. */
const isMaliciousSource = (source: string) => source === 'osv' || source.startsWith('verdict:');
const shortPkg = (pkgId: string) => pkgId.slice(pkgId.indexOf(':') + 1);

/** The title is derived from the key alone, so open and resolved items read the same. */
function titleFor(key: string): { kind: Kind; title: string } {
  const kind = key.slice(0, key.indexOf(':')) as Kind;
  const rest = key.slice(kind.length + 1);
  const pkgOf = (s: string) => shortPkg(s.slice(0, s.lastIndexOf(':')));
  switch (kind) {
    case 'malicious':
      return { kind, title: `${pkgOf(rest)} is malicious` };
    case 'blocked':
      return { kind, title: `${pkgOf(rest)} is blocked` };
    case 'flagged':
      return { kind, title: `${pkgOf(rest)} was flagged by a scanner` };
    case 'vuln': {
      const id = rest.slice(0, rest.indexOf(':'));
      return { kind, title: `${pkgOf(rest.slice(id.length + 1))} has ${id}` };
    }
    case 'conflict':
      return { kind, title: `${shortPkg(rest)} was republished upstream` };
    case 'silent':
      return { kind, title: `${rest} has had no requests in ${SILENT_DAYS} days` };
    default:
      return { kind, title: key };
  }
}

type LookupRow = { eco: string; name: string; version: string; blocks: string; vulns: string; verdicts: string };

async function currentItems(env: Env, project: string, now: Date): Promise<Current[]> {
  const db = env.DB;
  const from = windowDays(now, INSTALLED_DAYS)[0]!;
  const silentFrom = windowDays(now, SILENT_DAYS)[0]!;
  const [installed, pols, activity, conflicts] = await db.batch([
    db.prepare(`SELECT DISTINCT project_id, eco, name, version FROM serve_log WHERE ${SCOPE} AND day >= ?2`).bind(project, from),
    db
      .prepare(
        `SELECT pol.project_id, pol.json FROM policies pol JOIN projects p ON p.id = pol.project_id AND pol.ref = p.main_ref
         WHERE ?1 = 'all' OR pol.project_id = ?1`,
      )
      .bind(project),
    // Latest activity per project: each MAX is a probe of the (project_id, day) prefix.
    db
      .prepare(
        `SELECT p.id, (SELECT MAX(day) FROM serve_log s WHERE s.project_id = p.id) AS s,
                      (SELECT MAX(day) FROM request_counts r WHERE r.project_id = p.id) AS r
         FROM projects p WHERE ?1 = 'all' OR p.id = ?1`,
      )
      .bind(project),
    db.prepare(`SELECT eco, name, version FROM versions WHERE conflict = 1 AND ?1 = 'all'`).bind(project),
  ]);

  const inst = installed!.results as { project_id: string; eco: string; name: string; version: string }[];
  const versions = new Map<string, [string, string, string]>();
  const projectsOf = new Map<string, string[]>();
  for (const r of inst) {
    const id = `${r.eco}:${r.name}@${r.version}`;
    versions.set(id, [r.eco, r.name, r.version]);
    const list = projectsOf.get(id) ?? [];
    list.push(r.project_id);
    projectsOf.set(id, list);
  }

  // Global facts per installed version, probed by primary key via json_each in chunks.
  const onInst = 'x.eco = i.eco AND x.name = i.name AND x.version = i.version';
  const lookup = db.prepare(
    `WITH i AS (SELECT json_extract(value, '$[0]') AS eco, json_extract(value, '$[1]') AS name, json_extract(value, '$[2]') AS version
                FROM json_each(?1))
     SELECT i.eco, i.name, i.version,
       (SELECT json_group_array(json_array(x.source, x.reason)) FROM global_blocks x WHERE ${onInst}) AS blocks,
       (SELECT json_group_array(json_array(x.id, x.severity, x.summary)) FROM vulns x
         WHERE ${onInst} AND (x.id LIKE 'MAL-%' OR x.severity IN ('critical', 'high'))) AS vulns,
       (SELECT json_group_array(json_array(x.scanner, x.result)) FROM verdicts x
         WHERE ${onInst} AND x.result IN ('flagged', 'malicious')) AS verdicts
     FROM i`,
  );
  const all = [...versions.values()];
  const chunks: string[] = [];
  for (let k = 0; k < all.length; k += INSTALLED_CHUNK) chunks.push(JSON.stringify(all.slice(k, k + INSTALLED_CHUNK)));
  const facts = chunks.length ? await db.batch(chunks.map((c) => lookup.bind(c))) : [];

  // Main-ref policy blocks per project.
  const policyBlocks = new Map<string, Map<string, string>>();
  for (const row of pols!.results as { project_id: string; json: string }[]) {
    let raw: unknown;
    try {
      raw = JSON.parse(row.json);
    } catch {
      continue;
    }
    const parsed = parsePolicy(raw);
    if (!parsed.ok) continue;
    policyBlocks.set(row.project_id, new Map(parsed.policy.block.map((b) => [b.package, b.reason])));
  }

  const out = new Map<string, Current>();
  const add = (c: Current) => {
    if (!out.has(c.key)) out.set(c.key, c);
  };
  for (const res of facts) {
    for (const r of res.results as LookupRow[]) {
      const id = `${r.eco}:${r.name}@${r.version}`;
      const blocks = JSON.parse(r.blocks) as [string, string][];
      const vulns = JSON.parse(r.vulns) as [string, string, string | null][];
      const verdicts = JSON.parse(r.verdicts) as [string, string][];
      const mal = vulns.filter(([vid]) => vid.startsWith('MAL-')).map(([vid]) => vid);
      const malSources = blocks.filter(([s]) => isMaliciousSource(s));
      const malScanners = verdicts.filter(([, res]) => res === 'malicious').map(([s]) => s);
      const malicious = mal.length > 0 || malSources.length > 0 || malScanners.length > 0;
      const malDetail = [
        ...(mal.length ? [`OSV ${mal.join(', ')}`] : []),
        ...malSources.filter(([s]) => s !== 'osv' || mal.length === 0).map(([s, why]) => `${s}: ${why}`),
        ...(malScanners.length ? [`malicious verdict from ${malScanners.join(', ')}`] : []),
      ].join('; ');
      const otherBlocks = blocks.filter(([s]) => !isMaliciousSource(s)).map(([s, why]) => `${s}: ${why}`);
      const flaggedBy = verdicts.filter(([, res]) => res === 'flagged').map(([s]) => s);

      for (const p of projectsOf.get(id)!) {
        if (malicious) add({ key: `malicious:${id}:${p}`, project: p, kind: 'malicious', detail: clip(malDetail), rank: RANK.malicious });
        const why = [...otherBlocks];
        const pol = policyBlocks.get(p)?.get(id);
        if (pol !== undefined && !why.some((w) => w.startsWith(`policy:${p}: `))) why.push(`policy: ${pol}`);
        if (why.length) add({ key: `blocked:${id}:${p}`, project: p, kind: 'blocked', detail: clip(why.join('; ')), rank: RANK.blocked });
        for (const [vid, sev, summary] of vulns) {
          if (vid.startsWith('MAL-')) continue;
          const s = sev as 'critical' | 'high';
          add({ key: `vuln:${vid}:${id}:${p}`, project: p, kind: 'vuln', detail: clip(summary ? `${s}: ${summary}` : s), rank: RANK[s] });
        }
        if (flaggedBy.length) add({ key: `flagged:${id}:${p}`, project: p, kind: 'flagged', detail: clip(`flagged by ${flaggedBy.join(', ')}`), rank: RANK.flagged });
      }
    }
  }

  for (const r of conflicts!.results as { eco: string; name: string; version: string }[]) {
    const id = `${r.eco}:${r.name}@${r.version}`;
    add({ key: `conflict:${id}`, project: null, kind: 'conflict', detail: 'upstream publish time changed after decant pinned it', rank: RANK.conflict });
  }

  for (const r of activity!.results as { id: string; s: string | null; r: string | null }[]) {
    const last = [r.s, r.r].filter((d): d is string => d !== null).sort().pop();
    if (last === undefined || last >= silentFrom) continue; // never active, or active recently
    add({ key: `silent:${r.id}`, project: r.id, kind: 'silent', detail: `last activity ${last}`, rank: RANK.silent });
  }
  return [...out.values()];
}

/**
 * Needs-attention items for `project` ('all' or a project id), diffed against alerts_state in one batch:
 * new keys open with first_seen = now, vanished open keys get resolved_at = now, and a reappearing key
 * clears resolved_at (keeping first_seen). A single project's call only touches that project's keys.
 */
export async function attention(env: Env, project: string, range: 7 | 30 | 90, now: Date): Promise<{ open: Item[]; resolved: Item[] }> {
  const db = env.DB;
  const items = await currentItems(env, project, now);
  const at = now.toISOString();
  const cur = JSON.stringify(items.map((i) => [i.key, i.project]));
  const resolvedFrom = `${windowDays(now, range)[0]!}T00:00:00.000Z`;
  const [, , open, resolved] = await db.batch([
    db
      .prepare(
        `INSERT INTO alerts_state (key, project_id, first_seen, resolved_at)
         SELECT j.value ->> 0, j.value ->> 1, ?2, NULL FROM json_each(?1) j WHERE true
         ON CONFLICT (key) DO UPDATE SET resolved_at = NULL WHERE alerts_state.resolved_at IS NOT NULL`,
      )
      .bind(cur, at),
    db
      .prepare(
        `UPDATE alerts_state SET resolved_at = ?2
         WHERE resolved_at IS NULL AND (?3 = 'all' OR project_id = ?3)
           AND key NOT IN (SELECT j.value ->> 0 FROM json_each(?1) j)`,
      )
      .bind(cur, at, project),
    db.prepare('SELECT key, first_seen FROM alerts_state WHERE key IN (SELECT j.value ->> 0 FROM json_each(?1) j)').bind(cur),
    db
      .prepare(
        `SELECT key, project_id, first_seen, resolved_at FROM alerts_state
         WHERE resolved_at IS NOT NULL AND resolved_at >= ?1 AND (?2 = 'all' OR project_id = ?2)
         ORDER BY resolved_at DESC, key LIMIT ?3`,
      )
      .bind(resolvedFrom, project, RESOLVED_LIMIT),
  ]);

  const firstSeen = new Map((open!.results as { key: string; first_seen: string }[]).map((r) => [r.key, r.first_seen]));
  const openItems = items
    .map((c) => ({ c, firstSeen: firstSeen.get(c.key) ?? at }))
    .sort((a, b) => a.c.rank - b.c.rank || (a.firstSeen < b.firstSeen ? 1 : a.firstSeen > b.firstSeen ? -1 : 0) || (a.c.key < b.c.key ? -1 : 1))
    .map(({ c, firstSeen }): Item => ({ key: c.key, project: c.project, kind: c.kind, title: titleFor(c.key).title, detail: c.detail, firstSeen }));
  const resolvedItems = (resolved!.results as { key: string; project_id: string | null; first_seen: string; resolved_at: string }[]).map(
    (r): Item => ({ key: r.key, project: r.project_id, ...titleFor(r.key), detail: '', firstSeen: r.first_seen, resolvedAt: r.resolved_at }),
  );
  return { open: openItems, resolved: resolvedItems };
}
