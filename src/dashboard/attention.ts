import type { Ecosystem, Env } from '../types';
import { parsePolicy } from '../policy/schema';
import { compareVersions, parseVersion } from '../semver';
import { INSTALLED_CHUNK, SCOPE, windowDays } from './queries';

export type Kind = 'malicious' | 'blocked' | 'vuln' | 'flagged' | 'conflict' | 'silent';
/** A link the page may render: built here, only to osv.dev, www.npmjs.com, pkg.go.dev, hub.docker.com or github.com. */
export interface Link { label: string; url: string }
/** One scanner rule that fired, with what the scanner said about it (untrusted package text). */
export interface Finding { rule: string; note: string }
export interface Item {
  key: string;
  project: string | null;
  kind: Kind;
  title: string;
  detail: string;
  firstSeen: string;
  resolvedAt?: string;
  /** What to do about it; `code` spans are marked with backticks. Empty for resolved items. */
  todo: string;
  links: Link[];
  /** Flagged items: the rules that fired, when the scanner recorded them. */
  findings?: Finding[];
}

// ---- To-dos and links (pure) ----

const REPO_RE = /^[A-Za-z0-9-]+\/(?!\.\.?$)[A-Za-z0-9._-]+$/; // owner/name; name is never . or ..
const ARCHIVE_ANOMALY = 'archive-anomaly';
const MAX_FINDINGS = 6;
const FINDING_MAX = 200;
const SETUP_GUIDE = 'https://github.com/sudarkoff/decant/blob/main/docs/adopt.md';

const segments = (path: string) => path.split('/').map(encodeURIComponent).join('/');

/** The registry page of one version. npm scopes keep their '@'; Go module paths keep their case. */
export function packageUrl(eco: Ecosystem, name: string, version: string): string {
  if (eco === 'go') return `https://pkg.go.dev/${segments(name)}@${encodeURIComponent(version)}`;
  return `https://www.npmjs.com/package/${segments(name).replace(/^%40/, '@')}/v/${encodeURIComponent(version)}`;
}

/** A path component of an image repository as decant stores it (lowercase, distribution-spec separators). */
const IMAGE_PART = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;

/**
 * The page of an image repository, when its host is known: Docker Hub (`/_/x` for official images,
 * `/r/ns/x` otherwise) or ghcr.io when the path is exactly owner/name (taken as the package of the
 * same-named repo). Anything else, including deeper ghcr.io paths, has no link.
 */
export function imageUrl(name: string): string | null {
  const parts = name.split('/');
  if (parts.slice(1).some((p) => !IMAGE_PART.test(p))) return null;
  if (parts[0] === 'docker.io' && parts.length === 3) {
    return parts[1] === 'library' ? `https://hub.docker.com/_/${parts[2]}` : `https://hub.docker.com/r/${parts[1]}/${parts[2]}`;
  }
  if (parts[0] === 'ghcr.io' && parts.length === 3) return `https://github.com/${parts[1]}/${parts[2]}/pkgs/container/${parts[2]}`;
  return null;
}

/** `node@sha256:0123456789ab`: Docker Hub names as people write them, the digest cut to 12 hex. */
export function imageLabel(name: string, digest: string): string {
  const short = name.replace(/^docker\.io\/library\//, '').replace(/^docker\.io\//, '');
  return `${short}@${digest.slice(0, 'sha256:'.length + 12)}`;
}

const packageLink = (eco: Ecosystem, name: string, version: string): Link | null => {
  if (eco === 'docker') {
    const url = imageUrl(name);
    return url === null ? null : { label: name.startsWith('docker.io/') ? 'View on Docker Hub' : 'View on GitHub', url };
  }
  return { label: eco === 'go' ? 'View on pkg.go.dev' : 'View on npm', url: packageUrl(eco, name, version) };
};
const advisoryLink = (id: string): Link => ({ label: 'Advisory', url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` });
/** An open-PR search in the project's repo; null when the repo is unknown or not owner/name. */
const prLink = (repo: string | null, label: string, query: string): Link | null =>
  repo !== null && REPO_RE.test(repo) ? { label, url: `https://github.com/${repo}/pulls?q=${query}` } : null;

/** The lowest of `fixed` above `installed`, or null (none above, list unknown, or installed does not parse). */
export function lowestFixed(fixed: string[] | null, installed: string, eco: Ecosystem): string | null {
  if (!fixed || parseVersion(installed, eco) === null) return null;
  let best: string | null = null;
  for (const f of fixed) {
    if (parseVersion(f, eco) === null || compareVersions(f, installed, eco) <= 0) continue;
    if (best === null || compareVersions(f, best, eco) < 0) best = f;
  }
  return best;
}

const parseJson = (s: string | null): unknown => {
  if (s === null) return null;
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
};

const clipTo = (s: string, n: number) => {
  const t = s.replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};

/**
 * Rules from a verdict's stored `details`: the action's finding objects ({rule, count, message, locations})
 * or the legacy list of rule names. Anything else is dropped; at most MAX_FINDINGS, text clipped.
 */
export function findingsOf(details: unknown): Finding[] {
  if (!Array.isArray(details)) return [];
  const out: Finding[] = [];
  for (const d of details) {
    if (out.length >= MAX_FINDINGS) break;
    if (typeof d === 'string' && d.trim()) {
      out.push({ rule: clipTo(d, 100), note: '' });
      continue;
    }
    if (!d || typeof d !== 'object' || typeof (d as { rule?: unknown }).rule !== 'string') continue;
    const o = d as { rule: string; count?: unknown; message?: unknown; locations?: unknown };
    if (!o.rule.trim()) continue;
    const parts: string[] = [];
    if (typeof o.message === 'string' && o.message.trim()) parts.push(o.message);
    else if (typeof o.count === 'number' && Number.isInteger(o.count) && o.count > 1) parts.push(`${o.count} hits`);
    const locs = Array.isArray(o.locations) ? o.locations.filter((l): l is string => typeof l === 'string' && l.trim() !== '').slice(0, 3) : [];
    if (locs.length) parts.push(`at ${locs.join(', ')}`);
    out.push({ rule: clipTo(o.rule, 100), note: clipTo(parts.join(' '), FINDING_MAX) });
  }
  return out;
}

type Pkg = { eco: Ecosystem; name: string; version: string };
export type TodoInput =
  /**
   * fixedKnown false: the advisory's fixed versions were not looked up yet (rows stored before 0007).
   * fixedPackage: docker only, the OS package in the image that `fixed` is a version of.
   */
  | ({ kind: 'vuln'; advisory: string; fixed: string | null; fixedKnown?: boolean; fixedPackage?: string; repo: string | null } & Pkg)
  /** noFindings: the verdict recorded no rule details (older action, or another writer). */
  | ({ kind: 'flagged'; notScanned: boolean; noFindings?: boolean; repo: string | null } & Pkg)
  | ({ kind: 'malicious'; advisories: string[] } & Pkg)
  | ({ kind: 'blocked' } & Pkg)
  | ({ kind: 'conflict' } & Pkg)
  | { kind: 'silent' };

/** The "What to do" line and the 1-2 links for one open item. */
export function todoFor(i: TodoInput): { todo: string; links: Link[] } {
  const some = (...l: (Link | null)[]) => l.filter((x): x is Link => x !== null);
  switch (i.kind) {
    case 'vuln':
      if (i.eco === 'docker') {
        const image = packageLink(i.eco, i.name, i.version);
        if (i.fixed === null) {
          return {
            todo: 'No fixed package yet. Nothing to do now: decant re-scans the image daily and this card updates when a fix ships.',
            links: some(advisoryLink(i.advisory), image),
          };
        }
        return {
          todo: `Fixed in \`${i.fixedPackage ?? '?'}\` \`${i.fixed}\`. The daily security PR bumps the image digest once a newer one with the fix has cleared the cooldown; if the tag has none yet, move to a newer tag.`,
          links: some(prLink(i.repo, 'Open security PRs', 'is%3Apr+is%3Aopen+label%3Adecant%3Asecurity'), advisoryLink(i.advisory), image),
        };
      }
      if (i.fixed === null && i.fixedKnown === false) {
        return {
          todo: 'decant has not looked up a fixed version yet (it will within a day). The advisory lists the fixed versions.',
          links: [advisoryLink(i.advisory)],
        };
      }
      if (i.fixed === null) {
        return {
          todo: 'No fixed version yet. Nothing to do now: decant re-checks daily and this card updates when a fix ships.',
          links: [advisoryLink(i.advisory)],
        };
      }
      return {
        todo: `Fixed in \`${i.fixed}\`. Merge the daily security PR: it includes this fix (security fixes skip the cooldown).`,
        links: some(prLink(i.repo, 'Open security PRs', 'is%3Apr+is%3Aopen+label%3Adecant%3Asecurity'), advisoryLink(i.advisory)),
      };
    case 'flagged': {
      const links = some(prLink(i.repo, 'PRs failing checks', 'is%3Apr+is%3Aopen+status%3Afailure'), packageLink(i.eco, i.name, i.version));
      if (i.notScanned) {
        const what = i.eco === 'go' ? 'module zip' : 'tarball';
        return {
          todo: `Nothing inside was scanned. Download the ${what} and check what makes it unusual (often zip test fixtures). Add \`decant:reviewed\` only once you have.`,
          links,
        };
      }
      if (i.noFindings) {
        return {
          todo: "decant didn't record which checks fired. Re-run the decant check on the PR to see them, then add the `decant:reviewed` label if they are expected; if not, block the version in `decant.json`.",
          links,
        };
      }
      return {
        todo: 'Read the findings. If they are expected, add the `decant:reviewed` label to the PR; if not, block the version in `decant.json`.',
        links,
      };
    }
    case 'malicious':
      return {
        todo: 'Remove it from the lockfile. If a build ever installed it, rotate any secrets that build could read.',
        links: some(i.advisories[0] !== undefined ? advisoryLink(i.advisories[0]) : null, packageLink(i.eco, i.name, i.version)),
      };
    case 'blocked':
      return {
        todo: 'Blocked by your policy. Remove or replace it, or lift the block in `decant.json`.',
        links: some(packageLink(i.eco, i.name, i.version)),
      };
    case 'conflict':
      return {
        todo: "decant keeps serving the copy it verified, so builds are unaffected. Check the package's repo for a re-publish notice; if you can't explain it, block the version.",
        links: some(packageLink(i.eco, i.name, i.version)),
      };
    case 'silent':
      return {
        todo: 'If the project is still building, its install step is probably bypassing decant. Check the registry setting and that its read token still works.',
        links: [{ label: 'Setup guide', url: SETUP_GUIDE }],
      };
  }
}

/** Installs in this many days count as "installed", whatever range the dashboard shows. */
const INSTALLED_DAYS = 30;
const SILENT_DAYS = 14;
const RESOLVED_LIMIT = 50;
const DETAIL_MAX = 200;

/** Sort rank: malicious, blocked, vuln critical, vuln high, flagged, conflict, silent. */
const RANK = { malicious: 0, blocked: 1, critical: 2, high: 3, flagged: 4, conflict: 5, silent: 6 } as const;

type Current = { key: string; project: string | null; kind: Kind; detail: string; rank: number; todo: string; links: Link[]; findings?: Finding[] };

const clip = (s: string) => (s.length > DETAIL_MAX ? `${s.slice(0, DETAIL_MAX - 1)}…` : s);
/** A malicious-package block, which the malicious rule reports instead of the blocked rule. */
const isMaliciousSource = (source: string) => source === 'osv' || source.startsWith('verdict:');
/** `name@version` of a package id; docker ids read as imageLabel. */
const shortPkg = (pkgId: string) => {
  const rest = pkgId.slice(pkgId.indexOf(':') + 1);
  if (!pkgId.startsWith('docker:')) return rest;
  const at = rest.lastIndexOf('@');
  return imageLabel(rest.slice(0, at), rest.slice(at + 1));
};

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

const GRYPE = 'grype';
const ADVISORY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;
type ImageVuln = { id: string; severity: 'critical' | 'high'; package: string; version: string; fixed: string[] };

/**
 * The High and Critical findings in a Grype verdict's `details` (the action's {id, severity, package,
 * version, fixed} objects; written by any project's CI, so untrusted). Anything malformed is dropped.
 */
export function grypeFindings(details: unknown): ImageVuln[] {
  if (!Array.isArray(details)) return [];
  const out: ImageVuln[] = [];
  const seen = new Set<string>();
  for (const d of details) {
    if (!d || typeof d !== 'object') continue;
    const o = d as Record<string, unknown>;
    if (typeof o.id !== 'string' || !ADVISORY_ID.test(o.id) || seen.has(o.id)) continue;
    if (o.severity !== 'critical' && o.severity !== 'high') continue;
    const str = (v: unknown) => (typeof v === 'string' ? clipTo(v, 100) : '?');
    const fixed = Array.isArray(o.fixed) ? o.fixed.filter((f): f is string => typeof f === 'string' && f.trim() !== '').map((f) => clipTo(f, 100)) : [];
    seen.add(o.id);
    out.push({ id: o.id, severity: o.severity, package: str(o.package), version: str(o.version), fixed });
  }
  return out;
}

type LookupRow = { eco: Ecosystem; name: string; version: string; blocks: string; vulns: string; verdicts: string };

async function currentItems(env: Env, project: string, now: Date): Promise<Current[]> {
  const db = env.DB;
  const from = windowDays(now, INSTALLED_DAYS)[0]!;
  const silentFrom = windowDays(now, SILENT_DAYS)[0]!;
  const [installed, pols, activity, conflicts, images] = await db.batch([
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
        `SELECT p.id, p.repo, (SELECT MAX(day) FROM serve_log s WHERE s.project_id = p.id) AS s,
                      (SELECT MAX(day) FROM request_counts r WHERE r.project_id = p.id) AS r
         FROM projects p WHERE ?1 = 'all' OR p.id = ?1`,
      )
      .bind(project),
    db.prepare(`SELECT eco, name, version FROM versions WHERE conflict = 1 AND ?1 = 'all'`).bind(project),
    // Base images in use on each project's default branch count as installed (they are never served by decant).
    db.prepare(`SELECT project_id, 'docker' AS eco, name, digest AS version FROM project_images WHERE ${SCOPE}`).bind(project),
  ]);
  const projectRows = activity!.results as { id: string; repo: string | null; s: string | null; r: string | null }[];
  const repoOf = new Map(projectRows.map((r) => [r.id, r.repo]));

  const inst = [...installed!.results, ...images!.results] as { project_id: string; eco: string; name: string; version: string }[];
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
       (SELECT json_group_array(json_array(x.id, x.severity, x.summary, x.fixed_versions)) FROM vulns x
         WHERE ${onInst} AND (x.id LIKE 'MAL-%' OR x.severity IN ('critical', 'high'))) AS vulns,
       (SELECT json_group_array(json_array(x.scanner, x.result, x.details)) FROM verdicts x
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
      const vulns = JSON.parse(r.vulns) as [string, string, string | null, string | null][];
      const verdicts = JSON.parse(r.verdicts) as [string, string, string | null][];
      const pkg = { eco: r.eco, name: r.name, version: r.version };
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
      // An image's Grype verdict lists its OS-package vulnerabilities: those become vuln items, not a flag.
      const isGrype = (scanner: string) => r.eco === 'docker' && scanner === GRYPE;
      const imageVulns = verdicts.filter(([sc, res]) => isGrype(sc) && res === 'flagged').flatMap(([, , details]) => grypeFindings(parseJson(details)));
      const flaggedRows = verdicts.filter(([sc, res]) => res === 'flagged' && !isGrype(sc));
      const flaggedBy = flaggedRows.map(([s]) => s);
      const findings = flaggedRows.flatMap(([, , details]) => findingsOf(parseJson(details))).slice(0, MAX_FINDINGS);
      const notScanned = findings.some((f) => f.rule === ARCHIVE_ANOMALY);
      const malTodo = todoFor({ kind: 'malicious', ...pkg, advisories: mal });
      const blockedTodo = todoFor({ kind: 'blocked', ...pkg });

      for (const p of projectsOf.get(id)!) {
        if (malicious) add({ key: `malicious:${id}:${p}`, project: p, kind: 'malicious', detail: clip(malDetail), rank: RANK.malicious, ...malTodo });
        const why = [...otherBlocks];
        const pol = policyBlocks.get(p)?.get(id);
        if (pol !== undefined && !why.some((w) => w.startsWith(`policy:${p}: `))) why.push(`policy: ${pol}`);
        if (why.length) add({ key: `blocked:${id}:${p}`, project: p, kind: 'blocked', detail: clip(why.join('; ')), rank: RANK.blocked, ...blockedTodo });
        const repo = repoOf.get(p) ?? null;
        for (const [vid, sev, summary, fixedJson] of vulns) {
          if (vid.startsWith('MAL-')) continue;
          const s = sev as 'critical' | 'high';
          const list = parseJson(fixedJson);
          const known = Array.isArray(list) && list.every((x) => typeof x === 'string');
          const todo = todoFor({
            kind: 'vuln', ...pkg, advisory: vid, repo, fixedKnown: known,
            fixed: known ? lowestFixed(list as string[], r.version, r.eco) : null,
          });
          add({ key: `vuln:${vid}:${id}:${p}`, project: p, kind: 'vuln', detail: clip(summary ? `${s}: ${summary}` : s), rank: RANK[s], ...todo });
        }
        for (const v of imageVulns) {
          const fixed = v.fixed[0] ?? null;
          const todo = todoFor({ kind: 'vuln', ...pkg, advisory: v.id, fixed, fixedPackage: v.package, repo });
          const detail = `${v.severity}: ${v.package} ${v.version}${fixed !== null ? ` (fixed in ${fixed})` : ' (no fix yet)'}`;
          add({ key: `vuln:${v.id}:${id}:${p}`, project: p, kind: 'vuln', detail: clip(detail), rank: RANK[v.severity], ...todo });
        }
        if (flaggedBy.length) {
          const todo = todoFor({ kind: 'flagged', ...pkg, notScanned, noFindings: findings.length === 0, repo });
          add({ key: `flagged:${id}:${p}`, project: p, kind: 'flagged', detail: clip(`flagged by ${flaggedBy.join(', ')}`), rank: RANK.flagged, ...todo, findings });
        }
      }
    }
  }

  for (const r of conflicts!.results as { eco: Ecosystem; name: string; version: string }[]) {
    const id = `${r.eco}:${r.name}@${r.version}`;
    const todo = todoFor({ kind: 'conflict', eco: r.eco, name: r.name, version: r.version });
    add({ key: `conflict:${id}`, project: null, kind: 'conflict', detail: 'upstream publish time changed after decant pinned it', rank: RANK.conflict, ...todo });
  }

  const silentTodo = todoFor({ kind: 'silent' });
  for (const r of projectRows) {
    const last = [r.s, r.r].filter((d): d is string => d !== null).sort().pop();
    if (last === undefined || last >= silentFrom) continue; // never active, or active recently
    add({ key: `silent:${r.id}`, project: r.id, kind: 'silent', detail: `last activity ${last}`, rank: RANK.silent, ...silentTodo });
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
    .map(({ c, firstSeen }): Item => ({
      key: c.key, project: c.project, kind: c.kind, title: titleFor(c.key).title, detail: c.detail, firstSeen,
      todo: c.todo, links: c.links, ...(c.findings ? { findings: c.findings } : {}),
    }));
  const resolvedItems = (resolved!.results as { key: string; project_id: string | null; first_seen: string; resolved_at: string }[]).map(
    (r): Item => ({ key: r.key, project: r.project_id, ...titleFor(r.key), detail: '', firstSeen: r.first_seen, resolvedAt: r.resolved_at, todo: '', links: [] }),
  );
  return { open: openItems, resolved: resolvedItems };
}
