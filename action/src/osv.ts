import type { Ecosystem } from '../../src/ids';
import type { Severity } from '../../src/policy/schema';
import { compareVersions } from '../../src/semver';
import { httpError, OSV_TIMEOUT_MS, readJson, request } from './http';
import type { Dep } from './lockfiles';

const OSV = 'https://api.osv.dev';
const OSV_ECO: Record<Ecosystem, string> = { npm: 'npm', go: 'Go' };
const BATCH = 1000; // OSV querybatch limit
const MAX_PAGES = 10;
const DETAIL_CONCURRENCY = 8;

export type Vuln = {
  id: string;
  aliases: string[];
  severity: Severity | 'unknown';
  summary: string;
  malicious: boolean;
  /** The `fixed` of the SEMVER/ECOSYSTEM range covering name@version, or null (not covered, or no fix). */
  fixedFor(eco: Ecosystem, name: string, version: string): string | null;
  /** True if a range or the explicit `versions` list covers name@version. */
  affects(eco: Ecosystem, name: string, version: string): boolean;
};

type OsvEvent = { introduced?: string; fixed?: string; last_affected?: string; limit?: string };
type OsvRecord = {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  database_specific?: { severity?: unknown };
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { type?: string; events?: OsvEvent[] }[];
    versions?: string[];
  }[];
};

/** "npm:a@1.0.0" / "go:mod@v1.2.3" — the key queryVulns results are stored under. */
export function depKey(d: Pick<Dep, 'eco' | 'name' | 'version'>): string {
  return `${d.eco}:${d.name}@${d.version}`;
}

const GHSA_SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'moderate', MEDIUM: 'moderate', LOW: 'low' };

/** OSV Go versions omit the leading v; decant's carry it. */
const withV = (eco: Ecosystem, v: string) => (eco === 'go' && !v.startsWith('v') ? `v${v}` : v);

type Cover = { covered: false } | { covered: true; fixed: string | null };

/** Walks one range's events (sorted by version) and reports whether `version` is inside an interval. */
function rangeCover(events: OsvEvent[], eco: Ecosystem, version: string): Cover {
  const cmp = (a: string, b: string) => compareVersions(a, b, eco);
  const pos = (e: OsvEvent): string | null => {
    const raw = e.introduced ?? e.fixed ?? e.last_affected ?? e.limit;
    if (raw === undefined) return null;
    return raw === '0' && e.introduced !== undefined ? null : withV(eco, raw);
  };
  // introduced "0" sorts first; otherwise by version.
  const sorted = [...events].sort((a, b) => {
    const pa = pos(a);
    const pb = pos(b);
    if (pa === null || pb === null) return pa === pb ? 0 : pa === null ? -1 : 1;
    return cmp(pa, pb);
  });
  let start: string | null | undefined; // undefined: no open interval; null: open from 0
  let best: Cover = { covered: false };
  const inside = (lo: string | null) => lo === null || cmp(version, lo) >= 0;
  for (const e of sorted) {
    if (e.introduced !== undefined) {
      if (start === undefined) start = e.introduced === '0' ? null : withV(eco, e.introduced);
      continue;
    }
    if (start === undefined) continue;
    if (e.fixed !== undefined || e.limit !== undefined) {
      const end = withV(eco, (e.fixed ?? e.limit)!);
      if (inside(start) && cmp(version, end) < 0) {
        if (e.fixed !== undefined) return { covered: true, fixed: end };
        best = { covered: true, fixed: null };
      }
      start = undefined;
    } else if (e.last_affected !== undefined) {
      if (inside(start) && cmp(version, withV(eco, e.last_affected)) <= 0) best = { covered: true, fixed: null };
      start = undefined;
    }
  }
  if (start !== undefined && inside(start)) best = { covered: true, fixed: null };
  return best;
}

export function toVuln(r: OsvRecord): Vuln {
  const sev = r.database_specific?.severity;
  const entries = (eco: Ecosystem, name: string) =>
    (r.affected ?? []).filter((a) => a.package?.ecosystem === OSV_ECO[eco] && a.package?.name === name);

  function cover(eco: Ecosystem, name: string, version: string): Cover {
    let covered = false;
    for (const a of entries(eco, name)) {
      for (const rg of a.ranges ?? []) {
        if (rg.type !== 'SEMVER' && rg.type !== 'ECOSYSTEM') continue;
        const c = rangeCover(rg.events ?? [], eco, version);
        if (c.covered && c.fixed !== null) return c;
        covered ||= c.covered;
      }
      if ((a.versions ?? []).some((v) => withV(eco, v) === version)) covered = true;
    }
    return covered ? { covered: true, fixed: null } : { covered: false };
  }

  return {
    id: r.id,
    aliases: r.aliases ?? [],
    severity: typeof sev === 'string' ? (GHSA_SEVERITY[sev.toUpperCase()] ?? 'unknown') : 'unknown',
    summary: r.summary ?? r.details?.split('\n')[0] ?? '',
    malicious: r.id.startsWith('MAL-'),
    fixedFor(eco, name, version) {
      const c = cover(eco, name, version);
      return c.covered ? c.fixed : null;
    },
    affects: (eco, name, version) => cover(eco, name, version).covered,
  };
}

type Query = { package: { ecosystem: string; name: string }; version: string; page_token?: string };
type BatchResult = { results?: { vulns?: { id: string }[]; next_page_token?: string }[] };

export type OsvClient = ReturnType<typeof createOsv>;

/** An OSV client with a per-instance cache of vulnerability details (one instance per run). */
export function createOsv(f: typeof fetch) {
  const details = new Map<string, Promise<Vuln | null>>();

  async function post<T>(path: string, body: unknown): Promise<T> {
    const label = `OSV POST ${path}`;
    const res = await request(
      f,
      `${OSV}${path}`,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) },
      { label, timeoutMs: OSV_TIMEOUT_MS },
    );
    if (!res.ok) throw await httpError(res, { label });
    return readJson<T>(res, label);
  }

  function vuln(id: string): Promise<Vuln | null> {
    let p = details.get(id);
    if (!p) {
      const label = `OSV GET /v1/vulns/${id}`;
      p = (async () => {
        const res = await request(f, `${OSV}/v1/vulns/${encodeURIComponent(id)}`, {}, { label, timeoutMs: OSV_TIMEOUT_MS });
        if (res.status === 404) return null;
        if (!res.ok) throw await httpError(res, { label });
        return toVuln(await readJson<OsvRecord>(res, label));
      })();
      p.catch(() => details.delete(id)); // a failure is not cached
      details.set(id, p);
    }
    return p;
  }

  /** Vulnerabilities per depKey (every queried dep gets an entry, possibly empty). Throws if OSV fails. */
  async function queryVulns(deps: Pick<Dep, 'eco' | 'name' | 'version'>[]): Promise<Map<string, Vuln[]>> {
    const unique = new Map<string, Pick<Dep, 'eco' | 'name' | 'version'>>();
    for (const d of deps) unique.set(depKey(d), d);
    const keys = [...unique.keys()];
    const ids = new Map<string, Set<string>>(keys.map((k) => [k, new Set()]));

    for (let i = 0; i < keys.length; i += BATCH) {
      let pending = keys.slice(i, i + BATCH).map((k) => {
        const d = unique.get(k)!;
        const q: Query = { package: { ecosystem: OSV_ECO[d.eco], name: d.name }, version: d.eco === 'go' ? d.version.replace(/^v/, '') : d.version };
        return { k, q };
      });
      for (let page = 0; pending.length > 0; page++) {
        if (page >= MAX_PAGES) throw new Error(`OSV: more than ${MAX_PAGES} pages of results`);
        const r = await post<BatchResult>('/v1/querybatch', { queries: pending.map((p) => p.q) });
        const next: typeof pending = [];
        pending.forEach((p, j) => {
          const res = r.results?.[j];
          for (const v of res?.vulns ?? []) ids.get(p.k)!.add(v.id);
          if (res?.next_page_token) next.push({ k: p.k, q: { ...p.q, page_token: res.next_page_token } });
        });
        pending = next;
      }
    }

    const all = [...new Set([...ids.values()].flatMap((s) => [...s]))];
    for (let i = 0; i < all.length; i += DETAIL_CONCURRENCY) await Promise.all(all.slice(i, i + DETAIL_CONCURRENCY).map(vuln));

    const out = new Map<string, Vuln[]>();
    for (const [k, s] of ids) {
      const vs: Vuln[] = [];
      for (const id of s) {
        const v = await vuln(id);
        if (v) vs.push(v);
      }
      out.set(k, vs);
    }
    return out;
  }

  return { queryVulns, vuln };
}

const perFetch = new WeakMap<typeof fetch, OsvClient>();

/** queryVulns with the detail cache shared by every call using the same fetch (i.e. per run). */
export function queryVulns(f: typeof fetch, deps: Pick<Dep, 'eco' | 'name' | 'version'>[]): Promise<Map<string, Vuln[]>> {
  let c = perFetch.get(f);
  if (!c) perFetch.set(f, (c = createOsv(f)));
  return c.queryVulns(deps);
}
