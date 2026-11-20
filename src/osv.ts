import { formatPackageId, type Deps, type Ecosystem, type PackageRef } from './types';
import type { Severity } from './policy/schema';
import { upstreamTimeout } from './upstream';
import { severityOf } from './vuln-severity';

const OSV = 'https://api.osv.dev';
const OSV_ECO: Record<Ecosystem, string> = { npm: 'npm', go: 'Go' };
const MAX_PAGES = 10;
const BATCH_SIZE = 1000; // OSV querybatch limit

export type AdvisoryCheck = 'verified' | 'not-fixed' | 'unknown-advisory' | 'unavailable';

class Unavailable extends Error {}

interface OsvVuln {
  id?: string;
  aliases?: string[];
  published?: string;
  summary?: string;
  database_specific?: { severity?: unknown };
  severity?: { type?: string; score?: string }[];
  affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { type?: string; events?: { fixed?: unknown }[] }[] }[];
}

const MAX_FIXED = 50;

/**
 * Every "fixed" event per package ("eco:name") in an OSV record, from SEMVER and ECOSYSTEM ranges
 * (GIT ranges hold commit hashes). Go versions get the 'v' the module proxy uses. At most MAX_FIXED per package.
 */
function fixedVersions(v: OsvVuln): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const a of Array.isArray(v.affected) ? v.affected : []) {
    const eco = (Object.keys(OSV_ECO) as Ecosystem[]).find((k) => OSV_ECO[k] === a?.package?.ecosystem);
    const name = a?.package?.name;
    if (!eco || typeof name !== 'string') continue;
    const list = (out[`${eco}:${name}`] ??= []);
    for (const r of Array.isArray(a.ranges) ? a.ranges : []) {
      if (r?.type === 'GIT' || !Array.isArray(r?.events)) continue;
      for (const ev of r.events) {
        if (typeof ev?.fixed !== 'string' || ev.fixed === '' || ev.fixed.length > 100) continue;
        const f = eco === 'go' && !ev.fixed.startsWith('v') ? `v${ev.fixed}` : ev.fixed;
        if (!list.includes(f) && list.length < MAX_FIXED) list.push(f);
      }
    }
  }
  return out;
}

function osvQuery(ref: PackageRef): { package: { name: string; ecosystem: string }; version: string } {
  // OSV's Go ecosystem uses versions without the leading 'v'.
  const version = ref.eco === 'go' ? ref.version.replace(/^v/, '') : ref.version;
  return { package: { name: ref.name, ecosystem: OSV_ECO[ref.eco] }, version };
}

/**
 * Network error, timeout, 5xx or 429 → Unavailable. Returns the response otherwise (caller checks other statuses).
 * The timeout also covers reading the body, so a stalled body fails in okJson as Unavailable.
 */
async function osvFetch(deps: Deps, path: string, body?: unknown): Promise<Response> {
  const signal = AbortSignal.timeout(upstreamTimeout(deps));
  let res: Response;
  try {
    res = await deps.fetch(
      `${OSV}${path}`,
      body === undefined
        ? { method: 'GET', signal }
        : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal },
    );
  } catch {
    throw new Unavailable();
  }
  if (res.status >= 500 || res.status === 429) throw new Unavailable();
  return res;
}

async function okJson<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Unavailable();
  try {
    return (await res.json()) as T;
  } catch {
    throw new Unavailable();
  }
}

/**
 * Confirms that `advisory` covers ref.name in ref's ecosystem and that ref.version is NOT affected by it.
 * A CVE id that OSV does not index directly 404s → 'unknown-advisory' (cite the GHSA instead).
 */
export async function verifyAdvisoryFix(
  deps: Deps,
  advisory: string,
  ref: PackageRef,
): Promise<{ result: AdvisoryCheck; published: string | null }> {
  let published: string | null = null;
  const done = (result: AdvisoryCheck) => ({ result, published });
  try {
    const res = await osvFetch(deps, `/v1/vulns/${encodeURIComponent(advisory)}`);
    if (res.status >= 400 && res.status < 500) return done('unknown-advisory');
    const vuln = await okJson<OsvVuln>(res);
    published = typeof vuln.published === 'string' ? vuln.published : null;
    const eco = OSV_ECO[ref.eco];
    const lists = (vuln.affected ?? []).some((a) => a.package?.ecosystem === eco && a.package?.name === ref.name);
    if (!lists) return done('unknown-advisory');

    // Match the advisory under any of its names: the cited id, OSV's canonical id and its aliases
    // (e.g. a cited GHSA can come back from /v1/query as its GO- alias).
    const ids = new Set([advisory, ...(vuln.id ? [vuln.id] : []), ...(vuln.aliases ?? [])]);
    let pageToken: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const q = { ...osvQuery(ref), ...(pageToken ? { page_token: pageToken } : {}) };
      const r = await okJson<{ vulns?: OsvVuln[]; next_page_token?: string }>(await osvFetch(deps, '/v1/query', q));
      const hit = (r.vulns ?? []).some((v) => (v.id !== undefined && ids.has(v.id)) || (v.aliases ?? []).some((a) => ids.has(a)));
      if (hit) return done('not-fixed');
      if (!r.next_page_token) return done('verified');
      pageToken = r.next_page_token;
    }
    return done('unavailable'); // too many pages to be sure: fail closed
  } catch (err) {
    if (err instanceof Unavailable) return done('unavailable');
    throw err;
  }
}

/** `fixed`: fixed versions per package ("eco:name") listed in the record; see fixedVersions. */
export interface VulnDetails { severity: Severity | 'unknown'; summary: string; published: string | null; fixed: Record<string, string[]> }

/** packageId → all advisory IDs, for refs with at least one. null if OSV is unavailable. */
export async function vulnIds(deps: Deps, refs: PackageRef[]): Promise<Map<string, string[]> | null> {
  const out = new Map<string, string[]>();
  try {
    for (let i = 0; i < refs.length; i += BATCH_SIZE) {
      // Pending queries: index into refs + optional page token.
      let pending: { ref: PackageRef; token?: string }[] = refs.slice(i, i + BATCH_SIZE).map((ref) => ({ ref }));
      for (let page = 0; pending.length > 0; page++) {
        if (page >= MAX_PAGES) return null;
        const queries = pending.map((p) => ({ ...osvQuery(p.ref), ...(p.token ? { page_token: p.token } : {}) }));
        const r = await okJson<{ results?: { vulns?: OsvVuln[]; next_page_token?: string }[] }>(
          await osvFetch(deps, '/v1/querybatch', { queries }),
        );
        const results = r.results ?? [];
        if (results.length !== pending.length) return null;
        const next: typeof pending = [];
        results.forEach((res, j) => {
          const ref = pending[j]!.ref;
          const ids = (res.vulns ?? []).map((v) => v.id).filter((id): id is string => !!id);
          if (ids.length > 0) {
            const key = formatPackageId(ref);
            out.set(key, [...new Set([...(out.get(key) ?? []), ...ids])]);
          }
          if (res.next_page_token) next.push({ ref, token: res.next_page_token });
        });
        pending = next;
      }
    }
    return out;
  } catch (err) {
    if (err instanceof Unavailable) return null;
    throw err;
  }
}

/** packageId → MAL- advisory IDs, for refs with at least one. null if OSV is unavailable. */
export async function maliciousIds(deps: Deps, refs: PackageRef[]): Promise<Map<string, string[]> | null> {
  const all = await vulnIds(deps, refs);
  if (all === null) return null;
  const out = new Map<string, string[]>();
  for (const [key, ids] of all) {
    const mal = ids.filter((id) => id.startsWith('MAL-'));
    if (mal.length > 0) out.set(key, mal);
  }
  return out;
}

/**
 * Severity, summary (first 200 chars) and publish time of one OSV record (empty details if OSV 404s); null if OSV is unavailable.
 * Successful lookups are memoised in `cache`, which the caller scopes to one run.
 */
export async function vulnDetails(deps: Deps, id: string, cache?: Map<string, VulnDetails>): Promise<VulnDetails | null> {
  const hit = cache?.get(id);
  if (hit) return hit;
  try {
    const res = await osvFetch(deps, `/v1/vulns/${encodeURIComponent(id)}`);
    // A record OSV does not have (4xx) is a settled answer: empty details, so it is never re-fetched.
    const v = res.status >= 400 && res.status < 500 ? {} : await okJson<OsvVuln>(res);
    const d: VulnDetails = {
      severity: severityOf(v),
      summary: typeof v.summary === 'string' ? v.summary.slice(0, 200) : '',
      published: typeof v.published === 'string' ? v.published : null,
      fixed: fixedVersions(v),
    };
    cache?.set(id, d);
    return d;
  } catch (err) {
    if (err instanceof Unavailable) return null;
    throw err;
  }
}
