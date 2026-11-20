import type { Fs } from './deps';
import { findLockfileTree, parseGoSum } from './lockfiles';

/** One installed package, for the dashboard's direct/transitive split. No URLs, hashes or secrets. */
export type SummaryDep = { eco: 'npm' | 'go'; name: string; version: string; direct: boolean; via: string[] };

export const MAX_VIA = 5;
/** The Worker rejects bodies over 1 MiB. */
export const MAX_SUMMARY_BYTES = 1024 * 1024;

type LockEntry = {
  name?: string;
  version?: string;
  resolved?: string;
  link?: boolean;
  inBundle?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'] as const;
const ROOT_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;

const NM = 'node_modules/';

function nameOf(key: string, e: LockEntry): string {
  return e.name ?? key.slice(key.lastIndexOf(NM) + NM.length);
}

/**
 * Where npm finds `dep` required from the package at `from`: `<dir>/node_modules/<dep>` for `from`
 * and then each ancestor directory, nearest first.
 */
function resolve(packages: Record<string, LockEntry>, from: string, dep: string): string | null {
  let dir = from;
  for (;;) {
    const candidate = dir === '' ? `${NM}${dep}` : `${dir}/${NM}${dep}`;
    if (packages[candidate]) return candidate;
    if (dir === '') return null;
    const i = dir.lastIndexOf('/');
    dir = i < 0 ? '' : dir.slice(0, i);
  }
}

/** Follows workspace/file links to the entry that carries the dependencies. */
function target(packages: Record<string, LockEntry>, key: string): string | null {
  const e = packages[key];
  if (!e) return null;
  if (e.link) return e.resolved !== undefined && packages[e.resolved] ? e.resolved : null;
  return key;
}

const byName = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * npm: direct = what the root package (`packages[""]`) lists in any dependency field; `via` = the direct
 * dependencies whose installed subtree contains the package, resolved through node_modules the npm way.
 */
export function summarizePackageLock(text: string): SummaryDep[] {
  const lock = JSON.parse(text) as { lockfileVersion?: number; packages?: Record<string, LockEntry> };
  if (!lock.packages || (lock.lockfileVersion ?? 1) < 2) throw new Error('regenerate package-lock.json with npm 7 or newer');
  const packages = lock.packages;
  const root = packages[''] ?? {};

  const rootDeps = new Set<string>();
  for (const f of ROOT_FIELDS) for (const d of Object.keys(root[f] ?? {})) rootDeps.add(d);

  // key of each direct dependency's entry (after links) → its real name
  const directKeys = new Map<string, string>();
  for (const d of rootDeps) {
    const k = resolve(packages, '', d);
    const t = k === null ? null : target(packages, k);
    if (k !== null && t !== null) directKeys.set(t, packages[k]!.link ? nameOf(k, packages[k]!) : nameOf(t, packages[t]!));
  }

  const via = new Map<string, Set<string>>();
  for (const [start, directName] of directKeys) {
    const seen = new Set<string>([start]);
    const queue = [start];
    while (queue.length > 0) {
      const at = queue.shift()!;
      const e = packages[at]!;
      for (const f of DEP_FIELDS) {
        for (const d of Object.keys(e[f] ?? {})) {
          const k = resolve(packages, at, d);
          const t = k === null ? null : target(packages, k);
          if (t === null || seen.has(t)) continue;
          seen.add(t);
          queue.push(t);
          let s = via.get(t);
          if (!s) via.set(t, (s = new Set()));
          s.add(directName);
        }
      }
    }
  }

  const out: SummaryDep[] = [];
  for (const [key, e] of Object.entries(packages)) {
    if (key === '' || e.link || e.inBundle || !key.includes(NM) || !e.version) continue;
    const name = nameOf(key, e);
    const direct = directKeys.has(key);
    const parents = [...(via.get(key) ?? [])].filter((n) => !(direct && n === name)).sort(byName);
    out.push({ eco: 'npm', name, version: e.version, direct, via: parents.slice(0, MAX_VIA) });
  }
  return out;
}

/** Module paths go.mod requires directly (no `// indirect`). */
function goDirect(goMod: string): Map<string, string> {
  const out = new Map<string, string>();
  let inBlock = false;
  for (const raw of goMod.split(/\r?\n/)) {
    const line = raw.trim();
    let spec: string | null = null;
    if (inBlock) {
      if (line.startsWith(')')) inBlock = false;
      else spec = line;
    } else if (/^require\s*\($/.test(line)) {
      inBlock = true;
    } else if (/^require\s+/.test(line)) {
      spec = line.replace(/^require\s+/, '');
    }
    if (!spec || spec.startsWith('//')) continue;
    const comment = spec.indexOf('//');
    const indirect = comment >= 0 && /^\/\/\s*indirect\b/.test(spec.slice(comment));
    const parts = (comment >= 0 ? spec.slice(0, comment) : spec).trim().split(/\s+/);
    if (parts.length !== 2 || indirect) continue;
    out.set(parts[0]!.replace(/^"|"$/g, ''), parts[1]!);
  }
  return out;
}

/** Go: direct = required in go.mod without `// indirect`; `via` is unknown without the toolchain. */
export function summarizeGo(goSum: string, goMod: string | null): SummaryDep[] {
  const direct = goMod === null ? new Map<string, string>() : goDirect(goMod);
  return parseGoSum(goSum, 'go.sum').map((d) => ({ eco: 'go', name: d.name, version: d.version, direct: direct.get(d.name) === d.version, via: [] }));
}

function merge(into: Map<string, SummaryDep>, deps: SummaryDep[]): void {
  for (const d of deps) {
    const k = `${d.eco}\0${d.name}\0${d.version}`;
    const cur = into.get(k);
    if (!cur) {
      into.set(k, { ...d, via: [...d.via] });
      continue;
    }
    cur.direct ||= d.direct;
    cur.via = [...new Set([...cur.via, ...d.via])].sort(byName).slice(0, MAX_VIA);
  }
}

/** Summarizes every package-lock.json and go.sum under `root` (symlinks are not followed). */
export async function dependencySummary(root: string, fs: Fs): Promise<{ deps: SummaryDep[]; warnings: string[] }> {
  const base = root.replace(/\/+$/, '');
  const tree = await findLockfileTree(base, fs);
  const all = new Map<string, SummaryDep>();
  const warnings: string[] = [];
  for (const rel of tree.files) {
    const abs = `${base}/${rel}`;
    try {
      if (rel.endsWith('go.sum')) {
        const modPath = `${abs.slice(0, -'go.sum'.length)}go.mod`;
        const goMod = (await fs.exists(modPath)) ? await fs.readFile(modPath) : null;
        merge(all, summarizeGo(await fs.readFile(abs), goMod));
      } else {
        merge(all, summarizePackageLock(await fs.readFile(abs)));
      }
    } catch (e) {
      warnings.push(`${rel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const deps = [...all.values()].sort((a, b) => byName(a.eco, b.eco) || byName(a.name, b.name) || byName(a.version, b.version));
  return { deps, warnings };
}

const size = (sha: string, deps: SummaryDep[]) => Buffer.byteLength(JSON.stringify({ sha, deps }));

/**
 * Keeps the request body under the Worker's 1 MiB limit: first drop every `via`, then keep only direct
 * dependencies. `trimmed` says which step was needed (null: none).
 */
export function capSummary(sha: string, deps: SummaryDep[]): { deps: SummaryDep[]; trimmed: null | 'via' | 'transitive' } {
  if (size(sha, deps) <= MAX_SUMMARY_BYTES) return { deps, trimmed: null };
  const noVia = deps.map((d) => ({ ...d, via: [] }));
  if (size(sha, noVia) <= MAX_SUMMARY_BYTES) return { deps: noVia, trimmed: 'via' };
  return { deps: noVia.filter((d) => d.direct), trimmed: 'transitive' };
}
