import type { Fs } from './deps';

export type Dep = {
  eco: 'npm' | 'go';
  name: string;
  version: string;
  file: string;
  source: 'registry' | 'other';
  resolved?: string;
  integrity?: string;
  mismatch?: boolean;
};

const NPM_REGISTRY = 'https://registry.npmjs.org/';
const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor']);
const LOCKFILES = new Set(['package-lock.json', 'go.sum']);

export type LockfileTree = {
  /** Regular lockfiles, relative to root, sorted. */
  files: string[];
  /** Symlinks never read through: lockfile-named entries and directories (outside skipped dirs). */
  symlinks: { path: string; dir: boolean }[];
};

/**
 * Walks `root` for package-lock.json / go.sum without following symlinks. Symlinked lockfiles and
 * symlinked directories are reported, so a caller that gates on lockfiles can refuse them (npm ci
 * and go follow symlinks; this walker does not).
 */
export async function findLockfileTree(root: string, fs: Fs): Promise<LockfileTree> {
  const files: string[] = [];
  const symlinks: { path: string; dir: boolean }[] = [];
  const base = root.replace(/\/+$/, '');
  async function walk(rel: string): Promise<void> {
    const entries = await fs.readdir(rel ? `${base}/${rel}` : base);
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymlink) {
        if (e.isDir || LOCKFILES.has(e.name)) symlinks.push({ path: r, dir: e.isDir });
        continue;
      }
      if (e.isDir) {
        if (!SKIP_DIRS.has(e.name)) await walk(r);
      } else if (LOCKFILES.has(e.name)) {
        files.push(r);
      }
    }
  }
  await walk('');
  const byPath = (a: { path: string }, b: { path: string }) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return { files: files.sort(), symlinks: symlinks.sort(byPath) };
}

export async function findLockfiles(root: string, fs: Fs): Promise<string[]> {
  return (await findLockfileTree(root, fs)).files;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
}

function decantPrefix(decantUrl: string): RegExp {
  return new RegExp(`^${escapeRe(decantUrl.replace(/\/+$/, ''))}(/r/[A-Za-z0-9._-]{1,64})?/npm/`);
}

type LockEntry = { integrity?: string; name?: string; version?: string; resolved?: string; link?: boolean; inBundle?: boolean };

function tarballMatches(resolved: string, name: string, version: string): boolean {
  let path: string;
  try {
    path = decodeURIComponent(new URL(resolved).pathname);
  } catch {
    return false;
  }
  const base = name.slice(name.lastIndexOf('/') + 1);
  return path === `/${name}/-/${base}-${version}.tgz`;
}

export function parsePackageLock(text: string, file: string, decantUrl?: string): Dep[] {
  const lock = JSON.parse(text) as { lockfileVersion?: number; packages?: Record<string, LockEntry> };
  if (!lock.packages || (lock.lockfileVersion ?? 1) < 2) {
    throw new Error('regenerate package-lock.json with npm 7 or newer');
  }
  const prefix = decantUrl ? decantPrefix(decantUrl) : null;
  const deps: Dep[] = [];
  for (const [key, entry] of Object.entries(lock.packages)) {
    if (key === '' || entry.link || entry.inBundle) continue;
    const idx = key.lastIndexOf('node_modules/');
    if (idx < 0) continue; // workspace package
    const name = entry.name ?? key.slice(idx + 'node_modules/'.length);
    const resolved = entry.resolved;
    const registry = !!entry.version && (resolved === undefined || resolved.startsWith(NPM_REGISTRY) || (prefix?.test(resolved) ?? false));
    const dep: Dep = { eco: 'npm', name, version: entry.version ?? '', file, source: registry ? 'registry' : 'other' };
    // decant URLs are stored normalized so diffs never see normalization as a change
    if (resolved !== undefined) dep.resolved = prefix ? resolved.replace(prefix, NPM_REGISTRY) : resolved;
    if (entry.integrity !== undefined) dep.integrity = entry.integrity;
    if (dep.source === 'registry' && dep.resolved !== undefined && !tarballMatches(dep.resolved, name, dep.version)) {
      dep.source = 'other';
      dep.mismatch = true;
    }
    deps.push(dep);
  }
  return deps;
}

export function parseGoSum(text: string, file: string): Dep[] {
  const seen = new Set<string>();
  const deps: Dep[] = [];
  for (const line of text.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length !== 3) continue;
    const [name, version, hash] = parts as [string, string, string];
    if (version.endsWith('/go.mod') || !version.startsWith('v') || !hash.startsWith('h1:')) continue;
    const k = `${name}@${version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    deps.push({ eco: 'go', name, version, file, source: 'registry' });
  }
  return deps;
}

const key = (d: Dep) =>
  d.eco === 'npm'
    ? `npm:${d.name}@${d.version}|${d.source}|${d.resolved ?? ''}|${d.integrity ?? ''}`
    : `${d.eco}:${d.name}@${d.version}`;

export function diffDeps(base: Dep[], head: Dep[]): Dep[] {
  const have = new Set(base.map(key));
  const out = new Map<string, Dep>();
  for (const d of head) {
    const k = key(d);
    if (!have.has(k) && !out.has(k)) out.set(k, d);
  }
  return [...out].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, d]) => d);
}

function resolvedRe(decantUrl: string): RegExp {
  return new RegExp(`("resolved"\\s*:\\s*")${escapeRe(decantUrl.replace(/\/+$/, ''))}(?:/r/[A-Za-z0-9._-]{1,64})?/npm/`, 'g');
}

export function normalizeLockfile(text: string, decantUrl: string): { text: string; changed: number } {
  let changed = 0;
  const out = text.replace(resolvedRe(decantUrl), (_m, head: string) => {
    changed++;
    return `${head}${NPM_REGISTRY}`;
  });
  return { text: out, changed };
}

export function containsDecantUrls(text: string, decantUrl: string): boolean {
  return new RegExp(resolvedRe(decantUrl).source).test(text);
}
