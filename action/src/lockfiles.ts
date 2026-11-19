import type { Fs } from './deps';

export type Dep = {
  eco: 'npm' | 'go';
  name: string;
  version: string;
  file: string;
  source: 'registry' | 'other';
  resolved?: string;
};

const NPM_REGISTRY = 'https://registry.npmjs.org/';
const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor']);
const LOCKFILES = new Set(['package-lock.json', 'go.sum']);

export async function findLockfiles(root: string, fs: Fs): Promise<string[]> {
  const out: string[] = [];
  const base = root.replace(/\/+$/, '');
  async function walk(rel: string): Promise<void> {
    const entries = await fs.readdir(rel ? `${base}/${rel}` : base);
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDir) {
        if (!SKIP_DIRS.has(e.name)) await walk(r);
      } else if (LOCKFILES.has(e.name)) {
        out.push(r);
      }
    }
  }
  await walk('');
  return out.sort();
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
}

function decantPrefix(decantUrl: string): RegExp {
  return new RegExp(`^${escapeRe(decantUrl.replace(/\/+$/, ''))}(/r/[A-Za-z0-9._-]{1,64})?/npm/`);
}

type LockEntry = { name?: string; version?: string; resolved?: string; link?: boolean; inBundle?: boolean };

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
    if (!entry.version) continue;
    const name = entry.name ?? key.slice(idx + 'node_modules/'.length);
    const resolved = entry.resolved;
    const registry = resolved === undefined || resolved.startsWith(NPM_REGISTRY) || (prefix?.test(resolved) ?? false);
    const dep: Dep = { eco: 'npm', name, version: entry.version, file, source: registry ? 'registry' : 'other' };
    if (resolved !== undefined) dep.resolved = resolved;
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

const key = (d: Dep) => `${d.eco}:${d.name}@${d.version}`;

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
