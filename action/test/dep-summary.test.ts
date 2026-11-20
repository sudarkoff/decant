import { describe, expect, it } from 'vitest';
import { capSummary, dependencySummary, MAX_SUMMARY_BYTES, summarizeGo, summarizePackageLock, type SummaryDep } from '../src/dep-summary';
import { memFs } from './fakes';

const reg = (name: string, version: string, extra: Record<string, unknown> = {}) => ({
  version,
  resolved: `https://registry.npmjs.org/${name}/-/${name.slice(name.lastIndexOf('/') + 1)}-${version}.tgz`,
  ...extra,
});

const LOCK = JSON.stringify({
  name: 'app',
  lockfileVersion: 3,
  packages: {
    '': {
      name: 'app',
      dependencies: { a: '^1', '@s/p': '^2', alias: 'npm:real@^5' },
      devDependencies: { t: '^1' },
      optionalDependencies: { o: '^1' },
      peerDependencies: { pe: '^1' },
    },
    'node_modules/a': reg('a', '1.0.0', { dependencies: { b: '^1', c: '^1' } }),
    // a's own b (nested) shadows the hoisted b@2
    'node_modules/a/node_modules/b': reg('b', '1.0.0', { dependencies: { d: '^1' } }),
    'node_modules/b': reg('b', '2.0.0'),
    'node_modules/c': reg('c', '1.0.0'),
    'node_modules/d': reg('d', '1.0.0'),
    'node_modules/@s/p': reg('@s/p', '2.0.0', { dependencies: { '@s/q': '^1', c: '^1' } }),
    'node_modules/@s/q': reg('@s/q', '1.0.0'),
    'node_modules/alias': reg('real', '5.0.0', { name: 'real' }),
    'node_modules/t': reg('t', '1.0.0', { dev: true, dependencies: { b: '^2' } }),
    'node_modules/o': reg('o', '1.0.0', { optional: true }),
    'node_modules/pe': reg('pe', '1.0.0', { peer: true }),
    'node_modules/bun': reg('bun', '3.0.0', { inBundle: true }),
    'node_modules/orphan': reg('orphan', '1.0.0'),
  },
});

const byKey = (deps: SummaryDep[]) => new Map(deps.map((d) => [`${d.name}@${d.version}`, d]));

describe('summarizePackageLock', () => {
  const m = byKey(summarizePackageLock(LOCK));

  it('marks root dependencies of every kind as direct, by their real name', () => {
    for (const k of ['a@1.0.0', '@s/p@2.0.0', 'real@5.0.0', 't@1.0.0', 'o@1.0.0', 'pe@1.0.0']) expect(m.get(k)?.direct, k).toBe(true);
    for (const k of ['b@1.0.0', 'b@2.0.0', 'c@1.0.0', 'd@1.0.0', '@s/q@1.0.0', 'orphan@1.0.0']) expect(m.get(k)?.direct, k).toBe(false);
  });

  it('resolves via through nested node_modules the npm way (nearest first)', () => {
    expect(m.get('b@1.0.0')?.via).toEqual(['a']); // a/node_modules/b, not the hoisted one
    expect(m.get('d@1.0.0')?.via).toEqual(['a']); // a → b@1 → d (walks up from a/node_modules/b)
    expect(m.get('b@2.0.0')?.via).toEqual(['t']); // only t reaches the hoisted b
  });

  it('collects every direct parent, scoped names included, sorted', () => {
    expect(m.get('c@1.0.0')?.via).toEqual(['@s/p', 'a']);
    expect(m.get('@s/q@1.0.0')?.via).toEqual(['@s/p']);
  });

  it('unreachable packages have empty via; bundled packages are skipped; npm only', () => {
    expect(m.get('orphan@1.0.0')?.via).toEqual([]);
    expect(m.has('bun@3.0.0')).toBe(false);
    expect([...m.values()].every((d) => d.eco === 'npm')).toBe(true);
  });

  it('a direct dep does not list itself in via', () => {
    expect(m.get('a@1.0.0')?.via).toEqual([]);
  });

  it('caps via at 5 names', () => {
    const roots = Object.fromEntries(['p1', 'p2', 'p3', 'p4', 'p5', 'p6'].map((n) => [n, '^1']));
    const pkgs: Record<string, unknown> = { '': { dependencies: roots }, 'node_modules/shared': reg('shared', '1.0.0') };
    for (const n of Object.keys(roots)) pkgs[`node_modules/${n}`] = reg(n, '1.0.0', { dependencies: { shared: '^1' } });
    const s = byKey(summarizePackageLock(JSON.stringify({ lockfileVersion: 3, packages: pkgs })));
    expect(s.get('shared@1.0.0')?.via).toEqual(['p1', 'p2', 'p3', 'p4', 'p5']);
  });

  it('follows workspace links from the root', () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { ws: '*' } },
        'packages/ws': { name: 'ws', version: '0.0.1', dependencies: { x: '^1' } },
        'node_modules/ws': { resolved: 'packages/ws', link: true },
        'node_modules/x': reg('x', '1.0.0'),
      },
    };
    expect(byKey(summarizePackageLock(JSON.stringify(lock))).get('x@1.0.0')?.via).toEqual(['ws']);
  });

  it('rejects v1 lockfiles', () => {
    expect(() => summarizePackageLock(JSON.stringify({ lockfileVersion: 1, dependencies: {} }))).toThrow('npm 7');
  });
});

describe('summarizeGo', () => {
  const GOMOD = `module example.com/app

go 1.22

require github.com/one/direct v1.0.0

require (
\tgithub.com/two/direct v2.0.0 // pinned
\tgolang.org/x/net v0.1.0 // indirect
)
`;
  const GOSUM = [
    'github.com/one/direct v1.0.0 h1:a=',
    'github.com/one/direct v1.0.0/go.mod h1:b=',
    'github.com/two/direct v2.0.0 h1:c=',
    'golang.org/x/net v0.1.0 h1:d=',
    'golang.org/x/text v0.3.0 h1:e=',
  ].join('\n');

  it('direct = required without // indirect; via is always empty', () => {
    const m = byKey(summarizeGo(GOSUM, GOMOD));
    expect(m.get('github.com/one/direct@v1.0.0')).toEqual({ eco: 'go', name: 'github.com/one/direct', version: 'v1.0.0', direct: true, via: [] });
    expect(m.get('github.com/two/direct@v2.0.0')?.direct).toBe(true);
    expect(m.get('golang.org/x/net@v0.1.0')?.direct).toBe(false);
    expect(m.get('golang.org/x/text@v0.3.0')?.direct).toBe(false);
  });

  it('without go.mod nothing is direct', () => {
    expect(summarizeGo(GOSUM, null).every((d) => !d.direct)).toBe(true);
  });
});

describe('dependencySummary', () => {
  it('walks the tree, reads go.mod next to go.sum, merges duplicates (direct wins, via unioned)', async () => {
    const lock2 = JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { dependencies: { c: '^1' } }, 'node_modules/c': reg('c', '1.0.0') },
    });
    const fs = memFs({
      '/r/package-lock.json': LOCK,
      '/r/web/package-lock.json': lock2,
      '/r/svc/go.sum': 'golang.org/x/net v0.1.0 h1:d=\n',
      '/r/svc/go.mod': 'module m\n\nrequire golang.org/x/net v0.1.0\n',
      '/r/node_modules/z/package-lock.json': '{}',
    });
    const { deps, warnings } = await dependencySummary('/r', fs);
    expect(warnings).toEqual([]);
    const m = byKey(deps);
    expect(m.get('c@1.0.0')).toEqual({ eco: 'npm', name: 'c', version: '1.0.0', direct: true, via: ['@s/p', 'a'] });
    expect(m.get('golang.org/x/net@v0.1.0')?.direct).toBe(true);
  });

  it('a bad lockfile is a warning, not a failure', async () => {
    const fs = memFs({ '/r/package-lock.json': 'nope', '/r/a/package-lock.json': LOCK });
    const { deps, warnings } = await dependencySummary('/r', fs);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('package-lock.json');
    expect(deps.length).toBeGreaterThan(0);
  });
});

describe('capSummary', () => {
  const dep = (i: number, direct: boolean): SummaryDep => ({
    eco: 'npm',
    name: `pkg-${'x'.repeat(150)}-${i}`,
    version: '1.0.0',
    direct,
    via: direct ? [] : ['a'.repeat(200), 'b'.repeat(200), 'c'.repeat(200), 'd'.repeat(200), 'e'.repeat(200)],
  });

  it('keeps a small summary as is', () => {
    const deps = [dep(1, true), dep(2, false)];
    expect(capSummary('sha', deps)).toEqual({ deps, trimmed: null });
  });

  it('over 1 MB: drops via first', () => {
    const deps = Array.from({ length: 1200 }, (_, i) => dep(i, i % 10 === 0));
    const r = capSummary('sha', deps);
    expect(r.trimmed).toBe('via');
    expect(r.deps).toHaveLength(1200);
    expect(r.deps.every((d) => d.via.length === 0)).toBe(true);
    expect(Buffer.byteLength(JSON.stringify({ sha: 'sha', deps: r.deps }))).toBeLessThanOrEqual(MAX_SUMMARY_BYTES);
  });

  it('still over 1 MB: direct only', () => {
    const deps = Array.from({ length: 6000 }, (_, i) => dep(i, i % 100 === 0));
    const r = capSummary('sha', deps);
    expect(r.trimmed).toBe('transitive');
    expect(r.deps).toHaveLength(60);
    expect(r.deps.every((d) => d.direct)).toBe(true);
  });
});
