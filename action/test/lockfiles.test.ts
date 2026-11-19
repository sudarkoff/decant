import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { containsDecantUrls, diffDeps, findLockfiles, normalizeLockfile, parseGoSum, parsePackageLock, type Dep } from '../src/lockfiles';
import { memFs } from './fakes';

const fx = (n: string) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8');
const D = 'https://d.example';

describe('parsePackageLock', () => {
  const deps = parsePackageLock(fx('package-lock-v3.json'), 'package-lock.json', D);
  const by = (n: string) => deps.find((d) => d.name === n);
  it('names nested and scoped entries', () => {
    expect(by('b')?.version).toBe('1.0.0');
    expect(by('@s/p')?.version).toBe('2.0.0');
    expect(by('real')?.version).toBe('5.0.0');
  });
  it('skips root, link, inBundle, workspaces', () => {
    const names = deps.map((d) => d.name);
    expect(names).not.toContain('app');
    expect(names).not.toContain('ws');
    expect(names).not.toContain('bun');
  });
  it('classifies sources', () => {
    expect(by('g')?.source).toBe('other');
    expect(by('a')?.source).toBe('registry');
    expect(by('nores')?.source).toBe('registry');
    expect(by('d')?.source).toBe('registry');
    expect(parsePackageLock(fx('package-lock-v3.json'), 'f').find((d) => d.name === 'd')?.source).toBe('other');
  });
  it('rejects v1', () => {
    expect(() => parsePackageLock(fx('package-lock-v1.json'), 'f')).toThrow('regenerate package-lock.json with npm 7 or newer');
  });
});

describe('parseGoSum', () => {
  it('keeps module zips only, deduped, case preserved', () => {
    const deps = parseGoSum(fx('go.sum'), 'go.sum');
    expect(deps.map((d) => `${d.name}@${d.version}`)).toEqual(['github.com/Azure/go-sdk@v1.2.3', 'golang.org/x/net@v0.1.0']);
    expect(deps[0]).toMatchObject({ eco: 'go', file: 'go.sum', source: 'registry' });
  });
});

describe('diffDeps', () => {
  const mk = (name: string, version: string, file = 'f'): Dep => ({ eco: 'npm', name, version, file, source: 'registry' });
  it('returns new entries, deduped and sorted', () => {
    const r = diffDeps([mk('a', '1')], [mk('z', '1'), mk('a', '1', 'g'), mk('b', '2'), mk('b', '2', 'h')]);
    expect(r.map((d) => d.name)).toEqual(['b', 'z']);
  });
});

describe('normalizeLockfile', () => {
  it('rewrites resolved only, preserving bytes', () => {
    const t = `{\n  "x": {\n    "resolved":   "${D}/r/pr-3/npm/left-pad/-/left-pad-1.3.0.tgz",\n    "integrity": "${D}/npm/keep"\n  }\n}\n`;
    const r = normalizeLockfile(t, D);
    expect(r.changed).toBe(1);
    expect(r.text).toBe(t.replace(`${D}/r/pr-3/npm/`, 'https://registry.npmjs.org/'));
  });
  it('handles plain /npm/ and escapes regex metachars in url', () => {
    expect(normalizeLockfile('"resolved": "https://d.example/npm/a/-/a-1.tgz"', D).changed).toBe(1);
    expect(normalizeLockfile('"resolved": "https://dXexample/npm/a"', D).changed).toBe(0);
  });
  it('containsDecantUrls', () => {
    expect(containsDecantUrls(`"resolved": "${D}/npm/a"`, D)).toBe(true);
    expect(containsDecantUrls('"resolved": "https://registry.npmjs.org/a"', D)).toBe(false);
  });
});

describe('findLockfiles', () => {
  it('skips node_modules, .git, vendor; sorted relative', async () => {
    const fs = memFs({
      '/r/package-lock.json': '',
      '/r/go.sum': '',
      '/r/sub/go.sum': '',
      '/r/node_modules/x/package-lock.json': '',
      '/r/vendor/go.sum': '',
      '/r/.git/go.sum': '',
    });
    expect(await findLockfiles('/r', fs)).toEqual(['go.sum', 'package-lock.json', 'sub/go.sum']);
  });
});
