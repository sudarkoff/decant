import { describe, expect, it } from 'vitest';
import { filterPackument, type Packument } from '../src/npm/filter';

const T0 = '2026-01-01T00:00:00.000Z';
const T2 = '2026-02-01T00:00:00.000Z';
const T3 = '2026-03-01T00:00:00.000Z';
const T4 = '2026-04-01T00:00:00.000Z';
const BASE = 'https://h/npm';

function full(name = 'pkg'): Packument {
  const v = (version: string) => ({
    name,
    version,
    dist: { tarball: `https://registry.npmjs.org/${name}/-/${name.split('/').pop()}-${version}.tgz`, integrity: `sha512-${version}`, shasum: `sha-${version}` },
  });
  return {
    name,
    versions: { '1.0.0': v('1.0.0'), '2.0.0': v('2.0.0'), '1.0.1': v('1.0.1'), '3.0.0-beta.1': v('3.0.0-beta.1') },
    'dist-tags': { latest: '3.0.0-beta.1', next: '3.0.0-beta.1', legacy: '1.0.1' },
    time: { created: T0, modified: T4, '1.0.0': T0, '2.0.0': T2, '1.0.1': T3, '3.0.0-beta.1': T4 },
  };
}

describe('filterPackument', () => {
  const allowed = new Set(['1.0.0', '2.0.0', '1.0.1']);

  it('picks highest non-prerelease as latest, ignoring backport order and upstream latest', () => {
    const out = filterPackument(full(), allowed, BASE);
    expect(out['dist-tags']!.latest).toBe('2.0.0');
    expect(out['dist-tags']!.next).toBeUndefined();
    expect(out['dist-tags']!.legacy).toBe('1.0.1');
    expect(Object.keys(out.versions).sort()).toEqual(['1.0.0', '1.0.1', '2.0.0']);
  });

  it('prunes time, keeps created, sets modified to newest allowed', () => {
    const out = filterPackument(full(), allowed, BASE);
    expect(out.time!['3.0.0-beta.1']).toBeUndefined();
    expect(out.time!.created).toBe(T0);
    expect(out.time!.modified).toBe(T3);
  });

  it('empty allowed set yields empty versions and dist-tags', () => {
    const out = filterPackument(full(), new Set(), BASE);
    expect(out.versions).toEqual({});
    expect(out['dist-tags']).toEqual({});
    expect(out.time!.created).toBe(T0);
    expect(out.time!.modified).toBeUndefined();
  });

  it('falls back to highest prerelease for latest', () => {
    const out = filterPackument(full(), new Set(['3.0.0-beta.1']), BASE);
    expect(out['dist-tags']!.latest).toBe('3.0.0-beta.1');
  });

  it('rewrites scoped tarball, leaves integrity and shasum', () => {
    const out = filterPackument(full('@s/pkg'), allowed, BASE);
    expect(out.versions['1.0.0'].dist.tarball).toBe('https://h/npm/@s/pkg/-/pkg-1.0.0.tgz');
    expect(out.versions['1.0.0'].dist.integrity).toBe('sha512-1.0.0');
    expect(out.versions['1.0.0'].dist.shasum).toBe('sha-1.0.0');
  });

  it('skips unparseable versions for latest but may list them', () => {
    const doc = full();
    doc.versions['weird'] = { name: 'pkg', version: 'weird' };
    const out = filterPackument(doc, new Set(['weird', '1.0.0']), BASE);
    expect(out['dist-tags']!.latest).toBe('1.0.0');
    expect(out.versions['weird']).toBeDefined();
    expect(out.versions['weird'].dist).toBeUndefined();
  });

  it('handles abbreviated docs without time', () => {
    const doc = full();
    delete doc.time;
    doc.modified = T4;
    const out = filterPackument(doc, allowed, BASE);
    expect(out.time).toBeUndefined();
    expect(out.modified).toBe(T4);
    expect(out['dist-tags']!.latest).toBe('2.0.0');
  });

  it('does not mutate input', () => {
    const doc = full();
    const before = structuredClone(doc);
    filterPackument(doc, allowed, BASE);
    expect(doc).toEqual(before);
  });
});

describe('filterPackument: unpublished package', () => {
  it('does not throw when versions is missing; returns empty versions and dist-tags', () => {
    const doc = { name: 'gone', time: { created: T0, modified: T2, unpublished: { time: T2, versions: ['1.0.0'] } } } as unknown as Packument;
    const out = filterPackument(doc, new Set(['1.0.0']), BASE);
    expect(out.versions).toEqual({});
    expect(out['dist-tags']).toEqual({});
  });
});
