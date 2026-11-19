import { describe, expect, it } from 'vitest';
import type { Dep } from '../src/lockfiles';
import { createOsv, depKey, toVuln } from '../src/osv';
import { fakeFetch, jsonRes } from './fakes';

const dep = (eco: 'npm' | 'go', name: string, version: string): Dep => ({ eco, name, version, file: 'x', source: 'registry' });

const rec = (over: Record<string, unknown> = {}) => ({
  id: 'GHSA-aaaa-bbbb-cccc',
  aliases: ['CVE-2026-1'],
  summary: 's',
  affected: [{ package: { ecosystem: 'npm', name: 'a' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.4' }] }] }],
  ...over,
});

describe('Vuln', () => {
  it('fixedFor: introduced 0, fixed 1.2.4', () => {
    const v = toVuln(rec());
    expect(v.fixedFor('npm', 'a', '1.2.3')).toBe('1.2.4');
    expect(v.fixedFor('npm', 'a', '1.2.4')).toBeNull();
    expect(v.fixedFor('npm', 'other', '1.2.3')).toBeNull();
  });

  it('fixedFor picks the range covering the version', () => {
    const v = toVuln(
      rec({
        affected: [
          {
            package: { ecosystem: 'npm', name: 'a' },
            ranges: [
              { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.4' }] },
              { type: 'ECOSYSTEM', events: [{ introduced: '2.0.0' }, { fixed: '2.3.1' }] },
              { type: 'GIT', events: [{ introduced: '0' }, { fixed: 'deadbeef' }] },
            ],
          },
        ],
      }),
    );
    expect(v.fixedFor('npm', 'a', '2.1.0')).toBe('2.3.1');
    expect(v.fixedFor('npm', 'a', '1.0.0')).toBe('1.2.4');
    expect(v.fixedFor('npm', 'a', '1.5.0')).toBeNull();
    expect(v.affects('npm', 'a', '1.5.0')).toBe(false);
  });

  it('fixedFor compares Go versions with a leading v', () => {
    const v = toVuln(
      rec({ affected: [{ package: { ecosystem: 'Go', name: 'github.com/x/y' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.10.0' }, { fixed: '1.10.2' }] }] }] }),
    );
    expect(v.fixedFor('go', 'github.com/x/y', 'v1.10.1')).toBe('v1.10.2');
    expect(v.fixedFor('go', 'github.com/x/y', 'v1.9.0')).toBeNull();
  });

  it('versions list: listed version is affected with no fix', () => {
    const v = toVuln(rec({ affected: [{ package: { ecosystem: 'npm', name: 'a' }, versions: ['3.0.0'] }] }));
    expect(v.affects('npm', 'a', '3.0.0')).toBe(true);
    expect(v.fixedFor('npm', 'a', '3.0.0')).toBeNull();
  });

  it('open-ended or last_affected ranges affect without a fix', () => {
    const v = toVuln(rec({ affected: [{ package: { ecosystem: 'npm', name: 'a' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { last_affected: '1.4.0' }] }] }] }));
    expect(v.affects('npm', 'a', '1.4.0')).toBe(true);
    expect(v.fixedFor('npm', 'a', '1.4.0')).toBeNull();
    expect(v.affects('npm', 'a', '1.4.1')).toBe(false);
  });

  it('GHSA MODERATE → moderate; missing → unknown', () => {
    expect(toVuln(rec({ database_specific: { severity: 'MODERATE' } })).severity).toBe('moderate');
    expect(toVuln(rec({ database_specific: { severity: 'CRITICAL' } })).severity).toBe('critical');
    expect(toVuln(rec()).severity).toBe('unknown');
  });

  it('MAL- ids are malicious', () => {
    expect(toVuln(rec({ id: 'MAL-2025-1' })).malicious).toBe(true);
    expect(toVuln(rec()).malicious).toBe(false);
  });
});

describe('queryVulns', () => {
  it('batches, strips Go v, fetches details once per unique id, keys by depKey', async () => {
    const f = fakeFetch((c) => {
      if (c.url === 'https://api.osv.dev/v1/querybatch') {
        const qs = JSON.parse(c.body!).queries as unknown[];
        return jsonRes({ results: qs.map(() => ({ vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }] })) });
      }
      if (c.url === 'https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc') return jsonRes(rec());
    });
    const osv = createOsv(f);
    const deps = [dep('npm', 'a', '1.0.0'), dep('npm', 'a', '1.0.0'), dep('go', 'github.com/x/y', 'v1.0.0')];
    const m = await osv.queryVulns(deps);
    const body = JSON.parse(f.calls[0]!.body!);
    expect(body.queries).toEqual([
      { package: { ecosystem: 'npm', name: 'a' }, version: '1.0.0' },
      { package: { ecosystem: 'Go', name: 'github.com/x/y' }, version: '1.0.0' },
    ]);
    expect(m.get(depKey(deps[0]!))!.map((v) => v.id)).toEqual(['GHSA-aaaa-bbbb-cccc']);
    expect(m.get('go:github.com/x/y@v1.0.0')!.length).toBe(1);
    await osv.queryVulns([dep('npm', 'b', '1.0.0')]);
    expect(f.calls.filter((c) => c.url.includes('/v1/vulns/')).length).toBe(1);
    expect(f.calls.every((c) => c.signal instanceof AbortSignal)).toBe(true);
  });

  it('chunks queries at 1000', async () => {
    const f = fakeFetch((c) => jsonRes({ results: (JSON.parse(c.body!).queries as unknown[]).map(() => ({})) }));
    const deps = Array.from({ length: 1001 }, (_, i) => dep('npm', `p${i}`, '1.0.0'));
    const m = await createOsv(f).queryVulns(deps);
    expect(f.calls.length).toBe(2);
    expect(m.get('npm:p1000@1.0.0')).toEqual([]);
  });

  it('throws when OSV fails', async () => {
    await expect(createOsv(fakeFetch(() => new Response('x', { status: 503 }))).queryVulns([dep('npm', 'a', '1.0.0')])).rejects.toThrow(/OSV/);
  });
});
