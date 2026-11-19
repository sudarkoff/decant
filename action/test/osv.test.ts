import { describe, expect, it } from 'vitest';
import type { Dep } from '../src/lockfiles';
import { createOsv, cvss31BaseScore, depKey, mergeAliases, toVuln } from '../src/osv';
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

describe('review fixes: severity', () => {
  it('cvss31BaseScore matches known vectors', () => {
    expect(cvss31BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
    expect(cvss31BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
    expect(cvss31BaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N')).toBe(4.3);
    expect(cvss31BaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')).toBe(6.4);
    expect(cvss31BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(0);
    expect(cvss31BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    expect(cvss31BaseScore('garbage')).toBeNull();
  });

  it('a CVSS v3 vector sets severity when no GHSA severity', () => {
    const v = toVuln(rec({ id: 'GO-2026-1', aliases: [], severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }));
    expect(v.severity).toBe('critical');
    const low = toVuln(rec({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N' }] }));
    expect(low.severity).toBe('low');
  });

  it('takes the max of database_specific and CVSS', () => {
    const v = toVuln(rec({ database_specific: { severity: 'LOW' }, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N' }] }));
    expect(v.severity).toBe('moderate');
  });

  it('a GO- record takes severity from its GHSA alias, and alias groups merge into one GHSA-id Vuln', async () => {
    const go = {
      id: 'GO-2026-1',
      aliases: ['GHSA-xxxx-yyyy-zzzz', 'CVE-2026-9'],
      summary: 'go summary',
      affected: [{ package: { ecosystem: 'Go', name: 'github.com/x/y' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.0' }] }] }],
    };
    const ghsa = {
      id: 'GHSA-xxxx-yyyy-zzzz',
      aliases: ['CVE-2026-9'],
      summary: 'ghsa summary',
      database_specific: { severity: 'CRITICAL' },
      affected: [{ package: { ecosystem: 'Go', name: 'github.com/x/y' } }],
    };
    const f = fakeFetch((c) => {
      if (c.url.endsWith('/querybatch')) return jsonRes({ results: [{ vulns: [{ id: 'GO-2026-1' }, { id: 'GHSA-xxxx-yyyy-zzzz' }] }, { vulns: [{ id: 'GO-2026-1' }] }] });
      if (c.url.endsWith('/GO-2026-1')) return jsonRes(go);
      if (c.url.endsWith('/GHSA-xxxx-yyyy-zzzz')) return jsonRes(ghsa);
    });
    const m = await createOsv(f).queryVulns([dep('go', 'github.com/x/y', 'v1.0.0'), dep('go', 'github.com/x/z', 'v1.0.0')]);
    const both = m.get('go:github.com/x/y@v1.0.0')!;
    expect(both.length).toBe(1);
    expect(both[0]!.id).toBe('GHSA-xxxx-yyyy-zzzz');
    expect(new Set(both[0]!.aliases)).toEqual(new Set(['GO-2026-1', 'CVE-2026-9']));
    expect(both[0]!.severity).toBe('critical');
    expect(both[0]!.fixedFor('go', 'github.com/x/y', 'v1.0.0')).toBe('v1.2.0');
    // only GO- returned for this dep, but severity is still resolved via the cached GHSA alias
    const goOnly = m.get('go:github.com/x/z@v1.0.0')!;
    expect(goOnly.map((v) => [v.id, v.severity])).toEqual([['GO-2026-1', 'critical']]);
    expect(f.calls.filter((c) => c.url.endsWith('/GHSA-xxxx-yyyy-zzzz')).length).toBe(1);
  });
});

describe('review fixes: merged fixedFor', () => {
  it('returns the highest fixed version across an alias group', () => {
    const range = (fixed: string) => [{ package: { ecosystem: 'npm', name: 'a' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed }] }] }];
    const merged = mergeAliases([
      toVuln(rec({ id: 'GHSA-1111-1111-1111', aliases: ['CVE-2026-5'], affected: range('1.2.0') })),
      toVuln(rec({ id: 'GHSA-2222-2222-2222', aliases: ['CVE-2026-5'], affected: range('1.5.0') })),
    ]);
    expect(merged.length).toBe(1);
    expect(merged[0]!.fixedFor('npm', 'a', '1.0.0')).toBe('1.5.0');
  });
});

describe('review fixes: unparseable versions', () => {
  it('an unparseable version is not covered by ranges, but an exact versions[] match is', () => {
    const v = toVuln(
      rec({ affected: [{ package: { ecosystem: 'npm', name: 'a' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.4' }] }], versions: ['weird-1'] }] }),
    );
    expect(v.affects('npm', 'a', 'not-a-version')).toBe(false);
    expect(v.fixedFor('npm', 'a', 'not-a-version')).toBeNull();
    expect(v.affects('npm', 'a', 'weird-1')).toBe(true);
    expect(v.fixedFor('npm', 'a', 'weird-1')).toBeNull();
  });
});

describe('review fix: querybatch fails closed', () => {
  it('throws on a 200 with missing results or fewer results than queries', async () => {
    const deps = [
      { eco: 'npm' as const, name: 'a', version: '1.0.0' },
      { eco: 'npm' as const, name: 'b', version: '1.0.0' },
    ];
    await expect(createOsv(fakeFetch(() => jsonRes({}))).queryVulns(deps)).rejects.toThrow(/OSV/);
    await expect(createOsv(fakeFetch(() => jsonRes({ results: [{}] }))).queryVulns(deps)).rejects.toThrow(/OSV/);
  });
});
