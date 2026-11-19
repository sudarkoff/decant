import { describe, expect, it } from 'vitest';
import { maliciousIds, verifyAdvisoryFix } from '../src/osv';
import { fakeFetch, fixedClock, hang } from './helpers';
import type { PackageRef } from '../src/types';

const now = fixedClock('2026-11-19T00:00:00Z');
const OSV = 'https://api.osv.dev';
const ref: PackageRef = { eco: 'npm', name: 'lodash', version: '4.17.21' };
const ghsa = 'GHSA-35jh-r3h4-6jhm';

const vuln = (eco: string, name: string, id = ghsa, aliases: string[] = []) =>
  Response.json({ id, aliases, affected: [{ package: { ecosystem: eco, name } }] });

describe('verifyAdvisoryFix', () => {
  it('verified when the advisory lists the package and the version is not affected', async () => {
    let body: unknown;
    const f = fakeFetch({
      [`${OSV}/v1/vulns/${ghsa}`]: vuln('npm', 'lodash'),
      [`${OSV}/v1/query`]: async (req) => {
        body = await req.json();
        return Response.json({});
      },
    });
    expect(await verifyAdvisoryFix({ fetch: f, now }, ghsa, ref)).toBe('verified');
    expect(body).toEqual({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.21' });
  });

  it('not-fixed when the version is still affected (match by alias)', async () => {
    const f = fakeFetch({
      [`${OSV}/v1/vulns/CVE-2021-23337`]: vuln('npm', 'lodash', ghsa, ['CVE-2021-23337']),
      [`${OSV}/v1/query`]: Response.json({ vulns: [{ id: ghsa, aliases: ['CVE-2021-23337'] }] }),
    });
    expect(await verifyAdvisoryFix({ fetch: f, now }, 'CVE-2021-23337', ref)).toBe('not-fixed');
  });

  it('unknown-advisory on 404 or when the package is not listed', async () => {
    const f404 = fakeFetch({ [`${OSV}/v1/vulns/${ghsa}`]: new Response('nf', { status: 404 }) });
    expect(await verifyAdvisoryFix({ fetch: f404, now }, ghsa, ref)).toBe('unknown-advisory');
    const other = fakeFetch({ [`${OSV}/v1/vulns/${ghsa}`]: vuln('npm', 'underscore') });
    expect(await verifyAdvisoryFix({ fetch: other, now }, ghsa, ref)).toBe('unknown-advisory');
    const wrongEco = fakeFetch({ [`${OSV}/v1/vulns/${ghsa}`]: vuln('Go', 'lodash') });
    expect(await verifyAdvisoryFix({ fetch: wrongEco, now }, ghsa, ref)).toBe('unknown-advisory');
  });

  it('uses the Go ecosystem name and strips the v prefix for Go queries', async () => {
    let body: unknown;
    const f = fakeFetch({
      [`${OSV}/v1/vulns/GO-2024-0001`]: vuln('Go', 'github.com/x/y', 'GO-2024-0001'),
      [`${OSV}/v1/query`]: async (req) => {
        body = await req.json();
        return Response.json({ vulns: [] });
      },
    });
    const goRef: PackageRef = { eco: 'go', name: 'github.com/x/y', version: 'v1.2.3' };
    expect(await verifyAdvisoryFix({ fetch: f, now }, 'GO-2024-0001', goRef)).toBe('verified');
    expect(body).toEqual({ package: { name: 'github.com/x/y', ecosystem: 'Go' }, version: '1.2.3' });
  });

  it('not-fixed when the query returns an alias of the cited advisory (not the cited id)', async () => {
    const f = fakeFetch({
      [`${OSV}/v1/vulns/${ghsa}`]: Response.json({
        id: ghsa,
        aliases: ['GO-2025-1'],
        affected: [{ package: { ecosystem: 'Go', name: 'github.com/x/y' } }],
      }),
      [`${OSV}/v1/query`]: Response.json({ vulns: [{ id: 'GO-2025-1' }] }),
    });
    const goRef: PackageRef = { eco: 'go', name: 'github.com/x/y', version: 'v1.0.0' };
    expect(await verifyAdvisoryFix({ fetch: f, now }, ghsa, goRef)).toBe('not-fixed');
  });

  it('unavailable on network error, 5xx and 429', async () => {
    const thrown = fakeFetch({});
    expect(await verifyAdvisoryFix({ fetch: thrown, now }, ghsa, ref)).toBe('unavailable');
    for (const status of [500, 503, 429]) {
      const f = fakeFetch({ [`${OSV}/v1/vulns/${ghsa}`]: new Response('x', { status }) });
      expect(await verifyAdvisoryFix({ fetch: f, now }, ghsa, ref)).toBe('unavailable');
      const q = fakeFetch({
        [`${OSV}/v1/vulns/${ghsa}`]: vuln('npm', 'lodash'),
        [`${OSV}/v1/query`]: new Response('x', { status }),
      });
      expect(await verifyAdvisoryFix({ fetch: q, now }, ghsa, ref)).toBe('unavailable');
    }
  });

  it('follows query pagination', async () => {
    let n = 0;
    const f = fakeFetch({
      [`${OSV}/v1/vulns/${ghsa}`]: vuln('npm', 'lodash'),
      [`${OSV}/v1/query`]: async (req) => {
        const b = (await req.json()) as { page_token?: string };
        n++;
        return b.page_token === 'p2'
          ? Response.json({ vulns: [{ id: ghsa }] })
          : Response.json({ vulns: [{ id: 'GHSA-other' }], next_page_token: 'p2' });
      },
    });
    expect(await verifyAdvisoryFix({ fetch: f, now }, ghsa, ref)).toBe('not-fixed');
    expect(n).toBe(2);
  });
});

describe('maliciousIds', () => {
  it('maps MAL- IDs to their package and drops others', async () => {
    let body: unknown;
    const f = fakeFetch({
      [`${OSV}/v1/querybatch`]: async (req) => {
        body = await req.json();
        return Response.json({
          results: [
            { vulns: [{ id: 'MAL-2025-1' }, { id: 'GHSA-aaaa-bbbb-cccc' }] },
            { vulns: [{ id: 'GHSA-dddd-eeee-ffff' }] },
            {},
          ],
        });
      },
    });
    const refs: PackageRef[] = [
      { eco: 'npm', name: '@evil/pkg', version: '1.0.0' },
      { eco: 'npm', name: 'ok', version: '2.0.0' },
      { eco: 'go', name: 'github.com/a/b', version: 'v0.1.0' },
    ];
    const m = await maliciousIds({ fetch: f, now }, refs);
    expect(m).toEqual(new Map([['npm:@evil/pkg@1.0.0', ['MAL-2025-1']]]));
    expect(body).toEqual({
      queries: [
        { package: { name: '@evil/pkg', ecosystem: 'npm' }, version: '1.0.0' },
        { package: { name: 'ok', ecosystem: 'npm' }, version: '2.0.0' },
        { package: { name: 'github.com/a/b', ecosystem: 'Go' }, version: '0.1.0' },
      ],
    });
  });

  it('returns an empty map for no refs without calling OSV', async () => {
    const f = fakeFetch({});
    expect(await maliciousIds({ fetch: f, now }, [])).toEqual(new Map());
    expect(f.calls).toEqual([]);
  });

  it('returns null when OSV is unavailable', async () => {
    const refs: PackageRef[] = [{ eco: 'npm', name: 'a', version: '1.0.0' }];
    expect(await maliciousIds({ fetch: fakeFetch({}), now }, refs)).toBeNull();
    const f = fakeFetch({ [`${OSV}/v1/querybatch`]: new Response('x', { status: 502 }) });
    expect(await maliciousIds({ fetch: f, now }, refs)).toBeNull();
  });

  it('follows per-query page tokens', async () => {
    const f = fakeFetch({
      [`${OSV}/v1/querybatch`]: async (req) => {
        const b = (await req.json()) as { queries: { page_token?: string }[] };
        if (b.queries[0]!.page_token === 't') return Response.json({ results: [{ vulns: [{ id: 'MAL-2025-9' }] }] });
        return Response.json({ results: [{ vulns: [{ id: 'GHSA-x' }], next_page_token: 't' }] });
      },
    });
    const m = await maliciousIds({ fetch: f, now }, [{ eco: 'npm', name: 'a', version: '1.0.0' }]);
    expect(m).toEqual(new Map([['npm:a@1.0.0', ['MAL-2025-9']]]));
  });
});

describe('OSV timeouts', () => {
  it('a hung OSV is unavailable for both calls', async () => {
    const f = fakeFetch({ [`${OSV}/v1/vulns/${ghsa}`]: hang(), [`${OSV}/v1/querybatch`]: hang() });
    const deps = { fetch: f, now, timeoutMs: 20 };
    expect(await verifyAdvisoryFix(deps, ghsa, ref)).toBe('unavailable');
    expect(await maliciousIds(deps, [ref])).toBeNull();
  });
});
