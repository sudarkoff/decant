import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handleDashboardApi } from '../src/dashboard/api';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock } from './helpers';

const deps: Deps = { fetch: fakeFetch({}), now: fixedClock('2026-11-19T12:00:00Z') };
let e: Env;

async function get(path: string, method = 'GET'): Promise<{ status: number; body: any; res: Response }> {
  const p = path.split('?')[0]!;
  const req = new Request(`https://h/dashboard/api/${path}`, { method });
  const res = await handleDashboardApi(req, e, deps, p!);
  const txt = await res.text();
  return { status: res.status, body: txt ? JSON.parse(txt) : null, res };
}

async function exec(sql: string, ...rows: unknown[][]): Promise<void> {
  await e.DB.batch(rows.map((r) => e.DB.prepare(sql).bind(...r)));
}

const twocalPolicy = {
  project: 'twocal',
  cooldownDays: 3,
  autoShip: { critical: 'auto', high: 'approve', moderate: 'approve', low: 'approve' },
  allow: [{ package: 'npm:a@9.0.0', reason: 'r', advisory: 'GHSA-aaaa-bbbb-cccc', added: '2026-11-11' }],
  block: [
    { package: 'npm:x@1.0.0', reason: 'r' },
    { package: 'npm:y@1.0.0', reason: 'r' },
  ],
};
const otherPolicy = { project: 'other' };

describe('dashboard api: handler errors', () => {
  it('returns JSON 500 with no-store when a query throws', async () => {
    const broken = { DB: { prepare: () => { throw new Error('secret detail'); }, batch: () => { throw new Error('secret detail'); } } } as unknown as Env;
    const res = await handleDashboardApi(new Request('https://h/dashboard/api/projects'), broken, deps, 'projects');
    expect(res.status).toBe(500);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await res.json()).toEqual({ error: 'internal' });
  });
});

describe('dashboard api: fresh database', () => {
  beforeAll(() => {
    e = env as unknown as Env;
  });

  it('returns zeros and empty arrays with 200', async () => {
    const p = await get('projects');
    expect(p.status).toBe(200);
    expect(p.body).toEqual({ projects: [] });

    const a = await get('activity?range=7');
    expect(a.status).toBe(200);
    expect(a.body.days).toHaveLength(7);
    expect(a.body.days[0]).toEqual({ day: '2026-11-13', served: 0, cooldown: 0, blocked: 0, stale: 0, failed: 0 });
    expect(a.body.days[6].day).toBe('2026-11-19');
    expect(a.body.distinctPackages).toBe(0);
    expect(a.body.distinctVersions).toBe(0);

    expect((await get('security')).body).toEqual({
      blocksHit: 0,
      maliciousHits: 0,
      flagged: [],
      vulnsBySeverity: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 },
      fastLane: [],
    });
    expect((await get('freshness')).body).toEqual({ medianAgeDays: null, majorBehind: { direct: [], transitive: [] }, transitiveMajorBehindCount: 0, minorAvailable: 0 });
    expect((await get('uptime')).body).toEqual({ outageDays: [], staleServed: 0, failed: 0 });
    expect((await get('policy')).body).toEqual({ policies: [] });
    expect((await get('packages')).body).toEqual({ items: [], page: 1, hasMore: false });
  });
});

describe('dashboard api: seeded', () => {
  beforeAll(async () => {
    e = env as unknown as Env;
    await exec(
      'INSERT INTO projects (id, created_at) VALUES (?, ?)',
      ['twocal', '2026-01-01T00:00:00Z'],
      ['other', '2026-01-01T00:00:00Z'],
    );
    await exec(
      'INSERT INTO serve_log (project_id, eco, name, version, day) VALUES (?, ?, ?, ?, ?)',
      ['twocal', 'npm', 'a', '9.0.0', '2026-11-18'],
      ['twocal', 'npm', 'a', '9.0.0', '2026-11-19'],
      ['twocal', 'npm', 'a', '10.0.0', '2026-11-19'],
      ['twocal', 'npm', 'b', '1.0.0', '2026-11-10'],
      ['twocal', 'go', 'example.com/m', 'v1.2.0', '2026-11-19'],
      ['twocal', 'npm', '100%pct', '1.0.0', '2026-11-19'],
      ['twocal', 'npm', 'old', '1.0.0', '2026-09-01'],
      ['other', 'npm', 'secret', '1.0.0', '2026-11-19'],
    );
    await exec(
      'INSERT INTO request_counts (project_id, day, eco, kind, outcome, n) VALUES (?, ?, ?, ?, ?, ?)',
      ['twocal', '2026-11-19', 'npm', 'metadata', 'served', 5],
      ['twocal', '2026-11-19', 'npm', 'download', 'served', 3],
      ['twocal', '2026-11-19', 'npm', 'download', 'cooldown', 1],
      ['twocal', '2026-11-19', 'go', 'download', 'blocked', 2],
      ['twocal', '2026-11-18', 'npm', 'metadata', 'stale', 1],
      ['twocal', '2026-11-15', 'npm', 'metadata', 'failed', 2],
      ['twocal', '2026-10-01', 'npm', 'metadata', 'served', 100],
      ['other', '2026-11-19', 'npm', 'metadata', 'served', 10],
      ['other', '2026-11-17', 'go', 'metadata', 'failed', 4],
    );
    await exec(
      'INSERT INTO versions (eco, name, version, publish_time, first_seen) VALUES (?, ?, ?, ?, ?)',
      ['npm', 'a', '9.0.0', '2026-10-20T00:00:00Z', '2026-10-20T00:00:00Z'],
      ['npm', 'a', '10.0.0', '2026-11-09T12:00:00Z', '2026-11-09T12:00:00Z'],
      ['npm', 'b', '1.0.0', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z'],
      ['go', 'example.com/m', 'v1.2.0', '2026-10-30T12:00:00Z', '2026-10-30T12:00:00Z'],
      ['npm', '100%pct', '1.0.0', '2026-11-14T12:00:00Z', '2026-11-14T12:00:00Z'],
      ['npm', 'secret', '1.0.0', '2026-11-18T12:00:00Z', '2026-11-18T12:00:00Z'],
    );
    await exec(
      'INSERT INTO packages (eco, name, latest, checked_at) VALUES (?, ?, ?, ?)',
      ['npm', 'a', '11.0.0', '2026-11-19T00:00:00Z'],
      ['go', 'example.com/m', 'v1.2.0', '2026-11-19T00:00:00Z'],
      ['go', 'example.com/m/v2', 'v2.1.0', '2026-11-19T00:00:00Z'],
      ['npm', '100%pct', '1.1.0', '2026-11-19T00:00:00Z'],
      ['npm', 'secret', '1.0.0', '2026-11-19T00:00:00Z'],
    );
    await exec(
      'INSERT INTO global_blocks (eco, name, version, source, reason, at) VALUES (?, ?, ?, ?, ?, ?)',
      ['npm', 'a', '9.0.0', 'operator', 'r', '2026-11-01T00:00:00Z'],
      ['npm', 'b', '1.0.0', 'osv', 'r', '2026-11-01T00:00:00Z'],
      ['npm', 'old', '1.0.0', 'osv', 'r', '2026-11-01T00:00:00Z'],
    );
    await exec(
      'INSERT INTO verdicts (eco, name, version, scanner, scanner_version, result, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['npm', 'a', '10.0.0', 'guarddog', '1', 'flagged', '2026-11-19T00:00:00Z'],
      ['npm', 'a', '10.0.0', 'other', '1', 'clean', '2026-11-19T00:00:00Z'],
      ['go', 'example.com/m', 'v1.2.0', 'guarddog', '1', 'malicious', '2026-11-19T00:00:00Z'],
      ['npm', 'secret', '1.0.0', 'guarddog', '1', 'flagged', '2026-11-19T00:00:00Z'],
    );
    await exec(
      'INSERT INTO vulns (eco, name, version, id, severity, checked_at) VALUES (?, ?, ?, ?, ?, ?)',
      ['npm', 'a', '9.0.0', 'GHSA-1', 'high', 'x'],
      ['npm', 'a', '9.0.0', 'GHSA-2', 'critical', 'x'],
      ['npm', 'a', '10.0.0', 'GHSA-1', 'high', 'x'],
      ['npm', '100%pct', '1.0.0', 'MAL-2026-1', 'critical', 'x'],
      ['npm', 'b', '1.0.0', 'CVE-2026-1', 'unknown', 'x'],
      ['npm', 'old', '1.0.0', 'GHSA-3', 'low', 'x'],
      ['npm', 'secret', '1.0.0', 'GHSA-4', 'moderate', 'x'],
      ['npm', 'secret', '1.0.0', 'MAL-2026-2', 'critical', 'x'],
    );
    await exec(
      `INSERT INTO allows (project_id, ref, eco, name, version, advisory, reason, advisory_published, first_synced_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ['twocal', 'main', 'npm', 'a', '9.0.0', 'GHSA-aaaa-bbbb-cccc', 'r', '2026-11-10T00:00:00Z', '2026-11-11T06:30:00Z'],
      ['twocal', 'feature', 'npm', 'a', '9.0.0', 'GHSA-aaaa-bbbb-cccc', 'r', '2026-11-10T00:00:00Z', '2026-11-10T01:00:00Z'],
      ['twocal', 'main', 'npm', 'b', '1.0.0', 'GHSA-dddd-eeee-ffff', 'r', null, '2026-11-11T00:00:00Z'],
      ['twocal', 'main', 'npm', 'c', '1.0.0', null, 'r', null, null],
      ['other', 'main', 'npm', 'secret', '1.0.0', 'GHSA-gggg-hhhh-iiii', 'r', '2026-11-18T00:00:00Z', '2026-11-18T02:00:00Z'],
    );
    await exec(
      'INSERT INTO policies (project_id, ref, json, sha, synced_at) VALUES (?, ?, ?, ?, ?)',
      ['twocal', 'main', JSON.stringify(twocalPolicy), 'sha-main', '2026-11-18T00:00:00Z'],
      ['twocal', 'feature', JSON.stringify({ ...twocalPolicy, cooldownDays: 99 }), 'sha-feat', '2026-11-18T00:00:00Z'],
      ['other', 'main', JSON.stringify(otherPolicy), 'sha-other', '2026-11-17T00:00:00Z'],
    );
  });

  it('sets json content type and no-store on every response', async () => {
    for (const p of ['projects', 'activity', 'security', 'freshness', 'uptime', 'policy', 'packages', 'nope', 'activity?range=8']) {
      const r = await get(p);
      expect(r.res.headers.get('content-type')).toBe('application/json');
      expect(r.res.headers.get('cache-control')).toBe('no-store');
    }
  });

  it('HEAD attention returns an empty 200 without touching alerts_state', async () => {
    const count = async () => (await e.DB.prepare('SELECT COUNT(*) AS n FROM alerts_state').first<{ n: number }>())!.n;
    await e.DB.prepare('DELETE FROM alerts_state').run();
    const r = await get('attention', 'HEAD');
    expect(r.status).toBe(200);
    expect(r.body).toBeNull();
    expect(r.res.headers.get('content-type')).toBe('application/json');
    expect(r.res.headers.get('cache-control')).toBe('no-store');
    expect(await count()).toBe(0);
    // The same request as GET does run the diff (the seed has open items).
    expect((await get('attention')).body.open.length).toBeGreaterThan(0);
    expect(await count()).toBeGreaterThan(0);
  });

  it('projects lists ids', async () => {
    expect((await get('projects')).body).toEqual({ projects: [{ id: 'other' }, { id: 'twocal' }] });
  });

  it('validation: bad range, unknown project → 400; unknown route → 404; non-GET → 405', async () => {
    for (const p of ['activity?range=8', 'activity?range=', 'activity?range=30.0', 'security?project=nope', 'packages?project=nope', 'policy?project=nope', 'packages?page=0', 'packages?page=x']) {
      const r = await get(p);
      expect(r.status, p).toBe(400);
      expect(typeof r.body.error).toBe('string');
    }
    const nf = await get('whatever');
    expect(nf.status).toBe(404);
    expect(typeof nf.body.error).toBe('string');
    expect((await get('projects', 'POST')).status).toBe(405);
  });

  it('activity: twocal, 7 days', async () => {
    const { status, body } = await get('activity?project=twocal&range=7');
    expect(status).toBe(200);
    expect(body.days.map((d: { day: string }) => d.day)).toEqual([
      '2026-11-13', '2026-11-14', '2026-11-15', '2026-11-16', '2026-11-17', '2026-11-18', '2026-11-19',
    ]);
    expect(body.days[6]).toEqual({ day: '2026-11-19', served: 8, cooldown: 1, blocked: 2, stale: 0, failed: 0 });
    expect(body.days[5]).toEqual({ day: '2026-11-18', served: 0, cooldown: 0, blocked: 0, stale: 1, failed: 0 });
    expect(body.days[2]).toEqual({ day: '2026-11-15', served: 0, cooldown: 0, blocked: 0, stale: 0, failed: 2 });
    // a, example.com/m, 100%pct (b served 2026-11-10, outside 7 days)
    expect(body.distinctPackages).toBe(3);
    expect(body.distinctVersions).toBe(4);
  });

  it('activity: default range 30, all projects', async () => {
    const { body } = await get('activity');
    expect(body.days).toHaveLength(30);
    expect(body.days[0].day).toBe('2026-10-21');
    expect(body.days[29]).toEqual({ day: '2026-11-19', served: 18, cooldown: 1, blocked: 2, stale: 0, failed: 0 });
    expect(body.days.reduce((s: number, d: { served: number }) => s + d.served, 0)).toBe(18); // 2026-10-01 excluded
    expect(body.distinctPackages).toBe(5);
    expect(body.distinctVersions).toBe(6);
  });

  it('activity: range 90 includes older rows', async () => {
    const { body } = await get('activity?project=twocal&range=90');
    expect(body.days).toHaveLength(90);
    expect(body.days.reduce((s: number, d: { served: number }) => s + d.served, 0)).toBe(108);
  });

  it('security: twocal', async () => {
    const { body } = await get('security?project=twocal');
    expect(body).toEqual({
      blocksHit: 2, // a@9.0.0 (operator), b@1.0.0 (osv); old@1.0.0 not installed in range
      maliciousHits: 3, // b (osv block), 100%pct (MAL-), m (malicious verdict)
      flagged: [{ package: 'npm:a@10.0.0', scanner: 'guarddog' }],
      vulnsBySeverity: { critical: 1, high: 2, moderate: 0, low: 0, unknown: 1 },
      fastLane: [{ project: 'twocal', package: 'npm:a@9.0.0', advisory: 'GHSA-aaaa-bbbb-cccc', hoursToFix: 30.5 }],
    });
  });

  it('security: all aggregates', async () => {
    const { body } = await get('security?project=all&range=30');
    expect(body.blocksHit).toBe(2);
    expect(body.maliciousHits).toBe(4);
    expect(body.flagged).toEqual([
      { package: 'npm:a@10.0.0', scanner: 'guarddog' },
      { package: 'npm:secret@1.0.0', scanner: 'guarddog' },
    ]);
    expect(body.vulnsBySeverity).toEqual({ critical: 1, high: 2, moderate: 1, low: 0, unknown: 1 });
    expect(body.fastLane).toEqual([
      { project: 'other', package: 'npm:secret@1.0.0', advisory: 'GHSA-gggg-hhhh-iiii', hoursToFix: 2 },
      { project: 'twocal', package: 'npm:a@9.0.0', advisory: 'GHSA-aaaa-bbbb-cccc', hoursToFix: 30.5 },
    ]);
  });

  it('security: range 90 sees old installs', async () => {
    const { body } = await get('security?project=twocal&range=90');
    expect(body.blocksHit).toBe(3);
    expect(body.vulnsBySeverity.low).toBe(1);
  });

  it('freshness: twocal uses the most recently served version (tie → highest semver)', async () => {
    const { body } = await get('freshness?project=twocal&range=7');
    // a@10.0.0 (10 days), m v1.2.0 (20), 100%pct (5) → median 10
    expect(body.medianAgeDays).toBe(10);
    // No dependency summary synced: everything is listed as direct, unclassified.
    expect(body.majorBehind).toEqual({
      direct: [
        { project: 'twocal', package: 'go:example.com/m', version: 'v1.2.0', latest: 'v2.1.0', classified: false },
        { project: 'twocal', package: 'npm:a', version: '10.0.0', latest: '11.0.0', classified: false },
      ],
      transitive: [],
    });
    expect(body.transitiveMajorBehindCount).toBe(0);
    expect(body.minorAvailable).toBe(1);
  });

  it('freshness: all', async () => {
    const { body } = await get('freshness?project=all&range=7');
    // ages 1, 5, 10, 20 → median 7.5 → 8
    expect(body.medianAgeDays).toBe(8);
    expect(body.majorBehind.direct).toHaveLength(2);
    expect(body.minorAvailable).toBe(1);
  });

  it('freshness: project scoping', async () => {
    const { body } = await get('freshness?project=other&range=7');
    expect(body).toEqual({ medianAgeDays: 1, majorBehind: { direct: [], transitive: [] }, transitiveMajorBehindCount: 0, minorAvailable: 0 });
  });

  it('uptime: twocal and all', async () => {
    expect((await get('uptime?project=twocal')).body).toEqual({
      outageDays: ['2026-11-15', '2026-11-18'],
      staleServed: 1,
      failed: 2,
    });
    expect((await get('uptime?project=all&range=7')).body).toEqual({
      outageDays: ['2026-11-15', '2026-11-17', '2026-11-18'],
      staleServed: 1,
      failed: 6,
    });
  });

  it('policy: main ref only', async () => {
    expect((await get('policy?project=twocal')).body).toEqual({
      policies: [
        {
          project: 'twocal',
          cooldownDays: 3,
          autoShip: twocalPolicy.autoShip,
          allows: 1,
          blocks: 2,
          syncedAt: '2026-11-18T00:00:00Z',
          sha: 'sha-main',
        },
      ],
    });
    const all = (await get('policy')).body.policies;
    expect(all.map((p: { project: string }) => p.project)).toEqual(['other', 'twocal']);
    expect(all[0]).toMatchObject({ cooldownDays: 7, allows: 0, blocks: 0, sha: 'sha-other' });
  });

  it('packages: twocal list never includes other projects', async () => {
    const { body } = await get('packages?project=twocal');
    expect(body.page).toBe(1);
    expect(body.hasMore).toBe(false);
    expect(body.items.map((i: { name: string; version: string }) => `${i.name}@${i.version}`)).toEqual([
      '100%pct@1.0.0', 'a@10.0.0', 'a@9.0.0', 'b@1.0.0', 'example.com/m@v1.2.0',
    ]);
    expect(body.items.every((i: { project: string }) => i.project === 'twocal')).toBe(true);
    expect(body.items.find((i: { version: string }) => i.version === '9.0.0')).toEqual({
      project: 'twocal', eco: 'npm', name: 'a', version: '9.0.0',
      published: '2026-10-20T00:00:00Z', latest: '11.0.0', lastServed: '2026-11-19',
    });
    expect(body.items.find((i: { name: string }) => i.name === 'b')).toMatchObject({ published: '2026-10-01T00:00:00Z', latest: null });
    expect((await get('packages?project=other')).body.items.map((i: { name: string }) => i.name)).toEqual(['secret']);
  });

  it('packages: bounded by range (old@1.0.0 was served only before the 30-day window)', async () => {
    const d30 = (await get('packages?project=twocal&range=30')).body.items.map((i: { name: string }) => i.name);
    expect(d30).not.toContain('old');
    const d7 = (await get('packages?project=twocal&range=7')).body.items.map((i: { name: string }) => i.name);
    expect(d7).toEqual(['100%pct', 'a', 'a', 'example.com/m']);
    const d90 = (await get('packages?project=twocal&range=90')).body.items;
    expect(d90.find((i: { name: string }) => i.name === 'old')).toMatchObject({ published: null, latest: null, lastServed: '2026-09-01' });
    expect((await get('packages?range=8')).status).toBe(400);
  });

  it('packages: q is literal, so % matches only names containing %', async () => {
    const pct = (await get(`packages?q=${encodeURIComponent('%')}`)).body.items;
    expect(pct.map((i: { name: string }) => i.name)).toEqual(['100%pct']);
    const us = (await get(`packages?q=${encodeURIComponent('_')}`)).body.items;
    expect(us).toEqual([]);
    const bs = (await get(`packages?q=${encodeURIComponent('\\')}`)).body.items;
    expect(bs).toEqual([]);
    const sec = (await get('packages?q=ecr')).body.items;
    expect(sec.map((i: { project: string; name: string }) => `${i.project}/${i.name}`)).toEqual(['other/secret']);
  });

  it('packages: paginates 50 per page', async () => {
    const rows: unknown[][] = [];
    for (let i = 0; i < 52; i++) rows.push(['other', 'npm', `zz-${String(i).padStart(2, '0')}`, '1.0.0', '2026-11-19']);
    await exec('INSERT INTO serve_log (project_id, eco, name, version, day) VALUES (?, ?, ?, ?, ?)', ...rows);
    const p1 = (await get('packages?project=other&q=zz-')).body;
    expect(p1.items).toHaveLength(50);
    expect(p1.hasMore).toBe(true);
    const p2 = (await get('packages?project=other&q=zz-&page=2')).body;
    expect(p2.page).toBe(2);
    expect(p2.items.map((i: { name: string }) => i.name)).toEqual(['zz-50', 'zz-51']);
    expect(p2.hasMore).toBe(false);
  });

  it('security: installed sets over one lookup chunk (500) are counted fully', async () => {
    await exec('INSERT INTO projects (id, created_at) VALUES (?, ?)', ['bulk', '2026-01-01T00:00:00Z']);
    const rows: unknown[][] = [];
    for (let i = 0; i < 1203; i++) rows.push(['bulk', 'npm', `bulk-${String(i).padStart(4, '0')}`, '1.0.0', '2026-11-19']);
    await exec('INSERT INTO serve_log (project_id, eco, name, version, day) VALUES (?, ?, ?, ?, ?)', ...rows);
    await exec(
      'INSERT INTO global_blocks (eco, name, version, source, reason, at) VALUES (?, ?, ?, ?, ?, ?)',
      ['npm', 'bulk-0003', '1.0.0', 'operator', 'r', 'x'],
      ['npm', 'bulk-0700', '1.0.0', 'osv', 'r', 'x'],
      ['npm', 'bulk-1202', '1.0.0', 'operator', 'r', 'x'],
    );
    await exec(
      'INSERT INTO vulns (eco, name, version, id, severity, checked_at) VALUES (?, ?, ?, ?, ?, ?)',
      ['npm', 'bulk-0001', '1.0.0', 'GHSA-b1', 'low', 'x'],
      ['npm', 'bulk-1100', '1.0.0', 'GHSA-b2', 'low', 'x'],
    );
    await exec(
      'INSERT INTO verdicts (eco, name, version, scanner, scanner_version, result, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['npm', 'bulk-1201', '1.0.0', 'z', '1', 'flagged', 'x'],
      ['npm', 'bulk-0002', '1.0.0', 'z', '1', 'flagged', 'x'],
    );
    const { body } = await get('security?project=bulk&range=7');
    expect(body.blocksHit).toBe(3);
    expect(body.maliciousHits).toBe(1);
    expect(body.vulnsBySeverity.low).toBe(2);
    expect(body.flagged).toEqual([
      { package: 'npm:bulk-0002@1.0.0', scanner: 'z' },
      { package: 'npm:bulk-1201@1.0.0', scanner: 'z' },
    ]);
  });
});
