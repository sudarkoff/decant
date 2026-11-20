import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { handleDashboardApi } from '../src/dashboard/api';
import { attention } from '../src/dashboard/attention';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock } from './helpers';

const NOW = new Date('2026-11-19T12:00:00Z');
const e = env as unknown as Env;

async function exec(sql: string, ...rows: unknown[][]): Promise<void> {
  await e.DB.batch(rows.map((r) => e.DB.prepare(sql).bind(...r)));
}
const project = (...ids: string[]) => exec('INSERT INTO projects (id, created_at) VALUES (?, ?)', ...ids.map((id) => [id, '2026-01-01T00:00:00Z']));
const serve = (...rows: [string, string, string, string, string][]) =>
  exec('INSERT INTO serve_log (project_id, eco, name, version, day) VALUES (?, ?, ?, ?, ?)', ...rows);
const gblock = (...rows: [string, string, string, string, string][]) =>
  exec("INSERT INTO global_blocks (eco, name, version, source, reason, at) VALUES (?, ?, ?, ?, ?, '2026-11-01T00:00:00Z')", ...rows);
const policy = (id: string, block: { package: string; reason: string }[], ref = 'main') =>
  exec("INSERT INTO policies (project_id, ref, json, sha, synced_at) VALUES (?, ?, ?, 'abc', '2026-11-01T00:00:00Z')", [
    id,
    ref,
    JSON.stringify({ project: id, block }),
  ]);
const keys = (items: { key: string }[]) => items.map((i) => i.key);

beforeEach(async () => {
  for (const t of ['projects', 'serve_log', 'request_counts', 'global_blocks', 'policies', 'vulns', 'verdicts', 'versions', 'alerts_state']) {
    await e.DB.prepare(`DELETE FROM ${t}`).run();
  }
});

describe('attention items', () => {
  it('emits each kind when seeded, sorted by severity', async () => {
    await project('twocal', 'quiet', 'never');
    await serve(
      ['twocal', 'npm', 'x', '1.0.0', '2026-11-18'],
      ['twocal', 'npm', 'y', '1.0.0', '2026-11-18'],
      ['twocal', 'npm', 'm', '1.0.0', '2026-11-17'],
      ['twocal', 'npm', 'v', '1.0.0', '2026-11-16'],
      ['twocal', 'npm', 'f', '1.0.0', '2026-10-21'],
      ['twocal', 'npm', 'old', '1.0.0', '2026-10-20'], // outside the 30-day window
      ['quiet', 'npm', 'q', '1.0.0', '2026-10-01'],
    );
    await gblock(
      ['npm', 'x', '1.0.0', 'policy:twocal', 'bad build'],
      ['npm', 'm', '1.0.0', 'osv', 'OSV malicious-package advisory: MAL-2026-1'],
      ['npm', 'old', '1.0.0', 'operator', 'nope'],
    );
    await policy('twocal', [{ package: 'npm:y@1.0.0', reason: 'policy only' }]);
    await exec(
      "INSERT INTO vulns (eco, name, version, id, severity, summary, checked_at) VALUES (?, ?, ?, ?, ?, ?, '2026-11-01T00:00:00Z')",
      ['npm', 'm', '1.0.0', 'MAL-2026-1', 'critical', 'malware'],
      ['npm', 'v', '1.0.0', 'GHSA-aaaa-aaaa-aaaa', 'critical', 'RCE'],
      ['npm', 'v', '1.0.0', 'GHSA-bbbb-bbbb-bbbb', 'high', 'prototype pollution'],
      ['npm', 'v', '1.0.0', 'GHSA-cccc-cccc-cccc', 'moderate', 'meh'],
      ['npm', 'v', '1.0.0', 'GHSA-dddd-dddd-dddd', 'unknown', 'pending'],
    );
    await exec(
      "INSERT INTO verdicts (eco, name, version, scanner, scanner_version, result, scanned_at) VALUES (?, ?, ?, ?, '1', ?, '2026-11-01T00:00:00Z')",
      ['npm', 'f', '1.0.0', 'guarddog', 'flagged'],
      ['npm', 'v', '1.0.0', 'guarddog', 'clean'],
    );
    await exec(
      "INSERT INTO versions (eco, name, version, publish_time, first_seen, conflict) VALUES (?, ?, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', ?)",
      ['npm', 'c', '1.0.0', 1],
      ['npm', 'x', '1.0.0', 0],
    );

    const r = await attention(e, 'all', 30, NOW);
    expect(keys(r.open)).toEqual([
      'malicious:npm:m@1.0.0:twocal',
      'blocked:npm:x@1.0.0:twocal',
      'blocked:npm:y@1.0.0:twocal',
      'vuln:GHSA-aaaa-aaaa-aaaa:npm:v@1.0.0:twocal',
      'vuln:GHSA-bbbb-bbbb-bbbb:npm:v@1.0.0:twocal',
      'flagged:npm:f@1.0.0:twocal',
      'conflict:npm:c@1.0.0',
      'silent:quiet',
    ]);
    expect(r.resolved).toEqual([]);
    const byKey = Object.fromEntries(r.open.map((i) => [i.key, i]));
    expect(byKey['blocked:npm:x@1.0.0:twocal']).toEqual({
      key: 'blocked:npm:x@1.0.0:twocal',
      project: 'twocal',
      kind: 'blocked',
      title: 'x@1.0.0 is blocked',
      detail: 'policy:twocal: bad build',
      firstSeen: NOW.toISOString(),
      todo: 'Blocked by your policy. Remove or replace it, or lift the block in `decant.json`.',
      links: [{ label: 'View on npm', url: 'https://www.npmjs.com/package/x/v/1.0.0' }],
    });
    expect(byKey['blocked:npm:y@1.0.0:twocal']!.detail).toBe('policy: policy only');
    expect(byKey['malicious:npm:m@1.0.0:twocal']!.title).toBe('m@1.0.0 is malicious');
    expect(byKey['malicious:npm:m@1.0.0:twocal']!.detail).toContain('MAL-2026-1');
    expect(byKey['vuln:GHSA-aaaa-aaaa-aaaa:npm:v@1.0.0:twocal']!.detail).toBe('critical: RCE');
    expect(byKey['flagged:npm:f@1.0.0:twocal']!.detail).toBe('flagged by guarddog');
    expect(byKey['conflict:npm:c@1.0.0']!.project).toBeNull();
    expect(byKey['silent:quiet']!.detail).toBe('last activity 2026-10-01');
    expect(byKey['silent:quiet']!.links.map((l) => l.label)).toEqual(['Setup guide']);
    expect(byKey['conflict:npm:c@1.0.0']!.links).toEqual([{ label: 'View on npm', url: 'https://www.npmjs.com/package/c/v/1.0.0' }]);
    // no repo synced: no PR links
    expect(byKey['vuln:GHSA-aaaa-aaaa-aaaa:npm:v@1.0.0:twocal']!.links.map((l) => l.label)).toEqual(['Advisory']);
    expect(byKey['flagged:npm:f@1.0.0:twocal']!.findings).toEqual([]);
    expect(byKey['flagged:npm:f@1.0.0:twocal']!.todo).toMatch(/^decant didn't record which checks fired/);

    // conflicts are listed under "all" only
    expect(keys((await attention(e, 'twocal', 30, NOW)).open)).not.toContain('conflict:npm:c@1.0.0');
  });

  it('builds to-dos, links and findings from stored data', async () => {
    await project('web');
    await e.DB.prepare("UPDATE projects SET repo = 'acme/web-app' WHERE id = 'web'").run();
    await serve(
      ['web', 'npm', 'undici', '7.29.0', '2026-11-18'],
      ['web', 'npm', '@img/sharp-wasm32', '0.34.1', '2026-11-18'],
      ['web', 'go', 'github.com/Klaus/compress', 'v1.20.2', '2026-11-18'],
      ['web', 'npm', 'color-strng', '1.0.4', '2026-11-18'],
    );
    await exec(
      "INSERT INTO vulns (eco, name, version, id, severity, summary, checked_at, fixed_versions) VALUES (?, ?, ?, ?, ?, ?, '2026-11-01T00:00:00Z', ?)",
      ['npm', 'undici', '7.29.0', 'GHSA-fix', 'high', 'leak', '["6.21.3","7.29.1","8.0.0"]'],
      ['npm', 'undici', '7.29.0', 'GHSA-nofix', 'high', 'dos', '[]'],
      ['npm', 'undici', '7.29.0', 'GHSA-old', 'critical', 'legacy row', null],
      ['npm', 'color-strng', '1.0.4', 'MAL-2026-2211', 'critical', 'malware', null],
    );
    await exec(
      "INSERT INTO verdicts (eco, name, version, scanner, scanner_version, result, details, scanned_at) VALUES (?, ?, ?, 'guarddog', '3.2.0', 'flagged', ?, '2026-11-01T00:00:00Z')",
      ['npm', '@img/sharp-wasm32', '0.34.1', JSON.stringify([{ rule: 'npm-install-script', message: 'postinstall', locations: ['package/package.json:12'] }])],
      ['go', 'github.com/Klaus/compress', 'v1.20.2', JSON.stringify([{ rule: 'archive-anomaly', message: 'archive parser anomaly: multiple EOCD records' }])],
    );
    const by = Object.fromEntries((await attention(e, 'web', 30, NOW)).open.map((i) => [i.key, i]));

    const fix = by['vuln:GHSA-fix:npm:undici@7.29.0:web']!;
    expect(fix.todo).toContain('Fixed in `7.29.1`.');
    expect(fix.links).toEqual([
      { label: 'Open security PRs', url: 'https://github.com/acme/web-app/pulls?q=is%3Apr+is%3Aopen+label%3Adecant%3Asecurity' },
      { label: 'Advisory', url: 'https://osv.dev/vulnerability/GHSA-fix' },
    ]);
    expect(by['vuln:GHSA-nofix:npm:undici@7.29.0:web']!.todo).toMatch(/^No fixed version yet/);
    expect(by['vuln:GHSA-old:npm:undici@7.29.0:web']!.todo).toMatch(/^decant has not looked up a fixed version yet/);

    const flagged = by['flagged:npm:@img/sharp-wasm32@0.34.1:web']!;
    expect(flagged.findings).toEqual([{ rule: 'npm-install-script', note: 'postinstall at package/package.json:12' }]);
    expect(flagged.todo).toMatch(/^Read the findings/);
    expect(flagged.links.map((l) => l.url)).toEqual([
      'https://github.com/acme/web-app/pulls?q=is%3Apr+is%3Aopen+status%3Afailure',
      'https://www.npmjs.com/package/@img/sharp-wasm32/v/0.34.1',
    ]);

    const anomaly = by['flagged:go:github.com/Klaus/compress@v1.20.2:web']!;
    expect(anomaly.findings).toEqual([{ rule: 'archive-anomaly', note: 'archive parser anomaly: multiple EOCD records' }]);
    expect(anomaly.todo).toMatch(/^Nothing inside was scanned\. Download the module zip/);
    expect(anomaly.links[1]).toEqual({ label: 'View on pkg.go.dev', url: 'https://pkg.go.dev/github.com/Klaus/compress@v1.20.2' });

    const mal = by['malicious:npm:color-strng@1.0.4:web']!;
    expect(mal.links).toEqual([
      { label: 'Advisory', url: 'https://osv.dev/vulnerability/MAL-2026-2211' },
      { label: 'View on npm', url: 'https://www.npmjs.com/package/color-strng/v/1.0.4' },
    ]);
  });

  it('a malicious verdict is malicious, and its verdict block does not also emit blocked', async () => {
    await project('p');
    await serve(['p', 'npm', 'z', '2.0.0', '2026-11-19']);
    await exec(
      "INSERT INTO verdicts (eco, name, version, scanner, scanner_version, result, scanned_at) VALUES ('npm', 'z', '2.0.0', 'guarddog', '1', 'malicious', '2026-11-01T00:00:00Z')",
      [],
    );
    await gblock(['npm', 'z', '2.0.0', 'verdict:guarddog', 'malicious verdict from guarddog 1']);
    expect(keys((await attention(e, 'all', 30, NOW)).open)).toEqual(['malicious:npm:z@2.0.0:p']);
  });

  it('resolves a removed block, then reopens the same key without a duplicate row', async () => {
    await project('p');
    await serve(['p', 'npm', 'x', '1.0.0', '2026-11-18']);
    await gblock(['npm', 'x', '1.0.0', 'operator', 'bad']);
    const key = 'blocked:npm:x@1.0.0:p';

    const t0 = new Date('2026-11-17T12:00:00Z');
    expect(keys((await attention(e, 'p', 30, t0)).open)).toEqual([key]);

    await e.DB.prepare('DELETE FROM global_blocks').run();
    const t1 = new Date('2026-11-18T12:00:00Z');
    const r1 = await attention(e, 'p', 30, t1);
    expect(r1.open).toEqual([]);
    expect(r1.resolved).toEqual([
      { key, project: 'p', kind: 'blocked', title: 'x@1.0.0 is blocked', detail: '', firstSeen: t0.toISOString(), resolvedAt: t1.toISOString(), todo: '', links: [] },
    ]);

    await gblock(['npm', 'x', '1.0.0', 'operator', 'bad']);
    const r2 = await attention(e, 'p', 30, NOW);
    expect(r2.open.map((i) => [i.key, i.firstSeen])).toEqual([[key, t0.toISOString()]]);
    expect(r2.resolved).toEqual([]);
    const n = await e.DB.prepare('SELECT COUNT(*) AS n, MAX(resolved_at) AS r FROM alerts_state WHERE key = ?').bind(key).first<{ n: number; r: string | null }>();
    expect(n).toEqual({ n: 1, r: null });
  });

  it('resolved honours the range', async () => {
    await project('p');
    await serve(['p', 'npm', 'x', '1.0.0', '2026-11-05']);
    await gblock(['npm', 'x', '1.0.0', 'operator', 'bad']);
    await attention(e, 'p', 30, new Date('2026-11-08T00:00:00Z'));
    await e.DB.prepare('DELETE FROM global_blocks').run();
    await attention(e, 'p', 30, new Date('2026-11-09T00:00:00Z'));
    expect(keys((await attention(e, 'p', 7, NOW)).resolved)).toEqual([]);
    expect(keys((await attention(e, 'p', 30, NOW)).resolved)).toEqual(['blocked:npm:x@1.0.0:p']);
  });

  it("keeps project A's items out of project B and never resolves them from B", async () => {
    await project('a', 'b');
    await serve(['a', 'npm', 'x', '1.0.0', '2026-11-18'], ['b', 'npm', 'ok', '1.0.0', '2026-11-18']);
    await gblock(['npm', 'x', '1.0.0', 'operator', 'bad']);
    expect(keys((await attention(e, 'a', 30, NOW)).open)).toEqual(['blocked:npm:x@1.0.0:a']);
    const b = await attention(e, 'b', 30, NOW);
    expect(b).toEqual({ open: [], resolved: [] });
    const row = await e.DB.prepare('SELECT resolved_at FROM alerts_state WHERE key = ?').bind('blocked:npm:x@1.0.0:a').first();
    expect(row).toEqual({ resolved_at: null });
    // A's main policy block does not leak into B either
    await policy('a', [{ package: 'npm:ok@1.0.0', reason: 'r' }]);
    expect(keys((await attention(e, 'b', 30, NOW)).open)).toEqual([]);
  });

  it('silent: not for recent serves or requests, not for never-active projects', async () => {
    await project('served', 'requested', 'never', 'stale');
    await serve(['served', 'npm', 'a', '1.0.0', '2026-11-16'], ['requested', 'npm', 'a', '1.0.0', '2026-09-01']);
    await exec(
      "INSERT INTO request_counts (project_id, day, eco, kind, outcome, n) VALUES (?, ?, 'npm', 'metadata', 'served', 1)",
      ['requested', '2026-11-06'],
      ['stale', '2026-11-05'],
    );
    expect(keys((await attention(e, 'all', 30, NOW)).open)).toEqual(['silent:stale']);
  });
});

describe('attention route', () => {
  const deps: Deps = { fetch: fakeFetch({}), now: fixedClock('2026-11-19T12:00:00Z') };
  const get = (q: string) => handleDashboardApi(new Request(`https://h/dashboard/api/attention${q}`), e, deps, 'attention');

  it('validates project and range, returns no-store JSON', async () => {
    await project('p');
    expect((await get('?project=nope')).status).toBe(400);
    expect((await get('?range=5')).status).toBe(400);
    const res = await get('?project=p&range=7');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await res.json()).toEqual({ open: [], resolved: [] });
  });
});
