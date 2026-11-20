import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { runScheduled } from '../src/cron';
import { blockedVersions } from '../src/policy/store';
import type { Env } from '../src/types';

const e = env as unknown as Env;
const NOW = new Date('2026-11-19T00:00:00.000Z');
const day = (n: number) => new Date(NOW.getTime() - n * 86400_000).toISOString();

async function addVersion(name: string, version: string, checked: string | null = null): Promise<void> {
  await e.DB.prepare(
    'INSERT INTO versions (eco, name, version, publish_time, first_seen, stored_at, osv_checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).bind('npm', name, version, day(100), day(100), day(50), checked).run();
}

function osvFetch(flag: Set<string>, status = 200): typeof fetch {
  return (async (_u: RequestInfo | URL, init?: RequestInit) => {
    if (status !== 200) return new Response('x', { status });
    const body = JSON.parse(String(init!.body)) as { queries: { package: { name: string } }[] };
    const results = body.queries.map((q) => (flag.has(q.package.name) ? { vulns: [{ id: 'MAL-2026-1' }] } : {}));
    return Response.json({ results });
  }) as typeof fetch;
}

async function checkedAt(name: string): Promise<string | null> {
  const r = await e.DB.prepare('SELECT osv_checked_at AS c FROM versions WHERE name = ?').bind(name).first<{ c: string | null }>();
  return r!.c;
}

describe('OSV re-check', () => {
  it('flags malicious versions and marks all checked', async () => {
    for (const n of ['c-a', 'c-b', 'c-c']) await addVersion(n, '1.0.0');
    const res = await runScheduled(e, { fetch: osvFetch(new Set(['c-b'])), now: () => NOW });
    expect(res.checked).toBe(3);
    expect(res.blocked).toBe(1);
    expect([...(await blockedVersions(e, 'npm', 'c-b'))]).toEqual(['1.0.0']);
    expect(await checkedAt('c-a')).toBe(NOW.toISOString());
  });

  it('does nothing when OSV is down, but still expires overlays', async () => {
    await e.DB.prepare('DELETE FROM versions').run();
    await addVersion('d-a', '1.0.0');
    await e.DB.prepare('INSERT INTO projects (id, created_at) VALUES (?, ?)').bind('pd', day(90)).run();
    await e.DB.prepare('INSERT INTO policies (project_id, ref, json, sha, synced_at) VALUES (?, ?, ?, ?, ?)')
      .bind('pd', 'old', '{}', 's', day(15)).run();
    const res = await runScheduled(e, { fetch: osvFetch(new Set(), 500), now: () => NOW });
    expect(res).toEqual({ checked: 0, blocked: 0, overlaysExpired: 1 });
    expect(await checkedAt('d-a')).toBeNull();
  });

  it('checks never-checked versions first', async () => {
    await e.DB.prepare('DELETE FROM versions').run();
    await addVersion('o-old', '1.0.0', day(5));
    await addVersion('o-new', '1.0.0', null);
    const seen: string[] = [];
    const f = (async (_u: RequestInfo | URL, init?: RequestInit) => {
      const b = JSON.parse(String(init!.body)) as { queries: { package: { name: string } }[] };
      seen.push(...b.queries.map((q) => q.package.name));
      return Response.json({ results: b.queries.map(() => ({})) });
    }) as typeof fetch;
    await runScheduled(e, { fetch: f, now: () => NOW });
    expect(seen).toEqual(['o-new', 'o-old']);
  });
});

interface VulnRow { name: string; id: string; severity: string; summary: string | null; published: string | null }

/** OSV mock: querybatch returns ids per package name; GET /v1/vulns/<id> returns records. */
function vulnFetch(ids: Record<string, string[]>, records: Record<string, object>, calls: string[] = []): typeof fetch {
  return (async (u: RequestInfo | URL, init?: RequestInit) => {
    const url = String(u);
    if (init?.method === 'GET') {
      calls.push(url);
      const rec = records[decodeURIComponent(url.split('/').pop()!)];
      return rec ? Response.json(rec) : new Response('nf', { status: 404 });
    }
    const body = JSON.parse(String(init!.body)) as { queries: { package: { name: string } }[] };
    return Response.json({ results: body.queries.map((q) => ({ vulns: (ids[q.package.name] ?? []).map((id) => ({ id })) })) });
  }) as typeof fetch;
}

const REC = {
  'GHSA-a': { id: 'GHSA-a', summary: 'Bad thing', published: '2026-01-01T00:00:00Z', database_specific: { severity: 'HIGH' } },
  'MAL-1': { id: 'MAL-1', summary: 'Malware', published: '2026-02-01T00:00:00Z' },
};

async function vulnRows(name: string): Promise<VulnRow[]> {
  return (await e.DB.prepare('SELECT name, id, severity, summary, published FROM vulns WHERE name = ? ORDER BY id').bind(name).all<VulnRow>()).results;
}

describe('vulnerability recording', () => {
  it('stores a row per id with severity, and still blocks MAL', async () => {
    await e.DB.prepare('DELETE FROM versions').run();
    await e.DB.prepare('DELETE FROM vulns').run();
    await addVersion('v-a', '1.0.0');
    await runScheduled(e, { fetch: vulnFetch({ 'v-a': ['GHSA-a', 'MAL-1'] }, REC), now: () => NOW });
    expect(await vulnRows('v-a')).toEqual([
      { name: 'v-a', id: 'GHSA-a', severity: 'high', summary: 'Bad thing', published: '2026-01-01T00:00:00Z' },
      { name: 'v-a', id: 'MAL-1', severity: 'unknown', summary: 'Malware', published: '2026-02-01T00:00:00Z' },
    ]);
    expect([...(await blockedVersions(e, 'npm', 'v-a'))]).toEqual(['1.0.0']);
  });

  it('deletes a row whose id is gone on the next run', async () => {
    await runScheduled(e, { fetch: vulnFetch({ 'v-a': ['MAL-1'] }, REC), now: () => NOW });
    expect((await vulnRows('v-a')).map((r) => r.id)).toEqual(['MAL-1']);
  });

  it('leaves rows untouched when OSV is down', async () => {
    await runScheduled(e, { fetch: osvFetch(new Set(), 500), now: () => NOW });
    expect((await vulnRows('v-a')).map((r) => r.id)).toEqual(['MAL-1']);
  });

  it('does not re-fetch an id whose details came back empty', async () => {
    await e.DB.prepare('DELETE FROM versions').run();
    await e.DB.prepare('DELETE FROM vulns').run();
    await addVersion('v-empty', '1.0.0');
    const records = { 'MAL-9': { id: 'MAL-9' } };
    const c1: string[] = [];
    await runScheduled(e, { fetch: vulnFetch({ 'v-empty': ['MAL-9', 'GHSA-404'] }, records, c1), now: () => NOW });
    expect(c1).toHaveLength(2);
    const c2: string[] = [];
    await runScheduled(e, { fetch: vulnFetch({ 'v-empty': ['MAL-9', 'GHSA-404'] }, records, c2), now: () => NOW });
    expect(c2).toHaveLength(0);
  });

  it('still blocks MAL and marks checked when recording vulns fails', async () => {
    await e.DB.prepare('DELETE FROM versions').run();
    await addVersion('v-fail', '1.0.0');
    const db = new Proxy(e.DB, {
      get(t, k) {
        if (k === 'prepare') {
          return (sql: string) => {
            if (/vulns/.test(sql)) throw new Error('boom');
            return t.prepare(sql);
          };
        }
        const v = Reflect.get(t, k) as unknown;
        return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
    const bad = { ...e, DB: db } as unknown as Env;
    await runScheduled(bad, { fetch: vulnFetch({ 'v-fail': ['MAL-1'] }, REC), now: () => NOW });
    expect([...(await blockedVersions(e, 'npm', 'v-fail'))]).toEqual(['1.0.0']);
    expect(await checkedAt('v-fail')).toBe(NOW.toISOString());
  });

  it('blocks MAL in every batch before any detail fetch, even when detail fetching fails', async () => {
    await e.DB.prepare('DELETE FROM versions').run();
    for (let i = 0; i < 1001; i++) await addVersion(`mb-${String(i).padStart(4, '0')}`, '1.0.0', i === 1000 ? null : day(1));
    const order: string[] = [];
    const f = (async (u: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'GET') { order.push('GET'); throw new Error('detail down'); }
      order.push('POST');
      const body = JSON.parse(String(init!.body)) as { queries: { package: { name: string } }[] };
      return Response.json({ results: body.queries.map((q) => (q.package.name === 'mb-0000' || q.package.name === 'mb-1000' ? { vulns: [{ id: 'MAL-1' }] } : {})) });
    }) as typeof fetch;
    await runScheduled(e, { fetch: f, now: () => NOW });
    expect([...(await blockedVersions(e, 'npm', 'mb-0000'))]).toEqual(['1.0.0']);
    expect([...(await blockedVersions(e, 'npm', 'mb-1000'))]).toEqual(['1.0.0']);
    expect(order.filter((x) => x === 'POST')).toHaveLength(2);
    expect(order.indexOf('GET')).toBeGreaterThan(order.lastIndexOf('POST'));
    await e.DB.prepare('DELETE FROM versions').run();
  });

  it('caps detail fetches at 200 per run, stores placeholders, and fills them later', async () => {
    await e.DB.prepare('DELETE FROM versions').run();
    await e.DB.prepare('DELETE FROM vulns').run();
    const all = Array.from({ length: 205 }, (_, i) => `GHSA-${i}`);
    const records = Object.fromEntries(all.map((id) => [id, { id, summary: `s ${id}`, database_specific: { severity: 'LOW' } }]));
    await addVersion('v-big', '1.0.0');
    const calls: string[] = [];
    await runScheduled(e, { fetch: vulnFetch({ 'v-big': all }, records, calls), now: () => NOW });
    expect(calls).toHaveLength(200);
    const rows = await vulnRows('v-big');
    expect(rows).toHaveLength(205);
    expect(rows.filter((r) => r.severity === 'unknown' && r.summary === '' && r.published === null)).toHaveLength(5);
    const calls2: string[] = [];
    await runScheduled(e, { fetch: vulnFetch({ 'v-big': all }, records, calls2), now: () => NOW });
    expect(calls2).toHaveLength(5);
    expect((await vulnRows('v-big')).filter((r) => r.severity === 'unknown')).toHaveLength(0);
  });
});

describe('overlay expiry', () => {
  it('removes stale overlays, keeps fresh ones, never touches main', async () => {
    await e.DB.prepare('DELETE FROM policies').run();
    await e.DB.prepare('DELETE FROM allows').run();
    await e.DB.prepare('DELETE FROM versions').run();
    await e.DB.prepare('INSERT INTO projects (id, main_ref, created_at) VALUES (?, ?, ?)').bind('pe', 'main', day(90)).run();
    const pol = e.DB.prepare('INSERT INTO policies (project_id, ref, json, sha, synced_at) VALUES (?, ?, ?, ?, ?)');
    const al = e.DB.prepare('INSERT INTO allows (project_id, ref, eco, name, version, reason) VALUES (?, ?, ?, ?, ?, ?)');
    await e.DB.batch([
      pol.bind('pe', 'main', '{}', 's', day(100)),
      pol.bind('pe', 'stale', '{}', 's', day(15)),
      pol.bind('pe', 'fresh', '{}', 's', day(13)),
      al.bind('pe', 'main', 'npm', 'x', '1.0.0', 'r'),
      al.bind('pe', 'stale', 'npm', 'x', '1.0.0', 'r'),
      al.bind('pe', 'fresh', 'npm', 'x', '1.0.0', 'r'),
    ]);
    const res = await runScheduled(e, { fetch: osvFetch(new Set()), now: () => NOW });
    expect(res.overlaysExpired).toBe(1);
    const refs = async (t: string) =>
      (await e.DB.prepare(`SELECT ref FROM ${t} ORDER BY ref`).all<{ ref: string }>()).results.map((r) => r.ref);
    expect(await refs('policies')).toEqual(['fresh', 'main']);
    expect(await refs('allows')).toEqual(['fresh', 'main']);
  });
});
