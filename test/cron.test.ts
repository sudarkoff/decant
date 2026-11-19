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
