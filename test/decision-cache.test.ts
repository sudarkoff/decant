import { env } from 'cloudflare:workers';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { clearAuthCache, hashToken } from '../src/auth';
import { handle } from '../src/index';
import { clearDecisionCaches, POLICY_TTL_MS } from '../src/policy/decider';
import type { Deps, Env } from '../src/types';
import { fakeFetch, flakyDb, seedProject } from './helpers';

// Decision inputs are cached per isolate for POLICY_TTL_MS (30 s): a new block, allow, cooldown or
// publish-time conflict reaches every request within that bound. Nothing is served when they can't be read.

const PROXY = 'https://proxy.golang.org';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OLD = '2026-11-01T00:00:00Z'; // 18 days before T0: past the default 7-day cooldown
const YOUNG = '2026-11-18T00:00:00Z'; // inside it
const T0 = Date.parse('2026-11-19T12:00:00Z');

let e: Env;

beforeAll(() => {
  e = env as unknown as Env;
});

afterEach(() => vi.restoreAllMocks());

function goRoutes(mod: string, time = OLD) {
  const base = `${PROXY}/${mod}/@v/v1.0.0`;
  return {
    [`${base}.info`]: () => new Response(JSON.stringify({ Version: 'v1.0.0', Time: time })),
    [`${base}.mod`]: () => new Response(`module ${mod}\n`),
    [`${base}.zip`]: () => new Response('zip', { headers: { 'content-length': '3' } }),
    [OSV_BATCH]: () => new Response(JSON.stringify({ results: [{}] })),
  };
}

/** A client whose clock the test moves. */
async function client(project: string, mod: string, opts: { db?: D1Database; time?: string } = {}) {
  const tok = (await seedProject(e, project)).read;
  let t = T0;
  const deps: Deps = { fetch: fakeFetch(goRoutes(mod, opts.time)), now: () => new Date(t) };
  const envX: Env = { ...e, ...(opts.db ? { DB: opts.db } : {}) };
  const req = async (file: 'info' | 'mod' | 'zip', token = tok) => {
    const pending: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {} } as unknown as ExecutionContext;
    const r = await handle(new Request(`https://h/go/${mod}/@v/v1.0.0.${file}`, { headers: { authorization: `Bearer ${token}` } }), envX, deps, ctx);
    const body = await r.text();
    while (pending.length) await Promise.allSettled(pending.splice(0));
    return { status: r.status, body };
  };
  return { req, tok, at: (ms: number) => void (t = T0 + ms) };
}

describe('decision cache TTL', () => {
  it('a block added after a serve is enforced once the cached block list expires (≤ 30 s)', async () => {
    const c = await client('dc-block', 'example.com/dc/block');
    expect((await c.req('mod')).status).toBe(200);
    await e.DB.prepare(
      "INSERT INTO global_blocks (eco, name, version, source, reason, at) VALUES ('go', 'example.com/dc/block', 'v1.0.0', 'manual', 'bad', 'x')",
    ).run();
    c.at(POLICY_TTL_MS - 1_000);
    expect((await c.req('mod')).status).toBe(200); // still within the propagation bound
    c.at(POLICY_TTL_MS);
    expect(await c.req('mod')).toMatchObject({ status: 404, body: expect.stringContaining('blocked') });
    expect((await c.req('zip')).status).toBe(404);
  });

  it('a publish-time conflict is enforced within the TTL even though the version facts are cached', async () => {
    const c = await client('dc-conflict', 'example.com/dc/conflict');
    expect((await c.req('zip')).status).toBe(200); // stores the zip
    expect((await c.req('zip')).status).toBe(200); // served from R2; version facts now cached
    await e.DB.prepare("UPDATE versions SET conflict = 1 WHERE eco = 'go' AND name = 'example.com/dc/conflict'").run();
    c.at(POLICY_TTL_MS);
    expect((await c.req('zip')).status).toBe(404);
    expect((await c.req('mod')).status).toBe(404);
  });

  it('a new allow and a policy cooldown change both take effect once the policy view expires', async () => {
    const c = await client('dc-policy', 'example.com/dc/policy', { time: YOUNG });
    expect((await c.req('mod')).status).toBe(404); // in cooldown
    await e.DB.prepare(
      "INSERT INTO allows (project_id, ref, eco, name, version, advisory, reason, verified_at) VALUES ('dc-policy', 'main', 'go', 'example.com/dc/policy', 'v1.0.0', NULL, 'r', NULL)",
    ).run();
    expect((await c.req('mod')).status).toBe(404); // cached view
    c.at(POLICY_TTL_MS);
    expect((await c.req('mod')).status).toBe(200);

    const d = await client('dc-cool', 'example.com/dc/cool');
    expect((await d.req('mod')).status).toBe(200); // 18 days old, default cooldown 7
    await e.DB.prepare(
      `INSERT INTO policies (project_id, ref, json, sha, synced_at) VALUES ('dc-cool', 'main', '{"cooldownDays":30,"allow":[],"block":[]}', 's', 'x')`,
    ).run();
    d.at(POLICY_TTL_MS);
    expect((await d.req('mod')).status).toBe(404);
  });

  it('a revoked token stops working within 60 s', async () => {
    const c = await client('dc-tok', 'example.com/dc/tok');
    expect((await c.req('mod')).status).toBe(200);
    await e.DB.prepare('DELETE FROM tokens WHERE hash = ?').bind(await hashToken(c.tok)).run();
    c.at(59_000);
    expect((await c.req('mod')).status).toBe(200); // cached
    c.at(60_000);
    expect((await c.req('mod')).status).toBe(401);
  });

  it('an absent token is never cached: a new token works at once', async () => {
    const c = await client('dc-newtok', 'example.com/dc/newtok');
    const fresh = 'dk_read_brand-new-token';
    expect((await c.req('mod', fresh)).status).toBe(401);
    await e.DB.prepare("INSERT INTO tokens (hash, project_id, kind, created_at) VALUES (?, 'dc-newtok', 'read', 'x')")
      .bind(await hashToken(fresh))
      .run();
    expect((await c.req('mod', fresh)).status).toBe(200);
  });
});

describe('fail-closed', () => {
  it('a decision read that fails after every retry is a 502 with a logged reason, never a serve', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const seed = await client('dc-fail-seed', 'example.com/dc/fail');
    expect((await seed.req('zip')).status).toBe(200); // pinned and stored
    // Same token, a D1 whose policy reads always fail, and an expired cache.
    const db = flakyDb(e.DB, (sql) => sql.includes('global_blocks'));
    const c = await client('dc-fail', 'example.com/dc/fail', { db });
    c.at(POLICY_TTL_MS * 2);
    const r = await c.req('zip');
    expect(r).toEqual({ status: 502, body: 'decant: internal error' });
    expect(db.failures).toBe(3); // first try + 2 retries
    const line = err.mock.calls.map((a) => String(a[0])).find((l) => l.startsWith('decant: internal error'));
    expect(line).toMatch(/^decant: internal error \(go\): Error: D1_ERROR: D1 DB is overloaded/);
  });

  it('a burst where every D1 call is shed twice before it succeeds: every cached request is served', async () => {
    const seed = await client('dc-burst', 'example.com/dc/burst');
    const mods = Array.from({ length: 10 }, (_, i) => `example.com/dc/burst${i}`);
    const routes = Object.assign({}, ...mods.map((m) => goRoutes(m)));
    // Warm R2 and D1 (pinned, stored), then drop this isolate's caches.
    const warm: Deps = { fetch: fakeFetch(routes), now: () => new Date(T0) };
    const go = (db: D1Database, deps: Deps, m: string, ext: string) => {
      const pending: Promise<unknown>[] = [];
      const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {} } as unknown as ExecutionContext;
      return handle(new Request(`https://h/go/${m}/@v/v1.0.0.${ext}`, { headers: { authorization: `Bearer ${seed.tok}` } }), { ...e, DB: db }, deps, ctx).then(
        async (r) => ({ status: r.status, body: await r.text(), done: await Promise.allSettled(pending) }),
      );
    };
    for (const m of mods) expect((await go(e.DB, warm, m, 'zip')).status).toBe(200);

    // Every statement or batch fails its first two attempts with an overload error (D1 shedding load).
    let shed = 0;
    const tries = new WeakMap<object, number>();
    const overloaded = (key: object) => {
      const n = (tries.get(key) ?? 0) + 1;
      tries.set(key, n);
      if (n <= 2) {
        shed++;
        throw new Error('D1_ERROR: D1 DB is overloaded. Requests queued for too long.');
      }
    };
    const real = new WeakMap<object, D1PreparedStatement>();
    const wrap = (s: D1PreparedStatement): D1PreparedStatement => {
      const w: Record<string, unknown> = {
        bind: (...v: unknown[]) => wrap(s.bind(...v)),
        first: async (c?: string) => (overloaded(w), c === undefined ? s.first() : s.first(c)),
        all: async () => (overloaded(w), s.all()),
        run: async () => (overloaded(w), s.run()),
        raw: async () => (overloaded(w), s.raw()),
      };
      real.set(w, s);
      return w as unknown as D1PreparedStatement;
    };
    const db = {
      prepare: (q: string) => wrap(e.DB.prepare(q)),
      batch: async (stmts: D1PreparedStatement[]) => (overloaded(stmts[0]!), e.DB.batch(stmts.map((s) => real.get(s) ?? s))),
    } as unknown as D1Database;

    vi.spyOn(console, 'error').mockImplementation(() => {});
    clearAuthCache();
    clearDecisionCaches();
    const later: Deps = { fetch: fakeFetch(routes), now: () => new Date(T0 + 1_000) };
    const results = await Promise.all(mods.flatMap((m) => ['zip', 'mod', 'info'].map((ext) => go(db, later, m, ext))));
    expect(results.map((r) => r.status)).toEqual(Array(30).fill(200));
    expect(shed).toBeGreaterThan(0);
  });

  it('an overload error is retried and the request is served', async () => {
    let n = 0;
    const db = flakyDb(e.DB, (sql) => sql.includes('global_blocks') && n++ < 2);
    const c = await client('dc-retry', 'example.com/dc/retry', { db });
    expect((await c.req('mod')).status).toBe(200);
    expect(db.failures).toBe(2);
  });
});
