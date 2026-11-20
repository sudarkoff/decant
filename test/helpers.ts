import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { hashToken, newToken } from '../src/auth';
import { configureStatsBuffer } from '../src/stats/record';
import type { Env } from '../src/types';

// Setup (runs via vitest setupFiles): apply migrations/ to the test D1.
// Request counts are written on every request in tests (production buffers them; see stats/record.ts).
configureStatsBuffer({ intervalMs: 0 });
await applyD1Migrations(
  (env as unknown as Env).DB,
  (env as unknown as { TEST_MIGRATIONS: Parameters<typeof applyD1Migrations>[1] }).TEST_MIGRATIONS,
);

export function fixedClock(iso: string): () => Date {
  return () => new Date(iso);
}

type Route = Response | ((req: Request) => Response | Promise<Response>);

export function fakeFetch(routes: Record<string, Route>): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const fn = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const req = new Request(input, init);
    calls.push(req.url);
    const route = routes[req.url];
    if (route === undefined) throw new Error(`fakeFetch: unexpected URL ${req.url}`);
    return typeof route === 'function' ? route(req) : route.clone();
  };
  return Object.assign(fn, { calls }) as typeof fetch & { calls: string[] };
}

export async function seedProject(env: Env, id: string): Promise<{ read: string; ci: string; sync: string }> {
  const read = newToken('read');
  const ci = newToken('ci');
  const sync = newToken('sync');
  const at = '2026-11-19T00:00:00Z';
  await env.DB.batch([
    env.DB.prepare('INSERT INTO projects (id, created_at) VALUES (?, ?)').bind(id, at),
    env.DB.prepare('INSERT INTO tokens (hash, project_id, kind, created_at) VALUES (?, ?, ?, ?)').bind(
      await hashToken(read), id, 'read', at),
    env.DB.prepare('INSERT INTO tokens (hash, project_id, kind, created_at) VALUES (?, ?, ?, ?)').bind(
      await hashToken(ci), id, 'ci', at),
    env.DB.prepare('INSERT INTO tokens (hash, project_id, kind, created_at) VALUES (?, ?, ?, ?)').bind(
      await hashToken(sync), id, 'sync', at),
  ]);
  return { read, ci, sync };
}

/** A route that never answers but honors the request's abort signal, like a hung upstream. */
export function hang(): (req: Request) => Promise<Response> {
  return (req) =>
    new Promise((_, reject) => {
      if (req.signal.aborted) return reject(req.signal.reason);
      req.signal.addEventListener('abort', () => reject(req.signal.reason));
    });
}

/**
 * Wraps a D1 binding so statements whose SQL matches `fail` throw a D1-style transient error
 * whenever `fail` returns true for them. A batch fails if any statement in it would.
 * With `lostAck`, a statement's run() executes first and then throws (the write landed, the answer was lost).
 */
export function flakyDb(
  db: D1Database,
  fail: (sql: string) => boolean,
  opts: { lostAck?: boolean } = {},
): D1Database & { failures: number } {
  const real = new WeakMap<object, { s: D1PreparedStatement; sql: string }>();
  let failures = 0;
  const boom = (sql: string) => {
    if (!fail(sql)) return;
    failures++;
    throw new Error('D1_ERROR: D1 DB is overloaded. Too many requests queued. SQLITE_BUSY');
  };
  const wrap = (s: D1PreparedStatement, sql: string): D1PreparedStatement => {
    const w = {
      bind: (...v: unknown[]) => wrap(s.bind(...v), sql),
      first: async (c?: string) => (boom(sql), c === undefined ? s.first() : s.first(c)),
      run: async () => {
        if (!opts.lostAck) return boom(sql), s.run();
        const r = await s.run();
        boom(sql);
        return r;
      },
      all: async () => (boom(sql), s.all()),
      raw: async () => (boom(sql), s.raw()),
    };
    real.set(w, { s, sql });
    return w as unknown as D1PreparedStatement;
  };
  return {
    prepare: (q: string) => wrap(db.prepare(q), q),
    batch: async (stmts: D1PreparedStatement[]) => {
      const r = stmts.map((x) => real.get(x)!);
      if (!opts.lostAck) {
        for (const x of r) boom(x.sql);
        return db.batch(r.map((x) => x.s));
      }
      const res = await db.batch(r.map((x) => x.s));
      for (const x of r) boom(x.sql);
      return res;
    },
    exec: (q: string) => db.exec(q),
    get failures() {
      return failures;
    },
  } as unknown as D1Database & { failures: number };
}
