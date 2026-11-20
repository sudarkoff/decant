import { env } from 'cloudflare:workers';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { clearAuthCache } from '../src/auth';
import { handle } from '../src/index';
import { clearDecisionCaches } from '../src/policy/decider';
import { clearServeLogCache } from '../src/policy/store';
import { configureStatsBuffer, STATS_INTERVAL_MS, STATS_MAX_PENDING } from '../src/stats/record';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock, seedProject } from './helpers';

// D1 round trips per request on the hot path: a package already cached in R2 and pinned in D1.
// Incident 2026-11-20: a parallel `npm ci` + `go mod download` drove D1 to ~23k reads/min and queued
// statements failed. These budgets keep a cached request to a handful of round trips.

const REG = 'https://registry.npmjs.org';
const PROXY = 'https://proxy.golang.org';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const ABBREV = 'application/vnd.npm.install-v1+json';
const OLD = '2026-11-01T00:00:00.000Z';
const now = fixedClock('2026-11-19T12:00:00Z');

interface Count {
  trips: number;
  stmts: number;
  rows: number; // meta.rows_read, what D1 bills
  stats: number; // request_counts statements (best-effort counters)
  sql: string[];
}

/** Counts round trips (each first/all/run/raw call, each batch), statements and rows read. */
function countingDb(db: D1Database, c: Count): D1Database {
  const real = new WeakMap<object, { s: D1PreparedStatement; sql: string }>();
  const note = (sql: string) => {
    c.stmts++;
    c.sql.push(sql.replace(/\s+/g, ' ').slice(0, 60));
    if (sql.includes('request_counts')) c.stats++;
  };
  const rows = (meta: unknown) => {
    c.rows += (meta as { rows_read?: number } | undefined)?.rows_read ?? 0;
  };
  const wrap = (s: D1PreparedStatement, sql: string): D1PreparedStatement => {
    const start = () => {
      c.trips++;
      note(sql);
    };
    const w = {
      bind: (...v: unknown[]) => wrap(s.bind(...v), sql),
      // first() returns no meta: run it as all().
      first: async (col?: string) => {
        start();
        const r = await s.all<Record<string, unknown>>();
        rows(r.meta);
        const row = r.results[0];
        return row === undefined ? null : col === undefined ? row : row[col];
      },
      all: async () => (start(), s.all().then((r) => (rows(r.meta), r))),
      run: async () => (start(), s.run().then((r) => (rows(r.meta), r))),
      raw: () => {
        throw new Error('countingDb: raw() not supported');
      },
    };
    real.set(w, { s, sql });
    return w as unknown as D1PreparedStatement;
  };
  return {
    prepare: (q: string) => wrap(db.prepare(q), q),
    batch: async (stmts: D1PreparedStatement[]) => {
      c.trips++;
      const r = stmts.map((x) => real.get(x)!);
      for (const x of r) note(x.sql);
      const res = await db.batch(r.map((x) => x.s));
      for (const x of res) rows(x.meta);
      return res;
    },
    exec: (q: string) => db.exec(q),
  } as unknown as D1Database;
}

let e: Env;
let tok: string;

async function routes(): Promise<Record<string, Response | ((r: Request) => Response)>> {
  const tgz = new TextEncoder().encode('tarball-bytes');
  const d = new Uint8Array(await crypto.subtle.digest('SHA-512', tgz));
  const integrity = `sha512-${btoa(String.fromCharCode(...d))}`;
  const versions = { '1.0.0': { name: 'calls', version: '1.0.0', dist: { tarball: `${REG}/calls/-/calls-1.0.0.tgz`, integrity } } };
  const full = { name: 'calls', 'dist-tags': { latest: '1.0.0' }, versions, time: { '1.0.0': OLD } };
  const abbrev = { name: 'calls', 'dist-tags': { latest: '1.0.0' }, versions };
  const base = `${PROXY}/example.com/calls/@v/v1.0.0`;
  return {
    [`${REG}/calls`]: (r) =>
      new Response(JSON.stringify((r.headers.get('accept') ?? '').includes(ABBREV) ? abbrev : full)),
    [`${REG}/calls/-/calls-1.0.0.tgz`]: () => new Response(tgz, { headers: { 'content-length': String(tgz.length) } }),
    [OSV_BATCH]: () => new Response(JSON.stringify({ results: [{}] })),
    [`${base}.info`]: () => new Response(JSON.stringify({ Version: 'v1.0.0', Time: OLD })),
    [`${base}.mod`]: () => new Response('module example.com/calls\n'),
    [`${base}.zip`]: () => new Response('zip', { headers: { 'content-length': '3' } }),
  };
}

async function request(path: string, c: Count, accept?: string): Promise<Response> {
  const deps: Deps = { fetch: fakeFetch(await routes()), now };
  const pending: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {} } as unknown as ExecutionContext;
  const headers = new Headers({ authorization: `Bearer ${tok}` });
  if (accept) headers.set('accept', accept);
  const r = await handle(new Request(`https://h${path}`, { headers }), { ...e, DB: countingDb(e.DB, c) }, deps, ctx);
  await r.arrayBuffer();
  while (pending.length) await Promise.allSettled(pending.splice(0));
  return r;
}

const fresh = (): Count => ({ trips: 0, stmts: 0, rows: 0, stats: 0, sql: [] });

/**
 * Round trips for one request after a warm-up request has stored and pinned everything: `cold` with this
 * isolate's caches emptied first (a new isolate, or 30 s later), `warm` right after another request.
 */
async function measure(path: string, accept?: string): Promise<{ cold: Count; warm: Count }> {
  expect((await request(path, fresh(), accept)).status).toBe(200);
  clearAuthCache();
  clearDecisionCaches();
  clearServeLogCache();
  const cold = fresh();
  expect((await request(path, cold, accept)).status).toBe(200);
  const warm = fresh();
  expect((await request(path, warm, accept)).status).toBe(200);
  return { cold, warm };
}

const PATHS = {
  'npm tarball': ['/npm/calls/-/calls-1.0.0.tgz'],
  'npm packument (abbrev)': ['/npm/calls', ABBREV],
  'npm packument (full)': ['/npm/calls'],
  'go .info': ['/go/example.com/calls/@v/v1.0.0.info'],
  'go .mod': ['/go/example.com/calls/@v/v1.0.0.mod'],
  'go .zip': ['/go/example.com/calls/@v/v1.0.0.zip'],
} as const;

// Budgets: round trips on the request and its waitUntil work, request counts included (buffered: the
// test isolate flushes every 10 s or 200 requests, as in production), and rows read on a cold isolate.
// The project has 300 allows for other packages: a cold request must not read them.
// Before the fix every row was 5–6 round trips and 6–7 statements.
const BUDGET: Record<keyof typeof PATHS, { cold: number; warm: number; coldRows: number }> = {
  'npm tarball': { cold: 3, warm: 0, coldRows: 10 },
  'npm packument (abbrev)': { cold: 2, warm: 0, coldRows: 10 },
  'npm packument (full)': { cold: 2, warm: 0, coldRows: 10 },
  'go .info': { cold: 2, warm: 0, coldRows: 10 },
  'go .mod': { cold: 2, warm: 0, coldRows: 10 },
  'go .zip': { cold: 3, warm: 0, coldRows: 10 },
};

beforeAll(async () => {
  configureStatsBuffer({ intervalMs: STATS_INTERVAL_MS, maxPending: STATS_MAX_PENDING, timer: false });
  e = env as unknown as Env;
  tok = (await seedProject(e, 'calls')).read;
  await e.DB.prepare(
    `INSERT INTO allows (project_id, ref, eco, name, version, advisory, reason, verified_at)
     SELECT 'calls', 'main', 'npm', 'other-' || value, '1.0.0', NULL, 'r', NULL FROM json_each(?)`,
  )
    .bind(JSON.stringify(Array.from({ length: 300 }, (_, i) => i)))
    .run();
  // Warm the npm packument so the tarball's version is pinned.
  await request('/npm/calls', fresh());
});

afterAll(() => configureStatsBuffer({ intervalMs: 0, timer: true }));

describe('D1 round trips per cached request (main ref)', () => {
  const report: Record<string, string> = {};
  for (const [label, [path, accept]] of Object.entries(PATHS) as [keyof typeof PATHS, readonly [string, string?]][]) {
    it(`${label}: within budget`, async () => {
      const { cold, warm } = await measure(path, accept);
      const line = (c: Count) => `${c.trips} trips/${c.stmts} stmts/${c.rows} rows${c.stats ? ` (${c.stats} stats)` : ''}`;
      report[label] = `cold ${line(cold)}, warm ${line(warm)} :: ${cold.sql.join(' | ')}`;
      const b = BUDGET[label];
      expect({ cold: cold.trips, warm: warm.trips }).toEqual({ cold: b.cold, warm: b.warm });
      expect(cold.rows).toBeLessThanOrEqual(b.coldRows);
      expect(warm.rows).toBe(0);
    });
  }
  it('report', () => {
    console.log(`D1 calls per cached request:\n${Object.entries(report).map(([k, v]) => `  ${k}: ${v}`).join('\n')}`);
  });
});
