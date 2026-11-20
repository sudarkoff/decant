import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handle } from '../src/index';
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
  stats: number; // request_counts statements (best-effort counters)
  sql: string[];
}

/** Counts round trips (each first/all/run/raw call, each batch) and statements. */
function countingDb(db: D1Database, c: Count): D1Database {
  const real = new WeakMap<object, { s: D1PreparedStatement; sql: string }>();
  const note = (sql: string) => {
    c.stmts++;
    c.sql.push(sql.replace(/\s+/g, ' ').slice(0, 60));
    if (sql.includes('request_counts')) c.stats++;
  };
  const wrap = (s: D1PreparedStatement, sql: string): D1PreparedStatement => {
    const call =
      (m: 'first' | 'all' | 'run' | 'raw') =>
      (...a: unknown[]) => {
        c.trips++;
        note(sql);
        return (s[m] as (...x: unknown[]) => unknown)(...a);
      };
    const w = { bind: (...v: unknown[]) => wrap(s.bind(...v), sql), first: call('first'), all: call('all'), run: call('run'), raw: call('raw') };
    real.set(w, { s, sql });
    return w as unknown as D1PreparedStatement;
  };
  return {
    prepare: (q: string) => wrap(db.prepare(q), q),
    batch: (stmts: D1PreparedStatement[]) => {
      c.trips++;
      const r = stmts.map((x) => real.get(x)!);
      for (const x of r) note(x.sql);
      return db.batch(r.map((x) => x.s));
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

const fresh = (): Count => ({ trips: 0, stmts: 0, stats: 0, sql: [] });

/** Round trips for one request, after a warm-up request has cached and pinned everything. */
async function measure(path: string, accept?: string): Promise<Count> {
  expect((await request(path, fresh(), accept)).status).toBe(200);
  const c = fresh();
  expect((await request(path, c, accept)).status).toBe(200);
  return c;
}

const PATHS = {
  'npm tarball': ['/npm/calls/-/calls-1.0.0.tgz'],
  'npm packument (abbrev)': ['/npm/calls', ABBREV],
  'npm packument (full)': ['/npm/calls'],
  'go .info': ['/go/example.com/calls/@v/v1.0.0.info'],
  'go .mod': ['/go/example.com/calls/@v/v1.0.0.mod'],
  'go .zip': ['/go/example.com/calls/@v/v1.0.0.zip'],
} as const;

// Budgets: round trips on the request (and its waitUntil work), stats counters excluded.
const BUDGET: Record<keyof typeof PATHS, number> = {
  'npm tarball': 6,
  'npm packument (abbrev)': 5,
  'npm packument (full)': 5,
  'go .info': 5,
  'go .mod': 5,
  'go .zip': 6,
};

beforeAll(async () => {
  e = env as unknown as Env;
  tok = (await seedProject(e, 'calls')).read;
  // Warm the npm packument so the tarball's version is pinned.
  await request('/npm/calls', fresh());
});

describe('D1 round trips per cached request (main ref)', () => {
  const report: Record<string, string> = {};
  for (const [label, [path, accept]] of Object.entries(PATHS) as [keyof typeof PATHS, readonly [string, string?]][]) {
    it(`${label}: within budget`, async () => {
      const c = await measure(path, accept);
      report[label] = `${c.trips} trips, ${c.stmts} stmts (${c.stats} stats) :: ${c.sql.join(' | ')}`;
      expect(c.trips - c.stats).toBeLessThanOrEqual(BUDGET[label]);
    });
  }
  it('report', () => {
    console.log(`D1 calls per cached request:\n${Object.entries(report).map(([k, v]) => `  ${k}: ${v}`).join('\n')}`);
  });
});
