import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handle } from '../src/index';
import { pinPublishTimes } from '../src/policy/store';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock, seedProject } from './helpers';

// D1 bills rows scanned. These budgets guard against queries whose reads grow with N² (or with
// the size of unrelated tables) on a package with many versions.

const REG = 'https://registry.npmjs.org';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const ABBREV = 'application/vnd.npm.install-v1+json';
const NAME = 'huge';
const N = 4_000;
const OLD = '2026-01-01T00:00:00.000Z';
const now = fixedClock('2026-11-19T12:00:00Z');

let e: Env;
let tok: string;

/** Wraps a D1 database so every statement's meta.rows_read is added to `counter.rows`. */
function countingDb(db: D1Database, counter: { rows: number }): D1Database {
  const real = new WeakMap<object, D1PreparedStatement>();
  const add = (meta: unknown) => {
    counter.rows += (meta as { rows_read?: number } | undefined)?.rows_read ?? 0;
  };
  const wrap = (stmt: D1PreparedStatement): D1PreparedStatement => {
    const p = new Proxy(stmt, {
      get(target, prop) {
        if (prop === 'bind') return (...args: unknown[]) => wrap(target.bind(...args));
        if (prop === 'run' || prop === 'all')
          return async () => {
            const r = await target[prop]();
            add(r.meta);
            return r;
          };
        // first() and raw() return no meta: route them through all().
        if (prop === 'first')
          return async (col?: string) => {
            const r = await target.all<Record<string, unknown>>();
            add(r.meta);
            const row = r.results[0];
            if (!row) return null;
            return col === undefined ? row : row[col];
          };
        if (prop === 'raw') throw new Error('countingDb: raw() not supported');
        const v = Reflect.get(target, prop, target);
        return typeof v === 'function' ? v.bind(target) : v;
      },
    });
    real.set(p, stmt);
    return p;
  };
  return new Proxy(db, {
    get(target, prop) {
      if (prop === 'prepare') return (sql: string) => wrap(target.prepare(sql));
      if (prop === 'batch')
        return async (stmts: D1PreparedStatement[]) => {
          const rs = await target.batch(stmts.map((s) => real.get(s) ?? s));
          for (const r of rs) add(r.meta);
          return rs;
        };
      const v = Reflect.get(target, prop, target);
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
}

function versionList(n: number): string[] {
  return Array.from({ length: n }, (_, i) => `${Math.floor(i / 100)}.${i % 100}.0`);
}

function docs(times: Record<string, string>) {
  const tgz = new TextEncoder().encode('tarball-bytes');
  const versions = Object.fromEntries(
    Object.keys(times).map((v) => [v, { name: NAME, version: v, dist: { tarball: `${REG}/${NAME}/-/${NAME}-${v}.tgz`, shasum: 'x' } }]),
  );
  const full = { name: NAME, 'dist-tags': { latest: '0.0.0' }, versions, time: { created: OLD, modified: OLD, ...times } };
  const abbrev = { name: NAME, modified: OLD, 'dist-tags': { latest: '0.0.0' }, versions };
  return { tgz, full, abbrev };
}

function client(counter: { rows: number }) {
  const times = Object.fromEntries(versionList(N).map((v) => [v, OLD]));
  const { tgz, full, abbrev } = docs(times);
  const f = fakeFetch({
    [`${REG}/${NAME}`]: (r) =>
      (r.headers.get('accept') ?? '').includes(ABBREV)
        ? new Response(JSON.stringify(abbrev), { headers: { 'content-type': ABBREV } })
        : new Response(JSON.stringify(full), { headers: { 'content-type': 'application/json' } }),
    [`${REG}/${NAME}/-/${NAME}-0.0.0.tgz`]: () => new Response(tgz, { headers: { 'content-length': String(tgz.length) } }),
    [OSV_BATCH]: () => new Response(JSON.stringify({ results: [{}] })),
  });
  const deps: Deps = { fetch: f, now };
  const counted = { ...e, DB: countingDb(e.DB, counter) } as Env;
  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil: (p: Promise<unknown>) => void pending.push(p),
    passThroughOnException() {},
  } as unknown as ExecutionContext;
  return async (path: string, accept?: string) => {
    const headers = new Headers({ authorization: `Bearer ${tok}` });
    if (accept) headers.set('accept', accept);
    const r = await handle(new Request(`https://h${path}`, { headers }), counted, deps, ctx);
    await Promise.allSettled(pending.splice(0));
    return r;
  };
}

async function measure(fn: (req: ReturnType<typeof client>) => Promise<Response>): Promise<number> {
  const counter = { rows: 0 };
  const r = await fn(client(counter));
  expect(r.status).toBe(200);
  await r.arrayBuffer();
  return counter.rows;
}

beforeAll(async () => {
  e = env as unknown as Env;
  tok = (await seedProject(e, 'dr')).read;
  // 20,000 unrelated version rows across 200 other packages.
  for (let p = 0; p < 200; p += 20) {
    const stmts = [];
    for (let q = p; q < p + 20; q++) {
      stmts.push(
        e.DB.prepare(
          `INSERT INTO versions (eco, name, version, publish_time, first_seen) SELECT 'npm', ?1, value, ?2, ?2 FROM json_each(?3)`,
        ).bind(`other-${q}`, OLD, JSON.stringify(versionList(100))),
      );
    }
    await e.DB.batch(stmts);
  }
  // Allows and blocks: some for this package, many for others.
  const allows = [];
  for (let i = 0; i < 500; i++) {
    allows.push(
      e.DB.prepare("INSERT INTO allows (project_id, ref, eco, name, version, advisory, reason, verified_at) VALUES ('dr', 'main', 'npm', ?, ?, NULL, 'r', NULL)").bind(`other-${i % 200}`, `9.${i}.0`),
    );
  }
  allows.push(e.DB.prepare("INSERT INTO allows (project_id, ref, eco, name, version, advisory, reason, verified_at) VALUES ('dr', 'main', 'npm', ?, '1.1.0', NULL, 'r', NULL)").bind(NAME));
  allows.push(e.DB.prepare("INSERT INTO global_blocks VALUES ('npm', ?, '1.2.0', 'manual', 'bad', 'x')").bind(NAME));
  allows.push(e.DB.prepare("INSERT INTO global_blocks VALUES ('npm', 'other-1', '0.1.0', 'manual', 'bad', 'x')"));
  await e.DB.batch(allows);
});

describe('D1 rows_read budgets (4,000-version npm package)', () => {
  const reads: Record<string, number> = {};

  it('cold full-metadata request pins all versions under 50,000 rows_read', async () => {
    reads.cold = await measure((req) => req(`/npm/${NAME}`));
    console.log(`rows_read cold full-metadata pin: ${reads.cold}`);
    expect(reads.cold).toBeLessThan(50_000);
  });

  it('warm full-metadata request under 20,000 rows_read', async () => {
    reads.warm = await measure((req) => req(`/npm/${NAME}`));
    console.log(`rows_read warm full-metadata: ${reads.warm}`);
    expect(reads.warm).toBeLessThan(20_000);
  });

  it('warm abbreviated request under 20,000 rows_read', async () => {
    reads.abbrev = await measure((req) => req(`/npm/${NAME}`, ABBREV));
    console.log(`rows_read warm abbreviated: ${reads.abbrev}`);
    expect(reads.abbrev).toBeLessThan(20_000);
  });

  it('tarball request under 1,000 rows_read', async () => {
    reads.tarball = await measure((req) => req(`/npm/${NAME}/-/${NAME}-0.0.0.tgz`));
    console.log(`rows_read tarball: ${reads.tarball}`);
    expect(reads.tarball).toBeLessThan(1_000);
  });
});

describe('pinPublishTimes conflict handling', () => {
  it('marks only the changed version conflicted and keeps its stored time', async () => {
    const T1 = new Date('2026-01-01T00:00:00.000Z');
    const T2 = new Date('2026-02-01T00:00:00.000Z');
    const vs = versionList(50);
    await pinPublishTimes(e, 'npm', 'drift', new Map(vs.map((v) => [v, T1])), new Date(OLD));
    const next = new Map(vs.map((v) => [v, T1]));
    next.set('0.7.0', T2);
    next.set('9.9.9', T2); // new version alongside
    const out = await pinPublishTimes(e, 'npm', 'drift', next, new Date(OLD));
    expect(out.get('0.7.0')).toEqual({ publishTime: T1, conflict: true });
    expect(out.get('9.9.9')).toEqual({ publishTime: T2, conflict: false });
    for (const v of vs) if (v !== '0.7.0') expect(out.get(v)).toEqual({ publishTime: T1, conflict: false });
    const rows = await e.DB.prepare("SELECT version, publish_time, conflict FROM versions WHERE eco = 'npm' AND name = 'drift' AND conflict = 1").all();
    expect(rows.results).toEqual([{ version: '0.7.0', publish_time: T1.toISOString(), conflict: 1 }]);
    // Sticky: back to the original time does not clear it.
    const again = await pinPublishTimes(e, 'npm', 'drift', new Map([['0.7.0', T1]]), new Date(OLD));
    expect(again.get('0.7.0')).toEqual({ publishTime: T1, conflict: true });
  });
});
