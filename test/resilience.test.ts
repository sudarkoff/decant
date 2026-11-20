import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handle } from '../src/index';
import type { Deps, Env } from '../src/types';
import { cachedFetch } from '../src/upstream';
import { fakeFetch, fixedClock, flakyDb, seedProject } from './helpers';

// Error 1101 in production: parallel cold-cache `go build` downloads through an overlay ref. Every
// failure inside a request must become a clean response, never an exception out of the fetch handler.

const PROXY = 'https://proxy.golang.org';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OLD = '2026-11-01T00:00:00Z';
const now = fixedClock('2026-11-19T12:00:00Z');

let e: Env;
let tok: string;

beforeAll(async () => {
  e = env as unknown as Env;
  tok = (await seedProject(e, 'rp')).read;
});

function testCtx() {
  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil(p: Promise<unknown>) {
      pending.push(p);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;
  /** Settles every background promise; returns how many rejected. */
  const flush = async () => {
    let rejected = 0;
    while (pending.length) {
      for (const r of await Promise.allSettled(pending.splice(0))) if (r.status === 'rejected') rejected++;
    }
    return rejected;
  };
  return { ctx, flush };
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
const info = (v: string, t: string) => JSON.stringify({ Version: v, Time: t });

type Routes = Record<string, Response | ((r: Request) => Response | Promise<Response>)>;

/** Upstream for a module: every file slow by `ms`; the zip optionally breaks mid-stream. */
function moduleRoutes(esc: string, v: string, opts: { ms?: number; brokenZip?: boolean } = {}): Routes {
  const base = `${PROXY}/${esc}/@v/${v}`;
  const slow = (make: () => Response) => async () => (await delay(opts.ms ?? 0), make());
  const zip = `zip-${esc}`;
  return {
    [`${base}.info`]: slow(() => new Response(info(v, OLD))),
    [`${base}.mod`]: slow(() => new Response(`module ${esc}\n`)),
    [`${base}.zip`]: slow(() =>
      opts.brokenZip
        ? new Response(
            new ReadableStream<Uint8Array>({
              start(c) {
                c.enqueue(new TextEncoder().encode('partial'));
                setTimeout(() => c.error(new Error('upstream reset')), 5);
              },
            }),
            { headers: { 'content-length': '1000' } },
          )
        : new Response(zip, { headers: { 'content-length': String(zip.length) } }),
    ),
  };
}

function run(db: D1Database, routes: Routes, bucket?: R2Bucket) {
  const deps: Deps = { fetch: fakeFetch(routes), now, timeoutMs: 2000 };
  const { ctx, flush } = testCtx();
  const envX: Env = { ...e, DB: db, ...(bucket ? { BUCKET: bucket } : {}) };
  const req = (path: string) => handle(new Request(`https://h${path}`, { headers: { authorization: `Bearer ${tok}` } }), envX, deps, ctx);
  return { req, flush };
}

/** Status and (fully read) body; a body that errors mid-stream counts as a truncated 200. */
async function settle(r: Response): Promise<{ status: number; type: string | null; body: string }> {
  let body: string;
  try {
    body = await r.text();
  } catch {
    body = '<truncated>';
  }
  return { status: r.status, type: r.headers.get('content-type'), body };
}

describe('registry requests never throw', () => {
  it('30 concurrent overlay downloads, a slow and a broken upstream and a flaky D1: every request answers', async () => {
    const mods = ['example.com/c/one', 'example.com/c/two', 'example.com/c/three', 'example.com/c/four', 'example.com/c/five'];
    const routes: Routes = { [OSV_BATCH]: () => new Response(JSON.stringify({ results: [{}] })) };
    mods.forEach((m, i) => Object.assign(routes, moduleRoutes(m, 'v1.0.0', { ms: i * 7, brokenZip: i === 2 })));
    // Each distinct statement fails once, the way D1 sheds load under a burst.
    const seen = new Set<string>();
    const db = flakyDb(e.DB, (sql) => !seen.has(sql) && !!seen.add(sql));
    const { req, flush } = run(db, routes);

    const paths: string[] = [];
    for (let round = 0; round < 2; round++)
      for (const m of mods) for (const ext of ['info', 'mod', 'zip']) paths.push(`/r/pr-928/go/${m}/@v/v1.0.0.${ext}`);
    expect(paths.length).toBe(30);

    const results = await Promise.allSettled(paths.map((p) => req(p).then(settle)));
    expect(results.filter((r) => r.status === 'rejected')).toEqual([]);
    for (const [i, r] of results.entries()) {
      const { status, type, body } = (r as PromiseFulfilledResult<Awaited<ReturnType<typeof settle>>>).value;
      if (paths[i]!.includes('/three/') && paths[i]!.endsWith('.zip')) {
        expect(status).toBe(200); // headers were already sent when the upstream broke
        continue;
      }
      expect({ path: paths[i], status }).toEqual({ path: paths[i], status: 200 });
      expect(body).not.toBe('<truncated>');
      if (status !== 200) expect(type).toMatch(/^text\/plain/);
    }
    expect(db.failures).toBeGreaterThan(0);
    expect(await flush()).toBe(0);

    // The broken zip was not stored; the next request goes upstream again (and works once upstream does).
    const again = run(e.DB, { ...routes, ...moduleRoutes('example.com/c/three', 'v1.0.0') });
    const z = await settle(await again.req('/r/pr-928/go/example.com/c/three/@v/v1.0.0.zip'));
    expect(z).toMatchObject({ status: 200, body: 'zip-example.com/c/three' });
    expect(await again.flush()).toBe(0);
  });

  it('a D1 statement that keeps failing yields a clean 502, not an exception', async () => {
    const db = flakyDb(e.DB, (sql) => sql.includes('INSERT OR IGNORE INTO versions'));
    const { req, flush } = run(db, moduleRoutes('example.com/d1/down', 'v1.0.0'));
    const r = await req('/r/pr-928/go/example.com/d1/down/@v/v1.0.0.mod');
    expect(r.status).toBe(502);
    expect(r.headers.get('content-type')).toMatch(/^text\/plain/);
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(await r.text()).toBe('decant: internal error');
    expect(await flush()).toBe(0);
  });

  it('a single transient D1 failure is retried and the request succeeds', async () => {
    let failed = false;
    const db = flakyDb(e.DB, (sql) => !failed && sql.includes('FROM versions WHERE') && (failed = true));
    const { req, flush } = run(db, moduleRoutes('example.com/d1/blip', 'v1.0.0'));
    const r = await req('/go/example.com/d1/blip/@v/v1.0.0.zip');
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('zip-example.com/d1/blip');
    expect(db.failures).toBe(1);
    expect(await flush()).toBe(0);
  });

  it('the npm handler answers a failing D1 with a clean 502 too', async () => {
    const db = flakyDb(e.DB, (sql) => sql.includes('FROM versions'));
    const doc = { name: 'leftpad-x', versions: { '1.0.0': {} }, time: { '1.0.0': OLD }, 'dist-tags': { latest: '1.0.0' } };
    const { req } = run(db, { 'https://registry.npmjs.org/leftpad-x': () => new Response(JSON.stringify(doc)) });
    const r = await req('/npm/leftpad-x');
    expect(r.status).toBe(502);
    expect(await r.text()).toBe('decant: internal error');
  });

  it('a request joining a single-flight fetch that never settles fetches for itself', async () => {
    const key = 'go/example.com/sf/orphan/@v/v1.0.0.mod';
    const url = `${PROXY}/example.com/sf/orphan/@v/v1.0.0.mod`;
    // The owner's request was cancelled: its fetch never settles, and ignores its abort signal.
    const owner = cachedFetch(e, { fetch: () => new Promise<Response>(() => {}), now, timeoutMs: 50 }, { key, url, immutable: true });
    const joiner = await cachedFetch(e, { fetch: fakeFetch({ [url]: new Response('module x\n') }), now, timeoutMs: 50 }, { key, url, immutable: true });
    expect(joiner.status).toBe('ok');
    void owner;
  });

  it('a stuck single-flight owner is dropped once a joiner times out: later requests do not wait again', async () => {
    const key = 'go/example.com/sf/stuck/@v/v1.0.0.mod';
    const url = `${PROXY}/example.com/sf/stuck/@v/v1.0.0.mod`;
    const good = (): Deps => ({ fetch: fakeFetch({ [url]: new Response('module x\n') }), now, timeoutMs: 50 });
    void cachedFetch(e, { fetch: () => new Promise<Response>(() => {}), now, timeoutMs: 50 }, { key, url, immutable: true });
    expect((await cachedFetch(e, good(), { key, url, immutable: true })).status).toBe('ok'); // waits ~1.1 s
    // R2 now holds it, but the point is the wait: a later request must not join the stuck owner.
    const t0 = Date.now();
    expect((await cachedFetch(e, good(), { key, url, immutable: true })).status).toBe('ok');
    expect(Date.now() - t0).toBeLessThan(500);
  });

  it('stats upserts are never retried: a lost ack does not count a request twice', async () => {
    const day = '2026-11-19';
    const count = async () =>
      (await e.DB.prepare(
        "SELECT COALESCE(SUM(n), 0) AS n FROM request_counts WHERE project_id = 'rp' AND day = ? AND eco = 'go' AND kind = 'download'",
      )
        .bind(day)
        .first<number>('n')) ?? 0;
    const before = await count();
    let failed = false;
    const db = flakyDb(e.DB, (sql) => !failed && sql.includes('INSERT INTO request_counts') && (failed = true), { lostAck: true });
    const { req, flush } = run(db, moduleRoutes('example.com/stats/once', 'v1.0.0'));
    const r = await req('/go/example.com/stats/once/@v/v1.0.0.mod');
    expect(r.status).toBe(200);
    await r.text();
    expect(await flush()).toBe(0);
    expect(db.failures).toBe(1);
    expect((await count()) - before).toBe(1);
  });

  it('an R2 read failure on the cold path falls through to upstream', async () => {
    const b = e.BUCKET;
    const bucket = {
      get: async () => {
        throw new Error('R2 internal error');
      },
      put: (...a: Parameters<R2Bucket['put']>) => b.put(...a),
      delete: (...a: Parameters<R2Bucket['delete']>) => b.delete(...a),
      head: (...a: Parameters<R2Bucket['head']>) => b.head(...a),
    } as unknown as R2Bucket;
    const { req, flush } = run(e.DB, moduleRoutes('example.com/r2/down', 'v1.0.0'), bucket);
    const r = await req('/go/example.com/r2/down/@v/v1.0.0.mod');
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('module example.com/r2/down\n');
    expect(await flush()).toBe(0);
  });
});
