import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handle } from '../src/index';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock, seedProject } from './helpers';

const REG = 'https://registry.npmjs.org';
const PROXY = 'https://proxy.golang.org';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const ABBREV = 'application/vnd.npm.install-v1+json';
const OLD = '2026-11-01T00:00:00.000Z'; // past the cooldown
const YOUNG = '2026-11-18T00:00:00.000Z'; // inside it
const DAY = '2026-11-19';
const now = fixedClock('2026-11-19T12:00:00Z');

let e: Env;

beforeAll(() => {
  e = env as unknown as Env;
});

type Routes = Record<string, Response | ((r: Request) => Response | Promise<Response>)>;

function testCtx(): ExecutionContext & { flush(): Promise<void> } {
  const pending: Promise<unknown>[] = [];
  return {
    waitUntil(p: Promise<unknown>) {
      pending.push(p);
    },
    passThroughOnException() {},
    async flush() {
      while (pending.length) await Promise.allSettled(pending.splice(0));
    },
  } as unknown as ExecutionContext & { flush(): Promise<void> };
}

function client(routes: Routes, token: string | null, envOverride?: Env) {
  const deps: Deps = { fetch: fakeFetch(routes), now };
  const ctx = testCtx();
  const req = async (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    if (token) headers.set('authorization', `Bearer ${token}`);
    const r = await handle(new Request(`https://h${path}`, { ...init, headers }), envOverride ?? e, deps, ctx);
    await ctx.flush();
    return r;
  };
  return { req, ctx };
}

/** npm package with 1.0.0 (OLD) and 2.0.0 (YOUNG); latest is 2.0.0. */
async function npmRoutes(name: string): Promise<Routes> {
  const tgz = new TextEncoder().encode(`tarball-${name}`);
  const d = new Uint8Array(await crypto.subtle.digest('SHA-512', tgz));
  const integrity = `sha512-${btoa(String.fromCharCode(...d))}`;
  const url = (v: string) => `${REG}/${name}/-/${name}-${v}.tgz`;
  const versions = Object.fromEntries(
    ['1.0.0', '2.0.0'].map((v) => [v, { name, version: v, dist: { tarball: url(v), shasum: 'x', integrity } }]),
  );
  const full = { name, 'dist-tags': { latest: '2.0.0' }, versions, time: { created: OLD, modified: YOUNG, '1.0.0': OLD, '2.0.0': YOUNG } };
  const abbrev = { name, modified: YOUNG, 'dist-tags': { latest: '2.0.0' }, versions };
  return {
    [`${REG}/${name}`]: (r) =>
      (r.headers.get('accept') ?? '').includes(ABBREV)
        ? new Response(JSON.stringify(abbrev), { headers: { 'content-type': ABBREV } })
        : new Response(JSON.stringify(full), { headers: { 'content-type': 'application/json' } }),
    [url('1.0.0')]: () => new Response(tgz, { headers: { 'content-length': String(tgz.length) } }),
    [url('2.0.0')]: () => new Response(tgz, { headers: { 'content-length': String(tgz.length) } }),
    [OSV_BATCH]: () => new Response(JSON.stringify({ results: [{}] })),
  };
}

async function counts(project: string): Promise<Record<string, number>> {
  const { results } = await e.DB.prepare('SELECT day, eco, kind, outcome, n FROM request_counts WHERE project_id = ?')
    .bind(project)
    .all<{ day: string; eco: string; kind: string; outcome: string; n: number }>();
  return Object.fromEntries(results.map((r) => [`${r.day}/${r.eco}/${r.kind}/${r.outcome}`, r.n]));
}

async function totalCount(): Promise<number> {
  return (await e.DB.prepare('SELECT COALESCE(SUM(n), 0) AS t FROM request_counts').first<number>('t')) ?? 0;
}

describe('request recording', () => {
  it('served npm metadata increments (proj, today, npm, metadata, served)', async () => {
    const tok = (await seedProject(e, 's-meta')).read;
    const { req } = client(await npmRoutes('st-meta'), tok);
    expect((await req('/npm/st-meta')).status).toBe(200);
    expect(await counts('s-meta')).toEqual({ [`${DAY}/npm/metadata/served`]: 1 });
    expect((await req('/npm/st-meta')).status).toBe(200);
    expect(await counts('s-meta')).toEqual({ [`${DAY}/npm/metadata/served`]: 2 });
  });

  it('cooldown-refused tarball → download/cooldown; blocked → download/blocked', async () => {
    const tok = (await seedProject(e, 's-deny')).read;
    await e.DB.prepare(
      "INSERT INTO global_blocks (eco, name, version, source, reason, at) VALUES ('npm', 'st-deny', '1.0.0', 'manual', 'bad', '2026-11-19')",
    ).run();
    const { req } = client(await npmRoutes('st-deny'), tok);
    expect((await req('/npm/st-deny/-/st-deny-2.0.0.tgz')).status).toBe(404);
    expect((await req('/npm/st-deny/-/st-deny-1.0.0.tgz')).status).toBe(404);
    expect(await counts('s-deny')).toEqual({
      [`${DAY}/npm/download/cooldown`]: 1,
      [`${DAY}/npm/download/blocked`]: 1,
    });
  });

  it('served tarball → download/served', async () => {
    const tok = (await seedProject(e, 's-tar')).read;
    const { req } = client(await npmRoutes('st-tar'), tok);
    const r = await req('/npm/st-tar/-/st-tar-1.0.0.tgz');
    expect(r.status).toBe(200);
    await r.arrayBuffer();
    expect(await counts('s-tar')).toEqual({ [`${DAY}/npm/download/served`]: 1 });
  });

  it('upstream down with a stored copy → metadata/stale; with nothing stored → metadata/failed', async () => {
    const tok = (await seedProject(e, 's-stale')).read;
    const routes = await npmRoutes('st-stale');
    const doc = await (await (routes[`${REG}/st-stale`] as (r: Request) => Response)(new Request(`${REG}/st-stale`))).text();
    await e.BUCKET.put('npm/meta/full/st-stale.json', doc, { customMetadata: { fetchedAt: '2026-11-01T00:00:00.000Z' } });
    const { req } = client(
      { [`${REG}/st-stale`]: new Response('', { status: 503 }), [`${REG}/st-gone`]: new Response('', { status: 503 }) },
      tok,
    );
    const r = await req('/npm/st-stale');
    expect(r.status).toBe(200);
    expect(r.headers.get('x-decant-stale')).toBe('1');
    expect((await req('/npm/st-gone')).status).toBe(502);
    expect(await counts('s-stale')).toEqual({
      [`${DAY}/npm/metadata/stale`]: 1,
      [`${DAY}/npm/metadata/failed`]: 1,
    });
  });

  it('go .zip serve → go/download/served; .info and list → go/metadata/served', async () => {
    const tok = (await seedProject(e, 's-go')).read;
    const base = `${PROXY}/example.com/stz/@v`;
    const zip = 'zip-bytes';
    const { req } = client(
      {
        [`${base}/list`]: () => new Response('v1.0.0\n'),
        [`${base}/v1.0.0.info`]: () => new Response(JSON.stringify({ Version: 'v1.0.0', Time: OLD })),
        [`${base}/v1.0.0.zip`]: () => new Response(zip, { headers: { 'content-length': String(zip.length) } }),
        [OSV_BATCH]: () => new Response(JSON.stringify({ results: [{}] })),
      },
      tok,
    );
    const z = await req('/go/example.com/stz/@v/v1.0.0.zip');
    expect(z.status).toBe(200);
    expect(await z.text()).toBe(zip);
    expect((await req('/go/example.com/stz/@v/v1.0.0.info')).status).toBe(200);
    expect((await req('/go/example.com/stz/@v/list')).status).toBe(200);
    expect(await counts('s-go')).toEqual({
      [`${DAY}/go/download/served`]: 1,
      [`${DAY}/go/metadata/served`]: 2,
    });
  });

  it('unknown route, unknown package, 405 and 401 record nothing', async () => {
    const tok = (await seedProject(e, 's-none')).read;
    const before = await totalCount();
    const { req } = client({ [`${REG}/st-nope`]: new Response('{}', { status: 404 }) }, tok);
    expect((await req('/npm/a/b/c/d')).status).toBe(404);
    expect((await req('/npm/st-nope')).status).toBe(404);
    expect((await req('/npm/st-nope', { method: 'PUT' })).status).toBe(405);
    expect((await req('/go/example.com/x/@v/nonsense')).status).toBe(404);
    const anon = client({}, null);
    expect((await anon.req('/npm/st-nope')).status).toBe(401);
    expect(await counts('s-none')).toEqual({});
    expect(await totalCount()).toBe(before);
  });

  it('a request_counts insert that throws still yields the normal 200 tarball', async () => {
    const tok = (await seedProject(e, 's-throw')).read;
    const throwing = new Proxy(e.DB, {
      get(target, prop) {
        if (prop === 'prepare')
          return (sql: string) => {
            if (sql.includes('request_counts')) throw new Error('d1 down');
            return target.prepare(sql);
          };
        const v = Reflect.get(target, prop, target);
        return typeof v === 'function' ? v.bind(target) : v;
      },
    });
    const { req } = client(await npmRoutes('st-throw'), tok, { ...e, DB: throwing } as Env);
    const r = await req('/npm/st-throw/-/st-throw-1.0.0.tgz');
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('tarball-st-throw');
    expect(await counts('s-throw')).toEqual({});
  });
});

describe('package latest versions', () => {
  const pkg = (eco: string, name: string) =>
    e.DB.prepare('SELECT latest, latest_time, checked_at FROM packages WHERE eco = ? AND name = ?').bind(eco, name).first();

  it('a fresh upstream packument upserts packages; a cached hit does not write', async () => {
    const tok = (await seedProject(e, 's-pkg')).read;
    const { req } = client(await npmRoutes('st-pkg'), tok);
    expect((await req('/npm/st-pkg')).status).toBe(200);
    expect(await pkg('npm', 'st-pkg')).toEqual({ latest: '2.0.0', latest_time: YOUNG, checked_at: '2026-11-19T12:00:00.000Z' });
    await e.DB.prepare("DELETE FROM packages WHERE eco = 'npm' AND name = 'st-pkg'").run();
    expect((await req('/npm/st-pkg')).status).toBe(200); // within max-age: served from R2
    expect(await pkg('npm', 'st-pkg')).toBeNull();
  });

  it('abbreviated fresh doc records latest; time comes only from a fresh full doc', async () => {
    const tok = (await seedProject(e, 's-abbr')).read;
    const { req } = client(await npmRoutes('st-abbr'), tok);
    // Abbreviated doc fetched fresh (no time), then the full doc fetched fresh for pins.
    expect((await req('/npm/st-abbr', { headers: { accept: ABBREV } })).status).toBe(200);
    expect(await pkg('npm', 'st-abbr')).toMatchObject({ latest: '2.0.0', latest_time: YOUNG });
  });

  it('a fresh go @latest upserts packages with Version and Time', async () => {
    const tok = (await seedProject(e, 's-golatest')).read;
    const { req } = client(
      {
        [`${PROXY}/example.com/stl/@latest`]: () => new Response(JSON.stringify({ Version: 'v1.2.0', Time: OLD })),
        [OSV_BATCH]: () => new Response(JSON.stringify({ results: [{}] })),
      },
      tok,
    );
    expect((await req('/go/example.com/stl/@latest')).status).toBe(200);
    expect(await pkg('go', 'example.com/stl')).toEqual({ latest: 'v1.2.0', latest_time: OLD, checked_at: '2026-11-19T12:00:00.000Z' });
    expect(await counts('s-golatest')).toEqual({ [`${DAY}/go/metadata/served`]: 1 });
  });
});
