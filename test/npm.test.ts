import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handle } from '../src/index';
import { blockedVersions } from '../src/policy/store';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock, seedProject } from './helpers';

const REG = 'https://registry.npmjs.org';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const ABBREV = 'application/vnd.npm.install-v1+json';
const OLD = '2026-11-01T00:00:00.000Z'; // past the 7-day cooldown at the fixed clock
const YOUNG = '2026-11-18T00:00:00.000Z'; // inside it
const now = fixedClock('2026-11-19T12:00:00Z');

let e: Env;
let tok: string;

beforeAll(async () => {
  e = env as unknown as Env;
  tok = (await seedProject(e, 'np')).read;
  // Overlay ref pr-1 allows x-overlay@2.0.0 (young).
  await e.DB.prepare(
    "INSERT INTO allows (project_id, ref, eco, name, version, advisory, reason, verified_at) VALUES ('np', 'pr-1', 'npm', 'x-overlay', '2.0.0', NULL, 'r', NULL)",
  ).run();
});

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

async function sri(bytes: Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-512', bytes));
  return `sha512-${btoa(String.fromCharCode(...d))}`;
}

interface Fixture {
  name: string;
  tgz: Uint8Array;
  routes: Record<string, Response | ((r: Request) => Response | Promise<Response>)>;
  tarballUrl: (v: string) => string;
}

/** Package with 1.0.0 (OLD) and 2.0.0 (YOUNG). */
async function fixture(
  name: string,
  opts: { integrity?: string | null; contentLength?: boolean; osv?: unknown } = {},
): Promise<Fixture> {
  const base = name.split('/').pop()!;
  const tgz = new TextEncoder().encode(`tarball-bytes-of-${name}`);
  const integrity = opts.integrity === undefined ? await sri(tgz) : opts.integrity;
  const times: Record<string, string> = { '1.0.0': OLD, '2.0.0': YOUNG };
  const tarballUrl = (v: string) => `${REG}/${name}/-/${base}-${v}.tgz`;
  const ver = (v: string) => ({
    name,
    version: v,
    dist: { tarball: tarballUrl(v), shasum: 'x', ...(integrity ? { integrity } : {}) },
  });
  const versions = Object.fromEntries(Object.keys(times).map((v) => [v, ver(v)]));
  const full = { name, 'dist-tags': { latest: '2.0.0' }, versions, time: { created: OLD, modified: YOUNG, ...times } };
  const abbrev = { name, modified: YOUNG, 'dist-tags': { latest: '2.0.0' }, versions };
  const tarHeaders: Record<string, string> = opts.contentLength === false ? {} : { 'content-length': String(tgz.length) };
  const routes: Fixture['routes'] = {
    [`${REG}/${name.replace('/', '%2f')}`]: (r) =>
      (r.headers.get('accept') ?? '').includes(ABBREV)
        ? new Response(JSON.stringify(abbrev), { headers: { 'content-type': ABBREV } })
        : new Response(JSON.stringify(full), { headers: { 'content-type': 'application/json' } }),
    [tarballUrl('1.0.0')]: () => new Response(tgz, { headers: tarHeaders }),
    [tarballUrl('2.0.0')]: () => new Response(tgz, { headers: tarHeaders }),
    [OSV_BATCH]: () => new Response(JSON.stringify(opts.osv ?? { results: [{}] })),
  };
  return { name, tgz, routes, tarballUrl };
}

function client(routes: Fixture['routes']) {
  const f = fakeFetch(routes);
  const deps: Deps = { fetch: f, now };
  const ctx = testCtx();
  const req = (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    headers.set('authorization', `Bearer ${tok}`);
    return handle(new Request(`https://h${path}`, { ...init, headers }), e, deps, ctx);
  };
  return { f, ctx, req };
}

type Doc = { name: string; versions: Record<string, { dist: { tarball: string } }>; 'dist-tags': Record<string, string> };

describe('npm metadata', () => {
  it('@s/pkg, @s%2fpkg and @s%2Fpkg return the same filtered doc; scoped tarball route works', async () => {
    const fx = await fixture('@s/pkg');
    const { req, ctx } = client(fx.routes);
    const bodies: Doc[] = [];
    for (const p of ['/npm/@s/pkg', '/npm/@s%2fpkg', '/npm/@s%2Fpkg']) {
      const r = await req(p);
      expect(r.status).toBe(200);
      expect(r.headers.get('content-type')).toBe('application/json');
      expect(r.headers.get('cache-control')).toBe('no-store');
      bodies.push((await r.json()) as Doc);
    }
    expect(bodies[1]).toEqual(bodies[0]);
    expect(bodies[2]).toEqual(bodies[0]);
    expect(Object.keys(bodies[0]!.versions)).toEqual(['1.0.0']);
    expect(bodies[0]!['dist-tags']).toEqual({ latest: '1.0.0' });
    const url = bodies[0]!.versions['1.0.0']!.dist.tarball;
    expect(url).toBe('https://h/npm/@s/pkg/-/pkg-1.0.0.tgz');

    const t = await req(new URL(url).pathname);
    expect(t.status).toBe(200);
    expect(new Uint8Array(await t.arrayBuffer())).toEqual(fx.tgz);
    await ctx.flush();
    expect(await e.BUCKET.head('npm/tar/@s/pkg/pkg-1.0.0.tgz')).not.toBeNull();
  });

  it('abbreviated Accept → install-v1 content type and Vary: Accept', async () => {
    const fx = await fixture('abbr');
    const { req } = client(fx.routes);
    const r = await req('/npm/abbr', { headers: { accept: `${ABBREV}; q=1.0, application/json; q=0.8, */*` } });
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toBe(ABBREV);
    expect(r.headers.get('vary')).toBe('Accept');
    expect(r.headers.get('cache-control')).toBe('no-store');
    const doc = (await r.json()) as Doc;
    // Times come from the full doc (fetched because nothing was pinned yet).
    expect(Object.keys(doc.versions)).toEqual(['1.0.0']);
    expect(await e.BUCKET.head('npm/meta/abbrev/abbr.json')).not.toBeNull();
    expect(await e.BUCKET.head('npm/meta/full/abbr.json')).not.toBeNull();
  });

  it('unknown package → 404 JSON', async () => {
    const { req } = client({ [`${REG}/nope-pkg`]: new Response('{}', { status: 404 }) });
    const r = await req('/npm/nope-pkg');
    expect(r.status).toBe(404);
    expect(r.headers.get('content-type')).toBe('application/json');
    expect(r.headers.get('cache-control')).toBe('no-store');
  });

  it('unpublished package → 200 with no versions', async () => {
    const doc = { name: 'gone-pkg', time: { created: OLD, modified: YOUNG, unpublished: { time: YOUNG, versions: ['1.0.0'] } } };
    const { req } = client({ [`${REG}/gone-pkg`]: new Response(JSON.stringify(doc)) });
    const r = await req('/npm/gone-pkg');
    expect(r.status).toBe(200);
    expect(((await r.json()) as Doc).versions).toEqual({});
  });

  it('overlay ref pr-1 lists the young version with ref-prefixed tarball URLs; main does not', async () => {
    const fx = await fixture('x-overlay');
    const { req } = client(fx.routes);
    const ov = (await (await req('/r/pr-1/npm/x-overlay')).json()) as Doc;
    expect(Object.keys(ov.versions).sort()).toEqual(['1.0.0', '2.0.0']);
    expect(ov.versions['2.0.0']!.dist.tarball.startsWith('https://h/r/pr-1/npm/')).toBe(true);
    const main = (await (await req('/npm/x-overlay')).json()) as Doc;
    expect(Object.keys(main.versions)).toEqual(['1.0.0']);
    expect((await req('/r/pr-1/npm/x-overlay/-/x-overlay-2.0.0.tgz')).status).toBe(200);
  });
});

describe('npm tarballs', () => {
  it('cooldown-hidden version → 404 "in cooldown"', async () => {
    const fx = await fixture('young');
    const { req, f } = client(fx.routes);
    const r = await req('/npm/young/-/young-2.0.0.tgz');
    expect(r.status).toBe(404);
    expect(r.headers.get('content-type')).toBe('application/json');
    expect(await r.json()).toEqual({ error: 'npm:young@2.0.0 is not available: in cooldown' });
    expect(f.calls).not.toContain(fx.tarballUrl('2.0.0'));
  });

  it('blocked version → 404 "blocked", even when already in R2', async () => {
    const fx = await fixture('blk');
    const { req, ctx } = client(fx.routes);
    expect((await req('/npm/blk/-/blk-1.0.0.tgz')).status).toBe(200);
    await ctx.flush();
    expect(await e.BUCKET.head('npm/tar/blk/blk-1.0.0.tgz')).not.toBeNull();
    await e.DB.prepare(
      "INSERT INTO global_blocks (eco, name, version, source, reason, at) VALUES ('npm', 'blk', '1.0.0', 'manual', 'bad', '2026-11-19')",
    ).run();
    const r = await req('/npm/blk/-/blk-1.0.0.tgz');
    expect(r.status).toBe(404);
    expect(await r.json()).toEqual({ error: 'npm:blk@1.0.0 is not available: blocked' });
  });

  it('second request is served from R2 with no upstream call', async () => {
    const fx = await fixture('twice');
    const { req, ctx, f } = client(fx.routes);
    await (await req('/npm/twice/-/twice-1.0.0.tgz')).arrayBuffer();
    await ctx.flush();
    const before = f.calls.length;
    const r = await req('/npm/twice/-/twice-1.0.0.tgz');
    expect(r.status).toBe(200);
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(fx.tgz);
    expect(f.calls.length).toBe(before);
    const st = await e.DB.prepare("SELECT stored_at, osv_checked_at FROM versions WHERE eco='npm' AND name='twice' AND version='1.0.0'").first();
    expect(st).toEqual({ stored_at: '2026-11-19T12:00:00.000Z', osv_checked_at: '2026-11-19T12:00:00.000Z' });
  });

  it('no content-length upstream: buffered and stored', async () => {
    const fx = await fixture('nolen', { contentLength: false });
    const { req, ctx } = client(fx.routes);
    const r = await req('/npm/nolen/-/nolen-1.0.0.tgz');
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(fx.tgz);
    await ctx.flush();
    const obj = await e.BUCKET.get('npm/tar/nolen/nolen-1.0.0.tgz');
    expect(new Uint8Array(await obj!.arrayBuffer())).toEqual(fx.tgz);
  });

  it('sha512 mismatch → R2 object gone after waitUntil', async () => {
    const fx = await fixture('badsum', { integrity: await sri(new TextEncoder().encode('other')) });
    const { req, ctx } = client(fx.routes);
    const r = await req('/npm/badsum/-/badsum-1.0.0.tgz');
    expect(r.status).toBe(200);
    await r.arrayBuffer();
    await ctx.flush();
    expect(await e.BUCKET.head('npm/tar/badsum/badsum-1.0.0.tgz')).toBeNull();
    const st = await e.DB.prepare("SELECT stored_at FROM versions WHERE eco='npm' AND name='badsum' AND version='1.0.0'").first();
    expect(st).toEqual({ stored_at: null });
  });

  it('no sha512 integrity → still stored', async () => {
    const fx = await fixture('nosri', { integrity: null });
    const { req, ctx } = client(fx.routes);
    await (await req('/npm/nosri/-/nosri-1.0.0.tgz')).arrayBuffer();
    await ctx.flush();
    expect(await e.BUCKET.head('npm/tar/nosri/nosri-1.0.0.tgz')).not.toBeNull();
  });

  it('maliciousIds hit → 404 and the version is globally blocked', async () => {
    const fx = await fixture('mal', { osv: { results: [{ vulns: [{ id: 'MAL-2026-1' }] }] } });
    const { req, f } = client(fx.routes);
    const r = await req('/npm/mal/-/mal-1.0.0.tgz');
    expect(r.status).toBe(404);
    expect(await r.json()).toEqual({ error: 'npm:mal@1.0.0 is not available: blocked' });
    expect(await blockedVersions(e, 'npm', 'mal')).toEqual(new Set(['1.0.0']));
    expect(f.calls).not.toContain(fx.tarballUrl('1.0.0'));
  });

  it('OSV down → served anyway, osv_checked_at stays null', async () => {
    const fx = await fixture('osvdown');
    fx.routes[OSV_BATCH] = new Response('', { status: 503 });
    const { req, ctx } = client(fx.routes);
    expect((await req('/npm/osvdown/-/osvdown-1.0.0.tgz')).status).toBe(200);
    await ctx.flush();
    const st = await e.DB.prepare("SELECT osv_checked_at FROM versions WHERE eco='npm' AND name='osvdown' AND version='1.0.0'").first();
    expect(st).toEqual({ osv_checked_at: null });
  });

  it('unknown version or bad file name → 404', async () => {
    const fx = await fixture('vv');
    const { req } = client(fx.routes);
    expect((await req('/npm/vv/-/vv-9.9.9.tgz')).status).toBe(404);
    expect((await req('/npm/vv/-/other-1.0.0.tgz')).status).toBe(404);
  });

  it('serve log has a row for (project, npm, name, 1.0.0, 2026-11-19)', async () => {
    const fx = await fixture('logged');
    const { req, ctx } = client(fx.routes);
    await (await req('/npm/logged/-/logged-1.0.0.tgz')).arrayBuffer();
    await ctx.flush();
    const row = await e.DB.prepare("SELECT * FROM serve_log WHERE project_id='np' AND eco='npm' AND name='logged'").first();
    expect(row).toEqual({ project_id: 'np', eco: 'npm', name: 'logged', version: '1.0.0', day: '2026-11-19' });
  });
});

describe('npm audit and methods', () => {
  it('audit POST passes through with body; Authorization is not forwarded', async () => {
    let seen: { body: string; auth: string | null; ct: string | null } | null = null;
    const { req } = client({
      [`${REG}/-/npm/v1/security/advisories/bulk`]: async (r) => {
        seen = { body: await r.text(), auth: r.headers.get('authorization'), ct: r.headers.get('content-type') };
        return new Response('{"x":[]}', { headers: { 'content-type': 'application/json', 'set-cookie': 'a=b' } });
      },
    });
    const r = await req('/npm/-/npm/v1/security/advisories/bulk', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"lodash":["4.17.0"]}',
    });
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('{"x":[]}');
    expect(r.headers.get('set-cookie')).toBeNull();
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(seen).toEqual({ body: '{"lodash":["4.17.0"]}', auth: null, ct: 'application/json' });
  });

  it('PUT and DELETE → 405; other GET paths → 404', async () => {
    const { req } = client({});
    expect((await req('/npm/x', { method: 'PUT', body: '{}' })).status).toBe(405);
    expect((await req('/npm/x/-rev/1', { method: 'DELETE' })).status).toBe(405);
    expect((await req('/npm/')).status).toBe(404);
    expect((await req('/npm/-/v1/search')).status).toBe(404);
    expect((await req('/npm/x', { method: 'POST', body: '{}' })).status).toBe(404);
  });
});
