import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { escapeModulePath, unescapeModulePath } from '../src/go/escape';
import { handle } from '../src/index';
import { blockedVersions, getVersionState } from '../src/policy/store';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock, hang, seedProject } from './helpers';

const PROXY = 'https://proxy.golang.org';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OLD = '2026-11-01T00:00:00Z'; // past the 7-day cooldown at the fixed clock
const YOUNG = '2026-11-17T12:00:00Z'; // 2 days old
const now = fixedClock('2026-11-19T12:00:00Z');

let e: Env;
let tok: string;

beforeAll(async () => {
  e = env as unknown as Env;
  tok = (await seedProject(e, 'gp')).read;
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

type Routes = Record<string, Response | ((r: Request) => Response | Promise<Response>)>;

function client(routes: Routes, timeoutMs?: number) {
  const f = fakeFetch(routes);
  const deps: Deps = { fetch: f, now, ...(timeoutMs === undefined ? {} : { timeoutMs }) };
  const ctx = testCtx();
  const req = (path: string) =>
    handle(new Request(`https://h${path}`, { headers: { authorization: `Bearer ${tok}` } }), e, deps, ctx);
  return { f, ctx, req };
}

const info = (v: string, t: string) => JSON.stringify({ Version: v, Time: t });

/** Upstream routes for a module (escaped path) with versions → times. */
function moduleRoutes(esc: string, times: Record<string, string>, opts: { latest?: string; osv?: unknown } = {}): Routes {
  const base = `${PROXY}/${esc}/@v`;
  const routes: Routes = {
    [`${base}/list`]: () => new Response(Object.keys(times).join('\n') + '\n'),
    [OSV_BATCH]: () => new Response(JSON.stringify(opts.osv ?? { results: [{}] })),
  };
  for (const [v, t] of Object.entries(times)) {
    routes[`${base}/${v}.info`] = () => new Response(info(v, t));
    routes[`${base}/${v}.mod`] = () => new Response(`module ${esc}\n`);
    routes[`${base}/${v}.zip`] = () => new Response(`zip-${esc}-${v}`, { headers: { 'content-length': String(`zip-${esc}-${v}`.length) } });
  }
  if (opts.latest) routes[`${PROXY}/${esc}/@latest`] = () => new Response(info(opts.latest!, times[opts.latest!]!));
  return routes;
}

describe('module path escaping', () => {
  it('escapes uppercase as ! + lowercase and round-trips', () => {
    expect(escapeModulePath('github.com/Azure/azure-sdk-for-go')).toBe('github.com/!azure/azure-sdk-for-go');
    expect(unescapeModulePath('github.com/!azure/azure-sdk-for-go')).toBe('github.com/Azure/azure-sdk-for-go');
    expect(unescapeModulePath(escapeModulePath('github.com/BurntSushi/TOML'))).toBe('github.com/BurntSushi/TOML');
  });

  it('rejects uppercase and dangling ! in escaped form', () => {
    expect(unescapeModulePath('github.com/Azure')).toBeNull();
    expect(unescapeModulePath('github.com/x!')).toBeNull();
    expect(unescapeModulePath('github.com/!1x')).toBeNull();
  });

  it('a request for an escaped path goes upstream with the escape intact', async () => {
    const { f, req } = client(moduleRoutes('github.com/!azure/x', { 'v1.0.0': OLD }));
    const r = await req('/go/github.com/!azure/x/@v/list');
    expect(r.status).toBe(200);
    expect(f.calls).toContain(`${PROXY}/github.com/!azure/x/@v/list`);
    expect(await r.text()).toBe('v1.0.0\n');
    // Policy/store use the unescaped module path.
    expect(await getVersionState(e, { eco: 'go', name: 'github.com/Azure/x', version: 'v1.0.0' })).not.toBeNull();
  });

  it('accepts %21 for ! the way the go client sends it (path and version), and forwards the ! form', async () => {
    // A fresh module (R2 is shared across this file's tests, so reuse would hit the cache).
    const { f, req } = client(moduleRoutes('github.com/!burnt!sushi/toml', { 'v1.0.0': OLD }));
    const list = await req('/go/github.com/%21burnt%21sushi/toml/@v/list');
    expect(list.status).toBe(200);
    expect(f.calls).toContain(`${PROXY}/github.com/!burnt!sushi/toml/@v/list`);
    const info = await req('/go/github.com/%21burnt%21sushi/toml/@v/v1.0.0.info');
    expect(info.status).toBe(200);
  });

  it('rejects any other percent-escape in a module path', async () => {
    const { req } = client(moduleRoutes('github.com/!azure/x', { 'v1.0.0': OLD }));
    // (%2e%2e is normalized away by the URL parser before routing, so it isn't a case here.)
    expect((await req('/go/github.com/a%2Fb/@v/list')).status).toBe(404);
    expect((await req('/go/github.com/a%20b/@v/list')).status).toBe(404);
  });
});

describe('go list', () => {
  it('keeps old pinned, drops young, pins unpinned via .info', async () => {
    const esc = 'example.com/list1';
    const routes = moduleRoutes(esc, { 'v1.0.0': OLD, 'v1.1.0': YOUNG, 'v1.2.0': OLD });
    // Pin v1.0.0 and v1.1.0 first.
    await client(routes).req(`/go/${esc}/@v/v1.0.0.info`);
    await client(routes).req(`/go/${esc}/@v/v1.1.0.info`);
    const { f, req } = client(routes);
    const r = await req(`/go/${esc}/@v/list`);
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toMatch(/^text\/plain/);
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(await r.text()).toBe('v1.0.0\nv1.2.0\n');
    expect(f.calls.filter((u) => u.endsWith('.info'))).toEqual([`${PROXY}/${esc}/@v/v1.2.0.info`]);
  });

  it('fetches at most 10 .info files per request, highest first', async () => {
    const esc = 'example.com/many';
    const times: Record<string, string> = {};
    for (let i = 0; i < 15; i++) times[`v1.${i}.0`] = OLD;
    const { f, req } = client(moduleRoutes(esc, times));
    const r = await req(`/go/${esc}/@v/list`);
    expect(r.status).toBe(200);
    const fetched = f.calls.filter((u) => u.endsWith('.info'));
    expect(fetched.length).toBe(10);
    expect(fetched).toContain(`${PROXY}/${esc}/@v/v1.14.0.info`);
    expect(fetched).not.toContain(`${PROXY}/${esc}/@v/v1.4.0.info`);
    // Only the 10 pinned versions are listed, in upstream order.
    expect(await r.text()).toBe(Array.from({ length: 10 }, (_, i) => `v1.${i + 5}.0\n`).join(''));
  });

  it('nothing allowed → 200 empty body', async () => {
    const esc = 'example.com/empty';
    const { req } = client(moduleRoutes(esc, { 'v1.0.0': YOUNG }));
    const r = await req(`/go/${esc}/@v/list`);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('');
  });

  it('unknown module → 404 text; upstream down with nothing cached → 502 text', async () => {
    const { req } = client({ [`${PROXY}/example.com/gone/@v/list`]: new Response('nope', { status: 404 }) });
    const r = await req('/go/example.com/gone/@v/list');
    expect(r.status).toBe(404);
    expect(r.headers.get('content-type')).toMatch(/^text\/plain/);
    const d = client({ [`${PROXY}/example.com/down/@v/list`]: new Response('x', { status: 503 }) });
    const r2 = await d.req('/go/example.com/down/@v/list');
    expect(r2.status).toBe(502);
    expect(r2.headers.get('content-type')).toMatch(/^text\/plain/);
  });
});

describe('go @latest', () => {
  it('upstream latest allowed → its info', async () => {
    const esc = 'example.com/lat1';
    const { req } = client(moduleRoutes(esc, { 'v1.0.0': OLD, 'v1.1.0': OLD }, { latest: 'v1.1.0' }));
    const r = await req(`/go/${esc}/@latest`);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ Version: 'v1.1.0', Time: OLD });
  });

  it('upstream latest young → info of the highest allowed release', async () => {
    const esc = 'example.com/lat2';
    const { req } = client(
      moduleRoutes(esc, { 'v1.0.0': OLD, 'v1.1.0': OLD, 'v1.2.0-rc.1': OLD, 'v1.2.0': YOUNG }, { latest: 'v1.2.0' }),
    );
    const r = await req(`/go/${esc}/@latest`);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ Version: 'v1.1.0', Time: OLD });
  });

  it('nothing allowed → 404', async () => {
    const esc = 'example.com/lat3';
    const { req } = client(moduleRoutes(esc, { 'v1.0.0': YOUNG }, { latest: 'v1.0.0' }));
    const r = await req(`/go/${esc}/@latest`);
    expect(r.status).toBe(404);
  });
});

describe('go .info/.mod/.zip', () => {
  it('hidden version .zip → 404 text "in cooldown", nothing fetched', async () => {
    const esc = 'example.com/hid';
    const { f, req } = client(moduleRoutes(esc, { 'v1.0.0': YOUNG }));
    const r = await req(`/go/${esc}/@v/v1.0.0.zip`);
    expect(r.status).toBe(404);
    expect(r.headers.get('content-type')).toMatch(/^text\/plain/);
    expect(await r.text()).toBe('example.com/hid@v1.0.0 is not available: in cooldown');
    expect(f.calls).not.toContain(`${PROXY}/${esc}/@v/v1.0.0.zip`);
  });

  it('.info and .mod are served byte-for-byte and cached immutably', async () => {
    const esc = 'example.com/im';
    const { req } = client(moduleRoutes(esc, { 'v1.0.0': OLD }));
    const i = await req(`/go/${esc}/@v/v1.0.0.info`);
    expect(i.status).toBe(200);
    expect(i.headers.get('content-type')).toBe('application/json');
    expect(await i.text()).toBe(info('v1.0.0', OLD));
    const m = await req(`/go/${esc}/@v/v1.0.0.mod`);
    expect(m.status).toBe(200);
    expect(await m.text()).toBe(`module ${esc}\n`);
    expect(await e.BUCKET.head(`go/${esc}/@v/v1.0.0.info`)).not.toBeNull();
    expect(await e.BUCKET.head(`go/${esc}/@v/v1.0.0.mod`)).not.toBeNull();
  });

  it('.zip is stored; the second .zip comes from R2 with no upstream call; serve logged', async () => {
    const esc = 'example.com/zz';
    const { f, ctx, req } = client(moduleRoutes(esc, { 'v1.0.0': OLD }));
    const r = await req(`/go/${esc}/@v/v1.0.0.zip`);
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toBe('application/zip');
    expect(await r.text()).toBe(`zip-${esc}-v1.0.0`);
    await ctx.flush();
    expect(await e.BUCKET.head(`go/${esc}/@v/v1.0.0.zip`)).not.toBeNull();
    const tmp = await e.BUCKET.list({ prefix: 'go/tmp/' });
    expect(tmp.objects).toEqual([]);
    const before = f.calls.length;
    const r2 = await req(`/go/${esc}/@v/v1.0.0.zip`);
    expect(r2.status).toBe(200);
    expect(await r2.text()).toBe(`zip-${esc}-v1.0.0`);
    expect(f.calls.length).toBe(before);
    await ctx.flush();
    const row = await e.DB.prepare("SELECT 1 AS x FROM serve_log WHERE project_id = 'gp' AND eco = 'go' AND name = ?")
      .bind(esc)
      .first();
    expect(row).not.toBeNull();
  });

  it('.zip upstream hung before headers → 502 after the timeout, nothing stored', async () => {
    const esc = 'example.com/hangzip';
    const routes = moduleRoutes(esc, { 'v1.0.0': OLD });
    routes[`${PROXY}/${esc}/@v/v1.0.0.zip`] = hang();
    const { ctx, req } = client(routes, 20);
    const r = await req(`/go/${esc}/@v/v1.0.0.zip`);
    expect(r.status).toBe(502);
    await ctx.flush();
    expect(await e.BUCKET.head(`go/${esc}/@v/v1.0.0.zip`)).toBeNull();
  });

  it('hung .info/.mod upstream with a cached copy → served from R2', async () => {
    const esc = 'example.com/hangmod';
    const routes = moduleRoutes(esc, { 'v1.0.0': OLD });
    const first = client(routes);
    expect(await (await first.req(`/go/${esc}/@v/v1.0.0.mod`)).text()).toBe(`module ${esc}\n`);
    const hung: Routes = Object.fromEntries(Object.keys(routes).map((u) => [u, hang()]));
    const { req } = client(hung, 20);
    const r = await req(`/go/${esc}/@v/v1.0.0.mod`);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe(`module ${esc}\n`);
  });

  it('OSV MAL hit on first .zip → 404 blocked and globally blocked', async () => {
    const esc = 'example.com/mal';
    const { f, req } = client(moduleRoutes(esc, { 'v1.0.0': OLD }, { osv: { results: [{ vulns: [{ id: 'MAL-2026-1' }] }] } }));
    const r = await req(`/go/${esc}/@v/v1.0.0.zip`);
    expect(r.status).toBe(404);
    expect(await r.text()).toBe(`${esc}@v1.0.0 is not available: blocked`);
    expect(f.calls).not.toContain(`${PROXY}/${esc}/@v/v1.0.0.zip`);
    expect(await blockedVersions(e, 'go', esc)).toEqual(new Set(['v1.0.0']));
  });

  it('.info time changing upstream → the version is blocked', async () => {
    const esc = 'example.com/chg';
    await client(moduleRoutes(esc, { 'v1.0.0': OLD })).req(`/go/${esc}/@v/v1.0.0.info`);
    // Upstream now reports a different time for v1.0.0 (seen via @latest).
    const { req } = client({
      ...moduleRoutes(esc, { 'v1.0.0': OLD }),
      [`${PROXY}/${esc}/@latest`]: () => new Response(info('v1.0.0', '2026-10-01T00:00:00Z')),
    });
    expect((await req(`/go/${esc}/@latest`)).status).toBe(404);
    const r = await req(`/go/${esc}/@v/v1.0.0.info`);
    expect(r.status).toBe(404);
    expect(await r.text()).toBe(`${esc}@v1.0.0 is not available: blocked`);
  });

  it('pseudo-version with an old .info is allowed and served', async () => {
    const esc = 'example.com/pseudo';
    const v = 'v0.0.0-20240101000000-abcdef123456';
    const { ctx, req } = client(moduleRoutes(esc, { [v]: OLD }));
    const r = await req(`/go/${esc}/@v/${v}.zip`);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe(`zip-${esc}-${v}`);
    await ctx.flush();
    const i = await req(`/go/${esc}/@v/${v}.info`);
    expect(i.status).toBe(200);
  });

  it('invalid version or path → 404 without upstream calls', async () => {
    const { f, req } = client({});
    for (const p of [
      '/go/example.com/x/@v/master.info',
      '/go/example.com/x/@v/1.0.0.info',
      '/go/example.com/x/@v/v1.0.0.tar',
      '/go/Example.com/x/@v/list',
      '/go/example.com//x/@v/list',
      '/go/example.com/x!/@v/list',
      '/go/example.com/x',
    ]) {
      expect((await req(p)).status, p).toBe(404);
    }
    expect(f.calls).toEqual([]);
  });

  it('/go/sumdb/* → 404', async () => {
    const { f, req } = client({});
    const r = await req('/go/sumdb/sum.golang.org/latest');
    expect(r.status).toBe(404);
    expect(f.calls).toEqual([]);
  });
});
