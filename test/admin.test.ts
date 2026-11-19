import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { hashToken, newToken } from '../src/auth';
import { handle } from '../src/index';
import { blockedVersions, loadPolicyView } from '../src/policy/store';
import { fakeFetch, fixedClock, seedProject } from './helpers';
import type { Deps, Env } from '../src/types';

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const now = fixedClock('2026-11-19T12:00:00Z');
const OSV = 'https://api.osv.dev';
const GHSA = 'GHSA-35jh-r3h4-6jhm';
const opToken = newToken('op');
let e: Env;
type Tokens = { read: string; ci: string; sync: string };
let A: Tokens;
let B: Tokens;

beforeAll(async () => {
  e = { ...(env as unknown as Env), OPERATOR_TOKEN_HASH: await hashToken(opToken) };
  A = await seedProject(e, 'pa');
  B = await seedProject(e, 'pb');
});

function call(
  method: string,
  path: string,
  token: string | null,
  body?: unknown,
  fetch: typeof globalThis.fetch = fakeFetch({}),
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const init: RequestInit = { method, headers };
  if (body !== undefined) init.body = typeof body === 'string' ? body : JSON.stringify(body);
  const deps: Deps = { fetch, now };
  return handle(new Request(`https://h${path}`, init), e, deps, ctx);
}

const policy = (project: string, extra: Record<string, unknown> = {}) => ({ project, ...extra });
const allow = (pkg: string, advisory?: string) => ({ package: pkg, reason: 'r', added: '2026-11-18', ...(advisory ? { advisory } : {}) });
const block = (pkg: string) => ({ package: pkg, reason: 'bad' });
const sync = (token: string, project: string, p: unknown, ref = 'main', fetch?: typeof globalThis.fetch) =>
  call('PUT', `/api/projects/${project}/policy`, token, { policy: p, sha: 'abc123', ref }, fetch);

describe('projects and tokens', () => {
  it('operator creates a project and then a token that works', async () => {
    const r = await call('POST', '/api/projects', opToken, { id: 'newproj' });
    expect(r.status).toBe(201);
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect((await call('POST', '/api/projects', opToken, { id: 'newproj' })).status).toBe(409);

    const t = await call('POST', '/api/projects/newproj/tokens', opToken, { kind: 'ci' });
    expect(t.status).toBe(201);
    const { token } = (await t.json()) as { token: string };
    expect(token).toMatch(/^dk_ci_[A-Za-z0-9_-]{43}$/);
    const st = await call('GET', '/api/projects/newproj/status', token);
    expect(st.status).toBe(200);
    expect(await st.json()).toEqual({ mainSha: null, syncedAt: null, overlays: [], globalBlocks: expect.any(Number) });
  });

  it('token creation validates kind and project', async () => {
    expect((await call('POST', '/api/projects/pa/tokens', opToken, { kind: 'op' })).status).toBe(400);
    expect((await call('POST', '/api/projects/ghost/tokens', opToken, { kind: 'read' })).status).toBe(404);
    expect((await call('POST', '/api/projects', opToken, { id: 'bad id!' })).status).toBe(400);
  });

  it('a ci token cannot create projects or tokens', async () => {
    expect((await call('POST', '/api/projects', A.ci, { id: 'x1' })).status).toBe(403);
    expect((await call('POST', '/api/projects/pa/tokens', A.ci, { kind: 'ci' })).status).toBe(403);
  });

  it("project A's ci token on B's policy and status -> 403", async () => {
    expect((await sync(A.ci, 'pb', policy('pb'), 'pr-1')).status).toBe(403);
    expect((await sync(A.ci, 'pb', policy('pb'))).status).toBe(403);
    expect((await sync(A.sync, 'pb', policy('pb'))).status).toBe(403);
    expect((await call('GET', '/api/projects/pb/status', A.ci)).status).toBe(403);
  });

  it('sync token: main ref only; ci token: non-main only; wrong pairing -> 403', async () => {
    const s0 = await seedProject(e, 'pe');
    const ok = await sync(s0.sync, 'pe', policy('pe'));
    expect(ok.status).toBe(200);
    const syncOverlay = await sync(s0.sync, 'pe', policy('pe'), 'pr-1');
    expect(syncOverlay.status).toBe(403);
    expect(await syncOverlay.text()).toContain('sync tokens may only sync main');
    const ciMain = await sync(s0.ci, 'pe', policy('pe'));
    expect(ciMain.status).toBe(403);
    expect(await ciMain.text()).toContain('use the sync token for main');
    expect((await sync(s0.ci, 'pe', policy('pe'), 'pr-1')).status).toBe(200);
    // another project's sync token never works
    expect((await sync(A.sync, 'pe', policy('pe'))).status).toBe(403);
  });

  it('sync token gets 403 on verdicts, status and blocks', async () => {
    expect((await call('PUT', '/api/verdicts', A.sync, {})).status).toBe(403);
    expect((await call('GET', '/api/verdicts?package=npm:a@1.0.0', A.sync)).status).toBe(403);
    expect((await call('GET', '/api/projects/pa/status', A.sync)).status).toBe(403);
    expect((await call('GET', '/api/blocks', A.sync)).status).toBe(403);
  });

  it('GET /api/blocks (ci) lists blocks newest first', async () => {
    const p = await seedProject(e, 'pf');
    await sync(p.sync, 'pf', policy('pf', { block: [block('npm:blk-a@1.0.0')] }));
    await e.DB.prepare("INSERT INTO global_blocks (eco, name, version, source, reason, at) VALUES ('npm','blk-z','2.0.0','osv:X','r2','2099-01-01T00:00:00.000Z')").run();
    const r = await call('GET', '/api/blocks', p.ci);
    expect(r.status).toBe(200);
    const { blocks } = (await r.json()) as { blocks: { package: string; source: string; reason: string; at: string }[] };
    expect(blocks[0]).toEqual({ package: 'npm:blk-z@2.0.0', source: 'osv:X', reason: 'r2', at: '2099-01-01T00:00:00.000Z' });
    expect(blocks).toContainEqual({ package: 'npm:blk-a@1.0.0', source: 'policy:pf', reason: 'bad', at: '2026-11-19T12:00:00.000Z' });
    const ats = blocks.map((b) => b.at);
    expect(ats).toEqual([...ats].sort().reverse());
    expect((await call('GET', '/api/blocks', opToken)).status).toBe(403);
    expect((await call('GET', '/api/blocks', A.read)).status).toBe(403);
    expect((await call('POST', '/api/blocks', p.ci, {})).status).toBe(405);
  });

  it('operator can create sync tokens', async () => {
    const t = await call('POST', '/api/projects/pa/tokens', opToken, { kind: 'sync' });
    expect(t.status).toBe(201);
    expect(((await t.json()) as { token: string }).token).toMatch(/^dk_sync_/);
  });

  it('operator cannot sync policy or write verdicts', async () => {
    expect((await sync(opToken, 'pa', policy('pa'))).status).toBe(403);
    expect((await call('PUT', '/api/verdicts', opToken, {})).status).toBe(403);
  });

  it('a read token gets 403 on every /api route', async () => {
    const routes: [string, string][] = [
      ['GET', '/api'],
      ['GET', '/api/'],
      ['GET', '/api/nope'],
      ['POST', '/api/projects'],
      ['POST', '/api/projects/pa/tokens'],
      ['PUT', '/api/projects/pa/policy'],
      ['GET', '/api/projects/pa/status'],
      ['PUT', '/api/verdicts'],
      ['GET', '/api/verdicts?package=npm:a@1.0.0'],
      ['GET', '/api/blocks'],
    ];
    for (const [m, p] of routes) expect((await call(m, p, A.read, m === 'GET' ? undefined : {})).status, `${m} ${p}`).toBe(403);
  });

  it('unknown routes 404 and wrong methods 405', async () => {
    expect((await call('GET', '/api/nope', opToken)).status).toBe(404);
    expect((await call('GET', '/api', A.ci)).status).toBe(404);
    expect((await call('GET', '/api/projects', opToken)).status).toBe(405);
  });
});

describe('request bodies', () => {
  it('rejects non-JSON with 400 and >1 MB with 413', async () => {
    expect((await call('POST', '/api/projects', opToken, 'not json')).status).toBe(400);
    expect((await call('POST', '/api/projects', opToken, '[1]')).status).toBe(400);
    const big = JSON.stringify({ id: 'x'.repeat(1024 * 1024) });
    expect((await call('POST', '/api/projects', opToken, big)).status).toBe(413);
  });

  it('rejects malformed sync bodies', async () => {
    expect((await call('PUT', '/api/projects/pa/policy', A.sync, { policy: policy('pa'), sha: 'x' })).status).toBe(400);
    expect((await call('PUT', '/api/projects/pa/policy', A.sync, { policy: policy('pa'), sha: 'x', ref: 'bad ref' })).status).toBe(400);
    expect((await sync(A.sync, 'pa', { project: 'pa', cooldownDays: -1 })).status).toBe(422);
    const r = await sync(A.sync, 'pa', policy('pb'));
    expect(r.status).toBe(422);
  });
});

describe('policy sync', () => {
  it('main sync replaces blocks; re-sync without the entry clears it', async () => {
    const r = await sync(A.sync, 'pa', policy('pa', { block: [block('npm:evil@1.0.0')], allow: [allow('npm:fast@1.0.0')] }));
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ref: 'main', allows: 1, blocks: 1 });
    expect(await blockedVersions(e, 'npm', 'evil')).toEqual(new Set(['1.0.0']));
    expect((await loadPolicyView(e, 'pa', null, 'npm', 'fast')).allowed).toEqual(new Set(['1.0.0']));

    expect((await sync(A.sync, 'pa', policy('pa'))).status).toBe(200);
    expect(await blockedVersions(e, 'npm', 'evil')).toEqual(new Set());
    expect((await loadPolicyView(e, 'pa', null, 'npm', 'fast')).allowed).toEqual(new Set());
  });

  it('overlay before any main sync -> 409', async () => {
    const pc = await seedProject(e, 'pc');
    const r = await sync(pc.ci, 'pc', policy('pc'), 'pr-1');
    expect(r.status).toBe(409);
    expect(await r.text()).toContain('sync main first');
  });

  it('overlay rules: no cooldown/autoShip change, no missing blocks; only adds allows', async () => {
    const base = { cooldownDays: 5, block: [block('npm:evil@1.0.0')] };
    expect((await sync(A.sync, 'pa', policy('pa', base))).status).toBe(200);

    const diffCooldown = await sync(A.ci, 'pa', policy('pa', { ...base, cooldownDays: 0 }), 'pr-1');
    expect(diffCooldown.status).toBe(422);
    expect(await diffCooldown.text()).toContain('overlay may only add allow entries');
    const diffShip = await sync(A.ci, 'pa', policy('pa', { ...base, autoShip: { low: 'auto' } }), 'pr-1');
    expect(diffShip.status).toBe(422);
    const noBlock = await sync(A.ci, 'pa', policy('pa', { cooldownDays: 5 }), 'pr-1');
    expect(noBlock.status).toBe(422);

    const ok = await sync(A.ci, 'pa', policy('pa', { ...base, allow: [allow('npm:x@2.0.0')] }), 'pr-1');
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ ref: 'pr-1', allows: 1, blocks: 1 });
    expect((await loadPolicyView(e, 'pa', 'pr-1', 'npm', 'x')).allowed).toEqual(new Set(['2.0.0']));
    expect((await loadPolicyView(e, 'pa', null, 'npm', 'x')).allowed).toEqual(new Set());
    expect((await loadPolicyView(e, 'pb', 'pr-1', 'npm', 'x')).allowed).toEqual(new Set());

    const st = await call('GET', '/api/projects/pa/status', A.ci);
    const body = (await st.json()) as { mainSha: string; syncedAt: string; overlays: unknown[]; globalBlocks: number };
    expect(body.mainSha).toBe('abc123');
    expect(body.syncedAt).toBe('2026-11-19T12:00:00.000Z');
    expect(body.overlays).toEqual([{ ref: 'pr-1', syncedAt: '2026-11-19T12:00:00.000Z' }]);
    expect(body.globalBlocks).toBeGreaterThanOrEqual(1);
  });

  it('advisory allow still affected -> 422 naming the entry', async () => {
    const f = fakeFetch({
      [`${OSV}/v1/vulns/${GHSA}`]: Response.json({ id: GHSA, affected: [{ package: { ecosystem: 'npm', name: 'lodash' } }] }),
      [`${OSV}/v1/query`]: Response.json({ vulns: [{ id: GHSA }] }),
    });
    const r = await sync(B.sync, 'pb', policy('pb', { allow: [allow('npm:lodash@4.17.20', GHSA)] }), 'main', f);
    expect(r.status).toBe(422);
    expect(await r.text()).toContain('npm:lodash@4.17.20');
  });

  it('OSV 500 -> 503 and nothing is written', async () => {
    const before = await e.DB.prepare("SELECT COUNT(*) AS n FROM policies WHERE project_id = 'pb'").first<{ n: number }>();
    const f = fakeFetch({ [`${OSV}/v1/vulns/${GHSA}`]: new Response('boom', { status: 500 }) });
    const r = await sync(B.sync, 'pb', policy('pb', { allow: [allow('npm:plain@1.0.0'), allow('npm:lodash@4.17.21', GHSA)] }), 'main', f);
    expect(r.status).toBe(503);
    const after = await e.DB.prepare("SELECT COUNT(*) AS n FROM policies WHERE project_id = 'pb'").first<{ n: number }>();
    expect(after).toEqual(before);
    const allows = await e.DB.prepare("SELECT COUNT(*) AS n FROM allows WHERE project_id = 'pb'").first<{ n: number }>();
    expect(allows!.n).toBe(0);
  });

  it('verified advisory -> verified_at set and counted in the view', async () => {
    const f = fakeFetch({
      [`${OSV}/v1/vulns/${GHSA}`]: Response.json({ id: GHSA, affected: [{ package: { ecosystem: 'npm', name: 'lodash' } }] }),
      [`${OSV}/v1/query`]: Response.json({}),
    });
    const r = await sync(B.sync, 'pb', policy('pb', { allow: [allow('npm:lodash@4.17.21', GHSA), allow('npm:plain@1.0.0')] }), 'main', f);
    expect(r.status).toBe(200);
    const rows = await e.DB.prepare("SELECT name, verified_at FROM allows WHERE project_id = 'pb' ORDER BY name").all();
    expect(rows.results).toEqual([
      { name: 'lodash', verified_at: '2026-11-19T12:00:00.000Z' },
      { name: 'plain', verified_at: null },
    ]);
    expect((await loadPolicyView(e, 'pb', null, 'npm', 'lodash')).allowed).toEqual(new Set(['4.17.21']));
    expect((await loadPolicyView(e, 'pb', null, 'npm', 'plain')).allowed).toEqual(new Set(['1.0.0']));
  });

  it('syncs a large policy (200 plain allows, 100 blocks) in a handful of statements', async () => {
    const pd = await seedProject(e, 'pd');
    const allows = Array.from({ length: 200 }, (_, i) => allow(`npm:many@1.0.${i}`));
    const blocks = Array.from({ length: 100 }, (_, i) => block(`npm:bad-many@1.0.${i}`));
    // Count statements sent to D1: each one counts against the per-invocation query limit.
    let statements = 0;
    const unwrap = new WeakMap<object, D1PreparedStatement>();
    const wrapStmt = (st: D1PreparedStatement): D1PreparedStatement => {
      const w = new Proxy(st, {
        get(t, p) {
          const v = Reflect.get(t, p) as (...a: unknown[]) => unknown;
          if (p === 'bind') return (...a: unknown[]) => wrapStmt(v.apply(t, a) as D1PreparedStatement);
          if (p === 'first' || p === 'run' || p === 'all' || p === 'raw') return (...a: unknown[]) => ((statements += 1), v.apply(t, a));
          return typeof v === 'function' ? v.bind(t) : v;
        },
      });
      unwrap.set(w, st);
      return w;
    };
    const countingDb = new Proxy(e.DB, {
      get(t, p) {
        if (p === 'prepare') return (q: string) => wrapStmt(t.prepare(q));
        // D1 batch needs the real statement objects; count each one.
        if (p === 'batch') return (s: D1PreparedStatement[]) => ((statements += s.length), t.batch(s.map((x) => unwrap.get(x) ?? x)));
        const v = Reflect.get(t, p);
        return typeof v === 'function' ? v.bind(t) : v;
      },
    });
    const body = JSON.stringify({ policy: policy('pd', { allow: allows, block: blocks }), sha: 'abc123', ref: 'main' });
    const r = await handle(
      new Request('https://h/api/projects/pd/policy', { method: 'PUT', headers: { authorization: `Bearer ${pd.sync}` }, body }),
      { ...e, DB: countingDb },
      { fetch: fakeFetch({}), now },
      ctx,
    );
    expect(r.status).toBe(200);
    expect(statements).toBeLessThanOrEqual(10);
    expect(await r.json()).toEqual({ ref: 'main', allows: 200, blocks: 100 });
    expect((await loadPolicyView(e, 'pd', null, 'npm', 'many')).allowed.size).toBe(200);
    expect((await blockedVersions(e, 'npm', 'bad-many')).size).toBe(100);
    const row = await e.DB.prepare("SELECT reason, verified_at, advisory FROM allows WHERE project_id = 'pd' AND version = '1.0.7'").first();
    expect(row).toEqual({ reason: 'r', verified_at: null, advisory: null });
  });

  it('duplicate allow entries -> 422', async () => {
    const r = await sync(B.sync, 'pb', policy('pb', { allow: [allow('npm:d@1.0.0'), allow('npm:d@1.0.0')] }));
    expect(r.status).toBe(422);
  });
});

describe('verdicts', () => {
  it('malicious verdict -> blocked; GET lists verdicts', async () => {
    const v = { package: 'npm:mal@6.6.6', scanner: 'guarddog', scannerVersion: '2.1.0', result: 'malicious', details: { rule: 'exfil' } };
    const r = await call('PUT', '/api/verdicts', B.ci, v);
    expect(r.status).toBe(204);
    expect(await blockedVersions(e, 'npm', 'mal')).toEqual(new Set(['6.6.6']));
    const src = await e.DB.prepare("SELECT source FROM global_blocks WHERE name = 'mal'").first<{ source: string }>();
    expect(src!.source).toBe('verdict:guarddog');

    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, package: 'npm:fine@1.0.0', result: 'clean' })).status).toBe(204);
    expect(await blockedVersions(e, 'npm', 'fine')).toEqual(new Set());

    const g = await call('GET', '/api/verdicts?package=npm:mal@6.6.6', A.ci);
    expect(g.status).toBe(200);
    expect(await g.json()).toEqual({
      verdicts: [
        {
          package: 'npm:mal@6.6.6',
          scanner: 'guarddog',
          scannerVersion: '2.1.0',
          result: 'malicious',
          details: { rule: 'exfil' },
          scannedAt: '2026-11-19T12:00:00.000Z',
        },
      ],
    });
  });

  it('never downgrades a verdict; same-or-higher severity updates; writer project recorded', async () => {
    const v = { package: 'npm:sev@1.0.0', scanner: 'guarddog', scannerVersion: '2.1.0' };
    const get = async () =>
      e.DB.prepare("SELECT result, scanner_version, project_id FROM verdicts WHERE name = 'sev'").first<Record<string, string>>();

    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, result: 'clean' })).status).toBe(204);
    expect(await get()).toEqual({ result: 'clean', scanner_version: '2.1.0', project_id: 'pa' });

    expect((await call('PUT', '/api/verdicts', B.ci, { ...v, result: 'flagged', scannerVersion: '2.2.0' })).status).toBe(204);
    expect(await get()).toEqual({ result: 'flagged', scanner_version: '2.2.0', project_id: 'pb' });

    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, result: 'malicious' })).status).toBe(204);
    expect(await get()).toMatchObject({ result: 'malicious', project_id: 'pa' });

    const down = await call('PUT', '/api/verdicts', B.ci, { ...v, result: 'clean', scannerVersion: '9.9.9' });
    expect(down.status).toBe(204);
    expect(await get()).toEqual({ result: 'malicious', scanner_version: '2.1.0', project_id: 'pa' });
    expect((await call('PUT', '/api/verdicts', B.ci, { ...v, result: 'flagged' })).status).toBe(204);
    expect((await get())!.result).toBe('malicious');
    expect(await blockedVersions(e, 'npm', 'sev')).toEqual(new Set(['1.0.0']));
  });

  it('validates package and result', async () => {
    const v = { package: 'npm:a@1.0.0', scanner: 's', scannerVersion: '1', result: 'clean' };
    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, package: 'nope' })).status).toBe(400);
    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, result: 'evil' })).status).toBe(400);
    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, scanner: '' })).status).toBe(400);
    expect((await call('GET', '/api/verdicts?package=bad', A.ci)).status).toBe(400);
    expect((await call('GET', '/api/verdicts', A.ci)).status).toBe(400);
  });
});
