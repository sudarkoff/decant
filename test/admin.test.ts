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
let A: { read: string; ci: string };
let B: { read: string; ci: string };

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
    expect((await sync(A.ci, 'pb', policy('pb'))).status).toBe(403);
    expect((await call('GET', '/api/projects/pb/status', A.ci)).status).toBe(403);
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
    expect((await call('PUT', '/api/projects/pa/policy', A.ci, { policy: policy('pa'), sha: 'x' })).status).toBe(400);
    expect((await call('PUT', '/api/projects/pa/policy', A.ci, { policy: policy('pa'), sha: 'x', ref: 'bad ref' })).status).toBe(400);
    expect((await sync(A.ci, 'pa', { project: 'pa', cooldownDays: -1 })).status).toBe(422);
    const r = await sync(A.ci, 'pa', policy('pb'));
    expect(r.status).toBe(422);
  });
});

describe('policy sync', () => {
  it('main sync replaces blocks; re-sync without the entry clears it', async () => {
    const r = await sync(A.ci, 'pa', policy('pa', { block: [block('npm:evil@1.0.0')], allow: [allow('npm:fast@1.0.0')] }));
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ref: 'main', allows: 1, blocks: 1 });
    expect(await blockedVersions(e, 'npm', 'evil')).toEqual(new Set(['1.0.0']));
    expect((await loadPolicyView(e, 'pa', null)).allowedFor('npm', 'fast')).toEqual(new Set(['1.0.0']));

    expect((await sync(A.ci, 'pa', policy('pa'))).status).toBe(200);
    expect(await blockedVersions(e, 'npm', 'evil')).toEqual(new Set());
    expect((await loadPolicyView(e, 'pa', null)).allowedFor('npm', 'fast')).toEqual(new Set());
  });

  it('overlay before any main sync -> 409', async () => {
    const pc = await seedProject(e, 'pc');
    const r = await sync(pc.ci, 'pc', policy('pc'), 'pr-1');
    expect(r.status).toBe(409);
    expect(await r.text()).toContain('sync main first');
  });

  it('overlay rules: no cooldown/autoShip change, no missing blocks; only adds allows', async () => {
    const base = { cooldownDays: 5, block: [block('npm:evil@1.0.0')] };
    expect((await sync(A.ci, 'pa', policy('pa', base))).status).toBe(200);

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
    expect((await loadPolicyView(e, 'pa', 'pr-1')).allowedFor('npm', 'x')).toEqual(new Set(['2.0.0']));
    expect((await loadPolicyView(e, 'pa', null)).allowedFor('npm', 'x')).toEqual(new Set());
    expect((await loadPolicyView(e, 'pb', 'pr-1')).allowedFor('npm', 'x')).toEqual(new Set());

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
    const r = await sync(B.ci, 'pb', policy('pb', { allow: [allow('npm:lodash@4.17.20', GHSA)] }), 'main', f);
    expect(r.status).toBe(422);
    expect(await r.text()).toContain('npm:lodash@4.17.20');
  });

  it('OSV 500 -> 503 and nothing is written', async () => {
    const before = await e.DB.prepare("SELECT COUNT(*) AS n FROM policies WHERE project_id = 'pb'").first<{ n: number }>();
    const f = fakeFetch({ [`${OSV}/v1/vulns/${GHSA}`]: new Response('boom', { status: 500 }) });
    const r = await sync(B.ci, 'pb', policy('pb', { allow: [allow('npm:plain@1.0.0'), allow('npm:lodash@4.17.21', GHSA)] }), 'main', f);
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
    const r = await sync(B.ci, 'pb', policy('pb', { allow: [allow('npm:lodash@4.17.21', GHSA), allow('npm:plain@1.0.0')] }), 'main', f);
    expect(r.status).toBe(200);
    const rows = await e.DB.prepare("SELECT name, verified_at FROM allows WHERE project_id = 'pb' ORDER BY name").all();
    expect(rows.results).toEqual([
      { name: 'lodash', verified_at: '2026-11-19T12:00:00.000Z' },
      { name: 'plain', verified_at: null },
    ]);
    const v = await loadPolicyView(e, 'pb', null);
    expect(v.allowedFor('npm', 'lodash')).toEqual(new Set(['4.17.21']));
    expect(v.allowedFor('npm', 'plain')).toEqual(new Set(['1.0.0']));
  });

  it('duplicate allow entries -> 422', async () => {
    const r = await sync(B.ci, 'pb', policy('pb', { allow: [allow('npm:d@1.0.0'), allow('npm:d@1.0.0')] }));
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

  it('validates package and result', async () => {
    const v = { package: 'npm:a@1.0.0', scanner: 's', scannerVersion: '1', result: 'clean' };
    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, package: 'nope' })).status).toBe(400);
    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, result: 'evil' })).status).toBe(400);
    expect((await call('PUT', '/api/verdicts', A.ci, { ...v, scanner: '' })).status).toBe(400);
    expect((await call('GET', '/api/verdicts?package=bad', A.ci)).status).toBe(400);
    expect((await call('GET', '/api/verdicts', A.ci)).status).toBe(400);
  });
});
