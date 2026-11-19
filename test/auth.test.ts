import { env } from 'cloudflare:workers';
import { beforeAll, expect, it } from 'vitest';
import { authenticate, hashToken, newToken } from '../src/auth';
import { handle } from '../src/index';
import { fakeFetch, fixedClock, seedProject } from './helpers';
import type { Env } from '../src/types';

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const deps = { fetch: fakeFetch({}), now: fixedClock('2026-11-19T00:00:00Z') };
const opToken = newToken('op');
let e: Env;
let tokens: { read: string; ci: string; sync: string };

beforeAll(async () => {
  e = { ...(env as unknown as Env), OPERATOR_TOKEN_HASH: await hashToken(opToken) };
  tokens = await seedProject(e, 'proj1');
});

const get = (path: string, headers: Record<string, string> = {}, method = 'GET') =>
  handle(new Request(`https://h${path}`, { headers, method }), e, deps, ctx);
// The npm handler answers PUT with 405, which proves the request got past auth.
const bearer = (t: string) => ({ authorization: `Bearer ${t}` });

it('no header -> 401 with Basic challenge', async () => {
  const res = await get('/npm/x');
  expect(res.status).toBe(401);
  expect(res.headers.get('www-authenticate')).toBe('Basic realm="decant"');
});

it('unknown token -> 401', async () => {
  expect((await get('/npm/x', bearer(newToken('read')))).status).toBe(401);
});

it('read token over Bearer reaches /npm/', async () => {
  expect((await get('/npm/', bearer(tokens.read), 'PUT')).status).toBe(405);
});

it('ci token reaches /go/', async () => {
  expect((await get('/go/x', bearer(tokens.ci), 'POST')).status).toBe(405);
});

it('read token as Basic password reaches /go/', async () => {
  const b = btoa(`anyuser:${tokens.read}`);
  expect((await get('/go/x', { authorization: `Basic ${b}` }, 'POST')).status).toBe(405);
});

it('operator token on /npm/ -> 403', async () => {
  expect((await get('/npm/x', bearer(opToken))).status).toBe(403);
});

it('invalid refs -> 404 (before auth)', async () => {
  expect((await get('/r/bad$ref/npm/x', bearer(tokens.read))).status).toBe(404);
  expect((await get(`/r/${'a'.repeat(65)}/npm/x`, bearer(tokens.read))).status).toBe(404);
  expect((await get('/r/../npm/x')).status).toBe(401); // URL parser collapses to /npm/x
});

it('valid ref routes with auth', async () => {
  expect((await get('/r/pr-12/npm/x', bearer(tokens.read), 'PUT')).status).toBe(405);
});

it('read token reaches PR overlay routes for npm (Bearer) and Go (netrc Basic)', async () => {
  // `setup` on a PR points npm and GOPROXY at /r/pr-<n>/ with the read token.
  expect((await get('/r/pr-12/npm/', bearer(tokens.read), 'PUT')).status).toBe(405);
  const b = btoa(`decant:${tokens.read}`);
  expect((await get('/r/pr-12/go/x', { authorization: `Basic ${b}` }, 'POST')).status).toBe(405);
});

it('anything else -> 404; unknown /api/* is 404 for operator', async () => {
  expect((await get('/nope')).status).toBe(404);
  expect((await get('/api/x', bearer(opToken))).status).toBe(404);
});

it('/api/* requires authentication; per-route authz is the admin handler', async () => {
  const res = await get('/api/x');
  expect(res.status).toBe(401);
  expect(res.headers.get('www-authenticate')).toBe('Basic realm="decant"');
  expect((await get('/api/x', bearer(tokens.read))).status).toBe(403); // read tokens never reach admin routes
  expect((await get('/api/x', bearer(tokens.ci))).status).toBe(404); // CI not rejected at router; unknown route
});

it('empty OPERATOR_TOKEN_HASH never authenticates', async () => {
  const noOp = { ...e, OPERATOR_TOKEN_HASH: '' };
  for (const t of ['', await hashToken('')]) {
    const r = await authenticate(new Request('https://h/api/x', { headers: bearer(t) }), noOp);
    expect(r).toBeNull();
  }
  const r2 = await authenticate(new Request('https://h/api/x', { headers: { authorization: 'Basic ' + btoa('u:') } }), noOp);
  expect(r2).toBeNull();
});

it('OPERATOR_TOKEN_HASH is normalized: uppercase with whitespace authenticates; whitespace-only never does', async () => {
  const req = (t: string) => new Request('https://h/api/x', { headers: bearer(t) });
  const messy = { ...e, OPERATOR_TOKEN_HASH: `  ${(await hashToken(opToken)).toUpperCase()}\n` };
  expect(await authenticate(req(opToken), messy)).toEqual({ kind: 'operator' });
  const blank = { ...e, OPERATOR_TOKEN_HASH: ' \n\t ' };
  expect(await authenticate(req(opToken), blank)).toBeNull();
  expect(await authenticate(new Request('https://h/api/x', { headers: { authorization: 'Basic ' + btoa('u:') } }), blank)).toBeNull();
});

it('authenticate returns contexts', async () => {
  const req = (t: string) => new Request('https://h/', { headers: bearer(t) });
  expect(await authenticate(req(opToken), e)).toEqual({ kind: 'operator' });
  expect(await authenticate(req(tokens.read), e)).toEqual({ kind: 'read', projectId: 'proj1' });
  expect(await authenticate(req(tokens.ci), e)).toEqual({ kind: 'ci', projectId: 'proj1' });
  expect(await authenticate(req(tokens.sync), e)).toEqual({ kind: 'sync', projectId: 'proj1' });
});

it('hashToken is 64 hex; newToken format', async () => {
  expect(await hashToken('x')).toMatch(/^[0-9a-f]{64}$/);
  expect(newToken('ci')).toMatch(/^dk_ci_[A-Za-z0-9_-]{43}$/);
  expect(newToken('read')).toMatch(/^dk_read_[A-Za-z0-9_-]{43}$/);
  expect(newToken('sync')).toMatch(/^dk_sync_[A-Za-z0-9_-]{43}$/);
  expect(newToken('op')).toMatch(/^dk_op_[A-Za-z0-9_-]{43}$/);
});

it('sync token is not an install credential: 403 on npm and go routes', async () => {
  expect((await get('/npm/x', bearer(tokens.sync))).status).toBe(403);
  expect((await get('/r/pr-1/npm/x', bearer(tokens.sync))).status).toBe(403);
  expect((await get('/go/example.com/x/@v/list', bearer(tokens.sync))).status).toBe(403);
});

it('pre-existing kinds still authenticate and the widened CHECK accepts sync', async () => {
  // Limitation: the harness applies all migrations up front, so the 0003 row copy is not
  // exercised against pre-populated 0001/0002 data; we check the post-migration table instead.
  expect((await get('/npm/x', bearer(tokens.read))).status).not.toBe(401);
  await e.DB.prepare("INSERT INTO tokens (hash, project_id, kind, created_at) VALUES ('h-sync-ok', 'proj1', 'sync', 'x')").run();
  await expect(
    e.DB.prepare("INSERT INTO tokens (hash, project_id, kind, created_at) VALUES ('h-bad', 'proj1', 'admin', 'x')").run(),
  ).rejects.toThrow();
  await expect(
    e.DB.prepare("INSERT INTO tokens (hash, project_id, kind, created_at) VALUES ('h-fk', 'nope', 'ci', 'x')").run(),
  ).rejects.toThrow();
});
