import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { hashToken, newToken } from '../src/auth';
import { handle } from '../src/index';
import { fakeFetch, fixedClock, seedProject } from './helpers';
import type { Deps, Env } from '../src/types';

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const opToken = newToken('op');
let e: Env;
type Tokens = { read: string; ci: string; sync: string };
let A: Tokens;
let B: Tokens;

beforeAll(async () => {
  e = { ...(env as unknown as Env), OPERATOR_TOKEN_HASH: await hashToken(opToken) };
  A = await seedProject(e, 'da');
  B = await seedProject(e, 'db');
});

function put(project: string, token: string, body: unknown): Promise<Response> {
  const deps: Deps = { fetch: fakeFetch({}), now: fixedClock('2026-11-19T12:00:00Z') };
  const init: RequestInit = { method: 'PUT', headers: { authorization: `Bearer ${token}` }, body: typeof body === 'string' ? body : JSON.stringify(body) };
  return handle(new Request(`https://h/api/projects/${project}/deps`, init), e, deps, ctx);
}

const dep = (over: Record<string, unknown> = {}) => ({ eco: 'npm', name: 'a', version: '1.0.0', direct: true, via: [], ...over });
const row = (id: string) => e.DB.prepare('SELECT sha, synced_at, json FROM project_deps WHERE project_id = ?').bind(id).first<{ sha: string; synced_at: string; json: string }>();

describe('PUT /api/projects/:id/deps', () => {
  it("stores the project's summary with its own sync token, replacing the previous one", async () => {
    const first = await put('da', A.sync, { sha: 's1', deps: [dep(), dep({ name: 'b', direct: false, via: ['a'] })] });
    expect(first.status).toBe(200);
    expect(first.headers.get('cache-control')).toBe('no-store');
    expect(await first.json()).toEqual({ deps: 2 });
    expect((await put('da', A.sync, { sha: 's2', deps: [dep({ eco: 'go', name: 'example.com/m', version: 'v1.0.0' })] })).status).toBe(200);
    const r = await row('da');
    expect(r?.sha).toBe('s2');
    expect(r?.synced_at).toBe('2026-11-19T12:00:00.000Z');
    expect(JSON.parse(r!.json)).toEqual([{ eco: 'go', name: 'example.com/m', version: 'v1.0.0', direct: true, via: [] }]);
  });

  it('stores only the known fields', async () => {
    expect((await put('da', A.sync, { sha: 's3', deps: [dep({ resolved: 'https://x', extra: 1 })] })).status).toBe(200);
    expect(JSON.parse((await row('da'))!.json)).toEqual([dep()]);
  });

  it('ci, read, operator and another project’s sync token → 403; no token → 401', async () => {
    const body = { sha: 's', deps: [dep()] };
    expect((await put('da', A.ci, body)).status).toBe(403);
    expect((await put('da', A.read, body)).status).toBe(403);
    expect((await put('da', opToken, body)).status).toBe(403);
    expect((await put('da', B.sync, body)).status).toBe(403);
    const anon = await handle(new Request('https://h/api/projects/da/deps', { method: 'PUT', body: '{}' }), e, { fetch: fakeFetch({}), now: () => new Date() }, ctx);
    expect(anon.status).toBe(401);
    expect(await row('db')).toBeNull();
  });

  it('only PUT', async () => {
    const r = await handle(
      new Request('https://h/api/projects/da/deps', { method: 'GET', headers: { authorization: `Bearer ${A.sync}` } }),
      e,
      { fetch: fakeFetch({}), now: () => new Date() },
      ctx,
    );
    expect(r.status).toBe(405);
  });

  it('validates the body', async () => {
    const bad: unknown[] = [
      { deps: [dep()] },
      { sha: '', deps: [dep()] },
      { sha: 'x'.repeat(101), deps: [dep()] },
      { sha: 's' },
      { sha: 's', deps: {} },
      { sha: 's', deps: [null] },
      { sha: 's', deps: [dep({ eco: 'pypi' })] },
      { sha: 's', deps: [dep({ name: '' })] },
      { sha: 's', deps: [dep({ name: 'x'.repeat(215) })] },
      { sha: 's', deps: [dep({ name: 1 })] },
      { sha: 's', deps: [dep({ version: 'x'.repeat(129) })] },
      { sha: 's', deps: [dep({ version: 1 })] },
      { sha: 's', deps: [dep({ direct: 'yes' })] },
      { sha: 's', deps: [dep({ via: 'a' })] },
      { sha: 's', deps: [dep({ via: ['a', 'b', 'c', 'd', 'e', 'f'] })] },
      { sha: 's', deps: [dep({ via: [1] })] },
      { sha: 's', deps: [dep({ via: ['x'.repeat(215)] })] },
    ];
    for (const b of bad) {
      const r = await put('db', B.sync, b);
      expect(r.status, JSON.stringify(b).slice(0, 80)).toBe(400);
      expect(typeof ((await r.json()) as { error: string }).error).toBe('string');
    }
    expect((await put('db', B.sync, 'not json')).status).toBe(400);
    expect(await row('db')).toBeNull();
  });

  it('accepts names and versions at the limits', async () => {
    const r = await put('db', B.sync, { sha: 's', deps: [dep({ name: 'n'.repeat(214), version: 'v'.repeat(128), via: ['a', 'b', 'c', 'd', 'e'] })] });
    expect(r.status).toBe(200);
  });

  it('rejects a body over 1 MB with 413', async () => {
    const deps = Array.from({ length: 6000 }, (_, i) => dep({ name: `${'x'.repeat(200)}${i}` }));
    const r = await put('db', B.sync, { sha: 'big', deps });
    expect(r.status).toBe(413);
    expect((await row('db'))?.sha).not.toBe('big');
  });
});
