import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handle } from '../src/index';
import { fakeFetch, seedProject } from './helpers';
import type { Deps, Env } from '../src/types';

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let clock = new Date('2026-11-19T12:00:00Z');
let e: Env;
type Tokens = { read: string; ci: string; sync: string };
let A: Tokens;
let B: Tokens;

const dg = (c: string) => `sha256:${c.repeat(64)}`;
const NODE = 'docker.io/library/node';

beforeAll(async () => {
  e = env as unknown as Env;
  A = await seedProject(e, 'dka');
  B = await seedProject(e, 'dkb');
});

function call(method: string, path: string, token: string | null, body?: unknown, fetch: typeof globalThis.fetch = fakeFetch({})): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const init: RequestInit = { method, headers };
  if (body !== undefined) init.body = typeof body === 'string' ? body : JSON.stringify(body);
  const deps: Deps = { fetch, now: () => clock };
  return handle(new Request(`https://h${path}`, init), e, deps, ctx);
}

const syncPolicy = (token: string, project: string, p: unknown, ref = 'main') =>
  call('PUT', `/api/projects/${project}/policy`, token, { policy: p, sha: 'abc', ref });

type ImagesReply = {
  cooldownDays: number;
  images: { name: string; digest: string; firstSeen: string; eligibleAt: string; decision: string; blocks: { source: string; reason: string }[] }[];
};
const images = async (token: string, ref: string, list: { name: string; digest: string; files?: string[] }[]) => {
  const r = await call('POST', '/api/images', token, { ref, sha: 'abc', images: list });
  return { status: r.status, body: (await r.json()) as ImagesReply & { error?: string } };
};

describe('docker policy entries', () => {
  it('accepts docker allow (with an advisory, not checked against OSV) and block entries', async () => {
    // No OSV route: an OSV call would throw in fakeFetch.
    const r = await syncPolicy(A.sync, 'dka', {
      project: 'dka',
      allow: [{ package: `docker:${NODE}@${dg('1')}`, reason: 'urgent base fix', advisory: 'CVE-2026-1234', added: '2026-11-18' }],
      block: [{ package: `docker:ghcr.io/evil/img@${dg('2')}`, reason: 'bad' }],
    });
    expect(r.status).toBe(200);
    const row = await e.DB.prepare("SELECT verified_at FROM allows WHERE project_id = 'dka' AND eco = 'docker'").first<{ verified_at: string | null }>();
    expect(row?.verified_at).not.toBeNull();
  });

  it('rejects a docker entry that is not a normalized repository pinned by digest', async () => {
    const r = await syncPolicy(A.sync, 'dka', { project: 'dka', block: [{ package: 'docker:node@sha256:abc', reason: 'x' }] });
    expect(r.status).toBe(422);
    expect(JSON.stringify(await r.json())).toContain('docker:docker.io/library/node@sha256:');
  });
});

describe('POST /api/images', () => {
  it('records first-seen, keeps it on later calls, and decides cooldown / allow / blocked', async () => {
    await syncPolicy(A.sync, 'dka', {
      project: 'dka',
      cooldownDays: 7,
      allow: [{ package: `docker:${NODE}@${dg('1')}`, reason: 'needed now', added: '2026-11-18' }],
      block: [{ package: `docker:ghcr.io/evil/img@${dg('2')}`, reason: 'compromised' }],
    });
    clock = new Date('2026-11-19T12:00:00Z');
    const first = await images(A.ci, 'pr-3', [
      { name: NODE, digest: dg('1') },
      { name: 'ghcr.io/evil/img', digest: dg('2') },
      { name: NODE, digest: dg('3') },
    ]);
    expect(first.status).toBe(200);
    expect(first.body.cooldownDays).toBe(7);
    const by = (d: string) => first.body.images.find((i) => i.digest === d)!;
    expect(by(dg('1'))).toMatchObject({ name: NODE, decision: 'allow', firstSeen: '2026-11-19T12:00:00.000Z' });
    expect(by(dg('2'))).toMatchObject({ decision: 'blocked', blocks: [{ source: 'policy:dka', reason: 'compromised' }] });
    expect(by(dg('3'))).toMatchObject({ decision: 'cooldown', firstSeen: '2026-11-19T12:00:00.000Z', eligibleAt: '2026-11-26T12:00:00.000Z' });

    // Eight days later the clock has run out for dg('3'); first-seen did not move.
    clock = new Date('2026-11-27T12:00:00Z');
    const later = await images(A.ci, 'pr-4', [{ name: NODE, digest: dg('3') }]);
    expect(later.body.images[0]).toMatchObject({ decision: 'allow', firstSeen: '2026-11-19T12:00:00.000Z' });
    clock = new Date('2026-11-19T12:00:00Z');
  });

  it('first-seen is global: another project sees the same clock', async () => {
    await syncPolicy(B.sync, 'dkb', { project: 'dkb' });
    clock = new Date('2026-11-20T00:00:00Z');
    const r = await images(B.ci, 'pr-1', [{ name: NODE, digest: dg('3') }]);
    expect(r.body.images[0]!.firstSeen).toBe('2026-11-19T12:00:00.000Z');
    clock = new Date('2026-11-19T12:00:00Z');
  });

  it('main (sync token) replaces the images in use; a ci call never does', async () => {
    const main = await images(A.sync, 'main', [{ name: NODE, digest: dg('4'), files: ['Dockerfile', 'api/Dockerfile'] }]);
    expect(main.status).toBe(200);
    await images(A.ci, 'pr-9', [{ name: NODE, digest: dg('5') }]);
    const rows = await e.DB.prepare("SELECT name, digest, files FROM project_images WHERE project_id = 'dka'").all();
    expect(rows.results).toEqual([{ name: NODE, digest: dg('4'), files: '["Dockerfile","api/Dockerfile"]' }]);
    await images(A.sync, 'main', []);
    expect((await e.DB.prepare("SELECT COUNT(*) AS n FROM project_images WHERE project_id = 'dka'").first<{ n: number }>())!.n).toBe(0);
  });

  it('token rules: ci only for non-main refs, sync only for main; read and operator refused', async () => {
    expect((await images(A.ci, 'main', [])).status).toBe(403);
    expect((await images(A.sync, 'pr-1', [])).status).toBe(403);
    expect((await images(A.read, 'pr-1', [])).status).toBe(403);
    expect((await call('GET', '/api/images', A.ci)).status).toBe(405);
  });

  it('validates the body', async () => {
    const bad = async (body: unknown) => (await call('POST', '/api/images', A.ci, body)).status;
    expect(await bad({ ref: 'pr-1', images: [{ name: 'node', digest: dg('1') }] })).toBe(400);
    expect(await bad({ ref: 'pr-1', images: [{ name: NODE, digest: 'sha256:abc' }] })).toBe(400);
    expect(await bad({ ref: 'pr 1', images: [] })).toBe(400);
    expect(await bad({ ref: 'pr-1' })).toBe(400);
    expect(await bad({ ref: 'pr-1', images: Array.from({ length: 201 }, (_, i) => ({ name: NODE, digest: `sha256:${i.toString(16).padStart(64, '0')}` })) })).toBe(400);
    expect(await bad({ ref: 'pr-1', images: [{ name: NODE, digest: dg('1'), files: ['x'.repeat(600)] }] })).toBe(400);
  });
});

describe('docker verdicts', () => {
  it('stores a grype verdict keyed docker/repo/digest and never downgrades it', async () => {
    const id = `docker:${NODE}@${dg('6')}`;
    const put = (result: string) => call('PUT', '/api/verdicts', A.ci, { package: id, scanner: 'grype', scannerVersion: '0.121.3', result, details: [] });
    expect((await put('flagged')).status).toBe(204);
    expect((await put('clean')).status).toBe(204);
    const r = (await (await call('GET', `/api/verdicts?package=${encodeURIComponent(id)}`, A.ci)).json()) as { verdicts: { result: string }[] };
    expect(r.verdicts.map((v) => v.result)).toEqual(['flagged']);
  });
});
