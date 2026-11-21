import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { handle } from '../src/index';
import { seedProject } from './helpers';
import type { Deps, Env } from '../src/types';

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let clock = new Date('2026-11-19T12:00:00Z');
let e: Env;
type Tokens = { read: string; ci: string; sync: string };
let A: Tokens;
let B: Tokens;
let C: Tokens;

const dg = (c: string) => `sha256:${c.repeat(64)}`;
const NODE = 'docker.io/library/node';

beforeAll(async () => {
  e = env as unknown as Env;
  A = await seedProject(e, 'dka');
  B = await seedProject(e, 'dkb');
  C = await seedProject(e, 'dkc');
});

/**
 * A fake Docker Hub / ghcr.io: anonymous tokens for every repository except `private`, and manifests for the
 * digests in `pushed` (repo@digest). Records every request URL.
 */
const pushed = new Set<string>();
let registryDown = false;
const registryCalls: string[] = [];
const registry: typeof globalThis.fetch = async (input, init) => {
  const req = new Request(input, init);
  const u = new URL(req.url);
  registryCalls.push(`${req.method} ${req.url}`);
  if (registryDown) return new Response('down', { status: 503 });
  if (u.pathname === '/token') {
    const scope = u.searchParams.get('scope') ?? '';
    if (scope.includes(':private/')) return new Response('{"errors":[]}', { status: 401 });
    return Response.json({ token: 'anon' });
  }
  const m = /^\/v2\/(.+)\/manifests\/(sha256:[0-9a-f]{64})$/.exec(u.pathname);
  if (!m || req.headers.get('authorization') !== 'Bearer anon') return new Response('nope', { status: 401 });
  const host = u.host === 'registry-1.docker.io' ? 'docker.io' : u.host;
  if (!pushed.has(`${host}/${m[1]}@${m[2]}`)) return new Response('', { status: 404 });
  return new Response(null, { status: 200, headers: { 'docker-content-digest': m[2]! } });
};

function call(method: string, path: string, token: string | null, body?: unknown, fetch: typeof globalThis.fetch = registry): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const init: RequestInit = { method, headers };
  if (body !== undefined) init.body = typeof body === 'string' ? body : JSON.stringify(body);
  const deps: Deps = { fetch, now: () => clock };
  return handle(new Request(`https://h${path}`, init), e, deps, ctx);
}

const details = async (id: string) => {
  const r = (await (await call('GET', `/api/verdicts?package=${encodeURIComponent(id)}`, A.ci)).json()) as { verdicts: { details?: unknown }[] };
  return r.verdicts[0]?.details;
};

const syncPolicy = (token: string, project: string, p: unknown, ref = 'main') =>
  call('PUT', `/api/projects/${project}/policy`, token, { policy: p, sha: 'abc', ref });

type ImagesReply = {
  cooldownDays: number;
  images: { name: string; digest: string; clock: string; note?: string; firstSeen: string | null; eligibleAt: string | null; decision: string; blocks: { source: string; reason: string }[] }[];
};
const images = async (token: string, ref: string, list: { name: string; digest: string; files?: string[] }[]) => {
  const r = await call('POST', '/api/images', token, { ref, sha: 'abc', images: list });
  return { status: r.status, body: (await r.json()) as ImagesReply & { error?: string } };
};

describe('docker policy entries', () => {
  it('accepts docker allow (with an advisory, not checked against OSV) and block entries', async () => {
    // The fake fetch has no OSV route: this passes only because image advisories are not sent to OSV.
    const r = await syncPolicy(A.sync, 'dka', {
      project: 'dka',
      allow: [{ package: `docker:${NODE}@${dg('1')}`, reason: 'urgent base fix', advisory: 'CVE-2026-1234', added: '2026-11-18' }],
      block: [{ package: `docker:ghcr.io/evil/img@${dg('2')}`, reason: 'bad' }],
    });
    expect(r.status).toBe(200);
    expect(registryCalls.filter((c) => c.includes('osv.dev'))).toEqual([]);
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
    for (const d of ['1', '2', '3']) pushed.add(`${d === '2' ? 'ghcr.io/evil/img' : NODE}@${dg(d)}`);
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
    expect(by(dg('3'))).toMatchObject({ clock: 'shared', decision: 'cooldown', firstSeen: '2026-11-19T12:00:00.000Z', eligibleAt: '2026-11-26T12:00:00.000Z' });

    // Eight days later the clock has run out for dg('3'); first-seen did not move.
    clock = new Date('2026-11-27T12:00:00Z');
    registryCalls.length = 0;
    const later = await images(A.ci, 'pr-4', [{ name: NODE, digest: dg('3') }]);
    expect(later.body.images[0]).toMatchObject({ decision: 'allow', firstSeen: '2026-11-19T12:00:00.000Z' });
    expect(registryCalls).toEqual([]); // verified digests are immutable: never re-checked
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
    pushed.add(`${NODE}@${dg('4')}`);
    const main = await images(A.sync, 'main', [{ name: NODE, digest: dg('4'), files: ['Dockerfile', 'api/Dockerfile'] }]);
    expect(main.status).toBe(200);
    await images(A.ci, 'pr-9', [{ name: NODE, digest: dg('5') }]);
    const rows = await e.DB.prepare("SELECT name, digest, files FROM project_images WHERE project_id = 'dka'").all();
    expect(rows.results).toEqual([{ name: NODE, digest: dg('4'), files: '["Dockerfile","api/Dockerfile"]' }]);
    await images(A.sync, 'main', []);
    expect((await e.DB.prepare("SELECT COUNT(*) AS n FROM project_images WHERE project_id = 'dka'").first<{ n: number }>())!.n).toBe(0);
  });

  it('a digest the registry does not have (not pushed yet) starts no clock, and stays in cooldown until verified', async () => {
    clock = new Date('2026-11-19T12:00:00Z');
    const r = await images(A.ci, 'pr-5', [{ name: NODE, digest: dg('7') }]);
    expect(r.body.images[0]).toMatchObject({ clock: 'unverified', decision: 'cooldown', firstSeen: null, eligibleAt: null, note: 'registry does not have this digest' });
    expect(await e.DB.prepare("SELECT 1 FROM versions WHERE eco = 'docker' AND version = ?").bind(dg('7')).first()).toBeNull();

    // Pushed 8 days later: the clock starts at verification, not at the earlier report.
    clock = new Date('2026-11-27T12:00:00Z');
    pushed.add(`${NODE}@${dg('7')}`);
    const later = await images(B.ci, 'pr-5', [{ name: NODE, digest: dg('7') }]);
    expect(later.body.images[0]).toMatchObject({ clock: 'shared', decision: 'cooldown', firstSeen: '2026-11-27T12:00:00.000Z' });
    clock = new Date('2026-11-19T12:00:00Z');
  });

  it('a registry error fails closed: no clock, cooldown; an allow entry still lets it through', async () => {
    registryDown = true;
    try {
      const r = await images(A.ci, 'pr-6', [{ name: NODE, digest: dg('8') }, { name: NODE, digest: dg('1') }]);
      const by = (d: string) => r.body.images.find((i) => i.digest === d)!;
      expect(by(dg('8'))).toMatchObject({ clock: 'unverified', decision: 'cooldown', note: 'registry error: token endpoint HTTP 503' });
      expect(by(dg('1'))).toMatchObject({ clock: 'shared', decision: 'allow' }); // verified earlier: no registry call needed
    } finally {
      registryDown = false;
    }
    const allowedOnly = `sha256:${'9'.repeat(64)}`;
    await syncPolicy(A.sync, 'dka', { project: 'dka', allow: [{ package: `docker:${NODE}@${allowedOnly}`, reason: 'vendor hotfix', added: '2026-11-18' }] });
    const r = await images(A.ci, 'pr-6', [{ name: NODE, digest: allowedOnly }]);
    expect(r.body.images[0]).toMatchObject({ clock: 'unverified', decision: 'allow', allowed: true });
  });

  it('mainOnly: allow entries in an overlay (even one named audit-images) cannot skip the audit\'s cooldown', async () => {
    const d = `sha256:${'5'.repeat(64)}`;
    pushed.add(`${NODE}@${d}`);
    await syncPolicy(A.sync, 'dka', { project: 'dka' });
    const overlay = await syncPolicy(A.ci, 'dka', { project: 'dka', allow: [{ package: `docker:${NODE}@${d}`, reason: 'sneaky', added: '2026-11-18' }] }, 'audit-images');
    expect(overlay.status).toBe(200);
    const viaOverlay = await images(A.ci, 'audit-images', [{ name: NODE, digest: d }]);
    expect(viaOverlay.body.images[0]).toMatchObject({ decision: 'allow', allowed: true }); // a PR-style lookup honors its overlay
    const r = await call('POST', '/api/images', A.ci, { ref: 'audit-images', images: [{ name: NODE, digest: d }], mainOnly: true });
    expect(((await r.json()) as ImagesReply).images[0]).toMatchObject({ decision: 'cooldown', allowed: false });
  });

  it('a private or unsupported-registry digest gets a per-project clock that never affects other projects', async () => {
    const priv = 'docker.io/private/app';
    const quay = 'quay.io/acme/app';
    clock = new Date('2026-11-01T00:00:00Z');
    const a = await images(A.ci, 'pr-7', [{ name: priv, digest: dg('c') }, { name: quay, digest: dg('d') }]);
    expect(a.body.images.map((i) => [i.clock, i.firstSeen])).toEqual([
      ['project', '2026-11-01T00:00:00.000Z'],
      ['project', '2026-11-01T00:00:00.000Z'],
    ]);
    expect(registryCalls.some((c) => c.includes('quay.io'))).toBe(false); // never contacted
    clock = new Date('2026-11-19T12:00:00Z');
    expect((await images(A.ci, 'pr-7', [{ name: quay, digest: dg('d') }])).body.images[0]).toMatchObject({ clock: 'project', decision: 'allow' });
    // Project B's clock starts now: A's earlier report does not count for B.
    const b = await images(B.ci, 'pr-7', [{ name: quay, digest: dg('d') }]);
    expect(b.body.images[0]).toMatchObject({ clock: 'project', decision: 'cooldown', firstSeen: '2026-11-19T12:00:00.000Z' });
    expect(await e.DB.prepare("SELECT 1 FROM versions WHERE eco = 'docker' AND name = ?").bind(quay).first()).toBeNull();
  });

  it('verifies at most MAX_VERIFY new digests per call; the rest stay unverified', async () => {
    const many = Array.from({ length: 12 }, (_, i) => ({ name: 'docker.io/library/busybox', digest: `sha256:${(i + 100).toString(16).padStart(64, 'e')}` }));
    for (const m of many) pushed.add(`${m.name}@${m.digest}`);
    const r = await images(A.ci, 'pr-8', many);
    expect(r.body.images.filter((i) => i.clock === 'shared')).toHaveLength(10);
    expect(r.body.images.filter((i) => i.clock === 'unverified')).toHaveLength(2);
    const again = await images(A.ci, 'pr-8', many);
    expect(again.body.images.every((i) => i.clock === 'shared')).toBe(true);
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

  it('details are kept per writer and merged at read: a later write from another project erases nothing', async () => {
    const id = `docker:${NODE}@${dg('f')}`;
    const put = (token: string, details: unknown) =>
      call('PUT', '/api/verdicts', token, { package: id, scanner: 'grype', scannerVersion: '0.121.3', result: 'flagged', details });
    const a = { id: 'CVE-2026-1', severity: 'high', package: 'openssl', version: '1', fixed: ['2'] };
    const b = { id: 'CVE-2026-2', severity: 'critical', package: 'zlib', version: '1', fixed: [] };
    expect((await put(A.ci, [a])).status).toBe(204);
    expect((await put(B.ci, [b])).status).toBe(204);
    expect((await put(A.ci, { not: 'an array' })).status).toBe(204); // stores nothing for A
    expect((await put(C.ci, [])).status).toBe(204); // a less complete write
    expect(await details(id)).toEqual([b, a]);
  });

  it('one writer padding the list cannot hide another writer\'s Critical; malformed entries are dropped', async () => {
    const id = `docker:${NODE}@${dg('0')}`;
    const low = (n: number) => ({ id: `CVE-2026-${n}`, severity: 'low', package: 'p', version: '1', fixed: [] });
    const junk = [{ id: 'CVE-1' }, { id: '<script>', severity: 'critical', package: 'x', version: '1', fixed: [] }, 'string', { id: 'CVE-9', severity: 'urgent', package: 'x', version: '1', fixed: [] }];
    const put = (token: string, list: unknown[]) =>
      call('PUT', '/api/verdicts', token, { package: id, scanner: 'grype', scannerVersion: 'x', result: 'flagged', details: list });
    await put(A.ci, [...junk, ...Array.from({ length: 300 }, (_, i) => low(1000 + i))]);
    const crit = { id: 'CVE-2026-7777', severity: 'Critical', package: 'glibc', version: '2.36', fixed: ['2.36-9'] };
    await put(B.ci, [crit]);
    await put(A.ci, [...junk, ...Array.from({ length: 300 }, (_, i) => low(5000 + i))]); // A writes again, newer
    const list = (await details(id)) as { id: string; severity: string }[];
    expect(list[0]).toEqual({ ...crit, severity: 'critical' });
    expect(list).toHaveLength(101); // A's list capped at 100 per write, plus B's one
    expect(list.some((x) => x.id === 'CVE-1' || x.id === '<script>' || x.id === 'CVE-9')).toBe(false);
  });

  it("an unknown scanner's details never go per writer: they stay on the verdict row", async () => {
    const id = `docker:${NODE}@sha256:${'3'.repeat(64)}`;
    await call('PUT', '/api/verdicts', A.ci, { package: id, scanner: 'custom', scannerVersion: '1', result: 'flagged', details: [{ id: 'X-1' }] });
    const n = await e.DB.prepare("SELECT COUNT(*) AS n FROM verdict_details WHERE scanner = 'custom'").first<{ n: number }>();
    expect(n!.n).toBe(0);
    expect(await details(id)).toEqual([{ id: 'X-1' }]);
  });

  it("a lower-severity write from another project does not change the details shown for a flagged verdict", async () => {
    const id = `docker:${NODE}@sha256:${'4'.repeat(64)}`;
    const crit = { id: 'CVE-2026-4242', severity: 'critical', package: 'glibc', version: '1', fixed: ['2'] };
    const put = (token: string, result: string, d: unknown) => call('PUT', '/api/verdicts', token, { package: id, scanner: 'grype', scannerVersion: 'x', result, details: d });
    await put(A.ci, 'flagged', [crit]);
    await put(B.ci, 'clean', [{ id: 'CVE-2026-1', severity: 'low', package: 'p', version: '1', fixed: [] }]);
    expect(await details(id)).toEqual([crit]);
    const rows = await e.DB.prepare('SELECT project_id FROM verdict_details WHERE version = ?').bind(`sha256:${'4'.repeat(64)}`).all();
    expect(rows.results).toEqual([{ project_id: 'dka' }]);
    // The dashboard reads the same merged details: still the Critical, still flagged.
    await e.DB.prepare("INSERT OR IGNORE INTO project_images (project_id, name, digest, files, synced_at) VALUES ('dka', ?, ?, '[]', 'x')")
      .bind(NODE, `sha256:${'4'.repeat(64)}`)
      .run();
    const { attention } = await import('../src/dashboard/attention');
    const open = (await attention(e, 'dka', 30, clock)).open.map((i) => i.key);
    expect(open).toContain(`vuln:CVE-2026-4242:docker:${id.slice('docker:'.length)}:dka`);
  });

  it('merges legacy string details (GuardDog rule names) too', async () => {
    const id = `npm:merge-me@1.0.0`;
    const put = (token: string, d: unknown) => call('PUT', '/api/verdicts', token, { package: id, scanner: 'guarddog', scannerVersion: 'x', result: 'flagged', details: d });
    await put(A.ci, ['rule-a', { rule: 'rule-b', count: 2 }, { rule: 'bad', count: -1 }]);
    await put(B.ci, ['rule-c', 'rule-a']);
    const merged = (await details(id)) as unknown[];
    expect(merged).toHaveLength(3); // rule-a once; the malformed rule dropped
    expect(merged).toEqual(expect.arrayContaining(['rule-a', 'rule-c', { rule: 'rule-b', count: 2 }]));
  });
});
