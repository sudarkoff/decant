import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { run } from '../src/main';
import { fakeDeps, fakeFetch, jsonRes, memFs } from './fakes';

afterEach(() => vi.restoreAllMocks());

function cap() {
  const out: string[] = [];
  const err: string[] = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stdout.write);
  vi.spyOn(process.stderr, 'write').mockImplementation(((s: string) => (err.push(String(s)), true)) as typeof process.stderr.write);
  return { out, err };
}

function tmp() {
  const d = mkdtempSync(join(tmpdir(), 'decant-'));
  const f = (n: string) => join(d, n);
  const read = (n: string) => readFileSync(f(n), 'utf8');
  return { d, f, read };
}

const TOKEN = 'tok-secret-123';

function setupDeps(extra: Record<string, string> = {}) {
  const t = tmp();
  const fs = memFs({});
  const modes = new Map<string, number | undefined>();
  const w = fs.writeFile.bind(fs);
  fs.writeFile = async (p, data, mode) => {
    modes.set(p, mode);
    await w(p, data, mode);
  };
  const env = {
    HOME: '/home/r',
    GITHUB_ENV: t.f('env'),
    GITHUB_STEP_SUMMARY: t.f('summary'),
    GITHUB_ACTOR: 'alice',
    GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_REPOSITORY: 'o/r',
    GITHUB_RUN_ID: '99',
    INPUT_MODE: 'setup',
    INPUT_DECANT_URL: 'https://decant.example/',
    INPUT_TOKEN: TOKEN,
    ...extra,
  };
  writeFileSync(t.f('env'), '');
  writeFileSync(t.f('summary'), '');
  return { deps: fakeDeps({ env, fs }), fs, modes, t };
}

describe('setup', () => {
  it('writes npmrc, netrc 0600, GOPROXY without direct or token', async () => {
    const { deps, fs, modes, t } = setupDeps();
    cap();
    expect(await run(deps)).toBe(0);
    expect(fs.files.get('/home/r/.npmrc')).toBe(
      'registry=https://decant.example/npm/\n//decant.example/npm/:_authToken=tok-secret-123\nignore-scripts=true\n',
    );
    expect(fs.files.get('/home/r/.netrc')).toBe(`machine decant.example login decant password ${TOKEN}\n`);
    expect(modes.get('/home/r/.netrc')).toBe(0o600);
    const env = t.read('env');
    expect(env).toContain('GOPROXY');
    expect(env).toContain('https://decant.example/go');
    expect(env).not.toContain(',direct');
    expect(env).not.toContain(TOKEN);
    expect(env).not.toContain('GOSUMDB');
  });
  it('masks the token first', async () => {
    const { deps } = setupDeps();
    const { out } = cap();
    await run(deps);
    expect(out[0]).toBe(`::add-mask::${TOKEN}\n`);
  });
  it('missing token exits 1', async () => {
    const { deps } = setupDeps({ INPUT_TOKEN: '' });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('token is required (read token)');
  });
  it('missing HOME exits 1', async () => {
    const { deps } = setupDeps({ HOME: '' });
    cap();
    expect(await run(deps)).toBe(1);
  });
  it('bypass without reason exits 1', async () => {
    const { deps, fs } = setupDeps({ INPUT_BYPASS: 'true' });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('bypass requires bypass-reason');
    expect(fs.files.size).toBe(0);
  });
  it('bypass with reason uses public registries, warns, banners, writes no token', async () => {
    const { deps, fs, t } = setupDeps({ INPUT_BYPASS: 'TRUE', INPUT_BYPASS_REASON: 'outage' });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(fs.files.get('/home/r/.npmrc')).toBe('registry=https://registry.npmjs.org/\nignore-scripts=true\n');
    expect(fs.files.has('/home/r/.netrc')).toBe(false);
    expect(t.read('env')).toContain('https://proxy.golang.org');
    expect(out.join('')).toContain('::warning::decant BYPASSED by alice: outage');
    expect(t.read('summary')).toContain('## ⚠️ decant bypassed');
    expect(t.read('summary')).toContain('Actor: alice · Reason: outage · Run: https://github.com/o/r/actions/runs/99');
    for (const v of fs.files.values()) expect(v).not.toContain(TOKEN);
    expect(t.read('env')).not.toContain(TOKEN);
  });
  it('bypass other than true is false', async () => {
    const { deps, fs } = setupDeps({ INPUT_BYPASS: 'yes' });
    cap();
    await run(deps);
    expect(fs.files.get('/home/r/.npmrc')).toContain('decant.example');
  });
});

const POLICY = JSON.stringify({ project: 'proj' });

function syncDeps(over: { event?: string; payload?: unknown; files?: Record<string, string>; fetch?: typeof fetch; env?: Record<string, string> } = {}) {
  const t = tmp();
  writeFileSync(t.f('out'), '');
  const payload = over.payload ?? { pull_request: { number: 7 }, repository: { default_branch: 'main' } };
  const fs = memFs({ 'decant.json': POLICY, '/event.json': JSON.stringify(payload), ...over.files });
  const f = over.fetch ?? fakeFetch(() => jsonRes({ ok: true }));
  const env = {
    INPUT_MODE: 'sync',
    INPUT_DECANT_URL: 'https://decant.example',
    INPUT_TOKEN: 'ci-tok',
    INPUT_SYNC_TOKEN: 'sync-tok',
    GITHUB_EVENT_NAME: over.event ?? 'pull_request',
    GITHUB_EVENT_PATH: '/event.json',
    GITHUB_SHA: 'abc123',
    GITHUB_REF_NAME: 'main',
    GITHUB_OUTPUT: t.f('out'),
    ...over.env,
  };
  return { deps: fakeDeps({ env, fs, fetch: f }), t, f: f as ReturnType<typeof fakeFetch> };
}

describe('sync', () => {
  it('pull_request #7 → ref pr-7 with ci token', async () => {
    const { deps, t, f } = syncDeps();
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls[0].headers.get('authorization')).toBe('Bearer ci-tok');
    expect(f.calls[0].url).toBe('https://decant.example/api/projects/proj/policy');
    expect(JSON.parse(f.calls[0].body!)).toEqual({ policy: { project: 'proj' }, sha: 'abc123', ref: 'pr-7' });
    expect(t.read('out')).toContain('pr-7');
  });
  it('project input overrides policy.project', async () => {
    const { deps, f } = syncDeps({ env: { INPUT_PROJECT: 'other' } });
    cap();
    await run(deps);
    expect(f.calls[0].url).toContain('/projects/other/policy');
  });
  it('push to default → sync token, ref main', async () => {
    const { deps, t, f } = syncDeps({ event: 'push' });
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls[0].headers.get('authorization')).toBe('Bearer sync-tok');
    expect(JSON.parse(f.calls[0].body!).ref).toBe('main');
    expect(t.read('out')).toContain('main');
  });
  it('push to default without sync-token exits 1 naming input', async () => {
    const { deps } = syncDeps({ event: 'push', env: { INPUT_SYNC_TOKEN: '' } });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('sync-token is required on the default branch');
  });
  it('push to non-default branch → 0 with notice, no call', async () => {
    const { deps, f } = syncDeps({ event: 'push', env: { GITHUB_REF_NAME: 'feat' } });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(out.join('')).toContain('::notice::not the default branch; nothing to sync');
    expect(f.calls).toHaveLength(0);
  });
  it('unsupported event exits 1', async () => {
    const { deps } = syncDeps({ event: 'schedule' });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('unsupported event schedule');
  });
  it('missing policy file exits 1', async () => {
    const { deps } = syncDeps();
    deps.fs = memFs({ '/event.json': '{"pull_request":{"number":7}}' });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('decant.json not found at decant.json');
  });
  it('invalid policy lists errors', async () => {
    const { deps } = syncDeps({ files: { 'decant.json': '{"nope":1}' } });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('unknown key: nope');
  });
  it('server 422 exits 1 and prints its error, not the token', async () => {
    const { deps } = syncDeps({ fetch: fakeFetch(() => jsonRes({ error: 'cannot verify fix' }, 422)) });
    const { err, out } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('cannot verify fix');
    expect((err.join('') + out.join('')).replace(/::add-mask::[^\n]*/g, '')).not.toContain('ci-tok');
  });
  it('masks both tokens', async () => {
    const { deps } = syncDeps();
    const { out } = cap();
    await run(deps);
    expect(out.join('')).toContain('::add-mask::ci-tok');
    expect(out.join('')).toContain('::add-mask::sync-tok');
  });
});
