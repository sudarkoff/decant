import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { run } from '../src/main';
import { fakeDeps, fakeExec, fakeFetch, jsonRes, memFs } from './fakes';

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
    expect(t.read('env')).toContain('npm_config_registry<<');
    expect(t.read('env')).toContain('https://registry.npmjs.org/');
    expect(t.read('env')).not.toContain('decant.example');
  });
  it('bypass other than true is false', async () => {
    const { deps, fs } = setupDeps({ INPUT_BYPASS: 'yes' });
    cap();
    await run(deps);
    expect(fs.files.get('/home/r/.npmrc')).toContain('decant.example');
  });
});

const POLICY = JSON.stringify({ project: 'proj' });

const BASE_SHA = 'a'.repeat(40);

function syncDeps(
  over: { event?: string; payload?: unknown; files?: Record<string, string>; fetch?: typeof fetch; env?: Record<string, string>; base?: string | null } = {},
) {
  const t = tmp();
  writeFileSync(t.f('out'), '');
  const payload = over.payload ?? { pull_request: { number: 7, base: { sha: BASE_SHA } }, repository: { default_branch: 'main' } };
  // `git show <base>:./decant.json`: absent at base unless over.base is given.
  const exec = fakeExec((c) =>
    c.cmd === 'git'
      ? over.base == null
        ? { code: 128, stderr: `fatal: path 'decant.json' does not exist in '${BASE_SHA}'` }
        : { stdout: over.base }
      : {},
  );
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
    GITHUB_REF: 'refs/heads/main',
    GITHUB_OUTPUT: t.f('out'),
    ...over.env,
  };
  return { deps: fakeDeps({ env, fs, fetch: f, exec }), t, f: f as ReturnType<typeof fakeFetch>, exec };
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
    const { deps, f } = syncDeps({ event: 'push', env: { GITHUB_REF_NAME: 'feat', GITHUB_REF: 'refs/heads/feat' } });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(out.join('')).toContain('::notice::not the default branch; nothing to sync');
    expect(f.calls).toHaveLength(0);
  });
  it('unsupported event exits 1', async () => {
    const { deps } = syncDeps({ event: 'release' });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('unsupported event release');
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

describe('review fixes', () => {
  it('setup writes npmrc and netrc 0600 even when they pre-existed 0644', async () => {
    const { deps, fs } = setupDeps();
    fs.files.set('/home/r/.npmrc', 'old');
    fs.modes.set('/home/r/.npmrc', 0o644);
    fs.files.set('/home/r/.netrc', 'old');
    fs.modes.set('/home/r/.netrc', 0o644);
    cap();
    expect(await run(deps)).toBe(0);
    expect(fs.modes.get('/home/r/.npmrc')).toBe(0o600);
    expect(fs.modes.get('/home/r/.netrc')).toBe(0o600);
  });
  it('whitespace-only bypass-reason fails', async () => {
    const { deps } = setupDeps({ INPUT_BYPASS: 'true', INPUT_BYPASS_REASON: '   ' });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('bypass requires bypass-reason');
  });
  const noTok = { INPUT_TOKEN: '' };
  const pr = (head: unknown) => ({ pull_request: { number: 7, head, base: { sha: BASE_SHA } }, repository: { default_branch: 'main', full_name: 'o/r' } });
  it('fork PR with no token → 0 + notice', async () => {
    const { deps, f } = syncDeps({ env: noTok, payload: pr({ repo: { full_name: 'x/r' } }) });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(out.join('')).toContain('::notice::fork PR has no secrets; decant sync skipped');
    expect(f.calls).toHaveLength(0);
  });
  it('deleted fork (head.repo null) with no token → 0', async () => {
    const { deps } = syncDeps({ env: noTok, payload: pr({ repo: null }) });
    cap();
    expect(await run(deps)).toBe(0);
  });
  it('same-repo PR with no token → 1', async () => {
    const { deps } = syncDeps({ env: noTok, payload: pr({ repo: { full_name: 'o/r' } }) });
    cap();
    expect(await run(deps)).toBe(1);
  });
  it('fork PR with a token still syncs', async () => {
    const { deps, f } = syncDeps({ payload: pr({ repo: { full_name: 'x/r' } }) });
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls).toHaveLength(1);
  });
});

function exported(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\w+)<<(.+)$/.exec(lines[i]!);
    if (m) {
      const body: string[] = [];
      for (i++; i < lines.length && lines[i] !== m[2]; i++) body.push(lines[i]!);
      out[m[1]!] = body.join('\n');
    } else if (lines[i]!.includes('=')) {
      const j = lines[i]!.indexOf('=');
      out[lines[i]!.slice(0, j)] = lines[i]!.slice(j + 1);
    }
  }
  return out;
}

describe('setup through the PR overlay', () => {
  function prSetup(event: string, payload: unknown) {
    const { deps, fs, t } = setupDeps({ GITHUB_EVENT_NAME: event, GITHUB_EVENT_PATH: '/event.json' });
    fs.files.set('/event.json', JSON.stringify(payload));
    return { deps, fs, t };
  }
  const repo = { full_name: 'o/r', default_branch: 'main' };

  it('same-repo pull_request: npm registry, auth line and GOPROXY use /r/pr-<n>/; netrc stays host-level', async () => {
    const { deps, fs, t } = prSetup('pull_request', { pull_request: { number: 12, head: { repo: { full_name: 'o/r' } } }, repository: repo });
    cap();
    expect(await run(deps)).toBe(0);
    expect(fs.files.get('/home/r/.npmrc')).toBe(
      `registry=https://decant.example/r/pr-12/npm/\n//decant.example/r/pr-12/npm/:_authToken=${TOKEN}\nignore-scripts=true\n`,
    );
    expect(fs.files.get('/home/r/.netrc')).toBe(`machine decant.example login decant password ${TOKEN}\n`);
    expect(t.read('env')).toContain('https://decant.example/r/pr-12/go');
    expect(t.read('env')).not.toContain(TOKEN);
    expect(exported(t.read('env'))).toMatchObject({
      npm_config_registry: 'https://decant.example/r/pr-12/npm/',
      npm_config_ignore_scripts: 'true',
    });
  });
  it('fork pull_request keeps the main paths (no overlay is synced for forks)', async () => {
    const { deps, fs } = prSetup('pull_request', { pull_request: { number: 12, head: { repo: { full_name: 'x/r' } } }, repository: repo });
    cap();
    expect(await run(deps)).toBe(0);
    expect(fs.files.get('/home/r/.npmrc')).toContain('registry=https://decant.example/npm/\n');
  });
  it('push keeps the main paths', async () => {
    const { deps, fs, t } = prSetup('push', { repository: repo });
    cap();
    expect(await run(deps)).toBe(0);
    expect(fs.files.get('/home/r/.npmrc')).toContain('//decant.example/npm/:_authToken=');
    expect(t.read('env')).toContain('https://decant.example/go');
    expect(t.read('env')).not.toContain('/r/pr-');
    expect(exported(t.read('env'))).toMatchObject({
      npm_config_registry: 'https://decant.example/npm/',
      npm_config_ignore_scripts: 'true',
    });
    expect(t.read('env')).not.toContain(TOKEN);
  });
  it('pull_request payload without a number fails', async () => {
    const { deps } = prSetup('pull_request', { repository: repo });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('event payload has no pull_request.number');
  });
});

describe('sync bootstrap and base-derived overlays', () => {
  const entry = (pkg: string) => ({ package: pkg, reason: 'r', added: '2026-11-18' });
  const basePolicy = {
    project: 'proj',
    cooldownDays: 7,
    allow: [entry('npm:a@1.0.0')],
    block: [{ package: 'npm:evil@1.0.0', reason: 'bad' }],
  };
  const sent = (f: ReturnType<typeof fakeFetch>) => JSON.parse(f.calls[0].body!).policy;
  const dispatch = { repository: { default_branch: 'main' } };

  it('workflow_dispatch on the default branch syncs main with the sync token', async () => {
    const { deps, f, t } = syncDeps({ event: 'workflow_dispatch', payload: dispatch });
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls[0].headers.get('authorization')).toBe('Bearer sync-tok');
    expect(JSON.parse(f.calls[0].body!).ref).toBe('main');
    expect(t.read('out')).toContain('main');
  });
  it('workflow_dispatch on another branch fails', async () => {
    const { deps, f } = syncDeps({ event: 'workflow_dispatch', payload: dispatch, env: { GITHUB_REF_NAME: 'feat', GITHUB_REF: 'refs/heads/feat' } });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('sync must run on the default branch');
    expect(f.calls).toHaveLength(0);
  });
  it('workflow_dispatch on a tag named like the default branch fails', async () => {
    const { deps, f } = syncDeps({ event: 'workflow_dispatch', payload: dispatch, env: { GITHUB_REF_NAME: 'main', GITHUB_REF: 'refs/tags/main' } });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('sync must run on the default branch');
    expect(f.calls).toHaveLength(0);
  });
  it('push of a tag named like the default branch (refs/tags/main) does not sync', async () => {
    const { deps, f } = syncDeps({ event: 'push', payload: dispatch, env: { GITHUB_REF_NAME: 'main', GITHUB_REF: 'refs/tags/main' } });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(out.join('')).toContain('::notice::not the default branch; nothing to sync');
    expect(f.calls).toHaveLength(0);
  });
  it('workflow_dispatch without sync-token fails', async () => {
    const { deps } = syncDeps({ event: 'workflow_dispatch', payload: dispatch, env: { INPUT_SYNC_TOKEN: '' } });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('sync-token is required on the default branch');
  });
  it('PR tightening cooldown: syncs with the base cooldown and posts a notice', async () => {
    const { deps, f, exec } = syncDeps({ base: JSON.stringify(basePolicy), files: { 'decant.json': JSON.stringify({ ...basePolicy, cooldownDays: 14 }) } });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(exec.calls[0]).toMatchObject({ cmd: 'git', args: ['show', `${BASE_SHA}:./decant.json`] });
    expect(sent(f).cooldownDays).toBe(7);
    expect(out.join('')).toContain('::notice::policy changes in decant.json take effect after merge');
  });
  it('PR adding an allow entry: included in the overlay, no notice', async () => {
    const pr = { ...basePolicy, allow: [...basePolicy.allow, entry('npm:fix@2.0.0')] };
    const { deps, f } = syncDeps({ base: JSON.stringify(basePolicy), files: { 'decant.json': JSON.stringify(pr) } });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(sent(f).allow.map((a: { package: string }) => a.package)).toEqual(['npm:a@1.0.0', 'npm:fix@2.0.0']);
    expect(out.join('')).not.toContain('take effect after merge');
  });
  it('PR removing a block and changing autoShip: overlay keeps base block and autoShip, adds PR blocks; notice', async () => {
    const pr = { ...basePolicy, autoShip: { low: 'auto' }, block: [{ package: 'npm:other@1.0.0', reason: 'no' }] };
    const { deps, f } = syncDeps({ base: JSON.stringify(basePolicy), files: { 'decant.json': JSON.stringify(pr) } });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    const p = sent(f);
    expect(p.block.map((b: { package: string }) => b.package)).toEqual(['npm:evil@1.0.0', 'npm:other@1.0.0']);
    expect(p.autoShip).toBeUndefined();
    expect(out.join('')).toContain('take effect after merge');
  });
  it('PR removing a base allow entry: the overlay keeps it (base + PR additions)', async () => {
    const { deps, f } = syncDeps({ base: JSON.stringify(basePolicy), files: { 'decant.json': JSON.stringify({ ...basePolicy, allow: [] }) } });
    cap();
    expect(await run(deps)).toBe(0);
    expect(sent(f).allow).toEqual(basePolicy.allow);
  });
  it('policy absent at base: the PR file is synced as is', async () => {
    const pr = { ...basePolicy, cooldownDays: 3 };
    const { deps, f } = syncDeps({ base: null, files: { 'decant.json': JSON.stringify(pr) } });
    cap();
    expect(await run(deps)).toBe(0);
    expect(sent(f)).toEqual(pr);
  });
  it('invalid policy at base: warns and syncs the PR file', async () => {
    const { deps, f } = syncDeps({ base: '{"nope":1}' });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(out.join('')).toContain('::warning::decant.json at the base commit is invalid');
    expect(sent(f)).toEqual({ project: 'proj' });
  });
  it('git failure (shallow checkout) fails with the fetch-depth hint', async () => {
    const { deps } = syncDeps();
    deps.exec = fakeExec(() => ({ code: 128, stderr: 'fatal: bad object' }));
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('fetch-depth: 0');
  });
  it('pull_request without a base sha fails', async () => {
    const { deps } = syncDeps({ payload: { pull_request: { number: 7 }, repository: { default_branch: 'main' } } });
    const { err } = cap();
    expect(await run(deps)).toBe(1);
    expect(err.join('')).toContain('no valid pull_request.base.sha');
  });
});

describe('sync sends a dependency summary on the default branch', () => {
  const LOCK = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { a: '^1' } },
      'node_modules/a': { version: '1.0.0', dependencies: { b: '^1' } },
      'node_modules/b': { version: '1.0.0' },
    },
  });
  const files = { '/w/decant.json': POLICY, '/w/package-lock.json': LOCK };
  const env = { INPUT_WORKING_DIRECTORY: '/w' };
  const dispatch = { repository: { default_branch: 'main' } };

  it('push to main: PUTs /deps with the sync token after the policy', async () => {
    const { deps, f } = syncDeps({ event: 'push', payload: dispatch, files, env });
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      'PUT https://decant.example/api/projects/proj/policy',
      'PUT https://decant.example/api/projects/proj/deps',
    ]);
    expect(f.calls[1].headers.get('authorization')).toBe('Bearer sync-tok');
    expect(JSON.parse(f.calls[1].body!)).toEqual({
      sha: 'abc123',
      deps: [
        { eco: 'npm', name: 'a', version: '1.0.0', direct: true, via: [] },
        { eco: 'npm', name: 'b', version: '1.0.0', direct: false, via: ['a'] },
      ],
    });
  });

  it('workflow_dispatch on main also sends it', async () => {
    const { deps, f } = syncDeps({ event: 'workflow_dispatch', payload: dispatch, files, env });
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls.map((c) => c.url)).toContain('https://decant.example/api/projects/proj/deps');
  });

  it('weekly schedule on main syncs main and sends it', async () => {
    const { deps, f } = syncDeps({ event: 'schedule', payload: dispatch, files, env });
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls[0].headers.get('authorization')).toBe('Bearer sync-tok');
    expect(JSON.parse(f.calls[0].body!).ref).toBe('main');
    expect(f.calls.map((c) => c.url)).toContain('https://decant.example/api/projects/proj/deps');
  });

  it('schedule off the default branch does nothing', async () => {
    const { deps, f } = syncDeps({ event: 'schedule', payload: dispatch, files, env: { ...env, GITHUB_REF: 'refs/heads/feat' } });
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls).toHaveLength(0);
  });

  it('pull_request overlays never send it', async () => {
    const { deps, f } = syncDeps({ files, env });
    cap();
    expect(await run(deps)).toBe(0);
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0].url).toContain('/policy');
  });

  it('not sent when the policy sync fails', async () => {
    const { deps, f } = syncDeps({ event: 'push', payload: dispatch, files, env, fetch: fakeFetch(() => jsonRes({ error: 'no' }, 422)) });
    cap();
    expect(await run(deps)).toBe(1);
    expect(f.calls).toHaveLength(1);
  });

  it('a rejected summary is a warning; the sync still passes', async () => {
    const { deps } = syncDeps({
      event: 'push',
      payload: dispatch,
      files,
      env,
      fetch: fakeFetch((c) => (c.url.endsWith('/deps') ? jsonRes({ error: 'not found' }, 404) : jsonRes({ ok: true }))),
    });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(out.join('')).toContain('::warning::decant did not store the dependency summary (HTTP 404): not found');
  });

  it('an unreadable lockfile is a warning; the rest is still sent', async () => {
    const { deps, f } = syncDeps({ event: 'push', payload: dispatch, files: { ...files, '/w/sub/package-lock.json': 'nope' }, env });
    const { out } = cap();
    expect(await run(deps)).toBe(0);
    expect(out.join('')).toContain('::warning::dependency summary: sub/package-lock.json');
    expect(JSON.parse(f.calls[1].body!).deps).toHaveLength(2);
  });
});
