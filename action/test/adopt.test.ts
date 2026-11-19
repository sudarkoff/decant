import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { run } from '../src/main';
import { fakeDeps, fakeFetch, jsonRes, memFs, type FetchCall } from './fakes';

afterEach(() => vi.restoreAllMocks());

const D = 'https://decant.example';
const R = 'https://api.github.com/repos/o/r';
const HEAD = 'c'.repeat(40);
const PRHEAD = 'd'.repeat(40);

function lock(pkgs: { name: string; version: string; resolved?: string }[]): string {
  const packages: Record<string, unknown> = { '': { name: 'app', version: '1.0.0' } };
  for (const p of pkgs) {
    const base = p.name.slice(p.name.lastIndexOf('/') + 1);
    packages[`node_modules/${p.name}`] = {
      version: p.version,
      resolved: p.resolved ?? `https://registry.npmjs.org/${p.name}/-/${base}-${p.version}.tgz`,
      integrity: `sha512-${p.name}${p.version}`,
    };
  }
  return JSON.stringify({ name: 'app', lockfileVersion: 3, packages }, null, 2);
}

type World = {
  files: Record<string, string>;
  times?: Record<string, string>;
  failTime?: string;
  openPr?: boolean;
  symlinks?: string[];
  existingPolicy?: unknown;
  stale?: boolean;
  prFiles?: Record<string, string>;
  repo?: string;
  ref?: string;
  sha?: string;
};

function harness(w: World) {
  const d = mkdtempSync(join(tmpdir(), 'decant-adopt-'));
  const output = join(d, 'output');
  writeFileSync(output, '');
  const files = { ...w.files };
  if (w.existingPolicy) files['/w/decant.json'] = JSON.stringify(w.existingPolicy);
  const fs = memFs(files, w.symlinks ?? []);
  const commits: { input: any }[] = [];
  const prs: any[] = [];
  const branches: any[] = [];
  const patches: { url: string; body: any }[] = [];
  const f = fakeFetch((c: FetchCall) => {
    const u = new URL(c.url);
    const key = `${c.method} ${c.url}`;
    if (c.method === 'GET' && u.origin === 'https://registry.npmjs.org') {
      const name = decodeURIComponent(u.pathname.slice(1));
      if (name === w.failTime) return new Response('boom', { status: 500 });
      const time: Record<string, string> = {};
      for (const [k, v] of Object.entries(w.times ?? {})) if (k.startsWith(`${name}@`)) time[k.slice(name.length + 1)] = v;
      return jsonRes({ time });
    }
    if (key === `GET ${R}`) return jsonRes({ default_branch: 'main' });
    if (key === `GET ${R}/git/ref/heads/main`) return jsonRes({ object: { sha: HEAD } });
    if (c.method === 'GET' && c.url.startsWith(`${R}/pulls?`)) {
      return jsonRes(
        w.openPr
          ? [{ number: 9, node_id: 'N', title: 'decant: adopt', body: '', state: 'open', head: { ref: 'decant/adopt', sha: PRHEAD }, base: { ref: 'main', sha: HEAD } }]
          : [],
      );
    }
    if (key === `POST ${R}/git/refs`) {
      branches.push(JSON.parse(c.body!));
      if (w.stale) return new Response('Reference already exists', { status: 422 });
      return jsonRes({}, 201);
    }
    if (c.method === 'PATCH') {
      patches.push({ url: c.url, body: JSON.parse(c.body!) });
      return jsonRes({});
    }
    if (c.method === 'GET' && c.url.startsWith(`${R}/contents/`)) {
      const path = decodeURIComponent(u.pathname.slice('/repos/o/r/contents/'.length));
      const v = w.prFiles?.[path];
      if (v === undefined) return new Response('nf', { status: 404 });
      return jsonRes({ encoding: 'base64', content: Buffer.from(v).toString('base64') });
    }
    if (key === 'POST https://api.github.com/graphql') {
      commits.push(JSON.parse(c.body!).variables);
      return jsonRes({ data: { createCommitOnBranch: { commit: { oid: 'e'.repeat(40) } } } });
    }
    if (key === `POST ${R}/pulls`) {
      prs.push(JSON.parse(c.body!));
      return jsonRes({ number: 10, node_id: 'N2', html_url: 'https://github.com/o/r/pull/10' }, 201);
    }
    if (key === `POST ${R}/issues/10/labels`) return jsonRes([]);
    return undefined;
  });
  const env: Record<string, string> = {
    INPUT_MODE: 'adopt',
    INPUT_DECANT_URL: `${D}/`,
    INPUT_TOKEN: 'ci-secret',
    INPUT_GITHUB_TOKEN: 'ghs_secret',
    INPUT_WORKING_DIRECTORY: '/w',
    INPUT_POLICY_PATH: 'decant.json',
    GITHUB_REPOSITORY: w.repo ?? 'o/r',
    GITHUB_OUTPUT: output,
    GITHUB_REF: w.ref ?? 'refs/heads/main',
    GITHUB_SHA: w.sha ?? HEAD,
  };
  const out: string[] = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stdout.write);
  vi.spyOn(process.stderr, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stderr.write);
  const deps = fakeDeps({ env, fetch: f, fs });
  const written = () => {
    const additions = commits[0]!.input.fileChanges.additions as { path: string; contents: string }[];
    return Object.fromEntries(additions.map((a) => [a.path, Buffer.from(a.contents, 'base64').toString('utf8')]));
  };
  return { run: () => run(deps), f, commits, prs, branches, patches, written, log: () => out.join(''), outputs: () => readFileSync(output, 'utf8') };
}

const THREE = {
  files: { '/w/package-lock.json': lock([{ name: 'old', version: '1.0.0' }, { name: 'two', version: '2.0.0' }, { name: 'six', version: '3.0.0' }]) },
  times: { 'old@1.0.0': '2026-01-01T00:00:00Z', 'two@2.0.0': '2026-11-17T00:00:00Z', 'six@3.0.0': '2026-11-13T00:00:00Z' },
};

describe('adopt', () => {
  it('3 deps (old, 2d, 6d) -> 2 allow entries, new policy, branch + commit + PR', async () => {
    const h = harness(THREE);
    expect(await h.run()).toBe(0);
    expect(h.branches).toEqual([{ ref: 'refs/heads/decant/adopt', sha: HEAD }]);
    expect(h.commits[0]!.input.expectedHeadOid).toBe(HEAD);
    const w = h.written();
    const raw = w['decant.json']!;
    expect(raw.endsWith('}\n')).toBe(true);
    const pol = JSON.parse(raw);
    expect(pol.$schema).toBe('https://raw.githubusercontent.com/sudarkoff/decant/main/schema/policy.json');
    expect(pol.project).toBe('r');
    expect(pol.cooldownDays).toBe(7);
    expect(pol.allow).toEqual([
      { package: 'npm:six@3.0.0', reason: 'adopted', added: '2026-11-19' },
      { package: 'npm:two@2.0.0', reason: 'adopted', added: '2026-11-19' },
    ]);
    expect(pol.block).toEqual([]);
    expect(h.prs[0]).toMatchObject({ head: 'decant/adopt', base: 'main', title: 'decant: adopt' });
    expect(h.prs[0].body).toContain('2026-11-20'); // six: 11-13 + 7
    expect(h.prs[0].body).toContain('2026-11-24'); // two: 11-17 + 7
    expect(h.f.calls.some((c) => c.url === `${R}/issues/10/labels` && c.body!.includes('decant:adopt'))).toBe(true);
    expect(h.outputs()).toContain('result');
  });

  it('keeps an existing valid policy and its order; no duplicate allow', async () => {
    const h = harness({
      ...THREE,
      existingPolicy: { project: 'mine', cooldownDays: 7, autoShip: { low: 'auto' }, allow: [{ package: 'npm:two@2.0.0', reason: 'x', added: '2026-11-01' }, { package: 'npm:zzz@1.0.0', reason: 'y', added: '2026-11-01' }], block: [] },
    });
    expect(await h.run()).toBe(0);
    const pol = JSON.parse(h.written()['decant.json']!);
    expect(pol.project).toBe('mine');
    expect(pol.autoShip).toEqual({ low: 'auto' });
    expect(pol.allow.map((a: any) => a.package)).toEqual(['npm:two@2.0.0', 'npm:zzz@1.0.0', 'npm:six@3.0.0']);
  });

  it('normalizes decant URLs in lockfiles in the same commit', async () => {
    const h = harness({
      files: { '/w/package-lock.json': lock([{ name: 'old', version: '1.0.0', resolved: `${D}/npm/old/-/old-1.0.0.tgz` }]) },
      times: { 'old@1.0.0': '2026-01-01T00:00:00Z' },
    });
    expect(await h.run()).toBe(0);
    const w = h.written();
    expect(w['package-lock.json']).toContain('https://registry.npmjs.org/old/-/old-1.0.0.tgz');
    expect(w['package-lock.json']).not.toContain(D);
    expect(w['decant.json']).toBeDefined();
  });

  it('open PR: commits onto its head, no new branch or PR', async () => {
    const h = harness({ ...THREE, openPr: true });
    expect(await h.run()).toBe(0);
    expect(h.branches).toEqual([]);
    expect(h.prs).toEqual([]);
    expect(h.commits[0]!.input.expectedHeadOid).toBe(PRHEAD);
    expect(h.commits[0]!.input.branch.branchName).toBe('decant/adopt');
  });

  it('lookup failure: exit 1 naming the package, no commit', async () => {
    const h = harness({ ...THREE, failTime: 'two' });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('two@2.0.0');
    expect(h.commits).toEqual([]);
  });

  it('nothing to adopt: notice, exit 0, no PR', async () => {
    const h = harness({
      files: THREE.files,
      times: { 'old@1.0.0': '2026-01-01T00:00:00Z', 'two@2.0.0': '2026-01-01T00:00:00Z', 'six@3.0.0': '2026-01-01T00:00:00Z' },
      existingPolicy: { project: 'p', cooldownDays: 7, allow: [], block: [] },
    });
    expect(await h.run()).toBe(0);
    expect(h.log()).toContain('nothing to adopt');
    expect(h.commits).toEqual([]);
    expect(h.prs).toEqual([]);
  });

  it('non-registry deps are listed as not gated, no allow entry, no lookup', async () => {
    const h = harness({
      files: { '/w/package-lock.json': lock([{ name: 'git-dep', version: '1.0.0', resolved: 'https://example.com/x.tgz' }, { name: 'two', version: '2.0.0' }]) },
      times: { 'two@2.0.0': '2026-11-17T00:00:00Z' },
    });
    expect(await h.run()).toBe(0);
    expect(h.prs[0].body).toContain('not gated by decant');
    expect(h.prs[0].body).toContain('git-dep@1.0.0');
    expect(JSON.parse(h.written()['decant.json']!).allow).toHaveLength(1);
  });

  it('symlinked lockfile fails', async () => {
    const h = harness({ ...THREE, symlinks: ['/w/package-lock.json'] });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('lockfile is a symlink');
    expect(h.commits).toEqual([]);
  });

  it('invalid existing policy fails', async () => {
    const h = harness({ ...THREE, existingPolicy: { project: '' } });
    expect(await h.run()).toBe(1);
  });

  it('invalid final policy (empty project): exit 1, no commit', async () => {
    const h = harness({ ...THREE, repo: 'o/' });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('invalid policy');
    expect(h.commits).toEqual([]);
  });

  it('stale branch (422 on create): force-resets via updateRef then commits', async () => {
    const h = harness({ ...THREE, stale: true });
    expect(await h.run()).toBe(0);
    expect(h.patches).toContainEqual({ url: `${R}/git/refs/heads/decant/adopt`, body: { sha: HEAD, force: true } });
    expect(h.commits[0]!.input.expectedHeadOid).toBe(HEAD);
    expect(h.prs).toHaveLength(1);
  });

  it('open PR: body is refreshed after the commit', async () => {
    const h = harness({ ...THREE, openPr: true });
    expect(await h.run()).toBe(0);
    const p = h.patches.find((x) => x.url === `${R}/pulls/9`)!;
    expect(p.body.body).toContain('npm:two@2.0.0');
  });

  it('open PR already holding the same files: no commit', async () => {
    const first = harness(THREE);
    await first.run();
    const prFiles = first.written();
    const h = harness({ ...THREE, openPr: true, prFiles });
    expect(await h.run()).toBe(0);
    expect(h.log()).toContain('adopt PR already up to date');
    expect(h.commits).toEqual([]);
  });
});

describe('adopt: checkout guard', () => {
  it('non-default ref → exit 1, no writes', async () => {
    const h = harness({ ...THREE, ref: 'refs/heads/feature' });
    expect(await h.run()).toBe(1);
    expect(h.log()).toMatch(/runs on the default branch \(main\)/);
    expect(h.branches).toEqual([]);
    expect(h.commits).toEqual([]);
  });

  it('default branch moved since checkout → exit 1', async () => {
    const h = harness({ ...THREE, sha: 'f'.repeat(40) });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('default branch moved since checkout; re-run');
    expect(h.commits).toEqual([]);
  });
});
