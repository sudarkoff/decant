import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { run } from '../src/main';
import { fakeDeps, fakeExec, fakeFetch, jsonRes, memFs, type ExecCall, type FetchCall } from './fakes';

afterEach(() => vi.restoreAllMocks());

const D = 'https://decant.example';
const R = 'https://api.github.com/repos/o/r';
const HEAD = 'c'.repeat(40);
const GHSA = 'GHSA-aaaa-bbbb-cccc';
const REF = 'audit-ghsa-aaaa-bbbb-cccc';
const BRANCH = 'decant/fix-ghsa-aaaa-bbbb-cccc-lodash';
const SELF = 'github-actions[bot]';

function lock(pkgs: { name: string; version: string; path?: string; resolved?: string }[]): string {
  const packages: Record<string, unknown> = { '': { name: 'app', version: '1.0.0' } };
  for (const p of pkgs) {
    const base = p.name.slice(p.name.lastIndexOf('/') + 1);
    packages[p.path ?? `node_modules/${p.name}`] = {
      version: p.version,
      resolved: p.resolved ?? `https://registry.npmjs.org/${p.name}/-/${base}-${p.version}.tgz`,
      integrity: `sha512-${p.name}${p.version}`,
    };
  }
  return JSON.stringify({ name: 'app', lockfileVersion: 3, packages }, null, 2);
}

const npmRecord = (id: string, name: string, events: Record<string, string>[], severity = 'HIGH') => ({
  id,
  summary: `${name} is vulnerable`,
  database_specific: { severity },
  affected: [{ package: { ecosystem: 'npm', name }, ranges: [{ type: 'SEMVER', events }] }],
});

type World = {
  files: Record<string, string>;
  policy?: Record<string, unknown>;
  /** "name@version" → OSV ids */
  osv?: Record<string, string[]>;
  records?: Record<string, unknown>;
  osvDown?: boolean;
  openPrs?: string[];
  syncStatus?: number;
  blocks?: { package: string; source: string; reason: string; at: string }[];
  times?: Record<string, string>;
  issues?: { number: number; title: string; user: { login: string; type: string } }[];
  autoMergeFails?: boolean;
  createBranchStatus?: number;
  exec?: (c: ExecCall, fs: ReturnType<typeof memFs>) => { code?: number; stdout?: string; stderr?: string } | void;
};

const BASE_POLICY = { project: 'app', cooldownDays: 7, allow: [], block: [] };

function harness(w: World) {
  const d = mkdtempSync(join(tmpdir(), 'decant-audit-'));
  const output = join(d, 'output');
  const summary = join(d, 'summary');
  writeFileSync(output, '');
  writeFileSync(summary, '');
  const fs = memFs({ ...w.files, '/w/decant.json': JSON.stringify(w.policy ?? BASE_POLICY, null, 2) });
  const original = new Map(fs.files);
  const syncs: { auth: string | null; body: any }[] = [];
  const branches: any[] = [];
  const refPatches: { url: string; body: any }[] = [];
  const commits: any[] = [];
  const prs: any[] = [];
  const labels: { n: number; labels: string[] }[] = [];
  const autoMerges: any[] = [];
  const prPatches: number[] = [];
  const issueCreates: any[] = [];
  const issuePatches: { n: number; body: any }[] = [];
  let prN = 10;
  const f = fakeFetch((c: FetchCall) => {
    const u = new URL(c.url);
    const key = `${c.method} ${c.url}`;
    if (u.origin === 'https://api.osv.dev') {
      if (w.osvDown) return new Response('down', { status: 503 });
      if (key === 'POST https://api.osv.dev/v1/querybatch') {
        const qs = JSON.parse(c.body!).queries as { package: { name: string }; version: string }[];
        return jsonRes({ results: qs.map((q) => ({ vulns: (w.osv?.[`${q.package.name}@${q.version}`] ?? []).map((id) => ({ id })) })) });
      }
      const id = decodeURIComponent(u.pathname.replace('/v1/vulns/', ''));
      const r = w.records?.[id];
      return r ? jsonRes(r) : new Response('nf', { status: 404 });
    }
    if (u.origin === 'https://registry.npmjs.org') {
      const name = decodeURIComponent(u.pathname.slice(1));
      const time: Record<string, string> = {};
      for (const [k, v] of Object.entries(w.times ?? {})) if (k.startsWith(`${name}@`)) time[k.slice(name.length + 1)] = v;
      return jsonRes({ time });
    }
    if (key === `PUT ${D}/api/projects/app/policy`) {
      syncs.push({ auth: c.headers.get('authorization'), body: JSON.parse(c.body!) });
      const s = w.syncStatus ?? 200;
      return jsonRes(s === 200 ? { ok: true } : { error: 'advisory GHSA-aaaa-bbbb-cccc does not list 4.17.21 as fixed' }, s);
    }
    if (key === `GET ${D}/api/blocks`) return jsonRes({ blocks: w.blocks ?? [] });
    if (key === `GET ${R}`) return jsonRes({ default_branch: 'main' });
    if (key === `GET ${R}/git/ref/heads/main`) return jsonRes({ object: { sha: HEAD } });
    if (c.method === 'GET' && c.url.startsWith(`${R}/pulls?`)) {
      const head = decodeURIComponent(u.searchParams.get('head') ?? '').replace(/^o:/, '');
      return jsonRes(
        (w.openPrs ?? []).includes(head)
          ? [{ number: 3, node_id: 'OPEN', title: 't', body: '', state: 'open', head: { ref: head, sha: 'd'.repeat(40) }, base: { ref: 'main', sha: HEAD } }]
          : [],
      );
    }
    if (c.method === 'GET' && c.url.startsWith(`${R}/contents/`)) return new Response('nf', { status: 404 });
    if (key === `POST ${R}/git/refs`) {
      branches.push(JSON.parse(c.body!));
      if (w.createBranchStatus) return new Response('nope', { status: w.createBranchStatus });
      return jsonRes({}, 201);
    }
    const pp = new RegExp(`^${R}/pulls/(\\d+)$`).exec(c.url);
    if (c.method === 'PATCH' && pp) {
      prPatches.push(Number(pp[1]));
      return jsonRes({});
    }
    if (c.method === 'PATCH' && c.url.startsWith(`${R}/git/refs/`)) {
      refPatches.push({ url: c.url, body: JSON.parse(c.body!) });
      return jsonRes({});
    }
    if (key === 'POST https://api.github.com/graphql') {
      const b = JSON.parse(c.body!);
      if (b.query.includes('createCommitOnBranch')) {
        commits.push(b.variables.input);
        return jsonRes({ data: { createCommitOnBranch: { commit: { oid: 'e'.repeat(40) } } } });
      }
      if (b.query.includes('enablePullRequestAutoMerge')) {
        autoMerges.push(b.variables);
        if (w.autoMergeFails) return jsonRes({ errors: [{ message: 'Auto merge is not allowed for this repository' }] });
        return jsonRes({ data: { enablePullRequestAutoMerge: { clientMutationId: null } } });
      }
    }
    if (key === `POST ${R}/pulls`) {
      prs.push(JSON.parse(c.body!));
      const n = prN++;
      return jsonRes({ number: n, node_id: `PR_${n}`, html_url: `https://github.com/o/r/pull/${n}` }, 201);
    }
    const lab = new RegExp(`^${R}/issues/(\\d+)/labels$`).exec(c.url);
    if (c.method === 'POST' && lab) {
      labels.push({ n: Number(lab[1]), labels: JSON.parse(c.body!).labels });
      return jsonRes([]);
    }
    if (c.method === 'GET' && c.url.startsWith(`${R}/issues?`)) {
      const creator = u.searchParams.get('creator');
      return jsonRes((w.issues ?? []).filter((i) => !creator || i.user.login === creator));
    }
    if (key === `POST ${R}/issues`) {
      issueCreates.push(JSON.parse(c.body!));
      return jsonRes({ number: 50 }, 201);
    }
    const ip = new RegExp(`^${R}/issues/(\\d+)$`).exec(c.url);
    if (c.method === 'PATCH' && ip) {
      issuePatches.push({ n: Number(ip[1]), body: JSON.parse(c.body!) });
      return jsonRes({});
    }
    return undefined;
  });
  const exec = fakeExec((c) => w.exec?.(c, fs) ?? {});
  const env: Record<string, string> = {
    INPUT_MODE: 'audit',
    INPUT_DECANT_URL: `${D}/`,
    INPUT_TOKEN: 'ci-secret',
    INPUT_GITHUB_TOKEN: 'ghs_secret',
    INPUT_WORKING_DIRECTORY: '/w',
    INPUT_POLICY_PATH: 'decant.json',
    GITHUB_REPOSITORY: 'o/r',
    GITHUB_WORKSPACE: '/w',
    GITHUB_SHA: HEAD,
    GITHUB_OUTPUT: output,
    GITHUB_STEP_SUMMARY: summary,
    RUNNER_TEMP: '/rt',
    HOME: '/home/u',
    PATH: '/usr/bin',
  };
  const out: string[] = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stdout.write);
  vi.spyOn(process.stderr, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stderr.write);
  const deps = fakeDeps({ env, fetch: f, fs, exec });
  const written = (i = 0) => {
    const additions = commits[i]!.fileChanges.additions as { path: string; contents: string }[];
    return Object.fromEntries(additions.map((a) => [a.path, Buffer.from(a.contents, 'base64').toString('utf8')]));
  };
  return {
    run: () => run(deps),
    fs,
    original,
    exec,
    f,
    syncs,
    branches,
    refPatches,
    commits,
    prs,
    labels,
    autoMerges,
    prPatches,
    issueCreates,
    issuePatches,
    written,
    log: () => out.join(''),
    summary: () => readFileSync(summary, 'utf8'),
  };
}

const LODASH_RECORD = { [GHSA]: npmRecord(GHSA, 'lodash', [{ introduced: '0' }, { fixed: '4.17.21' }]) };
const overlayResolved = (name: string, v: string) => `${D}/r/${REF}/npm/${name}/-/${name}-${v}.tgz`;

/** npm fake: `install lodash@x` / bare `install` (with overrides) writes the fixed lockfile; `update` does what `update` says. */
function npmFake(opts: { update?: 'fixes' | 'noop'; overrideFixes?: boolean; installFixes?: boolean } = {}) {
  return (c: ExecCall, fs: ReturnType<typeof memFs>) => {
    if (c.cmd !== 'npm') return;
    const fixed = () => fs.files.set('/w/package-lock.json', lock([{ name: 'lodash', version: '4.17.21', resolved: overlayResolved('lodash', '4.17.21') }]));
    if (c.args[0] === 'install' && c.args[1] === 'lodash@4.17.21') {
      if (opts.installFixes !== false) {
        fixed();
        const pkg = JSON.parse(fs.files.get('/w/package.json')!);
        pkg.dependencies.lodash = '^4.17.21';
        fs.files.set('/w/package.json', JSON.stringify(pkg, null, 2));
      }
    } else if (c.args[0] === 'update') {
      if (opts.update === 'fixes') fixed();
    } else if (c.args[0] === 'install') {
      const pkg = JSON.parse(fs.files.get('/w/package.json')!);
      if (opts.overrideFixes && pkg.overrides?.lodash === '4.17.21') {
        fs.files.set(
          '/w/package-lock.json',
          lock([
            { name: 'a', version: '1.0.0' },
            { name: 'lodash', version: '4.17.21', path: 'node_modules/a/node_modules/lodash', resolved: overlayResolved('lodash', '4.17.21') },
          ]),
        );
      }
    }
  };
}

const DIRECT: World = {
  files: {
    '/w/package.json': JSON.stringify({ name: 'app', dependencies: { lodash: '^4.17.20' } }, null, 2),
    '/w/package-lock.json': lock([{ name: 'lodash', version: '4.17.20' }]),
  },
  osv: { 'lodash@4.17.20': [GHSA] },
  records: LODASH_RECORD,
};

const TRANSITIVE: World = {
  files: {
    '/w/package.json': JSON.stringify({ name: 'app', dependencies: { a: '^1.0.0' } }, null, 2),
    '/w/package-lock.json': lock([
      { name: 'a', version: '1.0.0' },
      { name: 'lodash', version: '4.17.20', path: 'node_modules/a/node_modules/lodash' },
    ]),
  },
  osv: { 'lodash@4.17.20': [GHSA] },
  records: LODASH_RECORD,
};

describe('audit: npm fix PRs', () => {
  it('direct high vuln with a fix → overlay sync, npm install via the overlay, normalized lockfile, labelled PR, auto-merge', async () => {
    let seenConfig: { text: string | undefined; mode: number | undefined } | null = null;
    const h = harness({
      ...DIRECT,
      exec: (c, fs) => {
        if (c.cmd === 'npm') {
          const p = c.args[c.args.indexOf('--userconfig') + 1]!;
          seenConfig = { text: fs.files.get(p), mode: fs.modes.get(p) };
        }
        return npmFake()(c, fs);
      },
    });
    expect(await h.run()).toBe(0);

    // overlay sync with the ci token: main policy plus one verified allow entry
    expect(h.syncs).toHaveLength(1);
    expect(h.syncs[0]!.auth).toBe('Bearer ci-secret');
    expect(h.syncs[0]!.body.ref).toBe(REF);
    expect(h.syncs[0]!.body.policy.allow).toEqual([
      { package: 'npm:lodash@4.17.21', advisory: GHSA, reason: 'security fix', added: '2026-11-19' },
    ]);
    expect(h.syncs[0]!.body.policy.cooldownDays).toBe(7);

    // npm install name@fixed through the overlay registry; token only in the 0600 userconfig
    const npm = h.exec.calls.filter((c) => c.cmd === 'npm');
    expect(npm).toHaveLength(1);
    const a = npm[0]!.args;
    expect(a.slice(0, 2)).toEqual(['install', 'lodash@4.17.21']);
    for (const flag of ['--ignore-scripts', '--package-lock-only', '--no-audit', '--no-fund']) expect(a).toContain(flag);
    expect(a[a.indexOf('--registry') + 1]).toBe(`${D}/r/${REF}/npm/`);
    const cfg = a[a.indexOf('--userconfig') + 1]!;
    expect(cfg.startsWith('/rt/')).toBe(true);
    expect(npm[0]!.opts?.cwd).toBe('/w');
    expect(Object.keys(npm[0]!.opts?.env ?? {}).sort()).toEqual(['HOME', 'PATH', 'RUNNER_TEMP']);
    expect(JSON.stringify(npm[0])).not.toContain('ci-secret');
    expect(seenConfig!.mode).toBe(0o600);
    expect(seenConfig!.text).toBe(`registry=${D}/r/${REF}/npm/\n//decant.example/r/${REF}/npm/:_authToken=ci-secret\nignore-scripts=true\n`);
    expect(h.fs.files.has(cfg)).toBe(false); // deleted afterwards

    // branch from the default head, committed files
    expect(h.branches).toEqual([{ ref: `refs/heads/${BRANCH}`, sha: HEAD }]);
    expect(h.commits[0]!.branch.branchName).toBe(BRANCH);
    expect(h.commits[0]!.expectedHeadOid).toBe(HEAD);
    const files = h.written();
    expect(Object.keys(files).sort()).toEqual(['decant.json', 'package-lock.json', 'package.json']);
    expect(files['package-lock.json']).toContain('https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz');
    expect(files['package-lock.json']).not.toContain(D);
    expect(JSON.parse(files['decant.json']!).allow).toEqual([
      { package: 'npm:lodash@4.17.21', advisory: GHSA, reason: 'security fix', added: '2026-11-19' },
    ]);

    // PR + labels + auto-merge
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]).toMatchObject({ head: BRANCH, base: 'main', title: `decant: lodash 4.17.20 → 4.17.21 (${GHSA})` });
    expect(h.prs[0]!.body).toContain(`https://github.com/advisories/${GHSA}`);
    expect(h.prs[0]!.body).toMatch(/cooldown/);
    expect(h.labels).toEqual([{ n: 10, labels: ['decant:security', 'decant:high'] }]);
    expect(h.autoMerges).toEqual([{ id: 'PR_10', method: 'SQUASH' }]);

    // the working tree is left as it was
    expect(h.fs.files.get('/w/package-lock.json')).toBe(h.original.get('/w/package-lock.json'));
    expect(h.fs.files.get('/w/package.json')).toBe(h.original.get('/w/package.json'));
    expect(h.summary()).toMatch(/GHSA-aaaa-bbbb-cccc.*lodash.*opened #10/);
    expect(h.log().replace(/::add-mask::.*\n/g, '')).not.toContain('ci-secret');
  });

  it("autoShip.high = 'approve' → PR without auto-merge", async () => {
    const h = harness({ ...DIRECT, policy: { ...BASE_POLICY, autoShip: { high: 'approve' } }, exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.autoMerges).toEqual([]);
  });

  it('auto-merge refused by GitHub → warning, PR stays open, exit 0', async () => {
    const h = harness({ ...DIRECT, autoMergeFails: true, exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.log()).toMatch(/::warning::.*auto-merge/);
  });

  it('re-run with the fix PR open → no sync, no branch, no PR', async () => {
    const h = harness({ ...DIRECT, openPrs: [BRANCH], exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.syncs).toEqual([]);
    expect(h.branches).toEqual([]);
    expect(h.prs).toEqual([]);
    expect(h.exec.calls).toEqual([]);
    expect(h.summary()).toMatch(/skipped/);
  });

  it('transitive dep npm update cannot lift → override added and install rerun', async () => {
    const h = harness({ ...TRANSITIVE, exec: npmFake({ update: 'noop', overrideFixes: true }) });
    expect(await h.run()).toBe(0);
    const npm = h.exec.calls.filter((c) => c.cmd === 'npm').map((c) => c.args.filter((x) => !x.startsWith('-') && !x.startsWith('/') && !x.startsWith('http')));
    expect(npm).toEqual([['update', 'lodash'], ['install']]);
    for (const c of h.exec.calls) expect(c.args).toContain('--ignore-scripts');
    const files = h.written();
    expect(JSON.parse(files['package.json']!).overrides).toEqual({ lodash: '4.17.21' });
    expect(files['package-lock.json']).toContain('https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz');
    expect(h.prs).toHaveLength(1);
  });

  it('transitive dep that npm update lifts → no override', async () => {
    const h = harness({ ...TRANSITIVE, exec: npmFake({ update: 'fixes' }) });
    expect(await h.run()).toBe(0);
    expect(h.exec.calls.map((c) => c.args[0])).toEqual(['update']);
    expect(Object.keys(h.written())).not.toContain('package.json');
  });

  it('still unresolved after the override → recorded, no PR', async () => {
    const h = harness({ ...TRANSITIVE, exec: npmFake({ update: 'noop', overrideFixes: false }) });
    expect(await h.run()).toBe(0);
    expect(h.branches).toEqual([]);
    expect(h.prs).toEqual([]);
    expect(h.summary()).toMatch(/unresolvable/);
    expect(h.fs.files.get('/w/package.json')).toBe(h.original.get('/w/package.json'));
  });

  it('npm command failure → recorded as failed, run continues, exit 0', async () => {
    const h = harness({ ...DIRECT, exec: (c) => (c.cmd === 'npm' ? { code: 1, stderr: 'ETARGET no matching version' } : undefined) });
    expect(await h.run()).toBe(0);
    expect(h.prs).toEqual([]);
    expect(h.summary()).toMatch(/failed.*ETARGET/);
    expect(h.fs.files.has('/rt/decant-audit-ghsa-aaaa-bbbb-cccc.npmrc')).toBe(false);
  });

  it('overlay sync rejected (422) → recorded as unverified, no npm, no PR', async () => {
    const h = harness({ ...DIRECT, syncStatus: 422, exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.exec.calls).toEqual([]);
    expect(h.prs).toEqual([]);
    expect(h.summary()).toMatch(/unverified/);
  });

  it('one PR per advisory group: GHSA + CVE aliases merge into one', async () => {
    const records = {
      [GHSA]: { ...npmRecord(GHSA, 'lodash', [{ introduced: '0' }, { fixed: '4.17.21' }]), aliases: ['CVE-2026-1234'] },
      'CVE-2026-1234': { ...npmRecord('CVE-2026-1234', 'lodash', [{ introduced: '0' }, { fixed: '4.17.21' }]), aliases: [GHSA] },
    };
    const h = harness({ ...DIRECT, osv: { 'lodash@4.17.20': [GHSA, 'CVE-2026-1234'] }, records, exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.syncs).toHaveLength(1);
  });

  it('same package in two lockfiles → fixed in both in one PR', async () => {
    const h = harness({
      files: {
        ...DIRECT.files,
        '/w/sub/package.json': JSON.stringify({ name: 'sub', dependencies: { lodash: '^4.17.20' } }, null, 2),
        '/w/sub/package-lock.json': lock([{ name: 'lodash', version: '4.17.20' }]),
      },
      osv: DIRECT.osv,
      records: LODASH_RECORD,
      exec: (c, fs) => {
        if (c.cmd === 'npm' && c.args[1] === 'lodash@4.17.21') {
          const dir = c.opts!.cwd!;
          fs.files.set(`${dir}/package-lock.json`, lock([{ name: 'lodash', version: '4.17.21', resolved: overlayResolved('lodash', '4.17.21') }]));
        }
      },
    });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(Object.keys(h.written()).sort()).toEqual(['decant.json', 'package-lock.json', 'sub/package-lock.json']);
  });
});

describe('audit: Go', () => {
  it('runs go get + go mod tidy with GOPROXY at the audit overlay and no token in the env', async () => {
    const GO = 'GO-2026-0001';
    let netrc: { text?: string; mode?: number } = {};
    const h = harness({
      files: {
        '/w/go.mod': 'module example.com/app\n\ngo 1.22\n\nrequire github.com/x/y v1.0.0\n',
        '/w/go.sum': 'github.com/x/y v1.0.0 h1:abc=\ngithub.com/x/y v1.0.0/go.mod h1:def=\n',
      },
      osv: { 'github.com/x/y@1.0.0': [GO] },
      records: {
        [GO]: {
          id: GO,
          database_specific: { severity: 'CRITICAL' },
          affected: [{ package: { ecosystem: 'Go', name: 'github.com/x/y' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] }],
        },
      },
      exec: (c, fs) => {
        if (c.cmd !== 'go') return;
        netrc = { text: fs.files.get(c.opts!.env!.NETRC!), mode: fs.modes.get(c.opts!.env!.NETRC!) };
        if (c.args[0] === 'get') {
          fs.files.set('/w/go.mod', 'module example.com/app\n\ngo 1.22\n\nrequire github.com/x/y v1.0.1\n');
          fs.files.set('/w/go.sum', 'github.com/x/y v1.0.1 h1:new=\ngithub.com/x/y v1.0.1/go.mod h1:new2=\n');
        }
      },
    });
    expect(await h.run()).toBe(0);
    const go = h.exec.calls.filter((c) => c.cmd === 'go');
    expect(go.map((c) => c.args)).toEqual([['get', 'github.com/x/y@v1.0.1'], ['mod', 'tidy']]);
    for (const c of go) {
      expect(c.opts?.cwd).toBe('/w');
      expect(c.opts?.env?.GOPROXY).toBe(`${D}/r/audit-go-2026-0001/go`);
      expect(c.opts?.env?.GOFLAGS).toBe('-mod=mod');
      expect(c.opts?.env?.NETRC?.startsWith('/rt/')).toBe(true);
      expect(c.opts?.env?.GOSUMDB).toBeUndefined();
      expect(JSON.stringify(c)).not.toContain('ci-secret');
    }
    expect(netrc).toEqual({ text: 'machine decant.example login decant password ci-secret\n', mode: 0o600 });
    expect([...h.fs.files.keys()].some((k) => k.startsWith('/rt/'))).toBe(false);
    expect(h.syncs[0]!.body.policy.allow[0]).toEqual({ package: 'go:github.com/x/y@v1.0.1', advisory: GO, reason: 'security fix', added: '2026-11-19' });
    expect(Object.keys(h.written()).sort()).toEqual(['decant.json', 'go.mod', 'go.sum']);
    expect(h.prs[0]).toMatchObject({ head: 'decant/fix-go-2026-0001-github.com-x-y', title: `decant: github.com/x/y v1.0.0 → v1.0.1 (${GO})` });
    expect(h.labels[0]!.labels).toEqual(['decant:security', 'decant:critical']);
  });
});

describe('audit: issues', () => {
  const UNFIXED: World = {
    ...DIRECT,
    records: { [GHSA]: npmRecord(GHSA, 'lodash', [{ introduced: '0' }]) },
  };

  it('no fix → unfixed-advisories issue upserted, no PR', async () => {
    const h = harness(UNFIXED);
    expect(await h.run()).toBe(0);
    expect(h.prs).toEqual([]);
    expect(h.syncs).toEqual([]);
    expect(h.issueCreates).toHaveLength(1);
    expect(h.issueCreates[0]).toMatchObject({ title: 'decant: unfixed advisories' });
    expect(h.issueCreates[0]!.body).toContain(GHSA);
    expect(h.issueCreates[0]!.body).toContain('lodash@4.17.20');
  });

  it('existing issue of ours is updated, not duplicated', async () => {
    const h = harness({ ...UNFIXED, issues: [{ number: 7, title: 'decant: unfixed advisories', user: { login: SELF, type: 'Bot' } }] });
    expect(await h.run()).toBe(0);
    expect(h.issueCreates).toEqual([]);
    expect(h.issuePatches.find((p) => p.n === 7)!.body.body).toContain(GHSA);
  });

  it('nothing unfixed and no blocks → our open issues are closed', async () => {
    const h = harness({
      files: { '/w/package.json': '{}', '/w/package-lock.json': lock([{ name: 'ok', version: '1.0.0' }]) },
      issues: [
        { number: 7, title: 'decant: unfixed advisories', user: { login: SELF, type: 'Bot' } },
        { number: 8, title: 'decant: blocked versions in lockfiles', user: { login: SELF, type: 'Bot' } },
      ],
    });
    expect(await h.run()).toBe(0);
    expect(h.issuePatches.map((p) => [p.n, p.body.state])).toEqual([
      [7, 'closed'],
      [8, 'closed'],
    ]);
  });

  it('block hitting a lockfile → blocked-versions issue upserted', async () => {
    const h = harness({
      files: { '/w/package.json': '{}', '/w/package-lock.json': lock([{ name: 'evil', version: '1.0.0' }, { name: 'ok', version: '1.0.0' }]) },
      blocks: [
        { package: 'npm:evil@1.0.0', source: 'osv', reason: 'malware', at: '2026-11-18T00:00:00Z' },
        { package: 'npm:other@2.0.0', source: 'manual', reason: 'x', at: '2026-11-18T00:00:00Z' },
      ],
    });
    expect(await h.run()).toBe(0);
    const issue = h.issueCreates.find((i) => i.title === 'decant: blocked versions in lockfiles');
    expect(issue).toBeDefined();
    expect(issue.body).toContain('npm:evil@1.0.0');
    expect(issue.body).not.toContain('npm:other@2.0.0');
  });
});

describe('audit: prune', () => {
  const PRUNE: World = {
    files: { '/w/package.json': '{}', '/w/package-lock.json': lock([{ name: 'ok', version: '1.0.0' }]) },
    policy: {
      ...BASE_POLICY,
      allow: [
        { package: 'npm:old@1.0.0', reason: 'adopted', added: '2026-11-01' },
        { package: 'npm:fresh@2.0.0', reason: 'adopted', added: '2026-11-18' },
      ],
    },
    times: { 'old@1.0.0': '2026-11-01T00:00:00Z', 'fresh@2.0.0': '2026-11-17T00:00:00Z' },
  };

  it('expired allow entry → prune PR without auto-merge', async () => {
    const h = harness(PRUNE);
    expect(await h.run()).toBe(0);
    expect(h.branches).toEqual([{ ref: 'refs/heads/decant/prune', sha: HEAD }]);
    expect(JSON.parse(h.written()['decant.json']!).allow).toEqual([{ package: 'npm:fresh@2.0.0', reason: 'adopted', added: '2026-11-18' }]);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]).toMatchObject({ head: 'decant/prune', title: 'decant: prune allow entries' });
    expect(h.prs[0]!.body).toContain('npm:old@1.0.0');
    expect(h.labels).toEqual([{ n: 10, labels: ['decant:prune'] }]);
    expect(h.autoMerges).toEqual([]);
  });

  it('prune PR already open → refreshed on its branch, no second PR', async () => {
    const h = harness({ ...PRUNE, openPrs: ['decant/prune'] });
    expect(await h.run()).toBe(0);
    expect(h.prPatches).toEqual([3]);
    expect(h.prs).toEqual([]);
    expect(h.commits[0]!.branch.branchName).toBe('decant/prune');
    expect(h.commits[0]!.expectedHeadOid).toBe('d'.repeat(40));
  });

  it('prune GitHub failure (non-auth) → recorded, exit 0', async () => {
    const h = harness({ ...PRUNE, createBranchStatus: 500 });
    expect(await h.run()).toBe(0);
    expect(h.summary()).toMatch(/Prune: failed: .*HTTP 500/);
  });

  it('decant rejects the ci token (403) on overlay sync → exit 1', async () => {
    const h = harness({ ...DIRECT, syncStatus: 403, exec: npmFake() });
    expect(await h.run()).toBe(1);
  });

  it('GitHub auth failure → exit 1', async () => {
    const h = harness({ ...PRUNE, createBranchStatus: 401 });
    expect(await h.run()).toBe(1);
  });

  it('nothing expired → no prune PR', async () => {
    const h = harness({ ...PRUNE, times: { 'old@1.0.0': '2026-11-15T00:00:00Z', 'fresh@2.0.0': '2026-11-17T00:00:00Z' } });
    expect(await h.run()).toBe(0);
    expect(h.prs).toEqual([]);
  });
});

describe('audit: systemic failures', () => {
  it('OSV unavailable → exit 1', async () => {
    const h = harness({ ...DIRECT, osvDown: true });
    expect(await h.run()).toBe(1);
    expect(h.prs).toEqual([]);
  });

  it('lockfile parse error → exit 1', async () => {
    const h = harness({ files: { '/w/package-lock.json': JSON.stringify({ lockfileVersion: 1, dependencies: {} }) } });
    expect(await h.run()).toBe(1);
    expect(h.log()).toMatch(/npm 7 or newer/);
  });

  it('missing github-token → exit 1', async () => {
    harness(DIRECT); // stdout/stderr spies
    const fs = memFs({ '/w/decant.json': JSON.stringify(BASE_POLICY) });
    const r = await run(fakeDeps({ env: { INPUT_MODE: 'audit', INPUT_DECANT_URL: D, INPUT_TOKEN: 'x', INPUT_WORKING_DIRECTORY: '/w' }, fs }));
    expect(r).toBe(1);
  });
});

describe('audit: names', () => {
  it('fixBranch sanitizes scoped names and stays within 100 chars', async () => {
    const { fixBranch, overlayRef } = await import('../src/modes/audit');
    expect(fixBranch(GHSA, '@Scope/pkg_name')).toBe('decant/fix-ghsa-aaaa-bbbb-cccc-scope-pkg-name');
    const long = fixBranch(GHSA, `github.com/${'a'.repeat(200)}`);
    expect(long.length).toBeLessThanOrEqual(100);
    expect(long.startsWith('decant/fix-ghsa-aaaa-bbbb-cccc-github.com-aaa')).toBe(true);
    expect(fixBranch(GHSA, 'x..y.')).toBe('decant/fix-ghsa-aaaa-bbbb-cccc-x.y');
    expect(overlayRef(GHSA)).toBe(REF);
    expect(overlayRef(`PYSEC-2026-${'9'.repeat(80)}`)).toMatch(/^[A-Za-z0-9._-]{1,64}$/);
  });
});
