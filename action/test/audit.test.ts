import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { run } from '../src/main';
import { fakeDeps, fakeExec, fakeFetch, jsonRes, memFs, type ExecCall, type FetchCall } from './fakes';

afterEach(() => vi.restoreAllMocks());

// The pinned tarball's checksum cannot be reproduced in a test: installing is covered in grype.test.ts.
vi.mock('../src/grype', async (orig) => ({ ...(await orig<typeof import('../src/grype')>()), installGrype: async () => ({ bin: '/rt/decant-grype/grype' }) }));

const D = 'https://decant.example';
const R = 'https://api.github.com/repos/o/r';
const HEAD = 'c'.repeat(40);
const OPEN_HEAD = 'd'.repeat(40);
const GHSA = 'GHSA-aaaa-bbbb-cccc';
const REF = 'audit';
const BRANCH = 'decant/security-fixes';
const SELF = 'github-actions[bot]';

const setHash = (ids: string[]) => createHash('sha256').update([...ids].sort().join('\n')).digest('hex');
const marker = (ids: string[]) => `<!-- decant-audit-set: ${setHash(ids)} -->`;

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

type SyncReply = { status: number; body: unknown };

type World = {
  files: Record<string, string>;
  policy?: Record<string, unknown>;
  /** "name@version" → OSV ids */
  osv?: Record<string, string[]>;
  records?: Record<string, unknown>;
  osvDown?: boolean;
  openPrs?: string[];
  /** Details of the open PR returned for any branch in openPrs. */
  openPr?: { body?: string; labels?: string[]; autoMerge?: boolean; user?: { login: string; type: string }; baseRef?: string };
  /** GET /compare/<base>...<head> reply. */
  compare?: (base: string, head: string) => unknown;
  disableAutoMergeFails?: boolean;
  /** HTTP status for GET /pulls (state=open / state=closed) lookups; default 200. */
  pullsStatus?: { open?: number; closed?: number };
  /** branch → body of its latest closed-unmerged PR. */
  closedPrs?: Record<string, string>;
  /** "path@ref" → file contents served by GET /contents. */
  contents?: Record<string, string>;
  syncStatus?: number;
  sync?: (policy: any, n: number) => SyncReply;
  blocks?: { package: string; source: string; reason: string; at: string }[];
  times?: Record<string, string>;
  issues?: { number: number; title: string; user: { login: string; type: string } }[];
  autoMergeFails?: boolean;
  createBranchStatus?: number;
  ref?: string;
  mainHead?: string;
  env?: Record<string, string | undefined>;
  exec?: (c: ExecCall, fs: ReturnType<typeof memFs>) => { code?: number; stdout?: string; stderr?: string } | void;
  /** Answers checked before the built-in routes (registries, /api/images, verdicts). */
  extraFetch?: (c: FetchCall) => Response | undefined;
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
  const labelDeletes: { n: number; label: string }[] = [];
  const autoMerges: any[] = [];
  const autoMergeOffs: any[] = [];
  const prPatches: { n: number; body: any }[] = [];
  const issueCreates: any[] = [];
  const issuePatches: { n: number; body: any }[] = [];
  let prN = 10;
  const f = fakeFetch((c: FetchCall) => {
    const u = new URL(c.url);
    const key = `${c.method} ${c.url}`;
    const extra = w.extraFetch?.(c);
    if (extra) return extra;
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
      const body = JSON.parse(c.body!);
      syncs.push({ auth: c.headers.get('authorization'), body });
      if (w.sync) {
        const r = w.sync(body.policy, syncs.length);
        return jsonRes(r.body, r.status);
      }
      const s = w.syncStatus ?? 200;
      return jsonRes(s === 200 ? { ok: true } : { error: 'nope' }, s);
    }
    if (key === `GET ${D}/api/blocks`) return jsonRes({ blocks: w.blocks ?? [] });
    if (key === `GET ${R}`) return jsonRes({ default_branch: 'main' });
    if (key === `GET ${R}/git/ref/heads/main`) return jsonRes({ object: { sha: w.mainHead ?? HEAD } });
    if (c.method === 'GET' && c.url.startsWith(`${R}/pulls?`)) {
      const head = decodeURIComponent(u.searchParams.get('head') ?? '').replace(/^o:/, '');
      const st = w.pullsStatus?.[u.searchParams.get('state') === 'closed' ? 'closed' : 'open'];
      if (st) return new Response('boom', { status: st });
      if (u.searchParams.get('state') === 'closed') {
        const body = w.closedPrs?.[head];
        return jsonRes(
          body === undefined
            ? []
            : [
                { number: 2, merged_at: '2026-01-01T00:00:00Z', closed_at: '2026-01-01T00:00:00Z', body: 'merged' },
                { number: 4, merged_at: null, closed_at: '2026-11-10T00:00:00Z', body },
                { number: 1, merged_at: null, closed_at: '2025-01-01T00:00:00Z', body: 'older' },
              ],
        );
      }
      return jsonRes(
        (w.openPrs ?? []).includes(head)
          ? [
              {
                number: 3,
                node_id: 'OPEN',
                title: 't',
                body: w.openPr?.body ?? '',
                state: 'open',
                labels: (w.openPr?.labels ?? []).map((name) => ({ name })),
                auto_merge: w.openPr?.autoMerge ? { merge_method: 'squash' } : null,
                user: w.openPr?.user ?? { login: 'decant-app[bot]', type: 'Bot' },
                head: { ref: head, sha: OPEN_HEAD },
                base: { ref: w.openPr?.baseRef ?? 'main', sha: HEAD },
              },
            ]
          : [],
      );
    }
    if (c.method === 'GET' && c.url.startsWith(`${R}/compare/`)) {
      const [base, head] = c.url.slice(`${R}/compare/`.length).split('...');
      return w.compare ? jsonRes(w.compare(base!, head!)) : new Response('nf', { status: 404 });
    }
    if (c.method === 'GET' && c.url.startsWith(`${R}/contents/`)) {
      const path = decodeURIComponent(u.pathname.slice(`/repos/o/r/contents/`.length));
      const v = w.contents?.[`${path}@${u.searchParams.get('ref')}`];
      return v === undefined ? new Response('nf', { status: 404 }) : jsonRes({ encoding: 'base64', content: Buffer.from(v).toString('base64') });
    }
    if (key === `POST ${R}/git/refs`) {
      branches.push(JSON.parse(c.body!));
      if (w.createBranchStatus) return new Response('nope', { status: w.createBranchStatus });
      return jsonRes({}, 201);
    }
    const pp = new RegExp(`^${R}/pulls/(\\d+)$`).exec(c.url);
    if (c.method === 'PATCH' && pp) {
      prPatches.push({ n: Number(pp[1]), body: JSON.parse(c.body!) });
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
      if (b.query.includes('disablePullRequestAutoMerge')) {
        autoMergeOffs.push(b.variables);
        if (w.disableAutoMergeFails) return jsonRes({ errors: [{ message: 'nope' }] });
        return jsonRes({ data: { disablePullRequestAutoMerge: { clientMutationId: null } } });
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
    const labDel = new RegExp(`^${R}/issues/(\\d+)/labels/(.+)$`).exec(c.url);
    if (c.method === 'DELETE' && labDel) {
      labelDeletes.push({ n: Number(labDel[1]), label: decodeURIComponent(labDel[2]!) });
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
    GITHUB_REF: w.ref ?? 'refs/heads/main',
    GITHUB_OUTPUT: output,
    GITHUB_STEP_SUMMARY: summary,
    RUNNER_TEMP: '/rt',
    DECANT_GRYPE_PLATFORM: 'linux',
    DECANT_GRYPE_ARCH: 'x64',
    HOME: '/home/u',
    PATH: '/usr/bin',
  };
  const out: string[] = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stdout.write);
  vi.spyOn(process.stderr, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stderr.write);
  for (const [k, v] of Object.entries(w.env ?? {})) {
    if (v === undefined) delete env[k];
    else env[k] = v;
  }
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
    labelDeletes,
    autoMerges,
    autoMergeOffs,
    prPatches,
    issueCreates,
    issuePatches,
    written,
    log: () => out.join(''),
    summary: () => readFileSync(summary, 'utf8'),
  };
}

const LODASH_RECORD = { [GHSA]: npmRecord(GHSA, 'lodash', [{ introduced: '0' }, { fixed: '4.17.21' }]) };
const overlayResolved = (name: string, v: string) => `${D}/r/${REF}/npm/${name}/-/${name.slice(name.lastIndexOf('/') + 1)}-${v}.tgz`;

/** Sets the lockfile entry at `path` (default node_modules/<name>) in `dir` to `version`, resolved through the overlay. */
function bump(fs: ReturnType<typeof memFs>, dir: string, name: string, version: string, path = `node_modules/${name}`) {
  const lockAbs = `${dir}/package-lock.json`;
  const l = JSON.parse(fs.files.get(lockAbs)!);
  l.packages[path] = { version, resolved: overlayResolved(name, version), integrity: `sha512-${name}${version}` };
  fs.files.set(lockAbs, JSON.stringify(l, null, 2));
}

/** npm fake: `install lodash@x` / bare `install` (with overrides) writes the fixed lockfile; `update` does what `update` says. */
function npmFake(opts: { update?: 'fixes' | 'noop'; overrideFixes?: boolean; installFixes?: boolean } = {}) {
  return (c: ExecCall, fs: ReturnType<typeof memFs>) => {
    if (c.cmd !== 'npm') return;
    const fixed = () => fs.files.set('/w/package-lock.json', lock([{ name: 'lodash', version: '4.17.21', resolved: overlayResolved('lodash', '4.17.21') }]));
    if (c.args[0] === 'install' && c.args.at(-1) === 'lodash@4.17.21') {
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
      if (opts.overrideFixes && pkg.overrides?.['lodash@^4'] === '4.17.21') {
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

// A batch: undici (direct) with three advisories, js-yaml (transitive), and a Go module.
const U1 = 'GHSA-und1-0001-aaaa'; // high, fixed 7.29.1
const U2 = 'GHSA-und2-0002-aaaa'; // critical, fixed 7.30.1
const U3 = 'GHSA-und3-0003-aaaa'; // moderate, fixed 7.29.1
const JY = 'GHSA-jsya-0001-aaaa'; // high, fixed 4.1.1
const GO = 'GO-2026-0001'; // critical, fixed 1.0.1
const GO_MOD = 'module example.com/app\n\ngo 1.22\n\nrequire github.com/x/y v1.0.0\n';
const GO_SUM = 'github.com/x/y v1.0.0 h1:abc=\ngithub.com/x/y v1.0.0/go.mod h1:def=\n';
const goRecord = (severity = 'CRITICAL', fixed = '1.0.1') => ({
  id: GO,
  summary: 'y is vulnerable',
  database_specific: { severity },
  affected: [{ package: { ecosystem: 'Go', name: 'github.com/x/y' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed }] }] }],
});
const BATCH_RECORDS = {
  [U1]: npmRecord(U1, 'undici', [{ introduced: '7.0.0' }, { fixed: '7.29.1' }], 'HIGH'),
  [U2]: npmRecord(U2, 'undici', [{ introduced: '7.0.0' }, { fixed: '7.30.1' }], 'CRITICAL'),
  [U3]: npmRecord(U3, 'undici', [{ introduced: '7.0.0' }, { fixed: '7.29.1' }], 'MODERATE'),
  [JY]: npmRecord(JY, 'js-yaml', [{ introduced: '4.0.0' }, { fixed: '4.1.1' }], 'HIGH'),
  [GO]: goRecord(),
};
const BATCH: World = {
  files: {
    '/w/package.json': JSON.stringify({ name: 'app', dependencies: { undici: '^7.28.0', a: '^1.0.0' } }, null, 2),
    '/w/package-lock.json': lock([
      { name: 'undici', version: '7.28.0' },
      { name: 'a', version: '1.0.0' },
      { name: 'js-yaml', version: '4.1.0', path: 'node_modules/a/node_modules/js-yaml' },
    ]),
    '/w/go.mod': GO_MOD,
    '/w/go.sum': GO_SUM,
  },
  osv: { 'undici@7.28.0': [U1, U2, U3], 'js-yaml@4.1.0': [JY], 'github.com/x/y@1.0.0': [GO] },
  records: BATCH_RECORDS,
};
const BATCH_IDS = ['go:github.com/x/y@v1.0.1', 'npm:js-yaml@4.1.1', 'npm:undici@7.30.1'];

/** Fake npm + go for BATCH: install undici@x bumps undici; update js-yaml lifts js-yaml (unless `stuck`); go get bumps y. */
function batchExec(opts: { stuck?: string[]; undiciMajor?: string } = {}) {
  return (c: ExecCall, fs: ReturnType<typeof memFs>) => {
    const dir = c.opts!.cwd!;
    if (c.cmd === 'npm') {
      const spec = c.args.at(-1)!;
      if (c.args[0] === 'install' && spec.startsWith('undici@')) {
        bump(fs, dir, 'undici', spec.slice('undici@'.length));
        const pkg = JSON.parse(fs.files.get(`${dir}/package.json`)!);
        pkg.dependencies.undici = `^${spec.slice('undici@'.length)}`;
        fs.files.set(`${dir}/package.json`, JSON.stringify(pkg, null, 2));
      } else if (c.args[0] === 'update' && spec === 'js-yaml' && !opts.stuck?.includes('js-yaml')) {
        bump(fs, dir, 'js-yaml', '4.1.1', 'node_modules/a/node_modules/js-yaml');
      }
    }
    if (c.cmd === 'go' && c.args[0] === 'get') {
      if (opts.stuck?.includes('github.com/x/y')) return;
      fs.files.set(`${dir}/go.mod`, GO_MOD.replace('v1.0.0', 'v1.0.1'));
      fs.files.set(`${dir}/go.sum`, 'github.com/x/y v1.0.1 h1:new=\ngithub.com/x/y v1.0.1/go.mod h1:new2=\n');
    }
  };
}

describe('audit: one security PR per run', () => {
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

    // overlay sync with the ci token: main policy plus one verified allow entry, ref "audit"
    expect(h.syncs).toHaveLength(1);
    expect(h.syncs[0]!.auth).toBe('Bearer ci-secret');
    expect(h.syncs[0]!.body.ref).toBe(REF);
    expect(h.syncs[0]!.body.policy.allow).toEqual([{ package: 'npm:lodash@4.17.21', advisory: GHSA, reason: 'security fix', added: '2026-11-19' }]);
    expect(h.syncs[0]!.body.policy.cooldownDays).toBe(7);

    // npm install name@fixed through the overlay registry; token only in the 0600 userconfig
    const npm = h.exec.calls.filter((c) => c.cmd === 'npm');
    expect(npm).toHaveLength(1);
    const a = npm[0]!.args;
    expect(a[0]).toBe('install');
    expect(a.slice(-2)).toEqual(['--', 'lodash@4.17.21']);
    for (const flag of ['--ignore-scripts', '--package-lock-only', '--no-audit', '--no-fund']) expect(a).toContain(flag);
    expect(a[a.indexOf('--registry') + 1]).toBe(`${D}/r/audit/npm/`);
    const cfg = a[a.indexOf('--userconfig') + 1]!;
    expect(cfg).toMatch(/^\/rt\/decant-audit-\w+\/[0-9a-f-]{36}\.npmrc$/);
    expect(h.fs.dirs.has(cfg.slice(0, cfg.lastIndexOf('/')))).toBe(false); // private dir removed
    expect(npm[0]!.opts?.cwd).toBe('/w');
    expect(Object.keys(npm[0]!.opts?.env ?? {}).sort()).toEqual(['HOME', 'PATH', 'RUNNER_TEMP']);
    expect(JSON.stringify(npm[0])).not.toContain('ci-secret');
    expect(seenConfig!.mode).toBe(0o600);
    expect(seenConfig!.text).toBe(`registry=${D}/r/audit/npm/\n//decant.example/r/audit/npm/:_authToken=ci-secret\nignore-scripts=true\n`);
    expect(h.fs.files.has(cfg)).toBe(false); // deleted afterwards

    // branch from the default head, committed files
    expect(h.branches).toEqual([{ ref: `refs/heads/${BRANCH}`, sha: HEAD }]);
    expect(h.commits).toHaveLength(1);
    expect(h.commits[0]!.branch.branchName).toBe(BRANCH);
    expect(h.commits[0]!.expectedHeadOid).toBe(HEAD);
    expect(h.commits[0]!.message.headline).toBe('decant: security fixes (1 package, 1 advisory)');
    const files = h.written();
    expect(Object.keys(files).sort()).toEqual(['decant.json', 'package-lock.json', 'package.json']);
    expect(files['package-lock.json']).toContain('https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz');
    expect(files['package-lock.json']).not.toContain(D);
    expect(JSON.parse(files['decant.json']!).allow).toEqual([{ package: 'npm:lodash@4.17.21', advisory: GHSA, reason: 'security fix', added: '2026-11-19' }]);

    // PR + labels + auto-merge
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]).toMatchObject({ head: BRANCH, base: 'main', title: 'decant: security fixes (1 package, 1 advisory)' });
    const body = h.prs[0]!.body as string;
    expect(body).toContain(`[${GHSA}](https://github.com/advisories/${GHSA})`);
    expect(body).toMatch(/\| `lodash` \| 4\.17\.20 → 4\.17\.21 \|.*\| high \|/);
    expect(body).toMatch(/cooldown/i);
    expect(body).toContain(marker(['npm:lodash@4.17.21']));
    expect(h.labels).toEqual([{ n: 10, labels: ['decant:security', 'decant:high'] }]);
    expect(h.autoMerges).toEqual([{ id: 'PR_10', method: 'SQUASH' }]);

    // the working tree is left as it was
    expect(h.fs.files.get('/w/package-lock.json')).toBe(h.original.get('/w/package-lock.json'));
    expect(h.fs.files.get('/w/package.json')).toBe(h.original.get('/w/package.json'));
    expect(h.summary()).toMatch(/lodash.*fixed/);
    expect(h.summary()).toMatch(/Security PR: opened #10/);
    expect(h.log().replace(/::add-mask::.*\n/g, '')).not.toContain('ci-secret');
  });

  it('undici (3 advisories) + js-yaml + a Go module → one sync, one commit, one PR; undici to the highest fix', async () => {
    const h = harness({ ...BATCH, exec: batchExec() });
    expect(await h.run()).toBe(0);

    // one overlay sync, one allow entry per package version; the highest-severity advisory cited, the rest in reason
    expect(h.syncs).toHaveLength(1);
    expect(h.syncs[0]!.body.ref).toBe('audit');
    const allow = [
      { package: 'go:github.com/x/y@v1.0.1', advisory: GO, reason: 'security fix', added: '2026-11-19' },
      { package: 'npm:js-yaml@4.1.1', advisory: JY, reason: 'security fix', added: '2026-11-19' },
      { package: 'npm:undici@7.30.1', advisory: U2, reason: `security fix: ${U1}, ${U3}`, added: '2026-11-19' },
    ];
    expect(h.syncs[0]!.body.policy.allow).toEqual(allow);

    // undici installed at 7.30.1 (not 7.29.1), js-yaml updated, Go module bumped — all via /r/audit/
    const cmds = h.exec.calls.map((c) => [c.cmd, ...c.args.filter((x) => !x.startsWith('-') && !x.startsWith('/') && !x.startsWith('http'))]);
    expect(cmds).toEqual([
      ['go', 'get', 'github.com/x/y@v1.0.1'],
      ['go', 'mod', 'tidy'],
      ['npm', 'update', 'js-yaml'],
      ['npm', 'install', 'undici@7.30.1'],
    ]);
    for (const c of h.exec.calls.filter((c) => c.cmd === 'go')) expect(c.opts?.env?.GOPROXY).toBe(`${D}/r/audit/go`);

    // one branch, one commit carrying every file, one PR
    expect(h.branches).toEqual([{ ref: `refs/heads/${BRANCH}`, sha: HEAD }]);
    expect(h.commits).toHaveLength(1);
    const files = h.written();
    expect(Object.keys(files).sort()).toEqual(['decant.json', 'go.mod', 'go.sum', 'package-lock.json', 'package.json']);
    const l = JSON.parse(files['package-lock.json']!);
    expect(l.packages['node_modules/undici'].version).toBe('7.30.1');
    expect(l.packages['node_modules/a/node_modules/js-yaml'].version).toBe('4.1.1');
    expect(files['package-lock.json']).not.toContain(D);
    expect(JSON.parse(files['decant.json']!).allow).toEqual(allow);

    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]!.title).toBe('decant: security fixes (3 packages, 5 advisories)');
    const body = h.prs[0]!.body as string;
    for (const id of [U1, U2, U3, JY]) expect(body).toContain(`[${id}](https://github.com/advisories/${id})`);
    expect(body).toContain(`[${GO}](https://osv.dev/vulnerability/${GO})`);
    expect(body).toMatch(/\| `undici` \| 7\.28\.0 → 7\.30\.1 \|.*\| critical \|/);
    expect(body).toMatch(/\| `js-yaml` \| 4\.1\.0 → 4\.1\.1 \|.*\| high \|/);
    expect(body).toMatch(/\| `github\.com\/x\/y` \| v1\.0\.0 → v1\.0\.1 \|.*\| critical \|/);
    expect(body).toContain(marker(BATCH_IDS));
    expect(h.labels).toEqual([{ n: 10, labels: ['decant:security', 'decant:critical'] }]);
    // U3 is moderate and autoShip.moderate defaults to approve → no auto-merge, and the body says why
    expect(h.autoMerges).toEqual([]);
    expect(body).toMatch(/autoShip\.moderate is `approve`/);

    for (const p of ['/w/package-lock.json', '/w/package.json', '/w/go.mod', '/w/go.sum']) expect(h.fs.files.get(p)).toBe(h.original.get(p));
  });

  it('open PR on decant/security-fixes → branch force-reset to the default head, recommitted, PR refreshed, never a second PR', async () => {
    const h = harness({
      ...BATCH,
      exec: batchExec(),
      openPrs: [BRANCH],
      openPr: { body: `old\n${marker(['npm:undici@7.29.1'])}`, labels: ['decant:security', 'decant:high', 'other'], autoMerge: true },
    });
    expect(await h.run()).toBe(0);
    expect(h.prs).toEqual([]);
    expect(h.branches).toEqual([]);
    expect(h.refPatches).toEqual([{ url: `${R}/git/refs/heads/decant/security-fixes`, body: { sha: HEAD, force: true } }]);
    expect(h.commits).toHaveLength(1);
    expect(h.commits[0]!.expectedHeadOid).toBe(HEAD);
    expect(h.prPatches).toHaveLength(1);
    expect(h.prPatches[0]!.n).toBe(3);
    expect(h.prPatches[0]!.body.title).toBe('decant: security fixes (3 packages, 5 advisories)');
    expect(h.prPatches[0]!.body.body).toContain(marker(BATCH_IDS));
    expect(h.labels).toEqual([{ n: 3, labels: ['decant:security', 'decant:critical'] }]);
    expect(h.labelDeletes).toEqual([{ n: 3, label: 'decant:high' }]);
    // the batch is no longer auto-mergeable (moderate advisory): auto-merge turned off
    expect(h.autoMergeOffs).toEqual([{ id: 'OPEN' }]);
    const at = (pred: (c: FetchCall) => boolean) => h.f.calls.findIndex(pred);
    expect(at((c) => c.body?.includes('disablePullRequestAutoMerge') ?? false)).toBeLessThan(at((c) => c.method === 'PATCH' && c.url.includes('/git/refs/')));
    expect(h.summary()).toMatch(/Security PR: updated #3/);
  });

  /** World for an open PR that already holds exactly this run's batch (ours unless overridden). */
  async function reuseWorld(over: Partial<World> = {}, commits = 1): Promise<World> {
    const first = harness({ ...BATCH, exec: batchExec(), ...(over.policy ? { policy: over.policy } : {}) });
    expect(await first.run()).toBe(0);
    const written = first.written();
    vi.restoreAllMocks();
    const contents: Record<string, string> = {};
    for (const [p, c] of Object.entries(written)) contents[`${p}@${OPEN_HEAD}`] = c;
    return {
      ...BATCH,
      exec: batchExec(),
      openPrs: [BRANCH],
      openPr: { body: marker(BATCH_IDS), labels: ['decant:security', 'decant:critical'] },
      contents,
      compare: (base, head) => ({
        status: 'ahead',
        ahead_by: commits,
        behind_by: 0,
        commits: Array.from({ length: commits }, (_, i) => ({ sha: `${head}${i}`, author: { login: 'decant-app[bot]', type: 'Bot' }, parents: [{ sha: base }] })),
        files: Object.keys(written).map((filename) => ({ filename })),
      }),
      ...over,
    };
  }

  it('open PR already holding our single commit with the same set and files → no commit, body refreshed', async () => {
    const h = harness(await reuseWorld());
    expect(await h.run()).toBe(0);
    expect(h.commits).toEqual([]);
    expect(h.refPatches).toEqual([]);
    expect(h.prs).toEqual([]);
    expect(h.prPatches.map((p) => p.n)).toEqual([3]);
    expect(h.f.calls.some((c) => c.url === `${R}/compare/${HEAD}...${OPEN_HEAD}`)).toBe(true);
    expect(h.summary()).toMatch(/Security PR: #3 up to date/);
  });

  it('same marker and files but the PR is not ours → force-reset and recommit', async () => {
    const h = harness(await reuseWorld({ openPr: { body: marker(BATCH_IDS), user: { login: 'mallory', type: 'User' } } }));
    expect(await h.run()).toBe(0);
    expect(h.refPatches).toHaveLength(1);
    expect(h.commits).toHaveLength(1);
  });

  it('same marker and files but the branch holds an extra commit → force-reset and recommit', async () => {
    const h = harness(await reuseWorld({}, 2));
    expect(await h.run()).toBe(0);
    expect(h.refPatches).toHaveLength(1);
    expect(h.commits).toHaveLength(1);
  });

  it('same marker but based on another branch → force-reset and recommit', async () => {
    const h = harness(await reuseWorld({ openPr: { body: marker(BATCH_IDS), baseRef: 'release' } }));
    expect(await h.run()).toBe(0);
    expect(h.commits).toHaveLength(1);
  });

  it('auto-eligible batch on a reused (unrewritten) open PR → auto-merge NOT enabled', async () => {
    const AUTO = { ...BASE_POLICY, autoShip: { critical: 'auto', high: 'auto', moderate: 'auto', low: 'approve' } };
    const h = harness(await reuseWorld({ policy: AUTO }));
    expect(await h.run()).toBe(0);
    expect(h.commits).toEqual([]);
    expect(h.autoMerges).toEqual([]);
  });

  it('auto-eligible batch on a rewritten open PR → auto-merge enabled', async () => {
    const AUTO = { ...BASE_POLICY, autoShip: { critical: 'auto', high: 'auto', moderate: 'auto', low: 'approve' } };
    const h = harness({ ...BATCH, policy: AUTO, exec: batchExec(), openPrs: [BRANCH], openPr: { body: 'old' } });
    expect(await h.run()).toBe(0);
    expect(h.commits).toHaveLength(1);
    expect(h.autoMerges).toEqual([{ id: 'OPEN', method: 'SQUASH' }]);
  });

  it('disabling auto-merge on the open PR fails → branch untouched, run fails after the issues', async () => {
    const h = harness({ ...BATCH, exec: batchExec(), openPrs: [BRANCH], openPr: { body: 'old', autoMerge: true }, disableAutoMergeFails: true });
    expect(await h.run()).toBe(1);
    expect(h.refPatches).toEqual([]);
    expect(h.commits).toEqual([]);
    expect(h.prPatches).toEqual([]);
    expect(h.log()).toMatch(/could not disable auto-merge/);
    expect(h.summary()).toMatch(/Prune:/);
  });

  it('latest closed-unmerged PR covered the same set → declined: no sync, no npm/go, no PR', async () => {
    const h = harness({ ...BATCH, exec: batchExec(), closedPrs: { [BRANCH]: `declined\n${marker(BATCH_IDS)}` } });
    expect(await h.run()).toBe(0);
    expect(h.syncs).toEqual([]);
    expect(h.exec.calls).toEqual([]);
    expect(h.prs).toEqual([]);
    expect(h.commits).toEqual([]);
    expect(h.summary()).toMatch(/Security PR: declined \(#4 closed without merging/);
  });

  it('a new advisory after a decline → a new PR for the new set (stale branch reset)', async () => {
    const h = harness({ ...BATCH, exec: batchExec(), createBranchStatus: 422, closedPrs: { [BRANCH]: marker(['npm:undici@7.29.1']) } });
    expect(await h.run()).toBe(0);
    expect(h.refPatches).toEqual([{ url: `${R}/git/refs/heads/decant/security-fixes`, body: { sha: HEAD, force: true } }]);
    expect(h.commits).toHaveLength(1);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]!.body).toContain(marker(BATCH_IDS));
  });

  it('one package unresolvable → reverted, excluded from the PR and decant.json, listed; the others still ship', async () => {
    const h = harness({ ...BATCH, exec: batchExec({ stuck: ['js-yaml'] }) });
    expect(await h.run()).toBe(0);
    // js-yaml: update did nothing, so an override was tried; still stuck → reverted
    const npm = h.exec.calls.filter((c) => c.cmd === 'npm').map((c) => c.args.filter((x) => !x.startsWith('-') && !x.startsWith('/') && !x.startsWith('http')));
    expect(npm).toEqual([['update', 'js-yaml'], ['install'], ['install', 'undici@7.30.1']]);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]!.title).toBe('decant: security fixes (2 packages, 4 advisories)');
    const files = h.written();
    expect(JSON.parse(files['package.json']!).overrides).toBeUndefined(); // the js-yaml override was reverted
    expect(JSON.parse(files['package.json']!).dependencies.undici).toBe('^7.30.1'); // undici's change kept
    const l = JSON.parse(files['package-lock.json']!);
    expect(l.packages['node_modules/undici'].version).toBe('7.30.1');
    expect(l.packages['node_modules/a/node_modules/js-yaml'].version).toBe('4.1.0');
    expect(JSON.parse(files['decant.json']!).allow.map((a: any) => a.package)).toEqual(['go:github.com/x/y@v1.0.1', 'npm:undici@7.30.1']);
    expect(h.prs[0]!.body).toMatch(/Not included[\s\S]*`js-yaml`.*unresolvable/);
    expect(h.prs[0]!.body).toContain(marker(['go:github.com/x/y@v1.0.1', 'npm:undici@7.30.1']));
    const issue = h.issueCreates.find((i) => i.title === 'decant: unfixed advisories');
    expect(issue.body).toContain(JY);
    expect(issue.body).toMatch(/unresolvable/);
    expect(h.summary()).toMatch(/js-yaml.*unresolvable/);
  });

  it('overlay rejects one entry → that package dropped, overlay retried once without it', async () => {
    const h = harness({
      ...BATCH,
      exec: batchExec(),
      sync: (policy) =>
        policy.allow.some((a: any) => a.package === 'npm:js-yaml@4.1.1')
          ? { status: 422, body: { error: `advisory not verified: npm:js-yaml@4.1.1 (${JY}: not-fixed)`, entries: [`npm:js-yaml@4.1.1 (${JY}: not-fixed)`] } }
          : { status: 200, body: { ok: true } },
    });
    expect(await h.run()).toBe(0);
    expect(h.syncs).toHaveLength(2);
    expect(h.syncs[1]!.body.policy.allow.map((a: any) => a.package)).toEqual(['go:github.com/x/y@v1.0.1', 'npm:undici@7.30.1']);
    expect(h.exec.calls.some((c) => c.args.includes('js-yaml'))).toBe(false);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]!.body).toMatch(/Not included[\s\S]*`js-yaml`.*not verified/);
    expect(h.summary()).toMatch(/js-yaml.*unverified/);
  });

  it('overlay still rejected after the retry → run fails with the server error, no PR', async () => {
    const h = harness({
      ...BATCH,
      exec: batchExec(),
      sync: (policy) => ({ status: 422, body: { error: `advisory not verified: ${policy.allow[0].package}`, entries: [`${policy.allow[0].package} (x: not-fixed)`] } }),
    });
    expect(await h.run()).toBe(1);
    expect(h.syncs).toHaveLength(2);
    expect(h.exec.calls).toEqual([]);
    expect(h.prs).toEqual([]);
    expect(h.log()).toMatch(/overlay sync HTTP 422: advisory not verified/);
    // the issue, blocks and prune steps still ran before the failure
    const issue = h.issueCreates.find((i) => i.title === 'decant: unfixed advisories');
    expect(issue.body).toContain(GO);
    expect(h.f.calls.some((c) => c.url === `${D}/api/blocks`)).toBe(true);
    expect(h.summary()).toMatch(/Security PR: failed: overlay sync HTTP 422/);
    expect(h.summary()).toMatch(/Prune: nothing expired/);
  });

  it('overlay rejected without naming entries → run fails', async () => {
    const h = harness({ ...DIRECT, syncStatus: 503, exec: npmFake() });
    expect(await h.run()).toBe(1);
    expect(h.prs).toEqual([]);
    expect(h.log()).toMatch(/overlay sync HTTP 503/);
  });

  it('decant rejects the ci token (403) on overlay sync → exit 1', async () => {
    const h = harness({ ...DIRECT, syncStatus: 403, exec: npmFake() });
    expect(await h.run()).toBe(1);
  });

  it('GHSA + CVE aliases merge into one advisory', async () => {
    const records = {
      [GHSA]: { ...npmRecord(GHSA, 'lodash', [{ introduced: '0' }, { fixed: '4.17.21' }]), aliases: ['CVE-2026-1234'] },
      'CVE-2026-1234': { ...npmRecord('CVE-2026-1234', 'lodash', [{ introduced: '0' }, { fixed: '4.17.21' }]), aliases: [GHSA] },
    };
    const h = harness({ ...DIRECT, osv: { 'lodash@4.17.20': [GHSA, 'CVE-2026-1234'] }, records, exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]!.title).toBe('decant: security fixes (1 package, 1 advisory)');
    expect(h.syncs).toHaveLength(1);
  });

  it('same package in two lockfiles → fixed in both in the one PR', async () => {
    const h = harness({
      files: {
        ...DIRECT.files,
        '/w/sub/package.json': JSON.stringify({ name: 'sub', dependencies: { lodash: '^4.17.20' } }, null, 2),
        '/w/sub/package-lock.json': lock([{ name: 'lodash', version: '4.17.20' }]),
      },
      osv: DIRECT.osv,
      records: LODASH_RECORD,
      exec: (c, fs) => {
        if (c.cmd === 'npm' && c.args.at(-1) === 'lodash@4.17.21') {
          const dir = c.opts!.cwd!;
          fs.files.set(`${dir}/package-lock.json`, lock([{ name: 'lodash', version: '4.17.21', resolved: overlayResolved('lodash', '4.17.21') }]));
        }
      },
    });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(Object.keys(h.written()).sort()).toEqual(['decant.json', 'package-lock.json', 'sub/package-lock.json']);
  });

  it('allow entry already in main decant.json → not duplicated', async () => {
    const existing = { package: 'npm:lodash@4.17.21', reason: 'adopted', added: '2026-11-18' };
    const h = harness({ ...DIRECT, policy: { ...BASE_POLICY, allow: [existing] }, exec: npmFake(), times: { 'lodash@4.17.21': '2026-11-17T00:00:00Z' } });
    expect(await h.run()).toBe(0);
    expect(h.syncs[0]!.body.policy.allow).toEqual([existing]);
    expect(Object.keys(h.written()).sort()).toEqual(['package-lock.json', 'package.json']);
  });
});

describe('audit: batch consistency', () => {
  const MIN = 'GHSA-mini-0001-aaaa';
  it("a package whose fix would undo an earlier package's fix → reverted as unresolvable; the earlier fix ships", async () => {
    const h = harness({
      files: {
        '/w/package.json': JSON.stringify({ name: 'app', dependencies: { lodash: '^4.17.20', minimist: '^1.2.5' } }, null, 2),
        '/w/package-lock.json': lock([{ name: 'lodash', version: '4.17.20' }, { name: 'minimist', version: '1.2.5' }]),
      },
      osv: { 'lodash@4.17.20': [GHSA], 'minimist@1.2.5': [MIN] },
      records: { ...LODASH_RECORD, [MIN]: npmRecord(MIN, 'minimist', [{ introduced: '0' }, { fixed: '1.2.6' }]) },
      exec: (c, fs) => {
        if (c.cmd !== 'npm' || c.args[0] !== 'install') return;
        if (c.args.at(-1) === 'lodash@4.17.21') bump(fs, '/w', 'lodash', '4.17.21');
        if (c.args.at(-1) === 'minimist@1.2.6') {
          bump(fs, '/w', 'minimist', '1.2.6');
          bump(fs, '/w', 'lodash', '4.17.20'); // drags lodash back down
        }
      },
    });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]!.title).toBe('decant: security fixes (1 package, 1 advisory)');
    const l = JSON.parse(h.written()['package-lock.json']!);
    expect(l.packages['node_modules/lodash'].version).toBe('4.17.21');
    expect(l.packages['node_modules/minimist'].version).toBe('1.2.5');
    expect(JSON.parse(h.written()['decant.json']!).allow.map((a: any) => a.package)).toEqual(['npm:lodash@4.17.21']);
    expect(h.summary()).toMatch(/minimist.*unresolvable: would regress lodash/);
  });

  it("a package whose install pulls in another package's overlay-only version → that package unresolvable and reverted; the others ship", async () => {
    const AC = 'GHSA-acrn-0001-aaaa';
    const BP = 'GHSA-bpkg-0001-aaaa';
    const CP = 'GHSA-cpkg-0001-aaaa';
    const h = harness({
      files: {
        '/w/package.json': JSON.stringify({ name: 'app', dependencies: { acorn: '^1.0.0', bpkg: '^2.0.0', cpkg: '^3.0.0' } }, null, 2),
        '/w/package-lock.json': lock([
          { name: 'acorn', version: '1.0.0' },
          { name: 'bpkg', version: '2.0.0' },
          { name: 'cpkg', version: '3.0.0' },
        ]),
      },
      osv: { 'acorn@1.0.0': [AC], 'bpkg@2.0.0': [BP], 'cpkg@3.0.0': [CP] },
      records: {
        [AC]: npmRecord(AC, 'acorn', [{ introduced: '0' }, { fixed: '1.0.1' }]),
        [BP]: npmRecord(BP, 'bpkg', [{ introduced: '0' }, { fixed: '2.0.1' }]),
        [CP]: npmRecord(CP, 'cpkg', [{ introduced: '0' }, { fixed: '3.0.1' }]),
      },
      exec: (c, fs) => {
        if (c.cmd !== 'npm' || c.args[0] !== 'install') return;
        const spec = c.args.at(-1)!;
        if (spec === 'acorn@1.0.1') bump(fs, '/w', 'acorn', '1.0.1');
        if (spec === 'bpkg@2.0.1') {
          bump(fs, '/w', 'bpkg', '2.0.1');
          bump(fs, '/w', 'cpkg', '3.0.1', 'node_modules/bpkg/node_modules/cpkg'); // cpkg's overlay-only fix, before cpkg ships
        }
        if (spec === 'cpkg@3.0.1') bump(fs, '/w', 'cpkg', '3.0.1');
      },
    });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]!.title).toBe('decant: security fixes (2 packages, 2 advisories)');
    const l = JSON.parse(h.written()['package-lock.json']!);
    expect(l.packages['node_modules/acorn'].version).toBe('1.0.1');
    expect(l.packages['node_modules/bpkg'].version).toBe('2.0.0');
    expect(l.packages['node_modules/bpkg/node_modules/cpkg']).toBeUndefined();
    expect(l.packages['node_modules/cpkg'].version).toBe('3.0.1');
    expect(JSON.parse(h.written()['decant.json']!).allow.map((a: any) => a.package)).toEqual(['npm:acorn@1.0.1', 'npm:cpkg@3.0.1']);
    expect(h.prs[0]!.body).toMatch(/Not included[\s\S]*`bpkg`.*unresolvable: pulls in overlay-only npm:cpkg@3\.0\.1/);
    expect(h.summary()).toMatch(/bpkg.*unresolvable: pulls in overlay-only npm:cpkg@3\.0\.1/);
  });

  it('pulling in the overlay-only version of a package that then fails → that package reverted, nothing ships', async () => {
    const AC = 'GHSA-acrn-0001-aaaa';
    const BP = 'GHSA-bpkg-0001-aaaa';
    const h = harness({
      files: {
        '/w/package.json': JSON.stringify({ name: 'app', dependencies: { acorn: '^1.0.0' } }, null, 2),
        '/w/package-lock.json': lock([{ name: 'acorn', version: '1.0.0' }]),
        '/w/sub/package.json': JSON.stringify({ name: 'sub', dependencies: { bpkg: '^2.0.0' } }, null, 2),
        '/w/sub/package-lock.json': lock([{ name: 'bpkg', version: '2.0.0' }]),
      },
      osv: { 'acorn@1.0.0': [AC], 'bpkg@2.0.0': [BP] },
      records: { [AC]: npmRecord(AC, 'acorn', [{ introduced: '0' }, { fixed: '1.0.1' }]), [BP]: npmRecord(BP, 'bpkg', [{ introduced: '0' }, { fixed: '2.0.1' }]) },
      exec: (c, fs) => {
        if (c.cmd !== 'npm') return;
        if (c.args.at(-1) === 'acorn@1.0.1') {
          bump(fs, '/w', 'acorn', '1.0.1');
          bump(fs, '/w', 'bpkg', '2.0.1', 'node_modules/acorn/node_modules/bpkg'); // pulled in via the overlay
          return;
        }
        if (c.args.at(-1) === 'bpkg@2.0.1') return { code: 1, stderr: 'E500' };
      },
    });
    expect(await h.run()).toBe(0);
    expect(h.prs).toEqual([]);
    expect(h.commits).toEqual([]);
    expect(h.summary()).toMatch(/acorn.*unresolvable: pulls in overlay-only npm:bpkg@2\.0\.1/);
    expect(h.fs.files.get('/w/package-lock.json')).toBe(h.original.get('/w/package-lock.json'));
  });
});

describe('audit: PR lookups', () => {
  it('open-PR lookup fails (non-auth) → run fails visibly after the issues, no PR', async () => {
    const h = harness({ ...BATCH, exec: batchExec(), pullsStatus: { open: 500 } });
    expect(await h.run()).toBe(1);
    expect(h.syncs).toEqual([]);
    expect(h.prs).toEqual([]);
    expect(h.log()).toMatch(/::error::decant audit: looking up the open security PR: .*HTTP 500/);
    expect(h.summary()).toMatch(/Security PR: failed: looking up the open security PR/);
  });

  it('closed-PR lookup fails (non-auth) → run fails visibly, no PR', async () => {
    const h = harness({ ...BATCH, exec: batchExec(), pullsStatus: { closed: 502 } });
    expect(await h.run()).toBe(1);
    expect(h.prs).toEqual([]);
    expect(h.commits).toEqual([]);
    expect(h.log()).toMatch(/looking up the closed security PR: .*HTTP 502/);
  });
});

describe('audit: auto-merge rules', () => {
  const AUTO_POLICY = { ...BASE_POLICY, autoShip: { critical: 'auto', high: 'auto', moderate: 'auto', low: 'approve' } };

  it('every severity auto and no major bump → auto-merge on', async () => {
    const h = harness({ ...BATCH, policy: AUTO_POLICY, exec: batchExec() });
    expect(await h.run()).toBe(0);
    expect(h.autoMerges).toEqual([{ id: 'PR_10', method: 'SQUASH' }]);
    expect(h.prs[0]!.body).toMatch(/auto-merge is on/);
  });

  it("any severity 'approve' → off, body names it", async () => {
    const h = harness({ ...DIRECT, policy: { ...BASE_POLICY, autoShip: { high: 'approve' } }, exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.autoMerges).toEqual([]);
    expect(h.prs[0]!.body).toMatch(/autoShip\.high is `approve`/);
  });

  it('a bump crossing a major line → off, body says so', async () => {
    const h = harness({
      ...BATCH,
      policy: AUTO_POLICY,
      records: { ...BATCH_RECORDS, [GO]: goRecord('CRITICAL', '2.0.0') },
      exec: (c, fs) => {
        if (c.cmd === 'go' && c.args[0] === 'get') {
          fs.files.set('/w/go.mod', GO_MOD.replace('v1.0.0', 'v2.0.0'));
          fs.files.set('/w/go.sum', 'github.com/x/y v2.0.0 h1:new=\ngithub.com/x/y v2.0.0/go.mod h1:new2=\n');
          return;
        }
        return batchExec()(c, fs);
      },
    });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.autoMerges).toEqual([]);
    expect(h.prs[0]!.body).toMatch(/major upgrade.*github\.com\/x\/y/);
  });

  it('auto-merge refused by GitHub → warning, PR stays open, exit 0', async () => {
    const h = harness({ ...DIRECT, autoMergeFails: true, exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.log()).toMatch(/::warning::.*auto-merge/);
  });
});

describe('audit: npm fixes', () => {
  it('transitive dep npm update cannot lift → override added and install rerun', async () => {
    const h = harness({ ...TRANSITIVE, exec: npmFake({ update: 'noop', overrideFixes: true }) });
    expect(await h.run()).toBe(0);
    const npm = h.exec.calls.filter((c) => c.cmd === 'npm').map((c) => c.args.filter((x) => !x.startsWith('-') && !x.startsWith('/') && !x.startsWith('http')));
    expect(npm).toEqual([['update', 'lodash'], ['install']]);
    for (const c of h.exec.calls) expect(c.args).toContain('--ignore-scripts');
    const files = h.written();
    expect(JSON.parse(files['package.json']!).overrides).toEqual({ 'lodash@^4': '4.17.21' });
    expect(files['package-lock.json']).toContain('https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz');
    expect(h.prs).toHaveLength(1);
  });

  it('transitive dep that npm update lifts → no override', async () => {
    const h = harness({ ...TRANSITIVE, exec: npmFake({ update: 'fixes' }) });
    expect(await h.run()).toBe(0);
    expect(h.exec.calls.map((c) => c.args[0])).toEqual(['update']);
    expect(Object.keys(h.written())).not.toContain('package.json');
  });

  it('still unresolved after the override → recorded, no PR, files restored', async () => {
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
    expect([...h.fs.files.keys()].some((k) => k.startsWith('/rt/'))).toBe(false);
  });

  it('two major lines → per-line override keys, both fixed, one allow entry per fixed version', async () => {
    const records = {
      [GHSA]: {
        ...npmRecord(GHSA, 'lodash', []),
        affected: [
          {
            package: { ecosystem: 'npm', name: 'lodash' },
            ranges: [
              { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.10.1' }] },
              { type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.17.21' }] },
            ],
          },
        ],
      },
    };
    const h = harness({
      files: {
        '/w/package.json': JSON.stringify({ name: 'app', dependencies: { a: '^1.0.0', b: '^1.0.0' } }, null, 2),
        '/w/package-lock.json': lock([
          { name: 'a', version: '1.0.0' },
          { name: 'b', version: '1.0.0' },
          { name: 'lodash', version: '3.10.0', path: 'node_modules/a/node_modules/lodash' },
          { name: 'lodash', version: '4.17.20', path: 'node_modules/b/node_modules/lodash' },
        ]),
      },
      osv: { 'lodash@3.10.0': [GHSA], 'lodash@4.17.20': [GHSA] },
      records,
      exec: (c, fs) => {
        if (c.cmd !== 'npm' || c.args[0] !== 'install') return;
        const o = JSON.parse(fs.files.get('/w/package.json')!).overrides ?? {};
        if (o['lodash@^3'] === '3.10.1' && o['lodash@^4'] === '4.17.21') {
          fs.files.set(
            '/w/package-lock.json',
            lock([
              { name: 'a', version: '1.0.0' },
              { name: 'b', version: '1.0.0' },
              { name: 'lodash', version: '3.10.1', path: 'node_modules/a/node_modules/lodash' },
              { name: 'lodash', version: '4.17.21', path: 'node_modules/b/node_modules/lodash' },
            ]),
          );
        }
      },
    });
    expect(await h.run()).toBe(0);
    expect(JSON.parse(h.written()['package.json']!).overrides).toEqual({ 'lodash@^3': '3.10.1', 'lodash@^4': '4.17.21' });
    expect(h.syncs[0]!.body.policy.allow.map((a: any) => a.package)).toEqual(['npm:lodash@3.10.1', 'npm:lodash@4.17.21']);
    expect(JSON.parse(h.written()['decant.json']!).allow).toHaveLength(2);
    expect(h.prs[0]!.body).toMatch(/\| `lodash` \| 3\.10\.0, 4\.17\.20 → 3\.10\.1, 4\.17\.21 \|/);
    expect(h.prs[0]!.body).toContain(marker(['npm:lodash@3.10.1', 'npm:lodash@4.17.21']));
    expect(h.autoMerges).toHaveLength(1);
  });

  it('overrideKey uses ^major, or ~0.minor for 0.x', async () => {
    const { overrideKey } = await import('../src/modes/audit');
    expect(overrideKey('x', '1.2.3')).toBe('x@^1');
    expect(overrideKey('@s/x', '0.3.1')).toBe('@s/x@~0.3');
  });

  it("OSV fixed 'file:../x' → treated as unfixed (invalid fixed version), no PR", async () => {
    const h = harness({ ...DIRECT, records: { [GHSA]: npmRecord(GHSA, 'lodash', [{ introduced: '0' }, { fixed: 'file:../x' }]) }, exec: npmFake() });
    expect(await h.run()).toBe(0);
    expect(h.syncs).toEqual([]);
    expect(h.prs).toEqual([]);
    const issue = h.issueCreates.find((i) => i.title === 'decant: unfixed advisories');
    expect(issue.body).toContain('invalid fixed version');
  });

  it('package name starting with - → recorded failed, nothing executed', async () => {
    const h = harness({
      files: { '/w/package.json': '{}', '/w/package-lock.json': lock([{ name: '-evil', version: '1.0.0' }]) },
      osv: { '-evil@1.0.0': [GHSA] },
      records: { [GHSA]: npmRecord(GHSA, '-evil', [{ introduced: '0' }, { fixed: '1.0.1' }]) },
    });
    expect(await h.run()).toBe(0);
    expect(h.exec.calls).toEqual([]);
    expect(h.syncs).toEqual([]);
    expect(h.summary()).toMatch(/failed: invalid package name/);
  });
});

describe('audit: guards', () => {
  it('non-default ref → exit 1, no writes', async () => {
    const h = harness({ ...DIRECT, ref: 'refs/heads/feature', exec: npmFake() });
    expect(await h.run()).toBe(1);
    expect(h.log()).toMatch(/runs on the default branch \(main\)/);
    expect(h.syncs).toEqual([]);
    expect(h.exec.calls).toEqual([]);
    expect(h.branches).toEqual([]);
  });

  it('default branch moved since checkout → exit 1', async () => {
    const h = harness({ ...DIRECT, mainHead: 'f'.repeat(40), exec: npmFake() });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('default branch moved since checkout; re-run');
    expect(h.syncs).toEqual([]);
    expect(h.branches).toEqual([]);
  });

  it('RUNNER_TEMP unset → exit 1', async () => {
    const h = harness({ ...DIRECT, env: { RUNNER_TEMP: undefined }, exec: npmFake() });
    expect(await h.run()).toBe(1);
    expect(h.log()).toMatch(/RUNNER_TEMP/);
  });

  it('without DECANT_GITHUB_LOGIN, an App-bot issue of ours is matched and closed', async () => {
    const h = harness({
      files: { '/w/package.json': '{}', '/w/package-lock.json': lock([{ name: 'ok', version: '1.0.0' }]) },
      issues: [{ number: 9, title: 'decant: unfixed advisories', user: { login: 'decant-app[bot]', type: 'Bot' } }],
    });
    expect(await h.run()).toBe(0);
    expect(h.issuePatches).toEqual([{ n: 9, body: { state: 'closed', state_reason: 'completed' } }]);
  });
});

describe('audit: Go', () => {
  it('runs go get + go mod tidy with GOPROXY at the audit overlay and no token in the env', async () => {
    let netrc: { text?: string; mode?: number } = {};
    const h = harness({
      files: { '/w/go.mod': GO_MOD, '/w/go.sum': GO_SUM },
      osv: { 'github.com/x/y@1.0.0': [GO] },
      records: { [GO]: goRecord() },
      exec: (c, fs) => {
        if (c.cmd !== 'go') return;
        netrc = { text: fs.files.get(c.opts!.env!.NETRC!), mode: fs.modes.get(c.opts!.env!.NETRC!) };
        return batchExec()(c, fs);
      },
    });
    expect(await h.run()).toBe(0);
    const go = h.exec.calls.filter((c) => c.cmd === 'go');
    expect(go.map((c) => c.args)).toEqual([['get', '--', 'github.com/x/y@v1.0.1'], ['mod', 'tidy']]);
    for (const c of go) {
      expect(c.opts?.cwd).toBe('/w');
      expect(c.opts?.env?.GOPROXY).toBe(`${D}/r/audit/go`);
      expect(c.opts?.env?.GOFLAGS).toBe('-mod=mod');
      expect(c.opts?.env?.NETRC).toMatch(/^\/rt\/decant-audit-\w+\/[0-9a-f-]{36}\.netrc$/);
      expect(c.opts?.env?.GOSUMDB).toBeUndefined();
      expect(JSON.stringify(c)).not.toContain('ci-secret');
    }
    expect(netrc).toEqual({ text: 'machine decant.example login decant password ci-secret\n', mode: 0o600 });
    expect([...h.fs.files.keys()].some((k) => k.startsWith('/rt/'))).toBe(false);
    expect(h.syncs[0]!.body.policy.allow[0]).toEqual({ package: 'go:github.com/x/y@v1.0.1', advisory: GO, reason: 'security fix', added: '2026-11-19' });
    expect(Object.keys(h.written()).sort()).toEqual(['decant.json', 'go.mod', 'go.sum']);
    expect(h.prs[0]).toMatchObject({ head: BRANCH, title: 'decant: security fixes (1 package, 1 advisory)' });
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
    expect(h.prPatches.map((p) => p.n)).toEqual([3]);
    expect(h.prs).toEqual([]);
    expect(h.commits[0]!.branch.branchName).toBe('decant/prune');
    expect(h.commits[0]!.expectedHeadOid).toBe('d'.repeat(40));
  });

  it('prune GitHub failure (non-auth) → recorded, exit 0', async () => {
    const h = harness({ ...PRUNE, createBranchStatus: 500 });
    expect(await h.run()).toBe(0);
    expect(h.summary()).toMatch(/Prune: failed: .*HTTP 500/);
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

describe('audit: base images', () => {
  const OLD = `sha256:${'1'.repeat(64)}`;
  const NEW = `sha256:${'2'.repeat(64)}`;
  const NODE = 'docker.io/library/node';
  const match = (id: string, severity: string, fixed: string[]) => ({
    vulnerability: { id, severity, fix: fixed.length ? { state: 'fixed', versions: fixed } : { state: 'not-fixed', versions: [] } },
    artifact: { name: 'openssl', version: '3.0', type: 'deb' },
  });
  type ImgWorld = { decision?: Record<string, unknown>; grype?: Record<string, unknown[]>; tag?: string | null };
  function world(o: ImgWorld = {}, extra: Partial<World> = {}): { w: World; posts: unknown[]; verdicts: { package: string; result: string }[] } {
    const posts: unknown[] = [];
    const verdicts: { package: string; result: string }[] = [];
    const w: World = {
      files: { '/w/Dockerfile': `# a comment\nFROM node:22@${OLD} AS build\nRUN true\nFROM build\n`, '/w/package-lock.json': lock([]) },
      extraFetch: (c) => {
        const u = new URL(c.url);
        if (c.url === `${D}/api/images`) {
          const b = JSON.parse(c.body!);
          posts.push(b);
          return jsonRes({
            cooldownDays: 7,
            images: b.images.map((i: { name: string; digest: string }) => ({
              name: i.name, digest: i.digest, clock: 'shared', firstSeen: '2026-11-01T00:00:00.000Z', eligibleAt: '2026-11-08T00:00:00.000Z',
              decision: 'allow', allowed: false, blocks: [], ...o.decision,
            })),
          });
        }
        if (c.url === `${D}/api/verdicts` && c.method === 'PUT') {
          verdicts.push(JSON.parse(c.body!));
          return new Response(null, { status: 204 });
        }
        if (u.host === 'auth.docker.io') return jsonRes({ token: 't' });
        if (u.host === 'registry-1.docker.io') {
          return o.tag === null ? new Response('', { status: 404 }) : new Response(null, { headers: { 'docker-content-digest': o.tag ?? NEW } });
        }
        return undefined;
      },
      exec: (c) => {
        if (c.cmd === '/rt/decant-grype/grype') {
          const target = c.args[0]!.replace(/^registry:docker\.io\/library\/node@/, '');
          return { stdout: JSON.stringify({ matches: o.grype?.[target] ?? [] }) };
        }
      },
      ...extra,
    };
    return { w, posts, verdicts };
  }

  it('a newer digest past cooldown that fixes a Critical → bumped in the one security PR, verdicts stored', async () => {
    const { w, posts, verdicts } = world({ grype: { [OLD]: [match('CVE-2026-1', 'Critical', ['3.1']), match('CVE-2026-2', 'High', [])], [NEW]: [match('CVE-2026-2', 'High', [])] } });
    const h = harness(w);
    expect(await h.run()).toBe(0);
    expect(posts).toEqual([{ ref: 'audit-images', images: [{ name: NODE, digest: NEW }], mainOnly: true }]);
    expect(verdicts.map((v) => [v.package, v.result])).toEqual([
      [`docker:${NODE}@${OLD}`, 'flagged'],
      [`docker:${NODE}@${NEW}`, 'flagged'],
    ]);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]).toMatchObject({ head: BRANCH, title: 'decant: security fixes (1 image, 1 advisory)' });
    const body = h.prs[0]!.body as string;
    expect(body).toContain('| `docker.io/library/node:22` | sha256:111111111111 → sha256:222222222222 | [CVE-2026-1](https://osv.dev/vulnerability/CVE-2026-1) | critical |');
    expect(body).toContain(marker([`docker:${NODE}@${NEW}`]));
    expect(h.written()).toEqual({ Dockerfile: `# a comment\nFROM node:22@${NEW} AS build\nRUN true\nFROM build\n` });
    expect(h.labels).toEqual([{ n: 10, labels: ['decant:security', 'decant:critical'] }]);
    expect(h.syncs).toEqual([]); // no overlay: image bumps need no allow entry
    expect(h.summary()).toContain('bump fixes CVE-2026-1');
  });

  it('a bump that would introduce a new High/Critical is refused, and the summary says why', async () => {
    const { w } = world({ grype: { [OLD]: [match('CVE-2026-1', 'Critical', ['3.1'])], [NEW]: [match('CVE-2026-5', 'High', ['9'])] } });
    const h = harness(w);
    expect(await h.run()).toBe(0);
    expect(h.prs).toEqual([]);
    expect(h.summary()).toContain('would introduce CVE-2026-5 (high); not bumped');
  });

  it('lower-severity findings a bump introduces are listed in the PR and count toward approval', async () => {
    const { w } = world({ grype: { [OLD]: [match('CVE-2026-1', 'High', ['3.1'])], [NEW]: [match('CVE-2026-6', 'Medium', [])] } });
    const h = harness(w);
    expect(await h.run()).toBe(0);
    const body = h.prs[0]!.body as string;
    expect(body).toContain('**Introduced by the new digests**');
    expect(body).toContain('[CVE-2026-6](https://osv.dev/vulnerability/CVE-2026-6) (moderate) in `openssl` 3.0');
    expect(body).toContain('autoShip.moderate is `approve`');
    expect(h.autoMerges).toEqual([]);
  });

  it('the newer digest is still in cooldown → no PR, summary says when', async () => {
    const { w } = world({ decision: { decision: 'cooldown', eligibleAt: '2026-11-25T00:00:00.000Z' }, grype: { [OLD]: [match('CVE-2026-1', 'Critical', ['3.1'])] } });
    const h = harness(w);
    expect(await h.run()).toBe(0);
    expect(h.prs).toEqual([]);
    expect(h.summary()).toContain('newer digest waiting (cooldown until 2026-11-25)');
  });

  it('a newer digest that fixes nothing High/Critical is not proposed; an up-to-date tag is just re-scanned', async () => {
    const { w } = world({ grype: { [OLD]: [match('CVE-2026-9', 'Medium', ['1'])] } });
    const h = harness(w);
    expect(await h.run()).toBe(0);
    expect(h.prs).toEqual([]);
    expect(h.summary()).toContain('fixes no High/Critical finding; not bumped');
    const same = world({ tag: OLD });
    const h2 = harness(same.w);
    expect(await h2.run()).toBe(0);
    expect(same.posts).toEqual([]);
    expect(same.verdicts).toHaveLength(1);
    expect(h2.summary()).toContain('clean; up to date');
  });

  it('npm fixes and image bumps share the one security PR and its set marker', async () => {
    const { w } = world({ grype: { [OLD]: [match('CVE-2026-1', 'High', ['3.1'])] } });
    const merged: World = {
      ...DIRECT,
      files: { ...DIRECT.files, '/w/Dockerfile': `FROM node:22@${OLD}\n` },
      exec: (c, fs) => (c.cmd === '/rt/decant-grype/grype' ? w.exec!(c, fs) : npmFake()(c, fs)),
      extraFetch: w.extraFetch,
    };
    const h = harness(merged);
    expect(await h.run()).toBe(0);
    expect(h.prs).toHaveLength(1);
    expect(h.prs[0]!.title).toBe('decant: security fixes (1 package, 1 image, 2 advisories)');
    expect(h.prs[0]!.body).toContain(marker(['npm:lodash@4.17.21', `docker:${NODE}@${NEW}`]));
    expect(Object.keys(h.written()).sort()).toEqual(['Dockerfile', 'decant.json', 'package-lock.json', 'package.json']);
  });
});
