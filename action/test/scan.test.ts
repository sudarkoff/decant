import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { actionDir, requirementsPath } from '../src/guarddog';
import { run } from '../src/main';
import { fakeDeps, fakeExec, fakeFetch, jsonRes, memFs, type ExecCall, type FetchCall } from './fakes';

afterEach(() => vi.restoreAllMocks());

const TOKEN = 'ci-secret-tok';
const GH = 'ghs_secret';
const D = 'https://decant.example';
const R = 'https://api.github.com/repos/o/r';
const BASE = 'a'.repeat(40);
const BOT = { login: 'github-actions[bot]', type: 'Bot' };

type LockPkg = { name: string; version: string; resolved?: string; integrity?: string };

function lock(pkgs: LockPkg[]): string {
  const packages: Record<string, unknown> = { '': { name: 'app', version: '1.0.0' } };
  for (const p of pkgs) {
    const base = p.name.slice(p.name.lastIndexOf('/') + 1);
    packages[`node_modules/${p.name}`] = {
      version: p.version,
      resolved: p.resolved ?? `https://registry.npmjs.org/${p.name}/-/${base}-${p.version}.tgz`,
      integrity: p.integrity ?? `sha512-${p.name}${p.version}`,
    };
  }
  return JSON.stringify({ name: 'app', lockfileVersion: 3, packages }, null, 2);
}

const LP = { name: 'left-pad', version: '1.3.0' };

type World = {
  head: string;
  base: string | null;
  verdicts?: Record<string, { scanner: string; result: string; scannerVersion?: string; details?: unknown }[]>;
  osv?: Record<string, { id: string; severity?: string }[]>;
  download?: 'ok' | 'cooldown' | 'blocked';
  guarddog?: Record<string, unknown>;
  labels?: string[];
  labeler?: { login: string; permission: string };
  token?: string;
  fork?: boolean;
  action?: string;
  failOn?: string;
  extraFiles?: Record<string, string>;
  publish?: string;
  symlinks?: string[];
  changes?: Record<string, unknown>;
  blocks?: { package: string; source: string; reason: string; at: string }[];
  osvStatus?: number;
  priorComment?: boolean;
  autoMerge?: boolean;
  python?: string;
  gdExit?: { code: number; stderr: string };
};

function harness(w: World) {
  const d = mkdtempSync(join(tmpdir(), 'decant-scan-'));
  const summary = join(d, 'summary');
  const output = join(d, 'output');
  writeFileSync(summary, '');
  writeFileSync(output, '');
  const payload = {
    action: w.action ?? 'opened',
    ...(w.changes ? { changes: w.changes } : {}),
    pull_request: { number: 7, base: { sha: BASE }, head: { sha: 'b'.repeat(40), repo: { full_name: w.fork ? 'evil/r' : 'o/r' } } },
    repository: { full_name: 'o/r', default_branch: 'main' },
  };
  const realReq = requirementsPath(actionDir(undefined));
  const req = readFileSync(realReq, 'utf8');
  const files: Record<string, string> = {
    '/ev.json': JSON.stringify(payload),
    '/w/package-lock.json': w.head,
    '/act/guarddog-requirements.txt': req,
    [realReq]: req,
    ...w.extraFiles,
  };
  const fs = memFs(files, w.symlinks ?? []);
  const labels = [...(w.labels ?? [])];
  const puts: unknown[] = [];
  const comments: string[] = [];
  const removed: string[] = [];
  const patched: string[] = [];
  const graphql: { query: string; variables: Record<string, unknown> }[] = [];
  const f = fakeFetch((c: FetchCall) => {
    const u = new URL(c.url);
    const key = `${c.method} ${c.url}`;
    if (key.startsWith(`GET ${D}/api/verdicts?`)) {
      const pkg = u.searchParams.get('package')!;
      return jsonRes({ verdicts: (w.verdicts?.[pkg] ?? []).map((v) => ({ package: pkg, scannerVersion: 'x', ...v })) });
    }
    if (key === `GET ${D}/api/blocks`) return jsonRes({ blocks: w.blocks ?? [] });
    if (key === `PUT ${D}/api/verdicts`) {
      puts.push(JSON.parse(c.body!));
      return new Response(null, { status: 204 });
    }
    if (c.method === 'GET' && u.origin === D && /^\/r\/pr-7\/npm\/[^/]+$/.test(u.pathname)) {
      const name = decodeURIComponent(u.pathname.split('/').pop()!);
      const dl = w.download ?? 'ok';
      if (dl === 'cooldown') return new Response(`${name}@x is not available: in cooldown`, { status: 404 });
      if (dl === 'blocked') return new Response(`${name}@x is not available: blocked`, { status: 404 });
      const base = name.slice(name.lastIndexOf('/') + 1);
      return jsonRes({ versions: { '1.3.0': { dist: { tarball: `${D}/r/pr-7/npm/${name}/-/${base}-1.3.0.tgz` } } } });
    }
    if (c.method === 'GET' && u.origin === D && u.pathname.endsWith('.tgz')) return new Response(new Uint8Array([1, 2, 3]));
    if (key === 'POST https://api.osv.dev/v1/querybatch') {
      if (w.osvStatus) return new Response('upstream down', { status: w.osvStatus });
      const qs = (JSON.parse(c.body!) as { queries: { package: { name: string }; version: string }[] }).queries;
      return jsonRes({ results: qs.map((q) => ({ vulns: (w.osv?.[`${q.package.name}@${q.version}`] ?? []).map((v) => ({ id: v.id })) })) });
    }
    if (c.method === 'GET' && c.url.startsWith('https://api.osv.dev/v1/vulns/')) {
      const id = decodeURIComponent(c.url.split('/').pop()!);
      const v = Object.values(w.osv ?? {})
        .flat()
        .find((x) => x.id === id)!;
      return jsonRes({ id, summary: `summary of ${id}`, database_specific: v.severity ? { severity: v.severity } : {} });
    }
    if (c.method === 'GET' && c.url.startsWith('https://registry.npmjs.org/')) {
      return jsonRes({ time: { '1.3.0': w.publish ?? '2026-11-15T10:00:00.000Z' } });
    }
    if (key === `GET ${R}/issues/7/labels?per_page=100`) return jsonRes(labels.map((name) => ({ name })));
    if (c.method === 'DELETE' && c.url.startsWith(`${R}/issues/7/labels/`)) {
      const name = decodeURIComponent(c.url.split('/').pop()!);
      removed.push(name);
      labels.splice(labels.indexOf(name), 1);
      return jsonRes([]);
    }
    if (key === `GET ${R}/issues/7/timeline?per_page=100`) {
      return jsonRes(w.labeler ? [{ event: 'labeled', label: { name: 'decant:reviewed' }, actor: { login: w.labeler.login } }] : []);
    }
    if (c.method === 'GET' && c.url.startsWith(`${R}/collaborators/`)) return jsonRes({ permission: w.labeler?.permission ?? 'read' });
    if (key === `GET ${R}/issues/7/comments?per_page=100`) {
      return jsonRes(w.priorComment ? [{ id: 42, body: '<!-- decant-scan -->\n## decant scan: ❌ fail', user: BOT }] : []);
    }
    if (key === `PATCH ${R}/issues/comments/42`) {
      patched.push((JSON.parse(c.body!) as { body: string }).body);
      return jsonRes({ id: 42 });
    }
    if (key === `GET ${R}/pulls/7`) {
      return jsonRes({
        number: 7, node_id: 'PR_node7', title: 't', body: '', state: 'open',
        labels: labels.map((name) => ({ name })),
        head: { ref: 'fix', sha: 'b'.repeat(40) }, base: { ref: 'main', sha: BASE },
        auto_merge: w.autoMerge ? { merge_method: 'squash' } : null,
      });
    }
    if (key === 'POST https://api.github.com/graphql') {
      graphql.push(JSON.parse(c.body!));
      return jsonRes({ data: { disablePullRequestAutoMerge: { clientMutationId: null } } });
    }
    if (key === `POST ${R}/issues/7/comments`) {
      comments.push((JSON.parse(c.body!) as { body: string }).body);
      return jsonRes({ id: 1 }, 201);
    }
    return undefined;
  });
  const gdOut = w.guarddog ?? { package: 'x', results: { 'threat-npm-preinstall-script': {} }, errors: {}, issues: 0, risks: [] };
  const exec = fakeExec((c: ExecCall) => {
    if (c.cmd === 'git') {
      return w.base === null ? { code: 128, stderr: `fatal: path 'package-lock.json' exists on disk, but not in '${BASE}'` } : { stdout: w.base };
    }
    if (c.cmd.endsWith('/bin/guarddog')) return w.gdExit ?? { stdout: JSON.stringify(gdOut) };
    if (c.args[0] === '-c') return { stdout: `${w.python ?? '3.12'}\n` };
    return {};
  });
  const env: Record<string, string> = {
    INPUT_MODE: 'scan',
    INPUT_DECANT_URL: `${D}/`,
    INPUT_TOKEN: w.token ?? TOKEN,
    INPUT_GITHUB_TOKEN: GH,
    INPUT_WORKING_DIRECTORY: '/w',
    INPUT_POLICY_PATH: 'decant.json',
    INPUT_FAIL_ON: w.failOn ?? 'high',
    GITHUB_EVENT_NAME: 'pull_request',
    GITHUB_EVENT_PATH: '/ev.json',
    GITHUB_REPOSITORY: 'o/r',
    GITHUB_STEP_SUMMARY: summary,
    GITHUB_OUTPUT: output,
    RUNNER_TEMP: '/rt',
    GITHUB_ACTION_PATH: '/act',
  };
  const out: string[] = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stdout.write);
  vi.spyOn(process.stderr, 'write').mockImplementation(((s: string) => (out.push(String(s)), true)) as typeof process.stderr.write);
  const deps = fakeDeps({ env, fetch: f, exec, fs });
  return {
    env,
    run: () => run(deps),
    f,
    exec,
    fs,
    puts,
    comments,
    removed,
    patched,
    graphql,
    log: () => out.join(''),
    summary: () => readFileSync(summary, 'utf8'),
    outputs: () => readFileSync(output, 'utf8'),
  };
}

const flaggedGd = {
  package: 'x',
  results: { 'threat-npm-preinstall-script': [{ location: 'package/package.json:5', message: 'preinstall' }] },
  errors: {},
  issues: 1,
  risks: [],
};

describe('scan', () => {
  it('fork PR with an empty token and no lockfile change: notice, exit 0, no network calls', async () => {
    const h = harness({ head: lock([LP]), base: lock([LP]), token: '', fork: true });
    expect(await h.run()).toBe(0);
    expect(h.log()).toContain('::notice::fork PR changes no lockfile; nothing to scan');
    expect(h.f.calls).toEqual([]);
    expect(h.exec.calls.map((c) => c.cmd)).toEqual(['git']);
    expect(h.outputs()).toMatch(/result<<\S+\npass\n/);
  });

  it('fork PR with an empty token that changes a lockfile fails: push the branch to this repo', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), token: '', fork: true });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('fork changes lockfiles (package-lock.json); push the branch to this repo to scan it');
    expect(h.f.calls).toEqual([]);
    expect(h.outputs()).toMatch(/result<<\S+\nfail\n/);
  });

  it('fork PR adding a new lockfile (absent at base) fails', async () => {
    const h = harness({ head: lock([LP]), base: null, token: '', fork: true });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('fork changes lockfiles');
  });

  it('fork PR with a symlinked lockfile fails', async () => {
    const h = harness({ head: lock([LP]), base: lock([LP]), token: '', fork: true, extraFiles: { '/w/sub/package-lock.json': lock([]) }, symlinks: ['/w/sub'] });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('fork changes lockfiles (sub)');
  });

  it('flagged + decant:security: disables auto-merge and says so; check still passes with decant:reviewed', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      guarddog: flaggedGd,
      labels: ['decant:security', 'decant:high', 'decant:reviewed'],
      labeler: { login: 'maint', permission: 'write' },
      autoMerge: true,
    });
    expect(await h.run()).toBe(0);
    expect(h.graphql).toHaveLength(1);
    expect(h.graphql[0]!.query).toContain('disablePullRequestAutoMerge');
    expect(h.graphql[0]!.variables).toEqual({ id: 'PR_node7' });
    expect(h.log()).toContain('auto-merge disabled');
    expect(h.comments[0]).toContain('**Auto-merge is off:**');
    expect(h.summary()).toContain('**Auto-merge is off:**');
  });

  it('flagged + decant:security without auto-merge on: no mutation, report still says merge manually', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), guarddog: flaggedGd, labels: ['decant:security'] });
    expect(await h.run()).toBe(1);
    expect(h.graphql).toEqual([]);
    expect(h.comments[0]).toContain('**Auto-merge is off:**');
  });

  it('flagged without decant:security leaves auto-merge alone', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), guarddog: flaggedGd, autoMerge: true });
    expect(await h.run()).toBe(1);
    expect(h.graphql).toEqual([]);
    expect(h.f.calls.some((c) => c.url === `${R}/pulls/7`)).toBe(false);
  });

  it('decant:security but nothing flagged leaves auto-merge alone', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), labels: ['decant:security'], autoMerge: true });
    expect(await h.run()).toBe(0);
    expect(h.graphql).toEqual([]);
    expect(h.comments[0]).not.toContain('Auto-merge is off');
  });

  it('same-repo PR with an empty token fails', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), token: '' });
    expect(await h.run()).toBe(1);
  });

  it('a changed lockfile with decant URLs fails with the sed hint', async () => {
    const head = lock([{ ...LP, resolved: `${D}/r/pr-7/npm/left-pad/-/left-pad-1.3.0.tgz` }]);
    const h = harness({ head, base: lock([]) });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain(
      `run: sed -i.bak -E 's#${D}(/r/[^/]+)?/npm/#https://registry.npmjs.org/#g' '/w/package-lock.json' && rm '/w/package-lock.json.bak'`,
    );
  });

  it('added left-pad with clean OSV and GuardDog passes, puts two verdicts, upserts one comment', async () => {
    const h = harness({ head: lock([LP]), base: lock([]) });
    expect(await h.run()).toBe(0);
    expect(h.puts).toEqual([
      expect.objectContaining({ package: 'npm:left-pad@1.3.0', scanner: 'osv', result: 'clean' }),
      expect.objectContaining({ package: 'npm:left-pad@1.3.0', scanner: 'guarddog', scannerVersion: '3.2.0', result: 'clean' }),
    ]);
    expect(h.comments).toHaveLength(1);
    expect(h.comments[0]).toContain('<!-- decant-scan -->');
    expect(h.comments[0]).toContain('| Package | Source | OSV | GuardDog | Vulns | Status |');
    expect(h.comments[0]).toContain('left-pad@1.3.0');
    expect(h.summary()).toContain('| Package | Source | OSV | GuardDog | Vulns | Status |');
    expect(h.outputs()).toMatch(/result<<\S+\npass\n/);
    expect(h.outputs()).toMatch(/flagged<<\S+\nfalse\n/);
    // the tarball went to RUNNER_TEMP with a safe name and was scanned there
    const gd = h.exec.calls.find((c) => c.cmd.endsWith('/bin/guarddog'))!;
    expect(gd.args.slice(0, 3)).toEqual(['npm', 'scan', '/rt/decant-scan/0.tgz']);
  });

  it('installs GuardDog without GITHUB_ACTION_PATH (a node action never gets it)', async () => {
    const h = harness({ head: lock([LP]), base: lock([]) });
    delete h.env.GITHUB_ACTION_PATH;
    expect(await h.run()).toBe(0);
    expect(h.log()).not.toContain('GITHUB_ACTION_PATH');
    const pip = h.exec.calls.find((c) => c.cmd.endsWith('/bin/pip'))!;
    expect(pip.args.at(-1)).toMatch(/\/action\/guarddog-requirements\.txt$/);
    expect(h.puts).toContainEqual(expect.objectContaining({ scanner: 'guarddog', result: 'clean' }));
  });

  it('an unsupported runner Python fails closed with the setup-python hint and never runs pip', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), python: '3.14' });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain("add actions/setup-python with python-version: '3.12' before the decant scan step");
    expect(h.exec.calls.some((c) => c.cmd.endsWith('/bin/pip'))).toBe(false);
    expect(h.puts).not.toContainEqual(expect.objectContaining({ scanner: 'guarddog' }));
  });

  it('uses the Python actions/setup-python installed', async () => {
    const h = harness({ head: lock([LP]), base: lock([]) });
    h.env.pythonLocation = '/opt/hostedtoolcache/Python/3.12.9/x64';
    expect(await h.run()).toBe(0);
    const venv = h.exec.calls.find((c) => c.args[0] === '-m' && c.args[1] === 'venv')!;
    expect(venv.cmd).toBe('/opt/hostedtoolcache/Python/3.12.9/x64/bin/python');
  });

  it('a lockfile new since base (git show fails with path-not-in-base) treats every dep as new', async () => {
    const h = harness({ head: lock([LP]), base: null });
    expect(await h.run()).toBe(0);
    expect(h.puts).toHaveLength(2);
  });

  it('unchanged deps are not scanned and no comment is posted', async () => {
    const h = harness({ head: lock([LP]), base: lock([LP]) });
    expect(await h.run()).toBe(0);
    expect(h.puts).toEqual([]);
    expect(h.comments).toEqual([]);
    expect(h.f.calls.filter((c) => c.url.startsWith(D))).toEqual([]);
  });

  it('cached clean verdicts skip download and scan', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      verdicts: { 'npm:left-pad@1.3.0': [{ scanner: 'osv', result: 'clean' }, { scanner: 'guarddog', result: 'clean' }] },
    });
    expect(await h.run()).toBe(0);
    expect(h.f.calls.some((c) => c.url.endsWith('.tgz'))).toBe(false);
    expect(h.f.calls.some((c) => c.url === `${D}/r/pr-7/npm/left-pad`)).toBe(true);
    expect(h.exec.calls.some((c) => c.cmd.endsWith('guarddog') || c.cmd === 'python3')).toBe(false);
    expect(h.puts).toEqual([]);
  });

  it('OSV MAL- fails and records a malicious verdict', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), osv: { 'left-pad@1.3.0': [{ id: 'MAL-2026-1' }] } });
    expect(await h.run()).toBe(1);
    expect(h.puts).toContainEqual(expect.objectContaining({ scanner: 'osv', result: 'malicious' }));
    expect(h.comments[0]).toContain('MAL-2026-1');
    expect(h.outputs()).toMatch(/result<<\S+\nfail\n/);
  });

  it('a high vuln fails with fail-on high and passes with fail-on critical', async () => {
    const osv = { 'left-pad@1.3.0': [{ id: 'GHSA-aaaa-bbbb-cccc', severity: 'HIGH' }] };
    const h1 = harness({ head: lock([LP]), base: lock([]), osv });
    expect(await h1.run()).toBe(1);
    expect(h1.comments[0]).toContain('GHSA-aaaa-bbbb-cccc (high)');
    // known vulns are reported, not recorded as verdicts
    expect(h1.puts).toContainEqual(expect.objectContaining({ scanner: 'osv', result: 'clean' }));
    vi.restoreAllMocks();
    const h2 = harness({ head: lock([LP]), base: lock([]), osv, failOn: 'critical' });
    expect(await h2.run()).toBe(0);
  });

  it('GuardDog flagged fails', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), guarddog: flaggedGd });
    expect(await h.run()).toBe(1);
    expect(h.puts).toContainEqual(expect.objectContaining({ scanner: 'guarddog', result: 'flagged' }));
    expect(h.outputs()).toMatch(/flagged<<\S+\ntrue\n/);
  });

  it('GuardDog flagged passes when a writer added decant:reviewed', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      guarddog: flaggedGd,
      labels: ['decant:reviewed'],
      labeler: { login: 'maint', permission: 'write' },
    });
    expect(await h.run()).toBe(0);
    expect(h.outputs()).toMatch(/flagged<<\S+\ntrue\n/);
  });

  it('GuardDog flagged still fails when a reader added decant:reviewed', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      guarddog: flaggedGd,
      labels: ['decant:reviewed'],
      labeler: { login: 'rando', permission: 'read' },
    });
    expect(await h.run()).toBe(1);
  });

  it('new commits (synchronize) remove decant:reviewed before evaluating', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      guarddog: flaggedGd,
      labels: ['decant:reviewed'],
      labeler: { login: 'maint', permission: 'write' },
      action: 'synchronize',
    });
    expect(await h.run()).toBe(1);
    expect(h.removed).toEqual(['decant:reviewed']);
    expect(h.log()).toContain('new commits: decant:reviewed removed; re-review required');
  });

  it('cooldown fails and the report shows publish time + cooldownDays', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      download: 'cooldown',
      publish: '2026-11-15T10:00:00.000Z',
      extraFiles: { '/w/decant.json': JSON.stringify({ project: 'app', cooldownDays: 5 }) },
    });
    expect(await h.run()).toBe(1);
    expect(h.comments[0]).toContain('waiting for cooldown until 2026-11-20 10:00 UTC');
  });

  it('blocked fails', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), download: 'blocked' });
    expect(await h.run()).toBe(1);
    expect(h.comments[0]).toContain('blocked');
  });

  it('a git-sourced dep is a warning and does not fail', async () => {
    const h = harness({ head: lock([{ name: 'gitdep', version: '1.0.0', resolved: 'git+ssh://git@github.com/x/gitdep.git#abc' }]), base: lock([]) });
    expect(await h.run()).toBe(0);
    expect(h.log()).toContain('::warning');
    expect(h.comments[0]).toContain('gitdep@1.0.0');
    expect(h.puts).toEqual([]);
  });

  it('a resolved URL naming a different package fails', async () => {
    const h = harness({
      head: lock([{ name: 'left-pad', version: '1.3.0', resolved: 'https://registry.npmjs.org/evil/-/evil-6.6.6.tgz' }]),
      base: lock([]),
    });
    expect(await h.run()).toBe(1);
    expect(h.comments[0]).toContain('resolved URL does not match package');
  });

  it('more than 500 new deps fails before any download', async () => {
    const many = Array.from({ length: 501 }, (_, i) => ({ name: `p${i}`, version: '1.0.0' }));
    const h = harness({ head: lock(many), base: lock([]) });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('too many new dependencies (501); split the change');
    expect(h.f.calls.filter((c) => c.url.startsWith(D))).toEqual([]);
  });

  it('installs GuardDog with --require-hashes once', async () => {
    const h = harness({ head: lock([LP, { name: 'right-pad', version: '1.3.0' }]), base: lock([]) });
    expect(await h.run()).toBe(0);
    const pip = h.exec.calls.filter((c) => c.cmd.endsWith('/bin/pip'));
    expect(pip).toHaveLength(1);
    expect(pip[0]!.args).toContain('--require-hashes');
    expect(pip[0]!.args).toContain('/act/guarddog-requirements.txt');
  });

  it('a GuardDog error fails closed and records no GuardDog verdict', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), guarddog: { package: 'x', issues: 0, errors: { 'download-package': 'boom' } } });
    expect(await h.run()).toBe(1);
    expect(h.puts).not.toContainEqual(expect.objectContaining({ scanner: 'guarddog' }));
    expect(h.comments[0]).toContain('scan error');
    expect(h.outputs()).toMatch(/result<<\S+\nfail\n/);
  });

  it('too many deps and decant URLs still set result=fail', async () => {
    const many = Array.from({ length: 501 }, (_, i) => ({ name: `p${i}`, version: '1.0.0' }));
    const h = harness({ head: lock(many), base: lock([]) });
    expect(await h.run()).toBe(1);
    expect(h.outputs()).toMatch(/result<<\S+\nfail\n/);
  });

  it('never prints tokens', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), guarddog: flaggedGd });
    await h.run();
    const log = h.log().replace(/::add-mask::.*\n/g, '');
    expect(log).not.toContain(TOKEN);
    expect(log).not.toContain(GH);
  });
});

describe('scan: GuardDog findings in the report', () => {
  const anomaly = {
    code: 1,
    stderr:
      "ERROR: Error occurred while scanning target /rt/decant-scan/0.tgz: 'archive parser anomaly: multiple End-Of-Central-Directory records (possible scan evasion via duplicate EOCD)'\n",
  };

  it('shows each rule, its message and locations in the summary, the comment and an annotation; stores them in the verdict', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), guarddog: flaggedGd });
    expect(await h.run()).toBe(1);
    const line = '- `left-pad@1.3.0` `threat-npm-preinstall-script` (1): `preinstall` at `package/package.json:5`';
    expect(h.summary()).toContain('### GuardDog findings');
    expect(h.summary()).toContain(line);
    expect(h.comments[0]).toContain(line);
    expect(h.log()).toContain('::warning::left-pad@1.3.0 flagged by GuardDog: threat-npm-preinstall-script (1): preinstall at package/package.json:5');
    expect(h.puts).toContainEqual(
      expect.objectContaining({
        scanner: 'guarddog',
        result: 'flagged',
        details: [{ rule: 'threat-npm-preinstall-script', count: 1, message: 'preinstall', locations: ['package/package.json:5'] }],
      }),
    );
  });

  it('escapes package-controlled text: no markdown, mentions, HTML or table breaks', async () => {
    const evil = {
      ...flaggedGd,
      results: { 'threat-x': [{ location: 'a`|b.js:1', message: 'hi @octocat <img src=x> | `code` [l](http://e)\n## h' }] },
    };
    const h = harness({ head: lock([LP]), base: lock([]), guarddog: evil });
    await h.run();
    const section = h.summary().slice(h.summary().indexOf('### GuardDog findings'));
    expect(section).not.toMatch(/@octocat|<img|\[l\]|`code`|\n## h/);
    expect(section).toContain('`a??b.js:1`');
    expect(h.log()).not.toContain('<img');
  });

  it('a cached flagged verdict still shows its rules', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      verdicts: {
        'npm:left-pad@1.3.0': [
          { scanner: 'osv', result: 'clean' },
          { scanner: 'guarddog', result: 'flagged', details: [{ rule: 'threat-shady-links', count: 2, message: 'shady URL' }] },
        ],
      },
    });
    expect(await h.run()).toBe(1);
    expect(h.summary()).toContain('- `left-pad@1.3.0` `threat-shady-links` (2): `shady URL`');
  });

  it('an archive parser anomaly is a flag (archive-anomaly), not a scan error', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), gdExit: anomaly });
    expect(await h.run()).toBe(1);
    expect(h.comments[0]).not.toContain('scan error');
    expect(h.comments[0]).toContain('flagged by GuardDog (needs decant:reviewed from a writer)');
    expect(h.comments[0]).toContain(
      '`archive-anomaly`: `archive parser anomaly: multiple End-Of-Central-Directory records (possible scan evasion via duplicate EOCD)`',
    );
    expect(h.puts).toContainEqual(expect.objectContaining({ scanner: 'guarddog', result: 'flagged', details: [expect.objectContaining({ rule: 'archive-anomaly' })] }));
    expect(h.outputs()).toMatch(/flagged<<\S+\ntrue\n/);
  });

  it('a writer\'s decant:reviewed clears an archive-anomaly flag', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), gdExit: anomaly, labels: ['decant:reviewed'], labeler: { login: 'maint', permission: 'write' } });
    expect(await h.run()).toBe(0);
    expect(h.outputs()).toMatch(/result<<\S+\npass\n/);
  });

  it('any other GuardDog failure is still a scan error (fails closed)', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), gdExit: { code: 1, stderr: "Error occurred while scanning target x: 'boom'" } });
    expect(await h.run()).toBe(1);
    expect(h.comments[0]).toContain('scan error');
    expect(h.puts).not.toContainEqual(expect.objectContaining({ scanner: 'guarddog' }));
  });
});

describe('scan review fixes', () => {
  const cachedClean = { 'npm:left-pad@1.3.0': [{ scanner: 'osv', result: 'clean' }, { scanner: 'guarddog', result: 'clean' }] };

  it('a symlinked lockfile fails', async () => {
    const h = harness({ head: lock([]), base: lock([]), extraFiles: { '/w/sub/package-lock.json': lock([LP]) }, symlinks: ['/w/sub/package-lock.json'] });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('sub/package-lock.json: lockfile is a symlink; not supported');
    expect(h.outputs()).toMatch(/result<<\S+\nfail\n/);
  });

  it('a symlinked directory fails', async () => {
    const h = harness({ head: lock([]), base: lock([]), extraFiles: { '/w/linked/x': '' }, symlinks: ['/w/linked'] });
    expect(await h.run()).toBe(1);
    expect(h.log()).toContain('linked: symlinked directory; not supported');
  });

  it.each([
    ['reopened', undefined],
    ['edited', { base: { ref: { from: 'old' } } }],
  ])('%s (new review scope) removes decant:reviewed', async (action, changes) => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      guarddog: flaggedGd,
      labels: ['decant:reviewed'],
      labeler: { login: 'maint', permission: 'write' },
      action,
      changes,
    });
    expect(await h.run()).toBe(1);
    expect(h.removed).toEqual(['decant:reviewed']);
  });

  it('edited without a base change keeps decant:reviewed', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      guarddog: flaggedGd,
      labels: ['decant:reviewed'],
      labeler: { login: 'maint', permission: 'write' },
      action: 'edited',
      changes: { title: { from: 'x' } },
    });
    expect(await h.run()).toBe(0);
    expect(h.removed).toEqual([]);
  });

  it('cached clean but globally blocked fails', async () => {
    const h = harness({
      head: lock([LP]),
      base: lock([]),
      verdicts: cachedClean,
      blocks: [{ package: 'npm:left-pad@1.3.0', source: 'verdict:osv', reason: 'malicious verdict', at: '2026-11-18T00:00:00Z' }],
    });
    expect(await h.run()).toBe(1);
    expect(h.comments[0]).toContain('blocked by decant');
  });

  it('cached clean but blocked through the PR ref fails', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), verdicts: cachedClean, download: 'blocked' });
    expect(await h.run()).toBe(1);
    expect(h.comments[0]).toContain('blocked by decant');
  });

  it('cached clean but in cooldown fails', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), verdicts: cachedClean, download: 'cooldown' });
    expect(await h.run()).toBe(1);
    expect(h.comments[0]).toContain('waiting for cooldown until');
  });

  it('OSV 5xx fails closed with result=fail', async () => {
    const h = harness({ head: lock([LP]), base: lock([]), osvStatus: 503 });
    expect(await h.run()).toBe(1);
    expect(h.outputs()).toMatch(/result<<\S+\nfail\n/);
  });

  it.each([
    ['fail-on', { failOn: 'bogus' }],
    ['github-token', {}],
  ])('early failure (%s) sets result=fail', async (_n, over) => {
    const h = harness({ head: lock([LP]), base: lock([]), ...over });
    if (_n === 'github-token') delete (h as unknown as { env: Record<string, string> }).env.INPUT_GITHUB_TOKEN;
    expect(await h.run()).toBe(1);
    expect(h.outputs()).toMatch(/result<<\S+\nfail\n/);
  });

  it('no new deps but a prior report comment: updates it to pass, creates none', async () => {
    const h = harness({ head: lock([LP]), base: lock([LP]), priorComment: true });
    expect(await h.run()).toBe(0);
    expect(h.comments).toEqual([]);
    expect(h.patched).toHaveLength(1);
    expect(h.patched[0]).toContain('decant scan: ✅ pass');
  });
});
