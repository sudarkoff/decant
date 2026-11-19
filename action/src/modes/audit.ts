import { randomUUID } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { formatPackageId, parsePackageId } from '../../../src/ids';
import { parsePolicy, type AllowEntry, type Policy, type Severity } from '../../../src/policy/schema';
import { compareVersions, parseVersion } from '../../../src/semver';
import { defaultHeadCheckout } from '../checkout';
import { decant, type DecantClient } from '../decant-client';
import type { ActionDeps } from '../deps';
import { appendSummary, error, mask, notice, setOutput, warning } from '../gh-io';
import { github, type GitHubClient } from '../github';
import { redact } from '../http';
import type { ModeCtx } from '../inputs';
import { findLockfileTree, normalizeLockfile, parseGoSum, parsePackageLock, type Dep } from '../lockfiles';
import { createOsv, depKey, type Vuln } from '../osv';
import { goPublishTime, npmPublishTime } from '../registries';

const DAY = 86_400_000;
const MAX_BRANCH = 100;
const PRUNE_BRANCH = 'decant/prune';
const UNFIXED_TITLE = 'decant: unfixed advisories';
const BLOCKED_TITLE = 'decant: blocked versions in lockfiles';
const ISSUE_LABELS = ['decant:security'];
/** npm package names (legacy uppercase allowed); never starting with '-', '.' or '_'. */
const NPM_NAME = /^(?:@[A-Za-z0-9~][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~][A-Za-z0-9._~-]*$/;
/** Go module paths; never starting with '-'. */
const GO_MODULE = /^[A-Za-z0-9][A-Za-z0-9._~+/-]*$/;

const safe = (s: string) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, '?');
const ymd = (d: Date) => d.toISOString().slice(0, 10);
const isPackageLock = (rel: string) => rel === 'package-lock.json' || rel.endsWith('/package-lock.json');

/** Lowercase, then anything outside [a-z0-9.-] becomes '-'; no '..' (invalid in git refs). */
const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/@/g, '')
    .replace(/\//g, '-')
    .replace(/[^a-z0-9.-]/g, '-')
    .replace(/\.{2,}/g, '.');

/** decant/fix-<id>-<name>, at most 100 chars, never ending in '.', '-' or '.lock'. */
export function fixBranch(id: string, name: string): string {
  const prefix = `decant/fix-${slug(id)}-`;
  const tail = slug(name)
    .slice(0, Math.max(1, MAX_BRANCH - prefix.length))
    .replace(/\.lock$/, '')
    .replace(/[.-]+$/, '');
  return `${prefix}${tail || 'pkg'}`;
}

/** audit-<id>, within the Worker's ref pattern ^[A-Za-z0-9._-]{1,64}$. */
export function overlayRef(id: string): string {
  return `audit-${slug(id)}`.slice(0, 64).replace(/[.-]+$/, '');
}

/** The compatibility line of a version: its major, or 0.<minor> below 1.0.0. */
function line(v: string, eco: 'npm' | 'go'): string {
  const p = parseVersion(v, eco);
  if (!p) return `?${v}`;
  return p.major > 0 ? String(p.major) : `0.${p.minor}`;
}

/** npm override selector for the copies on `version`'s line: name@^M, or name@~0.m for 0.x. */
export function overrideKey(name: string, version: string): string {
  const p = parseVersion(version, 'npm');
  if (!p) throw new GroupError('unresolvable', `cannot build an override for ${safe(name)}@${safe(version)}`);
  return p.major > 0 ? `${name}@^${p.major}` : `${name}@~0.${p.minor}`;
}

function advisoryUrl(id: string): string {
  return id.startsWith('GHSA-') ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

/** A GitHub/decant failure that no later group can survive (bad credentials). */
const systemic = (e: unknown) => /^(GitHub|decant) [A-Z]+ \S+: HTTP 40[13]\b/.test((e as Error)?.message ?? '');

/** One vulnerable locked copy and the fix for its own version line. */
type Copy = { dep: Dep; fix: string };

type Group = {
  vuln: Vuln;
  eco: 'npm' | 'go';
  name: string;
  copies: Copy[];
};

type Result = 'opened' | 'skipped' | 'declined' | 'unverified' | 'unresolvable' | 'failed';
type Outcome = { group: Group; result: Result; detail: string };

class GroupError extends Error {
  constructor(
    readonly result: 'unresolvable' | 'failed',
    msg: string,
  ) {
    super(msg);
  }
}

const uniqSorted = (vs: string[], eco: 'npm' | 'go') => [...new Set(vs)].sort((a, b) => compareVersions(a, b, eco));
const fixesOf = (g: Group) => uniqSorted(g.copies.map((c) => c.fix), g.eco);
const oldsOf = (g: Group) => uniqSorted(g.copies.map((c) => c.dep.version), g.eco);

/** The fix for `version` if the advisory affects it and names a valid fixed version; else null. */
function validFix(v: Vuln, eco: 'npm' | 'go', name: string, version: string): string | null {
  const f = v.fixedFor(eco, name, version);
  return f !== null && parseVersion(f, eco) !== null ? f : null;
}

export async function run({ deps, inputs }: ModeCtx): Promise<number> {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.githubToken);
  const stop = (msg: string) => {
    setOutput('result', 'fail', env);
    error(msg);
    process.stderr.write(`${msg}\n`);
    return 1;
  };

  if (!inputs.githubToken) return stop('github-token is required');
  if (!inputs.token) return stop('token is required (ci token)');
  if (!inputs.decantUrl) return stop('decant-url is required');
  // Credential files go in a private directory under the runner's per-job temp dir, never a shared /tmp.
  if (!env.RUNNER_TEMP) return stop('RUNNER_TEMP is not set; decant audit runs on GitHub Actions runners');
  const repo = env.GITHUB_REPOSITORY ?? '';
  const wd = inputs.workingDirectory;
  const policyAbs = join(wd, inputs.policyPath);
  const root = env.GITHUB_WORKSPACE || (isAbsolute(wd) ? wd : process.cwd());
  const repoPath = (abs: string) => relative(resolve(root), resolve(root, abs)).split('\\').join('/');
  const policyRel = repoPath(policyAbs);
  if (policyRel.startsWith('..')) return stop(`${policyAbs} is outside the repository`);

  // 1. Main policy, from the default-branch checkout.
  if (!(await deps.fs.exists(policyAbs))) return stop(`decant.json not found at ${policyAbs}`);
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(await deps.fs.readFile(policyAbs)) as Record<string, unknown>;
  } catch (e) {
    return stop(`${policyAbs} is not valid JSON: ${(e as Error).message}`);
  }
  const parsed = parsePolicy(raw);
  if (!parsed.ok) return stop(`invalid policy:\n${parsed.errors.map((m) => `- ${m}`).join('\n')}`);
  const policy: Policy = parsed.policy;
  const project = inputs.project || policy.project;

  // 2. Lockfiles (never through symlinks).
  const tree = await findLockfileTree(wd, deps.fs);
  if (tree.symlinks.length) {
    for (const l of tree.symlinks) {
      const msg = `${join(wd, l.path)}: ${l.dir ? 'symlinked directory' : 'lockfile is a symlink'}; not supported`;
      error(msg);
      process.stderr.write(`${msg}\n`);
    }
    return stop(`${tree.symlinks.length} symlink(s) in ${wd}; decant does not audit through symlinks`);
  }
  const all: Dep[] = [];
  for (const rel of tree.files) {
    const abs = join(wd, rel);
    try {
      const text = await deps.fs.readFile(abs);
      all.push(...(isPackageLock(rel) ? parsePackageLock(text, rel, inputs.decantUrl) : parseGoSum(text, rel)));
    } catch (e) {
      return stop(`${abs}: ${(e as Error).message}`);
    }
  }
  const registry = all.filter((d) => d.source === 'registry' && d.version);

  const now = deps.now();
  const today = ymd(now);
  const outcomes: Outcome[] = [];
  const lines: string[] = [];
  let tmp: Promise<string> | null = null;

  try {
    const gh = github(deps.fetch, inputs.githubToken, repo, { selfLogin: env.DECANT_GITHUB_LOGIN || undefined });
    // Commits carry checkout content, so the checkout must be the live default-branch head.
    const co = await defaultHeadCheckout(gh, env, 'audit');
    if (!co.ok) return stop(co.message);

    // 3. OSV (fails the run if unavailable).
    const vulnsByKey = registry.length ? await createOsv(deps.fetch).queryVulns(registry) : new Map<string, Vuln[]>();

    const groups = new Map<string, Group>();
    const unfixed: { vuln: Vuln; dep: Dep; reason: string }[] = [];
    for (const d of registry) {
      for (const v of vulnsByKey.get(depKey(d)) ?? []) {
        const raw = v.fixedFor(d.eco, d.name, d.version);
        const fix = validFix(v, d.eco, d.name, d.version);
        if (fix === null) {
          unfixed.push({ vuln: v, dep: d, reason: raw === null ? 'no fixed version' : 'invalid fixed version' });
          continue;
        }
        const k = `${v.id.toLowerCase()}|${d.eco}|${d.name}`;
        const g = groups.get(k);
        if (!g) groups.set(k, { vuln: v, eco: d.eco, name: d.name, copies: [{ dep: d, fix }] });
        else g.copies.push({ dep: d, fix });
      }
    }

    const client = decant(deps.fetch, inputs.decantUrl, inputs.token);
    const ctx: FixCtx = {
      deps,
      inputs,
      gh,
      client,
      raw,
      policy,
      project,
      today,
      wd,
      repoPath,
      policyRel,
      base: co.base,
      sha: co.sha,
      tmpFile: async (ext) => `${await (tmp ??= deps.fs.mkdtemp(`${env.RUNNER_TEMP}/decant-audit-`))}/${randomUUID()}.${ext}`,
    };

    // 4. One PR per (advisory group, package).
    const sorted = [...groups.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, g]) => g);
    for (const g of sorted) {
      try {
        outcomes.push(await fixGroup(ctx, g));
      } catch (e) {
        if (systemic(e)) throw e;
        const msg = redact((e as Error).message, [inputs.token, inputs.githubToken]);
        const result = e instanceof GroupError ? e.result : 'failed';
        if (result === 'failed') warning(`${g.vuln.id} ${safe(g.name)}: ${msg}`);
        outcomes.push({ group: g, result, detail: msg });
      }
    }

    // 5. Unfixed advisories → one issue.
    const unfixedIssue = await syncIssue(gh, UNFIXED_TITLE, unfixed.length ? unfixedBody(unfixed) : null);

    // 6. Global blocks that hit the lockfiles → one issue.
    const blocks = await client.blocks();
    const byId = new Map<string, Dep[]>();
    for (const d of all) {
      if (!d.version) continue;
      const id = formatPackageId(d);
      byId.set(id, [...(byId.get(id) ?? []), d]);
    }
    const hits = blocks.filter((b) => byId.has(b.package));
    const blockedIssue = await syncIssue(gh, BLOCKED_TITLE, hits.length ? blockedBody(hits.map((b) => ({ ...b, files: [...new Set(byId.get(b.package)!.map((d) => d.file))] }))) : null);

    // 7. Prune expired allow entries.
    let prune: string;
    try {
      prune = await pruneAllow(ctx, now);
    } catch (e) {
      if (systemic(e)) throw e;
      prune = `failed: ${redact((e as Error).message, [inputs.token, inputs.githubToken])}`;
      warning(`prune ${prune}`);
    }

    lines.push('## decant audit', '');
    if (outcomes.length) {
      lines.push('| Advisory | Package | Fix | Result |', '|---|---|---|---|');
      for (const o of outcomes) {
        const detail = o.detail.replace(/\s+/g, ' ').replace(/\|/g, '\\|').slice(0, 200);
        lines.push(`| ${safe(o.group.vuln.id)} | \`${safe(o.group.name)}\` | ${fixesOf(o.group).map(safe).join(', ')} | ${o.result}${detail ? `: ${detail}` : ''} |`);
      }
    } else lines.push('No fixable advisories.');
    const count = (r: Result) => outcomes.filter((o) => o.result === r).length;
    lines.push(
      '',
      `Fixes opened: ${count('opened')} · skipped: ${count('skipped')} · declined: ${count('declined')} · unverified: ${count('unverified')} · unresolvable: ${count('unresolvable')} · failed: ${count('failed')}`,
      `Unfixed advisories: ${unfixed.length}${unfixedIssue ? ` (issue #${unfixedIssue})` : ''}`,
      `Blocked versions in lockfiles: ${hits.length}${blockedIssue ? ` (issue #${blockedIssue})` : ''}`,
      `Prune: ${prune}`,
    );
  } catch (e) {
    return stop(`decant audit: ${redact((e as Error).message, [inputs.token, inputs.githubToken])}`);
  } finally {
    if (tmp) await deps.fs.rm(await tmp.catch(() => '')).catch(() => {});
  }
  appendSummary(lines.join('\n'), env);
  setOutput('result', 'pass', env);
  return 0;
}

type FixCtx = {
  deps: ActionDeps;
  inputs: ModeCtx['inputs'];
  gh: GitHubClient;
  client: DecantClient;
  raw: Record<string, unknown>;
  policy: Policy;
  project: string;
  today: string;
  wd: string;
  repoPath: (abs: string) => string;
  policyRel: string;
  /** Default branch and the checked-out sha it pointed at (base for new branches). */
  base: string;
  sha: string;
  /** A fresh randomly named path inside this run's private temp dir. */
  tmpFile: (ext: string) => Promise<string>;
};

async function fixGroup(ctx: FixCtx, g: Group): Promise<Outcome> {
  const { deps, inputs, gh, client } = ctx;
  const id = g.vuln.id;
  if (!(g.eco === 'npm' ? NPM_NAME : GO_MODULE).test(g.name) || g.name.includes('..')) {
    return { group: g, result: 'failed', detail: `invalid package name ${safe(g.name)}` };
  }
  const branch = fixBranch(id, g.name);
  const open = await gh.findOpenPr(branch);
  if (open) return { group: g, result: 'skipped', detail: `PR #${open.number} open` };
  const closed = await gh.findClosedUnmergedPr(branch);
  if (closed !== null) return { group: g, result: 'declined', detail: `PR #${closed} was closed without merging` };

  // Overlay: main policy + one allow entry per fixed version, verified by decant (OSV) at sync time.
  const fixes = fixesOf(g);
  const allow = (ctx.raw.allow as AllowEntry[] | undefined) ?? [];
  const added: AllowEntry[] = [];
  for (const fix of fixes) {
    const pkgId = formatPackageId({ eco: g.eco, name: g.name, version: fix });
    if (!allow.some((a) => a.package === pkgId && a.advisory === id)) added.push({ package: pkgId, advisory: id, reason: 'security fix', added: ctx.today });
  }
  const next = { ...ctx.raw, allow: [...allow, ...added] };
  const check = parsePolicy(next);
  if (!check.ok) return { group: g, result: 'failed', detail: `allow entry invalid: ${check.errors.join('; ')}` };
  const ref = overlayRef(id);
  const res = await client.syncPolicy(ctx.project, next, ctx.sha, ref);
  if (res.status === 401 || res.status === 403) throw new Error(`decant PUT /api/projects/${ctx.project}/policy: HTTP ${res.status}`);
  if (res.status < 200 || res.status >= 300) {
    const b = res.body as { error?: unknown } | string;
    const why = typeof b === 'object' && b && typeof b.error === 'string' ? b.error : typeof b === 'string' ? b : JSON.stringify(b);
    return { group: g, result: 'unverified', detail: `overlay sync HTTP ${res.status}: ${why.slice(0, 200)}` };
  }

  // Apply the upgrade in the working tree, then restore it whatever happens.
  const snapshot = new Map<string, string | null>();
  const track = async (abs: string) => {
    if (!snapshot.has(abs)) snapshot.set(abs, (await deps.fs.exists(abs)) ? await deps.fs.readFile(abs) : null);
  };
  const files: { path: string; contents: string }[] = [];
  try {
    const dirs = [...new Set(g.copies.map((c) => dirname(join(ctx.wd, c.dep.file))))].sort();
    for (const dir of dirs) {
      if (g.eco === 'npm') await fixNpm(ctx, g, ref, dir, track);
      else await fixGo(ctx, g, ref, dir, track);
    }
    for (const [abs, before] of snapshot) {
      const after = (await deps.fs.exists(abs)) ? await deps.fs.readFile(abs) : null;
      if (after !== null && after !== before) files.push({ path: ctx.repoPath(abs), contents: after });
    }
  } finally {
    for (const [abs, before] of snapshot) {
      if (before === null) await deps.fs.rm(abs);
      else await deps.fs.writeFile(abs, before);
    }
  }
  if (!files.length) throw new GroupError('unresolvable', 'no lockfile changes');
  if (added.length) files.push({ path: ctx.policyRel, contents: `${JSON.stringify(next, null, 2)}\n` });

  // Branch from the checked-out default head, one commit, PR.
  try {
    await gh.createBranch(branch, ctx.sha);
  } catch (e) {
    // A stale branch with no open PR (merged earlier): reset it to the default head.
    if (!/HTTP 422/.test((e as Error).message)) throw e;
    await gh.updateRef(branch, ctx.sha);
  }
  const olds = oldsOf(g);
  const title = `decant: ${g.name} ${olds.join(', ')} → ${fixes.join(', ')} (${id})`;
  await gh.commitFiles(branch, ctx.sha, title, files);
  const sev: Severity = g.vuln.severity === 'unknown' ? 'moderate' : g.vuln.severity;
  // Crossing a major (or 0.x minor) line may break callers: never merge that unattended.
  const major = g.copies.some((c) => line(c.dep.version, g.eco) !== line(c.fix, g.eco));
  const auto = ctx.policy.autoShip[sev] === 'auto' && !major;
  const pr = await gh.openPr({
    head: branch,
    base: ctx.base,
    title,
    body: fixBody(g, sev, auto, major, ctx.policy.cooldownDays, files.map((f) => f.path)),
    labels: ['decant:security', `decant:${sev}`],
  });
  let detail = `opened #${pr.number}`;
  if (auto) {
    try {
      await gh.enableAutoMerge(pr.nodeId, 'SQUASH');
      detail += ' (auto-merge)';
    } catch (e) {
      warning(`${pr.url}: could not enable auto-merge: ${(e as Error).message}`);
      detail += ' (auto-merge unavailable)';
    }
  } else if (major) detail += ' (major upgrade: auto-merge disabled)';
  notice(`${title}: ${pr.url}`);
  return { group: g, result: 'opened', detail };
}

function baseEnv(env: ActionDeps['env'], names: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const n of names) if (env[n] !== undefined) out[n] = env[n]!;
  return out;
}

async function run1(deps: ActionDeps, cmd: string, args: string[], cwd: string, env: Record<string, string>, secrets: string[]): Promise<void> {
  const r = await deps.exec(cmd, args, { cwd, env });
  if (r.code !== 0) {
    const what = [args[0], ...args.slice(args.indexOf('--') + 1 || args.length)].join(' ');
    const why = redact((r.stderr || r.stdout).trim().split('\n').slice(-3).join(' '), secrets).slice(0, 300);
    throw new GroupError('failed', `${cmd} ${what} exited ${r.code}: ${why}`);
  }
}

/** Copies of the group's package in the lockfile at `abs` that the advisory still affects (and that have a fix). */
async function stale(ctx: FixCtx, abs: string, g: Group): Promise<Copy[]> {
  const deps = parsePackageLock(await ctx.deps.fs.readFile(abs), abs, ctx.inputs.decantUrl);
  const out: Copy[] = [];
  for (const d of deps) {
    if (d.name !== g.name) continue;
    const fix = validFix(g.vuln, 'npm', d.name, d.version);
    if (fix !== null) out.push({ dep: d, fix });
  }
  return out;
}

async function fixNpm(ctx: FixCtx, g: Group, ref: string, dir: string, track: (abs: string) => Promise<void>): Promise<void> {
  const { deps, inputs } = ctx;
  const lockAbs = `${dir}/package-lock.json`;
  const pkgAbs = `${dir}/package.json`;
  await track(lockAbs);
  await track(pkgAbs);
  const base = inputs.decantUrl.replace(/\/+$/, '');
  const url = new URL(base);
  const registry = `${base}/r/${ref}/npm/`;
  const userconfig = await ctx.tmpFile('npmrc');
  const env = baseEnv(deps.env, ['PATH', 'HOME', 'RUNNER_TEMP']);
  // --registry on the command line beats any project .npmrc; the token lives only in the 0600 userconfig.
  const common = ['--userconfig', userconfig, '--registry', registry, '--ignore-scripts', '--package-lock-only', '--no-audit', '--no-fund'];
  const npm = (cmd: string, specs: string[]) => run1(deps, 'npm', [cmd, ...common, ...(specs.length ? ['--', ...specs] : [])], dir, env, [inputs.token]);
  await deps.fs.writeFile(userconfig, `registry=${registry}\n//${url.host}${url.pathname.replace(/\/+$/, '')}/r/${ref}/npm/:_authToken=${inputs.token}\nignore-scripts=true\n`, 0o600);
  try {
    await deps.fs.chmod(userconfig, 0o600);
    const pkgText = (await deps.fs.exists(pkgAbs)) ? await deps.fs.readFile(pkgAbs) : null;
    const pkg = pkgText === null ? null : (JSON.parse(pkgText) as Record<string, Record<string, string> | undefined>);
    const declared = !!pkg && ['dependencies', 'devDependencies', 'optionalDependencies'].some((k) => pkg[k]?.[g.name] !== undefined);
    // The direct dependency's own copy is the top-level node_modules/<name> entry.
    const lock = JSON.parse(await deps.fs.readFile(lockAbs)) as { packages?: Record<string, { version?: string }> };
    const topVersion = lock.packages?.[`node_modules/${g.name}`]?.version;
    const topFix = declared && topVersion ? validFix(g.vuln, 'npm', g.name, topVersion) : null;
    if (topFix !== null) {
      await npm('install', [`${g.name}@${topFix}`]);
    } else {
      await npm('update', [g.name]);
      const left = await stale(ctx, lockAbs, g);
      if (left.length) {
        if (!pkg || pkgText === null) throw new GroupError('unresolvable', `${ctx.repoPath(lockAbs)}: no package.json for an override`);
        // One selector per version line, each pinned to that line's fix.
        const overrides: Record<string, string> = { ...(pkg.overrides ?? {}) };
        const byKey = new Map<string, string>();
        for (const c of left) {
          const k = overrideKey(g.name, c.dep.version);
          const prev = byKey.get(k);
          if (!prev || compareVersions(c.fix, prev, 'npm') > 0) byKey.set(k, c.fix);
        }
        for (const [k, v] of [...byKey].sort(([a], [b]) => (a < b ? -1 : 1))) overrides[k] = v;
        pkg.overrides = overrides;
        const indent = /^\{\n(\s+)/.exec(pkgText)?.[1] ?? '  ';
        await deps.fs.writeFile(pkgAbs, `${JSON.stringify(pkg, null, indent)}${pkgText.endsWith('\n') ? '\n' : ''}`);
        await npm('install', []);
      }
    }
  } finally {
    await deps.fs.rm(userconfig);
  }
  const n = normalizeLockfile(await deps.fs.readFile(lockAbs), inputs.decantUrl);
  if (n.changed) await deps.fs.writeFile(lockAbs, n.text);
  const left = await stale(ctx, lockAbs, g);
  if (left.length) {
    throw new GroupError('unresolvable', `${ctx.repoPath(lockAbs)} still locks ${uniqSorted(left.map((c) => c.dep.version), 'npm').map(safe).join(', ')}`);
  }
}

async function fixGo(ctx: FixCtx, g: Group, ref: string, dir: string, track: (abs: string) => Promise<void>): Promise<void> {
  const { deps, inputs } = ctx;
  const sumAbs = `${dir}/go.sum`;
  await track(`${dir}/go.mod`);
  await track(sumAbs);
  // MVS selects one version per module: the highest fix needed by any copy in this module.
  const here = g.copies.filter((c) => dirname(join(ctx.wd, c.dep.file)) === dir).map((c) => c.fix);
  const target = uniqSorted(here.length ? here : fixesOf(g), 'go').at(-1)!;
  const base = inputs.decantUrl.replace(/\/+$/, '');
  const netrc = await ctx.tmpFile('netrc');
  const env = {
    ...baseEnv(deps.env, ['PATH', 'HOME', 'GOPATH', 'GOCACHE']),
    NETRC: netrc,
    GOPROXY: `${base}/r/${ref}/go`,
    GOFLAGS: '-mod=mod',
  };
  await deps.fs.writeFile(netrc, `machine ${new URL(base).hostname} login decant password ${inputs.token}\n`, 0o600);
  try {
    await deps.fs.chmod(netrc, 0o600);
    await run1(deps, 'go', ['get', '--', `${g.name}@${target}`], dir, env, [inputs.token]);
    await run1(deps, 'go', ['mod', 'tidy'], dir, env, [inputs.token]);
  } finally {
    await deps.fs.rm(netrc);
  }
  const left = parseGoSum(await deps.fs.readFile(sumAbs), sumAbs).filter((d) => d.name === g.name && validFix(g.vuln, 'go', d.name, d.version) !== null);
  if (left.length) throw new GroupError('unresolvable', `${ctx.repoPath(sumAbs)} still has ${left.map((d) => safe(d.version)).join(', ')}`);
}

async function syncIssue(gh: GitHubClient, title: string, body: string | null): Promise<number | null> {
  if (body !== null) return (await gh.upsertIssue(title, body, ISSUE_LABELS)).number;
  const n = await gh.findIssue(title, ISSUE_LABELS);
  if (n !== null) {
    await gh.closeIssue(n);
    notice(`closed #${n} (${title})`);
  }
  return null;
}

function fixBody(g: Group, sev: Severity, auto: boolean, major: boolean, cooldownDays: number, paths: string[]): string {
  const v = g.vuln;
  const fixes = fixesOf(g);
  const ids = fixes.map((f) => `\`${safe(formatPackageId({ eco: g.eco, name: g.name, version: f }))}\``).join(', ');
  const summary = v.summary.replace(/\s+/g, ' ').replace(/[<>]/g, '').slice(0, 300);
  return [
    `Security fix for **${safe(v.id)}** (${sev}) in \`${safe(g.name)}\`: ${oldsOf(g).map(safe).join(', ')} → ${fixes.map(safe).join(', ')}.`,
    '',
    summary ? `> ${summary}` : '',
    '',
    `Advisory: ${advisoryUrl(v.id)}${v.aliases.length ? ` (aliases: ${v.aliases.map(safe).join(', ')})` : ''}`,
    '',
    `**Cooldown skip:** this PR adds \`allow\` entries for ${ids} citing ${safe(v.id)}, so the fixed version ships without waiting out the ${cooldownDays}-day cooldown. decant honors it only while OSV lists this version as fixed; it is never exempt from the scan.`,
    '',
    'Files:',
    ...paths.map((p) => `- \`${p}\``),
    '',
    major
      ? '**major upgrade: auto-merge disabled.** A fix crosses a major (or 0.x minor) version line; review and merge.'
      : auto
        ? `autoShip.${sev} is \`auto\`: auto-merge is on; it merges once the required checks (including the decant scan) pass.`
        : `autoShip.${sev} is \`approve\`: review and merge.`,
  ]
    .filter((l, i, a) => !(l === '' && a[i - 1] === ''))
    .join('\n');
}

function unfixedBody(items: { vuln: Vuln; dep: Dep; reason: string }[]): string {
  const rows = [...new Map(items.map((i) => [`${i.vuln.id}|${depKey(i.dep)}|${i.dep.file}`, i])).values()].sort((a, b) =>
    a.vuln.id < b.vuln.id ? -1 : a.vuln.id > b.vuln.id ? 1 : 0,
  );
  return [
    'Advisories affecting locked versions with no usable fixed release. decant updates this issue daily and closes it when none remain.',
    '',
    '| Advisory | Severity | Package | Lockfile | Reason |',
    '|---|---|---|---|---|',
    ...rows.map((i) => `| [${safe(i.vuln.id)}](${advisoryUrl(i.vuln.id)}) | ${i.vuln.malicious ? 'malicious' : i.vuln.severity} | \`${safe(i.dep.name)}@${safe(i.dep.version)}\` | ${safe(i.dep.file)} | ${i.reason} |`),
  ].join('\n');
}

function blockedBody(hits: { package: string; source: string; reason: string; files: string[] }[]): string {
  return [
    'Versions in the lockfiles that decant blocks globally. Installs of these fail; upgrade or remove them. decant closes this issue when none remain.',
    '',
    '| Package | Source | Reason | Lockfiles |',
    '|---|---|---|---|',
    ...hits.map((h) => `| \`${safe(h.package)}\` | ${safe(h.source)} | ${h.reason.replace(/[|\n<>]/g, ' ').slice(0, 200)} | ${h.files.map(safe).join(', ')} |`),
  ].join('\n');
}

/** Opens or refreshes the single prune PR. Returns a one-line summary. */
async function pruneAllow(ctx: FixCtx, now: Date): Promise<string> {
  const { deps, gh } = ctx;
  const allow = (ctx.raw.allow as AllowEntry[] | undefined) ?? [];
  const expired: { e: AllowEntry; at: Date }[] = [];
  let unknown = 0;
  for (const e of allow) {
    const p = parsePackageId(e.package);
    if (!p) continue;
    let at: Date | null = null;
    try {
      at = p.eco === 'npm' ? await npmPublishTime(deps.fetch, p.name, p.version) : await goPublishTime(deps.fetch, p.name, p.version);
    } catch (err) {
      warning(`prune: ${safe(e.package)}: ${(err as Error).message}`);
    }
    if (!at) {
      unknown++;
      continue;
    }
    if (at.getTime() + ctx.policy.cooldownDays * DAY <= now.getTime()) expired.push({ e, at });
  }
  if (!expired.length) return `nothing expired${unknown ? ` (${unknown} publish time(s) unknown)` : ''}`;

  const gone = new Set(expired.map((x) => x.e));
  const next = { ...ctx.raw, allow: allow.filter((e) => !gone.has(e)) };
  const contents = `${JSON.stringify(next, null, 2)}\n`;
  const files = [{ path: ctx.policyRel, contents }];
  const body = [
    `These \`allow\` entries have aged past the ${ctx.policy.cooldownDays}-day cooldown and no longer do anything. Review, then merge (never auto-merged).`,
    '',
    '| package | reason | published |',
    '| --- | --- | --- |',
    ...expired.map((x) => `| ${safe(x.e.package)} | ${x.e.reason.replace(/[|\n<>]/g, ' ').slice(0, 100)} | ${ymd(x.at)} |`),
  ].join('\n');
  const title = 'decant: prune allow entries';

  const open = await gh.findOpenPr(PRUNE_BRANCH);
  const base = ctx.base;
  let head: string;
  if (open) {
    head = open.headSha;
    if ((await gh.fileAt(ctx.policyRel, head)) === contents) return `PR #${open.number} up to date (${expired.length} entr${expired.length === 1 ? 'y' : 'ies'})`;
  } else {
    head = ctx.sha;
    try {
      await gh.createBranch(PRUNE_BRANCH, head);
    } catch (e) {
      if (!/HTTP 422/.test((e as Error).message)) throw e;
      await gh.updateRef(PRUNE_BRANCH, head);
    }
  }
  await gh.commitFiles(PRUNE_BRANCH, head, title, files);
  if (open) {
    await gh.updatePr(open.number, { body });
    return `updated PR #${open.number} (${expired.length} expired)`;
  }
  const pr = await gh.openPr({ head: PRUNE_BRANCH, base, title, body, labels: ['decant:prune'] });
  notice(`${title}: ${pr.url}`);
  return `opened PR #${pr.number} (${expired.length} expired)`;
}
