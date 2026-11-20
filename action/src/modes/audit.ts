import { createHash, randomUUID } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { formatPackageId, parsePackageId } from '../../../src/ids';
import { parsePolicy, SEVERITIES, type AllowEntry, type Policy, type Severity } from '../../../src/policy/schema';
import { compareVersions, parseVersion } from '../../../src/semver';
import { defaultHeadCheckout } from '../checkout';
import { decant, type DecantClient } from '../decant-client';
import type { ActionDeps } from '../deps';
import { appendSummary, error, mask, notice, setOutput, warning } from '../gh-io';
import { github, type GitHubClient, type Pr } from '../github';
import { redact } from '../http';
import type { ModeCtx } from '../inputs';
import { findLockfileTree, normalizeLockfile, parseGoSum, parsePackageLock, type Dep } from '../lockfiles';
import { createOsv, depKey, type Vuln } from '../osv';
import { goPublishTime, npmPublishTime } from '../registries';

const DAY = 86_400_000;
/** The one branch (and PR) that carries every security fix of a run. */
const FIX_BRANCH = 'decant/security-fixes';
/** The overlay ref the run's fixes resolve through (/r/audit/); fits the Worker's ^[A-Za-z0-9._-]{1,64}$. */
const OVERLAY_REF = 'audit';
const PRUNE_BRANCH = 'decant/prune';
const UNFIXED_TITLE = 'decant: unfixed advisories';
const BLOCKED_TITLE = 'decant: blocked versions in lockfiles';
const ISSUE_LABELS = ['decant:security'];
const SET_MARKER = /<!-- decant-audit-set: ([0-9a-f]{64}) -->/;
/** npm package names (legacy uppercase allowed); never starting with '-', '.' or '_'. */
const NPM_NAME = /^(?:@[A-Za-z0-9~][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~][A-Za-z0-9._~-]*$/;
/** Go module paths; never starting with '-'. */
const GO_MODULE = /^[A-Za-z0-9][A-Za-z0-9._~+/-]*$/;

const safe = (s: string) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, '?');
const cell = (s: string, n = 200) => s.replace(/\s+/g, ' ').replace(/[|<>]/g, ' ').slice(0, n);
const ymd = (d: Date) => d.toISOString().slice(0, 10);
const isPackageLock = (rel: string) => rel === 'package-lock.json' || rel.endsWith('/package-lock.json');
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The compatibility line of a version: its major, or 0.<minor> below 1.0.0. */
function line(v: string, eco: 'npm' | 'go'): string {
  const p = parseVersion(v, eco);
  if (!p) return `?${v}`;
  return p.major > 0 ? String(p.major) : `0.${p.minor}`;
}

/** npm override selector for the copies on `version`'s line: name@^M, or name@~0.m for 0.x. */
export function overrideKey(name: string, version: string): string {
  const p = parseVersion(version, 'npm');
  if (!p) throw new PkgError('unresolvable', `cannot build an override for ${safe(name)}@${safe(version)}`);
  return p.major > 0 ? `${name}@^${p.major}` : `${name}@~0.${p.minor}`;
}

/** sha256 of the sorted package@target ids a security PR covers (stored as a hidden marker in its body). */
export function auditSetHash(ids: string[]): string {
  return createHash('sha256').update([...ids].sort().join('\n')).digest('hex');
}

const markerOf = (body: string) => SET_MARKER.exec(body)?.[1] ?? null;

function advisoryUrl(id: string): string {
  return id.startsWith('GHSA-') ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

/** A GitHub/decant failure that no later step can survive (bad credentials). */
const systemic = (e: unknown) => /^(GitHub|decant) [A-Z]+ \S+: HTTP 40[13]\b/.test((e as Error)?.message ?? '');

const sevOf = (v: Vuln): Severity => (v.severity === 'unknown' ? 'moderate' : v.severity);
const sevRank = (s: Severity) => SEVERITIES.indexOf(s); // 0 = critical
const maxSev = (ss: Severity[]): Severity => ss.reduce((a, b) => (sevRank(b) < sevRank(a) ? b : a), 'low' as Severity);
/** Highest severity first, then by id. */
const bySeverity = (a: Vuln, b: Vuln) => sevRank(sevOf(a)) - sevRank(sevOf(b)) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/** One vulnerable locked copy and the version it must reach (the highest fix its advisories need, on its line). */
type Copy = { dep: Dep; target: string; vulns: Vuln[] };

/** Every fixable advisory of one package (per ecosystem), across all its locked copies. */
type Pkg = {
  eco: 'npm' | 'go';
  name: string;
  copies: Copy[];
  /** Distinct fixable advisories affecting any copy, highest severity first. */
  vulns: Vuln[];
};

type Result = 'fixed' | 'declined' | 'unverified' | 'unresolvable' | 'failed';
type Outcome = { pkg: Pkg; result: Result; detail: string };

class PkgError extends Error {
  constructor(
    readonly result: 'unresolvable' | 'failed',
    msg: string,
  ) {
    super(msg);
  }
}

const uniqSorted = (vs: string[], eco: 'npm' | 'go') => [...new Set(vs)].sort((a, b) => compareVersions(a, b, eco));
const targetsOf = (p: Pkg) => uniqSorted(p.copies.map((c) => c.target), p.eco);
const oldsOf = (p: Pkg) => uniqSorted(p.copies.map((c) => c.dep.version), p.eco);
const idsOf = (p: Pkg) => targetsOf(p).map((t) => formatPackageId({ eco: p.eco, name: p.name, version: t }));

/** The fix for `version` if the advisory affects it and names a valid fixed version; else null. */
function validFix(v: Vuln, eco: 'npm' | 'go', name: string, version: string): string | null {
  const f = v.fixedFor(eco, name, version);
  return f !== null && parseVersion(f, eco) !== null ? f : null;
}

/**
 * The version `version` must reach so none of `vulns` still affects it: the highest fix, re-checked
 * from there until no advisory names a higher one. Null if none of them affects `version`.
 */
function targetFor(vulns: Vuln[], eco: 'npm' | 'go', name: string, version: string): string | null {
  let t = version;
  for (let i = 0; i < 16; i++) {
    let next: string | null = null;
    for (const v of vulns) {
      const f = validFix(v, eco, name, t);
      if (f !== null && compareVersions(f, t, eco) > 0 && (next === null || compareVersions(f, next, eco) > 0)) next = f;
    }
    if (next === null) break;
    t = next;
  }
  return t === version ? null : t;
}

/** True if any of the package's fixable advisories still affects `version` with a fix. */
const stillVulnerable = (p: Pkg, version: string) => p.vulns.some((v) => validFix(v, p.eco, p.name, version) !== null);

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

    // Group by package: each copy's target is the highest fix across the advisories affecting it.
    const byPkg = new Map<string, { eco: 'npm' | 'go'; name: string; copies: Map<Dep, Vuln[]> }>();
    const unfixed: { vuln: Vuln; dep: Dep; reason: string }[] = [];
    for (const d of registry) {
      for (const v of vulnsByKey.get(depKey(d)) ?? []) {
        const rawFix = v.fixedFor(d.eco, d.name, d.version);
        if (validFix(v, d.eco, d.name, d.version) === null) {
          unfixed.push({ vuln: v, dep: d, reason: rawFix === null ? 'no fixed version' : 'invalid fixed version' });
          continue;
        }
        const k = `${d.eco}:${d.name}`;
        const g = byPkg.get(k) ?? { eco: d.eco, name: d.name, copies: new Map<Dep, Vuln[]>() };
        byPkg.set(k, g);
        g.copies.set(d, [...(g.copies.get(d) ?? []), v]);
      }
    }
    const pkgs: Pkg[] = [];
    for (const [, g] of [...byPkg].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
      const vulns = [...new Map([...g.copies.values()].flat().map((v) => [v.id, v])).values()].sort(bySeverity);
      const copies = [...g.copies].map(([dep, vs]) => ({ dep, vulns: vs, target: targetFor(vulns, g.eco, g.name, dep.version)! }));
      const p: Pkg = { eco: g.eco, name: g.name, copies, vulns };
      if (!(g.eco === 'npm' ? NPM_NAME : GO_MODULE).test(g.name) || g.name.includes('..')) {
        outcomes.push({ pkg: p, result: 'failed', detail: `invalid package name ${safe(g.name)}` });
      } else pkgs.push(p);
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

    // 4. One security PR for the whole run.
    let prLine = 'no fixable advisories';
    if (pkgs.length) {
      const open = await gh.findOpenPr(FIX_BRANCH);
      const closed = open ? null : await gh.findClosedUnmergedPr(FIX_BRANCH);
      const declined = (set: Pkg[]) => closed !== null && markerOf(closed.body) === auditSetHash(set.flatMap(idsOf));
      if (declined(pkgs)) {
        prLine = `declined (#${closed!.number} closed without merging the same fixes)`;
        for (const p of pkgs) outcomes.push({ pkg: p, result: 'declined', detail: `PR #${closed!.number}` });
      } else {
        const batch = await syncOverlay(ctx, pkgs, outcomes);
        const { fixed, files } = await applyAll(ctx, batch, outcomes);
        if (!fixed.length) prLine = 'nothing to ship';
        else if (!open && declined(fixed)) prLine = `declined (#${closed!.number} closed without merging the same fixes)`;
        else {
          try {
            prLine = await publish(ctx, fixed, files, open, outcomes, unfixed);
          } catch (e) {
            if (systemic(e)) throw e;
            prLine = `failed: ${redact((e as Error).message, [inputs.token, inputs.githubToken])}`;
            warning(`security PR ${prLine}`);
          }
        }
      }
    }

    // 5. Unfixed advisories, plus fixes decant could not ship → one issue.
    for (const o of outcomes) {
      if (o.result === 'fixed' || o.result === 'declined') continue;
      for (const c of o.pkg.copies) for (const v of c.vulns) unfixed.push({ vuln: v, dep: c.dep, reason: `${o.result}: ${cell(o.detail, 120)}` });
    }
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
      lines.push('| Package | Upgrade | Advisories | Result |', '|---|---|---|---|');
      for (const o of outcomes) {
        const detail = o.detail.replace(/\s+/g, ' ').replace(/\|/g, '\\|').slice(0, 200);
        lines.push(
          `| \`${safe(o.pkg.name)}\` | ${oldsOf(o.pkg).map(safe).join(', ')} → ${targetsOf(o.pkg).map(safe).join(', ')} | ${o.pkg.vulns.map((v) => safe(v.id)).join(', ')} | ${o.result}${detail ? `: ${detail}` : ''} |`,
        );
      }
    } else lines.push('No fixable advisories.');
    const count = (r: Result) => outcomes.filter((o) => o.result === r).length;
    lines.push(
      '',
      `Security PR: ${prLine}`,
      `Packages fixed: ${count('fixed')} · declined: ${count('declined')} · unverified: ${count('unverified')} · unresolvable: ${count('unresolvable')} · failed: ${count('failed')}`,
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

const mainAllow = (ctx: FixCtx) => (ctx.raw.allow as AllowEntry[] | undefined) ?? [];

/**
 * One allow entry per fixed version of `p` that main does not already allow. Each cites the
 * highest-severity advisory its copies need; the others are listed in `reason`.
 */
function allowEntries(ctx: FixCtx, p: Pkg): AllowEntry[] {
  const have = new Set(mainAllow(ctx).map((a) => a.package));
  const out: AllowEntry[] = [];
  for (const t of targetsOf(p)) {
    const pkgId = formatPackageId({ eco: p.eco, name: p.name, version: t });
    if (have.has(pkgId)) continue;
    const vs = [...new Map(p.copies.filter((c) => c.target === t).flatMap((c) => c.vulns).map((v) => [v.id, v])).values()].sort(bySeverity);
    const rest = vs.slice(1).map((v) => v.id).sort();
    out.push({ package: pkgId, advisory: vs[0]!.id, reason: rest.length ? `security fix: ${rest.join(', ')}` : 'security fix', added: ctx.today });
  }
  return out;
}

const errorText = (b: unknown) =>
  (typeof b === 'object' && b && typeof (b as { error?: unknown }).error === 'string' ? (b as { error: string }).error : typeof b === 'string' ? b : JSON.stringify(b)).slice(0, 300);

/**
 * Syncs the run's overlay (ref "audit"): main policy + every package's allow entries, verified by
 * decant (OSV) at sync time. Packages whose entries decant rejects are dropped (recorded as
 * unverified) and the sync is retried once without them; any other failure fails the run.
 * Returns the packages that made it into the overlay.
 */
async function syncOverlay(ctx: FixCtx, pkgs: Pkg[], outcomes: Outcome[]): Promise<Pkg[]> {
  let batch: Pkg[] = [];
  for (const p of pkgs) {
    const check = parsePolicy({ ...ctx.raw, allow: [...mainAllow(ctx), ...allowEntries(ctx, p)] });
    if (check.ok) batch.push(p);
    else outcomes.push({ pkg: p, result: 'failed', detail: `allow entry invalid: ${check.errors.join('; ')}` });
  }
  for (let attempt = 0; batch.length; attempt++) {
    const next = { ...ctx.raw, allow: [...mainAllow(ctx), ...batch.flatMap((p) => allowEntries(ctx, p))] };
    const res = await ctx.client.syncPolicy(ctx.project, next, ctx.sha, OVERLAY_REF);
    if (res.status === 401 || res.status === 403) throw new Error(`decant PUT /api/projects/${ctx.project}/policy: HTTP ${res.status}`);
    if (res.status >= 200 && res.status < 300) return batch;
    const failure = `overlay sync HTTP ${res.status}: ${errorText(res.body)}`;
    const named = (res.body as { entries?: unknown } | null)?.entries;
    const rejected = Array.isArray(named) ? named.filter((e): e is string => typeof e === 'string') : [];
    const why = (p: Pkg) => rejected.filter((e) => idsOf(p).includes(e.split(' ')[0]!));
    const drop = batch.filter((p) => why(p).length);
    if (attempt > 0 || !drop.length) throw new Error(failure);
    for (const p of drop) outcomes.push({ pkg: p, result: 'unverified', detail: `not verified by decant: ${why(p).join('; ')}` });
    batch = batch.filter((p) => !drop.includes(p));
  }
  return batch;
}

/**
 * Applies every package's fix in one working tree, one package at a time. A package that fails or
 * does not reach its targets has its own changes reverted. Returns the fixed packages and the
 * changed files; the working tree is restored afterwards whatever happens.
 */
async function applyAll(ctx: FixCtx, pkgs: Pkg[], outcomes: Outcome[]): Promise<{ fixed: Pkg[]; files: { path: string; contents: string }[] }> {
  const { deps, inputs } = ctx;
  const read = async (abs: string) => ((await deps.fs.exists(abs)) ? await deps.fs.readFile(abs) : null);
  const put = async (abs: string, v: string | null) => (v === null ? deps.fs.rm(abs) : deps.fs.writeFile(abs, v));
  const orig = new Map<string, string | null>();
  const done: { p: Pkg; o: Outcome; dirs: string[] }[] = [];
  const files: { path: string; contents: string }[] = [];
  try {
    for (const p of pkgs) {
      const before = new Map<string, string | null>();
      const track = async (abs: string) => {
        const cur = await read(abs);
        if (!orig.has(abs)) orig.set(abs, cur);
        if (!before.has(abs)) before.set(abs, cur);
      };
      const dirs = [...new Set(p.copies.map((c) => dirname(join(ctx.wd, c.dep.file))))].sort();
      try {
        for (const dir of dirs) {
          if (p.eco === 'npm') await fixNpm(ctx, p, dir, track);
          else await fixGo(ctx, p, dir, track);
        }
        let changed = false;
        for (const [abs, b] of before) if ((await read(abs)) !== b) changed = true;
        if (!changed) throw new PkgError('unresolvable', 'no lockfile changes');
        const o: Outcome = { pkg: p, result: 'fixed', detail: '' };
        outcomes.push(o);
        done.push({ p, o, dirs });
      } catch (e) {
        if (systemic(e)) throw e;
        for (const [abs, b] of before) await put(abs, b);
        const msg = redact((e as Error).message, [inputs.token, inputs.githubToken]);
        const result = e instanceof PkgError ? e.result : 'failed';
        if (result === 'failed') warning(`${safe(p.name)}: ${msg}`);
        outcomes.push({ pkg: p, result, detail: msg });
      }
    }
    // A later package's npm/go run could have moved an earlier one: verify every copy once more.
    for (const d of done) {
      const left: string[] = [];
      for (const dir of d.dirs) left.push(...(await remaining(ctx, d.p, dir)));
      if (left.length) {
        d.o.result = 'unresolvable';
        d.o.detail = `regressed by a later fix in this run: ${left.join('; ')}`;
        warning(`${safe(d.p.name)}: ${d.o.detail}`);
      }
    }
    for (const [abs, b] of orig) {
      const after = await read(abs);
      if (after !== null && after !== b) files.push({ path: ctx.repoPath(abs), contents: after });
    }
  } finally {
    for (const [abs, b] of orig) await put(abs, b);
  }
  return { fixed: done.filter((d) => d.o.result === 'fixed').map((d) => d.p), files };
}

/** Descriptions of the package's copies in `dir` that its advisories still affect. */
async function remaining(ctx: FixCtx, p: Pkg, dir: string): Promise<string[]> {
  if (p.eco === 'npm') {
    const left = await stale(ctx, `${dir}/package-lock.json`, p);
    return left.length ? [`${ctx.repoPath(`${dir}/package-lock.json`)} still locks ${uniqSorted(left.map((c) => c.dep.version), 'npm').map(safe).join(', ')}`] : [];
  }
  const sumAbs = `${dir}/go.sum`;
  const left = parseGoSum(await ctx.deps.fs.readFile(sumAbs), sumAbs).filter((d) => d.name === p.name && stillVulnerable(p, d.version));
  return left.length ? [`${ctx.repoPath(sumAbs)} still has ${left.map((d) => safe(d.version)).join(', ')}`] : [];
}

/** Commits the batch to the one security branch and opens (or refreshes) its PR. Returns a summary line. */
async function publish(
  ctx: FixCtx,
  fixed: Pkg[],
  changed: { path: string; contents: string }[],
  open: Pr | null,
  outcomes: Outcome[],
  unfixed: { vuln: Vuln; dep: Dep }[],
): Promise<string> {
  const { gh } = ctx;
  const ids = fixed.flatMap(idsOf);
  const hash = auditSetHash(ids);
  const added = fixed.flatMap((p) => allowEntries(ctx, p));
  const files = [...changed];
  if (added.length) files.push({ path: ctx.policyRel, contents: `${JSON.stringify({ ...ctx.raw, allow: [...mainAllow(ctx), ...added] }, null, 2)}\n` });

  const vulns = [...new Map(fixed.flatMap((p) => p.vulns).map((v) => [v.id, v])).values()];
  const title = `decant: security fixes (${plural(fixed.length, 'package', 'packages')}, ${plural(vulns.length, 'advisory', 'advisories')})`;
  const sev = maxSev(vulns.map(sevOf));
  // Crossing a major (or 0.x minor) line may break callers: never merge that unattended.
  const majors = fixed.filter((p) => p.copies.some((c) => line(c.dep.version, p.eco) !== line(c.target, p.eco)));
  const approve = SEVERITIES.filter((s) => vulns.some((v) => sevOf(v) === s) && ctx.policy.autoShip[s] !== 'auto');
  const auto = !majors.length && !approve.length;
  const left = outcomes.filter((o) => o.result !== 'fixed' && o.result !== 'declined');
  const body = prBody({ fixed, added, left, unfixed, auto, majors, approve, cooldownDays: ctx.policy.cooldownDays, paths: files.map((f) => f.path), hash });
  const labels = ['decant:security', `decant:${sev}`];

  let pr: { number: number; nodeId: string; url: string };
  let what: string;
  let autoOn = false;
  if (open) {
    let same = markerOf(open.body) === hash;
    for (const f of files) if (same && (await gh.fileAt(f.path, open.headSha)) !== f.contents) same = false;
    if (!same) {
      // Rebuild the branch on the current default head: the fixes were computed against it.
      await gh.updateRef(FIX_BRANCH, ctx.sha);
      await gh.commitFiles(FIX_BRANCH, ctx.sha, title, files);
    }
    await gh.updatePr(open.number, { title, body });
    await gh.addLabels(open.number, labels);
    for (const l of open.labels) if (/^decant:(critical|high|moderate|low)$/.test(l) && l !== labels[1]) await gh.removeLabel(open.number, l);
    pr = { number: open.number, nodeId: open.nodeId, url: `#${open.number}` };
    what = same ? `#${open.number} up to date` : `updated #${open.number}`;
    autoOn = open.autoMerge;
    if (!auto && open.autoMerge) {
      try {
        await gh.disableAutoMerge(open.nodeId);
        what += ' (auto-merge turned off)';
      } catch (e) {
        warning(`#${open.number}: could not disable auto-merge: ${(e as Error).message}`);
      }
    }
  } else {
    try {
      await gh.createBranch(FIX_BRANCH, ctx.sha);
    } catch (e) {
      // A stale branch with no open PR (merged or declined earlier): reset it to the default head.
      if (!/HTTP 422/.test((e as Error).message)) throw e;
      await gh.updateRef(FIX_BRANCH, ctx.sha);
    }
    await gh.commitFiles(FIX_BRANCH, ctx.sha, title, files);
    pr = await gh.openPr({ head: FIX_BRANCH, base: ctx.base, title, body, labels });
    what = `opened #${pr.number}`;
  }
  if (auto && !autoOn) {
    try {
      await gh.enableAutoMerge(pr.nodeId, 'SQUASH');
      what += ' (auto-merge)';
    } catch (e) {
      warning(`${pr.url}: could not enable auto-merge: ${(e as Error).message}`);
      what += ' (auto-merge unavailable)';
    }
  } else if (!auto) what += majors.length ? ' (major upgrade: auto-merge disabled)' : ' (needs approval)';
  notice(`${title}: ${pr.url}`);
  return what;
}

function prBody(b: {
  fixed: Pkg[];
  added: AllowEntry[];
  left: Outcome[];
  unfixed: { vuln: Vuln; dep: Dep }[];
  auto: boolean;
  majors: Pkg[];
  approve: Severity[];
  cooldownDays: number;
  paths: string[];
  hash: string;
}): string {
  const link = (v: Vuln) => `[${safe(v.id)}](${advisoryUrl(v.id)})`;
  const out = [
    `Security fixes from decant audit: ${plural(b.fixed.length, 'package', 'packages')} upgraded to versions that fix their advisories.`,
    '',
    '| Package | From → To | Advisories | Severity |',
    '|---|---|---|---|',
    ...b.fixed.map(
      (p) =>
        `| \`${safe(p.name)}\` | ${oldsOf(p).map(safe).join(', ')} → ${targetsOf(p).map(safe).join(', ')} | ${p.vulns.map(link).join(', ')} | ${maxSev(p.vulns.map(sevOf))} |`,
    ),
    '',
  ];
  const summaries = b.fixed.flatMap((p) => p.vulns.filter((v) => v.summary).map((v) => `- ${link(v)}: ${cell(v.summary, 200)}`));
  if (summaries.length) out.push('<details><summary>Advisory summaries</summary>', '', ...[...new Set(summaries)], '', '</details>', '');
  if (b.left.length) {
    out.push('**Not included** (see the `decant: unfixed advisories` issue):');
    const label: Record<Result, string> = { fixed: 'fixed', declined: 'declined', unverified: 'not verified', unresolvable: 'unresolvable', failed: 'failed' };
    for (const o of b.left) out.push(`- \`${safe(o.pkg.name)}\` ${oldsOf(o.pkg).map(safe).join(', ')}: ${label[o.result]}: ${cell(o.detail)}`);
    out.push('');
  }
  if (b.unfixed.length) {
    const rows = [...new Map(b.unfixed.map((u) => [`${u.vuln.id}|${depKey(u.dep)}`, u])).values()];
    out.push('**No fixed release yet** (tracked in the `decant: unfixed advisories` issue):');
    for (const u of rows.slice(0, 30)) out.push(`- ${link(u.vuln)} \`${safe(u.dep.name)}@${safe(u.dep.version)}\``);
    if (rows.length > 30) out.push(`- …and ${rows.length - 30} more`);
    out.push('');
  }
  if (b.added.length) {
    out.push(
      `**Cooldown skip:** this PR adds \`allow\` entries for ${b.added.map((a) => `\`${safe(a.package)}\``).join(', ')}, each citing its advisory, so the fixed versions ship without waiting out the ${b.cooldownDays}-day cooldown. decant honors each only while OSV lists that version as fixed; none is exempt from the scan.`,
      '',
    );
  }
  out.push('Files:', ...b.paths.map((p) => `- \`${p}\``), '');
  if (b.auto) out.push('Every advisory severity here has autoShip `auto` and no upgrade crosses a major line: auto-merge is on; it merges once the required checks (including the decant scan) pass.');
  else {
    out.push('Auto-merge is off; review and merge.');
    if (b.majors.length) {
      out.push(`- **major upgrade: auto-merge disabled.** ${b.majors.map((p) => `\`${safe(p.name)}\``).join(', ')} crosses a major (or 0.x minor) version line.`);
    }
    for (const s of b.approve) out.push(`- autoShip.${s} is \`approve\`.`);
  }
  out.push('', `<!-- decant-audit-set: ${b.hash} -->`);
  return out.join('\n');
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
    throw new PkgError('failed', `${cmd} ${what} exited ${r.code}: ${why}`);
  }
}

/** Copies of the package in the lockfile at `abs` that its advisories still affect, with their targets. */
async function stale(ctx: FixCtx, abs: string, p: Pkg): Promise<Copy[]> {
  const deps = parsePackageLock(await ctx.deps.fs.readFile(abs), abs, ctx.inputs.decantUrl);
  const out: Copy[] = [];
  for (const d of deps) {
    if (d.name !== p.name) continue;
    const target = targetFor(p.vulns, 'npm', d.name, d.version);
    if (target !== null) out.push({ dep: d, target, vulns: [] });
  }
  return out;
}

async function fixNpm(ctx: FixCtx, p: Pkg, dir: string, track: (abs: string) => Promise<void>): Promise<void> {
  const { deps, inputs } = ctx;
  const lockAbs = `${dir}/package-lock.json`;
  const pkgAbs = `${dir}/package.json`;
  await track(lockAbs);
  await track(pkgAbs);
  const base = inputs.decantUrl.replace(/\/+$/, '');
  const url = new URL(base);
  const registry = `${base}/r/${OVERLAY_REF}/npm/`;
  const userconfig = await ctx.tmpFile('npmrc');
  const env = baseEnv(deps.env, ['PATH', 'HOME', 'RUNNER_TEMP']);
  // --registry on the command line beats any project .npmrc; the token lives only in the 0600 userconfig.
  const common = ['--userconfig', userconfig, '--registry', registry, '--ignore-scripts', '--package-lock-only', '--no-audit', '--no-fund'];
  const npm = (cmd: string, specs: string[]) => run1(deps, 'npm', [cmd, ...common, ...(specs.length ? ['--', ...specs] : [])], dir, env, [inputs.token]);
  await deps.fs.writeFile(userconfig, `registry=${registry}\n//${url.host}${url.pathname.replace(/\/+$/, '')}/r/${OVERLAY_REF}/npm/:_authToken=${inputs.token}\nignore-scripts=true\n`, 0o600);
  try {
    await deps.fs.chmod(userconfig, 0o600);
    const pkgText = (await deps.fs.exists(pkgAbs)) ? await deps.fs.readFile(pkgAbs) : null;
    const pkg = pkgText === null ? null : (JSON.parse(pkgText) as Record<string, Record<string, string> | undefined>);
    const declared = !!pkg && ['dependencies', 'devDependencies', 'optionalDependencies'].some((k) => pkg[k]?.[p.name] !== undefined);
    // The direct dependency's own copy is the top-level node_modules/<name> entry: bump it to the
    // highest fix any of the package's advisories needs on its line.
    const lock = JSON.parse(await deps.fs.readFile(lockAbs)) as { packages?: Record<string, { version?: string }> };
    const topVersion = lock.packages?.[`node_modules/${p.name}`]?.version;
    const topTarget = declared && topVersion ? targetFor(p.vulns, 'npm', p.name, topVersion) : null;
    if (topTarget !== null) {
      await npm('install', [`${p.name}@${topTarget}`]);
    } else {
      await npm('update', [p.name]);
      const left = await stale(ctx, lockAbs, p);
      if (left.length) {
        if (!pkg || pkgText === null) throw new PkgError('unresolvable', `${ctx.repoPath(lockAbs)}: no package.json for an override`);
        // One selector per version line, each pinned to the highest target on that line.
        const overrides: Record<string, string> = { ...(pkg.overrides ?? {}) };
        const byKey = new Map<string, string>();
        for (const c of left) {
          const k = overrideKey(p.name, c.dep.version);
          const prev = byKey.get(k);
          if (!prev || compareVersions(c.target, prev, 'npm') > 0) byKey.set(k, c.target);
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
  const left = await remaining(ctx, p, dir);
  if (left.length) throw new PkgError('unresolvable', left.join('; '));
}

async function fixGo(ctx: FixCtx, p: Pkg, dir: string, track: (abs: string) => Promise<void>): Promise<void> {
  const { deps, inputs } = ctx;
  await track(`${dir}/go.mod`);
  await track(`${dir}/go.sum`);
  // MVS selects one version per module: the highest target needed by any copy in this module.
  const here = p.copies.filter((c) => dirname(join(ctx.wd, c.dep.file)) === dir).map((c) => c.target);
  const target = uniqSorted(here.length ? here : targetsOf(p), 'go').at(-1)!;
  const base = inputs.decantUrl.replace(/\/+$/, '');
  const netrc = await ctx.tmpFile('netrc');
  const env = {
    ...baseEnv(deps.env, ['PATH', 'HOME', 'GOPATH', 'GOCACHE']),
    NETRC: netrc,
    GOPROXY: `${base}/r/${OVERLAY_REF}/go`,
    GOFLAGS: '-mod=mod',
  };
  await deps.fs.writeFile(netrc, `machine ${new URL(base).hostname} login decant password ${inputs.token}\n`, 0o600);
  try {
    await deps.fs.chmod(netrc, 0o600);
    await run1(deps, 'go', ['get', '--', `${p.name}@${target}`], dir, env, [inputs.token]);
    await run1(deps, 'go', ['mod', 'tidy'], dir, env, [inputs.token]);
  } finally {
    await deps.fs.rm(netrc);
  }
  const left = await remaining(ctx, p, dir);
  if (left.length) throw new PkgError('unresolvable', left.join('; '));
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

function unfixedBody(items: { vuln: Vuln; dep: Dep; reason: string }[]): string {
  const rows = [...new Map(items.map((i) => [`${i.vuln.id}|${depKey(i.dep)}|${i.dep.file}`, i])).values()].sort((a, b) =>
    a.vuln.id < b.vuln.id ? -1 : a.vuln.id > b.vuln.id ? 1 : 0,
  );
  return [
    'Advisories affecting locked versions that decant could not fix automatically: no usable fixed release, or the fix could not be verified or resolved. decant updates this issue daily and closes it when none remain.',
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
