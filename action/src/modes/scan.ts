import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { formatPackageId } from '../../../src/ids';
import { parsePolicy, SEVERITIES, type Severity } from '../../../src/policy/schema';
import { decant, type DecantClient, type Verdict, type VerdictResult } from '../decant-client';
import type { ActionDeps } from '../deps';
import { isForkPr, readPayload, type Payload } from '../event';
import { fileAtCommit as baseFile, SHA_RE } from '../git';
import { appendSummary, error, mask, notice, setOutput, warning } from '../gh-io';
import { github } from '../github';
import { actionDir, GUARDDOG_VERSION, installGuardDog, scanGo, scanNpm, type GuardDog } from '../guarddog';
import type { ModeCtx } from '../inputs';
import { containsDecantUrls, diffDeps, findLockfileTree, parseGoSum, parsePackageLock, type Dep } from '../lockfiles';
import { createOsv, depKey, type Vuln } from '../osv';
import { goPublishTime, npmPublishTime } from '../registries';

export const MARKER = '<!-- decant-scan -->';
const MAX_DEPS = 500;
const CONCURRENCY = 4;
const REVIEWED = 'decant:reviewed';
const SECURITY = 'decant:security';
const OSV_SCANNER_VERSION = 'api.osv.dev/v1';
const COMMENT_LIMIT = 60_000; // GitHub caps comment bodies at 65536 chars
const SEV_RANK: Record<Severity | 'unknown', number> = { low: 1, moderate: 2, unknown: 2, high: 3, critical: 4 };
const RESULT_RANK: Record<VerdictResult, number> = { clean: 0, flagged: 1, malicious: 2 };

function fail(msg: string): number {
  error(msg);
  process.stderr.write(`${msg}\n`);
  return 1;
}

type Row = {
  dep: Dep;
  osv: string;
  guarddog: string;
  vulns: Vuln[];
  problems: string[];
  notes: string[];
  warn: boolean;
  flagged: boolean;
};

/** Package names and ids in the report come from the PR's lockfile: keep only harmless characters. */
const safe = (s: string) => s.replace(/[^A-Za-z0-9@._~/+:-]/g, '?');

const isPackageLock = (rel: string) => rel === 'package-lock.json' || rel.endsWith('/package-lock.json');

/** POSIX single-quoting for a path in a copy-paste hint. */
const shellQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** Events after which an earlier decant:reviewed no longer covers the PR: new commits, reopen, base change. */
function newReviewScope(p: Payload): boolean {
  return p.action === 'synchronize' || p.action === 'reopened' || (p.action === 'edited' && !!p.changes?.base);
}

const fmtTime = (d: Date) => `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;

async function pool<T>(items: T[], n: number, fn: (x: T, i: number) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]!, i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
}

function parseLock(rel: string, text: string, decantUrl: string): Dep[] {
  return isPackageLock(rel) ? parsePackageLock(text, rel, decantUrl) : parseGoSum(text, rel);
}

async function cooldownNote(deps: ActionDeps, dep: Dep, cooldownDays: number): Promise<string> {
  try {
    const t = dep.eco === 'npm' ? await npmPublishTime(deps.fetch, dep.name, dep.version) : await goPublishTime(deps.fetch, dep.name, dep.version);
    if (t) return `waiting for cooldown until ${fmtTime(new Date(t.getTime() + cooldownDays * 86_400_000))}`;
  } catch {
    // the date is informational only
  }
  return 'waiting for cooldown (publish time unknown)';
}

function render(rows: Row[], pass: boolean, failOn: string, ref: string, limit = Infinity, note = ''): string {
  const head = [
    MARKER,
    `## decant scan: ${pass ? '✅ pass' : '❌ fail'}`,
    '',
    ...(note ? [note, ''] : []),
    `${rows.length} new dependency version${rows.length === 1 ? '' : 's'} (ref \`${ref}\`, fail-on \`${failOn}\`).`,
    '',
    '| Package | Source | OSV | GuardDog | Vulns | Status |',
    '|---|---|---|---|---|---|',
  ].join('\n');
  const lines: string[] = [];
  let size = head.length;
  for (const [i, r] of rows.entries()) {
    const vulns = r.vulns.length ? r.vulns.map((v) => `${safe(v.id)} (${v.malicious ? 'malicious' : v.severity})`).join(', ') : '—';
    const status = r.problems.length
      ? `❌ ${r.problems.join('; ')}`
      : r.warn
        ? `⚠️ ${r.notes.join('; ')}`
        : `✅ ${r.notes.length ? r.notes.join('; ') : 'ok'}`;
    const source = r.dep.source === 'registry' ? r.dep.eco : 'other';
    const line = `| \`${safe(r.dep.name)}@${safe(r.dep.version)}\` | ${source} | ${r.osv} | ${r.guarddog} | ${vulns} | ${status} |`;
    if (size + line.length + 1 > limit) {
      lines.push(`\n… and ${rows.length - i} more (see the job summary).`);
      break;
    }
    lines.push(line);
    size += line.length + 1;
  }
  return `${head}\n${lines.join('\n')}\n`;
}

/** Lockfiles (relative to wd) that differ from base; symlinked ones count as changed (never followed). */
async function changedLockfiles(deps: ActionDeps, wd: string, baseSha: string): Promise<string[]> {
  const tree = await findLockfileTree(wd, deps.fs);
  const out = tree.symlinks.map((l) => l.path);
  for (const rel of tree.files) {
    if ((await baseFile(deps, wd, baseSha, rel)) !== (await deps.fs.readFile(join(wd, rel)))) out.push(rel);
  }
  return out.map(safe);
}

export async function run({ deps, inputs }: ModeCtx): Promise<number> {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.githubToken);
  // Every failure sets result=fail, so `audit` never reads a missing output as anything else.
  const stop = (msg: string) => {
    setOutput('result', 'fail', env);
    return fail(msg);
  };

  if (env.GITHUB_EVENT_NAME !== 'pull_request') return stop(`scan runs on pull_request events, not ${env.GITHUB_EVENT_NAME ?? '(none)'}`);
  let payload;
  try {
    payload = await readPayload(deps);
  } catch (e) {
    return stop((e as Error).message);
  }
  const n = payload.pull_request?.number;
  if (typeof n !== 'number') return stop('event payload has no pull_request.number');
  const baseSha = payload.pull_request?.base?.sha ?? '';
  if (!SHA_RE.test(baseSha)) return stop('event payload has no valid pull_request.base.sha');
  const wd = inputs.workingDirectory;
  if (!inputs.token) {
    if (!isForkPr(payload)) return stop('token is required on pull requests (ci token)');
    // A fork PR gets no secrets, so it cannot be scanned; a lockfile diff needs none (git show).
    try {
      const changed = await changedLockfiles(deps, wd, baseSha);
      if (changed.length) return stop(`fork changes lockfiles (${changed.join(', ')}); push the branch to this repo to scan it`);
    } catch (e) {
      return stop(`decant scan: ${(e as Error).message}`);
    }
    notice('fork PR changes no lockfile; nothing to scan');
    setOutput('result', 'pass', env);
    return 0;
  }
  if (!inputs.githubToken) return stop('github-token is required');
  if (!SEVERITIES.includes(inputs.failOn as Severity)) return stop(`fail-on must be one of ${SEVERITIES.join(', ')}`);
  const failOn = inputs.failOn as Severity;

  let cooldownDays = 7;
  const policyFile = join(wd, inputs.policyPath);
  if (await deps.fs.exists(policyFile)) {
    let parsed;
    try {
      parsed = parsePolicy(JSON.parse(await deps.fs.readFile(policyFile)));
    } catch (e) {
      return stop(`${policyFile} is not valid JSON: ${(e as Error).message}`);
    }
    if (!parsed.ok) return stop(`invalid policy:\n${parsed.errors.map((m) => `- ${m}`).join('\n')}`);
    cooldownDays = parsed.policy.cooldownDays;
  }

  const ref = `pr-${n}`;
  const gh = github(deps.fetch, inputs.githubToken, env.GITHUB_REPOSITORY ?? '', {
    selfLogin: env.DECANT_GITHUB_LOGIN || 'github-actions[bot]',
  });

  try {
    // A review covers only the commits (and base) that existed when decant:reviewed was added.
    if (newReviewScope(payload)) {
      const hit = (await gh.prLabels(n)).find((l) => l.toLowerCase() === REVIEWED);
      if (hit) {
        await gh.removeLabel(n, hit);
        notice(`${payload.action === 'synchronize' ? 'new commits' : payload.action === 'reopened' ? 'reopened' : 'base changed'}: ${REVIEWED} removed; re-review required`);
      }
    }

    // 1. New dependency versions per changed lockfile.
    const added: Dep[] = [];
    const withDecantUrls: string[] = [];
    const tree = await findLockfileTree(wd, deps.fs);
    if (tree.symlinks.length) {
      for (const l of tree.symlinks) {
        const msg = `${join(wd, l.path)}: ${l.dir ? 'symlinked directory' : 'lockfile is a symlink'}; not supported`;
        error(msg);
        process.stderr.write(`${msg}\n`);
      }
      return stop(`${tree.symlinks.length} symlink(s) in ${wd}; decant does not scan through symlinks`);
    }
    for (const rel of tree.files) {
      const abs = join(wd, rel);
      const head = await deps.fs.readFile(abs);
      const base = await baseFile(deps, wd, baseSha, rel);
      if (base === head) continue;
      if (isPackageLock(rel) && containsDecantUrls(head, inputs.decantUrl)) {
        withDecantUrls.push(abs);
        continue;
      }
      let headDeps: Dep[];
      try {
        headDeps = parseLock(rel, head, inputs.decantUrl);
      } catch (e) {
        return stop(`${abs}: ${(e as Error).message}`);
      }
      let baseDeps: Dep[] = [];
      try {
        if (base !== null) baseDeps = parseLock(rel, base, inputs.decantUrl);
      } catch {
        // unparseable base (e.g. lockfile v1): every head dep counts as new
      }
      added.push(...diffDeps(baseDeps, headDeps));
    }
    if (withDecantUrls.length) {
      const url = inputs.decantUrl.replace(/\/+$/, '');
      for (const f of withDecantUrls) {
        error(`${f} contains decant URLs`, f);
        const q = shellQuote(f);
        const qb = shellQuote(`${f}.bak`);
        process.stderr.write(`${f} contains decant URLs; run: sed -i.bak -E 's#${url}(/r/[^/]+)?/npm/#https://registry.npmjs.org/#g' ${q} && rm ${qb}\n`);
      }
      setOutput('result', 'fail', env);
      return 1;
    }

    // 2. One row per registry package version (deduped across lockfiles), one per other-source entry.
    const registry = new Map<string, Dep>();
    const rows: Row[] = [];
    const row = (dep: Dep): Row => ({ dep, osv: '—', guarddog: '—', vulns: [], problems: [], notes: [], warn: false, flagged: false });
    for (const d of added) {
      if (d.source === 'registry') {
        if (!registry.has(formatPackageId(d))) registry.set(formatPackageId(d), d);
        continue;
      }
      const r = row(d);
      if (d.mismatch) r.problems.push('resolved URL does not match package');
      else {
        r.warn = true;
        r.notes.push('not from the registry; not scanned');
        warning(`${safe(d.name)}@${safe(d.version)} in ${d.file} is not from the registry and was not scanned`, d.file);
      }
      rows.push(r);
    }
    if (registry.size > MAX_DEPS) return stop(`too many new dependencies (${registry.size}); split the change`);

    // 3. OSV for all at once, then verdicts / download / GuardDog per package.
    const regDeps = [...registry.values()];
    const vulnsByKey = regDeps.length ? await createOsv(deps.fetch).queryVulns(regDeps) : new Map<string, Vuln[]>();
    const client = decant(deps.fetch, inputs.decantUrl, inputs.token);
    const scratch = `${env.RUNNER_TEMP || tmpdir()}/decant-scan`;
    let gd: Promise<GuardDog> | null = null;
    const guarddog = () => {
      gd ??= installGuardDog(deps.exec, deps.fs.readFile, `${env.RUNNER_TEMP || tmpdir()}/decant-guarddog`, actionDir(env.GITHUB_ACTION_PATH), env);
      return gd;
    };
    if (regDeps.length) await deps.fs.mkdir(scratch);
    const blocked = new Set(regDeps.length ? (await client.blocks()).map((b) => b.package) : []);

    const regRows = regDeps.map(row);
    await pool(regRows, CONCURRENCY, async (r, i) => {
      try {
        await evaluate(r, i);
      } catch (e) {
        const msg = (e as Error).message;
        error(`${safe(r.dep.name)}@${safe(r.dep.version)}: ${msg}`);
        r.problems.push('scan error (see log)');
      }
    });

    async function evaluate(r: Row, i: number): Promise<void> {
      const d = r.dep;
      const id = formatPackageId(d);
      const problem = (p: string) => {
        if (!r.problems.includes(p)) r.problems.push(p);
      };
      if (blocked.has(id)) problem('blocked by decant');
      const cached = await client.getVerdicts(id);
      const of = (s: string): Verdict | undefined => cached.find((v) => v.scanner === s);
      if (cached.some((v) => v.result === 'malicious')) r.problems.push(`malicious (${cached.filter((v) => v.result === 'malicious').map((v) => safe(v.scanner)).join(', ')})`);

      // OSV: always fresh (cheap, batched); the verdict records only MAL- (vulns go in the report).
      r.vulns = vulnsByKey.get(depKey(d)) ?? [];
      const mal = r.vulns.filter((v) => v.malicious).map((v) => v.id);
      const osvResult: VerdictResult = mal.length ? 'malicious' : 'clean';
      const cOsv = of('osv');
      if (!cOsv || RESULT_RANK[osvResult] > RESULT_RANK[cOsv.result]) {
        await client.putVerdict({ package: id, scanner: 'osv', scannerVersion: OSV_SCANNER_VERSION, result: osvResult, details: mal.length ? { malicious: mal } : undefined });
      }
      const osvWorst = cOsv && RESULT_RANK[cOsv.result] > RESULT_RANK[osvResult] ? cOsv.result : osvResult;
      r.osv = osvWorst;
      if (osvResult === 'malicious' && !r.problems.some((p) => p.startsWith('malicious'))) r.problems.push('malicious (osv)');
      const bad = r.vulns.filter((v) => !v.malicious && SEV_RANK[v.severity] >= SEV_RANK[failOn]);
      if (bad.length) r.problems.push(`vulnerable (≥ ${failOn})`);

      const unavailable = async (status: 'cooldown' | 'blocked' | 'missing') => {
        if (status === 'cooldown') problem(await cooldownNote(deps, d, cooldownDays));
        else problem(status === 'blocked' ? 'blocked by decant' : 'not found in decant');
      };

      // GuardDog: a cached verdict skips the download and scan, but not the availability check.
      const cGd = of('guarddog');
      let gdResult: VerdictResult | null = null;
      if (cGd) {
        gdResult = cGd.result;
        r.guarddog = `${cGd.result} (cached)`;
        const status = await client.availability(d.eco, d.name, d.version, ref);
        if (status !== 'ok') await unavailable(status);
      } else {
        const dl = d.eco === 'npm' ? await client.downloadNpm(d.name, d.version, ref) : await client.downloadGo(d.name, d.version, ref);
        if (dl.status !== 'ok') {
          await unavailable(dl.status);
        } else {
          const path = `${scratch}/${i}.${d.eco === 'npm' ? 'tgz' : 'zip'}`;
          await deps.fs.writeBytes(path, dl.bytes);
          const { bin } = await guarddog();
          const res = d.eco === 'npm' ? await scanNpm(deps.exec, bin, path) : await scanGo(deps.exec, bin, path);
          await client.putVerdict({ package: id, scanner: 'guarddog', scannerVersion: GUARDDOG_VERSION, result: res.result, details: res.details });
          gdResult = res.result;
          r.guarddog = res.result;
          if (res.details.length) r.notes.push(`GuardDog: ${res.details.map(safe).join(', ')}`);
        }
      }
      if (gdResult === 'flagged') r.flagged = true;
    }

    // 4. Flagged needs a writer's decant:reviewed.
    const anyFlagged = regRows.some((r) => r.flagged);
    const reviewed = anyFlagged ? await gh.labelAddedByWriter(n, REVIEWED) : false;
    for (const r of regRows) {
      if (!r.flagged) continue;
      if (reviewed) r.notes.unshift(`flagged; ${REVIEWED} by a writer`);
      else r.problems.push(`flagged by GuardDog (needs ${REVIEWED} from a writer)`);
    }

    // A flagged security fix never auto-merges: decant:reviewed can turn the check green, but a human merges.
    let securityNote = '';
    if (anyFlagged && (await gh.prLabels(n)).some((l) => l.toLowerCase() === SECURITY)) {
      const pr = await gh.getPr(n);
      if (pr.autoMerge) {
        await gh.disableAutoMerge(pr.nodeId);
        notice('flagged security PR: auto-merge disabled; merge it manually after review');
      }
      securityNote = `**Auto-merge is off:** a dependency was flagged by GuardDog, so this \`${SECURITY}\` PR must be merged manually after review.`;
    }

    const all = [...regRows, ...rows];
    const pass = all.every((r) => r.problems.length === 0);
    setOutput('result', pass ? 'pass' : 'fail', env);
    setOutput('flagged', anyFlagged ? 'true' : 'false', env);
    if (all.length === 0) {
      const body = `${MARKER}\n## decant scan: ✅ pass\n\nNo new dependency versions.`;
      appendSummary(body, env);
      // Replace an earlier report (e.g. the deps were since removed), but never start a new comment.
      await gh.updateComment(n, MARKER, body);
      return 0;
    }
    appendSummary(render(all, pass, failOn, ref, Infinity, securityNote), env);
    await gh.upsertComment(n, MARKER, render(all, pass, failOn, ref, COMMENT_LIMIT, securityNote));
    if (!pass) return fail(`decant scan failed: ${all.filter((r) => r.problems.length).length} dependency version(s) need attention`);
    return 0;
  } catch (e) {
    return stop(`decant scan: ${(e as Error).message}`);
  }
}
