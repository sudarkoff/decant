import { join } from 'node:path';
import { parsePolicy, type Policy } from '../../../src/policy/schema';
import { decant, type DecantClient } from '../decant-client';
import { capSummary, dependencySummary } from '../dep-summary';
import type { ActionDeps } from '../deps';
import { isForkPr, readPayload, type Payload } from '../event';
import { error, mask, notice, setOutput, warning } from '../gh-io';
import { fileAtCommit, SHA_RE } from '../git';
import type { ModeCtx } from '../inputs';

function fail(msg: string): number {
  error(msg);
  process.stderr.write(`${msg}\n`);
  return 1;
}

type Raw = Record<string, unknown>;

/**
 * The overlay a PR may sync: the base branch's policy (cooldownDays, autoShip, project) plus the
 * PR's new allow entries and the union of both block lists. The Worker rejects any other change
 * to an overlay, so policy edits in the PR wait for the merge. `changed` is true when the PR's
 * file changes something the overlay cannot carry.
 */
export function overlayPolicy(baseRaw: Raw, base: Policy, prRaw: Raw, pr: Policy): { raw: Raw; changed: boolean } {
  const baseAllow = new Set(base.allow.map((a) => a.package));
  const baseBlock = new Set(base.block.map((b) => b.package));
  const prBlock = new Set(pr.block.map((b) => b.package));
  const prAllowRaw = (prRaw.allow as unknown[] | undefined) ?? [];
  const prBlockRaw = (prRaw.block as unknown[] | undefined) ?? [];
  const allow = [...((baseRaw.allow as unknown[] | undefined) ?? []), ...prAllowRaw.filter((_, i) => !baseAllow.has(pr.allow[i]!.package))];
  const block = [...((baseRaw.block as unknown[] | undefined) ?? []), ...prBlockRaw.filter((_, i) => !baseBlock.has(pr.block[i]!.package))];
  const changed =
    pr.cooldownDays !== base.cooldownDays ||
    JSON.stringify(pr.autoShip) !== JSON.stringify(base.autoShip) ||
    base.block.some((b) => !prBlock.has(b.package));
  return { raw: { ...baseRaw, allow, block }, changed };
}

function parseRaw(text: string): { raw: Raw; policy: Policy } | null {
  try {
    const raw = JSON.parse(text) as unknown;
    const p = parsePolicy(raw);
    return p.ok ? { raw: raw as Raw, policy: p.policy } : null;
  } catch {
    return null;
  }
}

function errorText(b: unknown): string {
  return typeof b === 'object' && b !== null && typeof (b as { error?: unknown }).error === 'string'
    ? (b as { error: string }).error
    : typeof b === 'string'
      ? b
      : JSON.stringify(b);
}

const REPO_RE = /^[A-Za-z0-9-]+\/(?!\.\.?$)[A-Za-z0-9._-]+$/; // owner/name; name is never . or ..

/**
 * Default branch only: send the lockfiles' dependency summary (names, versions, direct or not, and which
 * direct dependencies pull each one in) for the dashboard. Best effort: every failure is a warning.
 */
async function sendDependencySummary(deps: ActionDeps, client: DecantClient, wd: string, project: string, sha: string): Promise<void> {
  try {
    const s = await dependencySummary(wd, deps.fs);
    for (const w of s.warnings) warning(`dependency summary: ${w}`);
    const c = capSummary(sha, s.deps);
    if (c.trimmed === 'via') warning('dependency summary is over 1 MB; sent without the held-back-by names');
    if (c.trimmed === 'transitive') warning('dependency summary is over 1 MB; sent direct dependencies only');
    // The repo (owner/name) lets the dashboard link to the project's open PRs; decant rejects anything else.
    const repo = deps.env.GITHUB_REPOSITORY ?? '';
    const res = await client.syncDeps(project, sha, c.deps, REPO_RE.test(repo) ? repo : undefined);
    if (res.status < 200 || res.status >= 300) warning(`decant did not store the dependency summary (HTTP ${res.status}): ${errorText(res.body)}`);
  } catch (e) {
    warning(`dependency summary not sent: ${e instanceof Error ? e.message : String(e)}`);
  }
}

export async function run({ deps, inputs }: ModeCtx): Promise<number> {
  const env = deps.env;
  mask(inputs.token);
  mask(inputs.syncToken);

  const policyFile = join(inputs.workingDirectory, inputs.policyPath);
  if (!(await deps.fs.exists(policyFile))) return fail(`decant.json not found at ${policyFile}`);
  let raw: unknown;
  try {
    raw = JSON.parse(await deps.fs.readFile(policyFile));
  } catch (e) {
    return fail(`${policyFile} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
  const parsed = parsePolicy(raw);
  if (!parsed.ok) return fail(`invalid policy:\n${parsed.errors.map((m) => `- ${m}`).join('\n')}`);

  let payload: Payload;
  try {
    payload = await readPayload(deps);
  } catch (e) {
    return fail((e as Error).message);
  }

  const event = env.GITHUB_EVENT_NAME ?? '';
  let ref: string;
  let token: string;
  let policy = parsed.policy;
  if (event === 'pull_request') {
    const n = payload.pull_request?.number;
    if (typeof n !== 'number') return fail('event payload has no pull_request.number');
    ref = `pr-${n}`;
    token = inputs.token;
    if (!token) {
      if (isForkPr(payload)) {
        notice('fork PR has no secrets; decant sync skipped');
        return 0;
      }
      return fail('token is required on pull requests');
    }
    const baseSha = payload.pull_request?.base?.sha ?? '';
    if (!SHA_RE.test(baseSha)) return fail('event payload has no valid pull_request.base.sha');
    let baseText: string | null;
    try {
      baseText = await fileAtCommit(deps, inputs.workingDirectory, baseSha, inputs.policyPath);
    } catch (e) {
      return fail((e as Error).message);
    }
    const base = baseText === null ? null : parseRaw(baseText);
    if (baseText !== null && !base) warning(`${inputs.policyPath} at the base commit is invalid; syncing the PR's policy as is`);
    if (base) {
      const o = overlayPolicy(base.raw, base.policy, raw as Raw, parsed.policy);
      raw = o.raw;
      policy = base.policy;
      if (o.changed) notice('policy changes in decant.json take effect after merge');
    }
  } else if (event === 'push' || event === 'workflow_dispatch' || event === 'schedule') {
    // Match the full ref: GITHUB_REF_NAME is also set for tags, so a tag named like the branch must not pass.
    const branch = payload.repository?.default_branch ?? '';
    if (!branch || env.GITHUB_REF !== `refs/heads/${branch}`) {
      if (event === 'workflow_dispatch') return fail('sync must run on the default branch');
      notice('not the default branch; nothing to sync');
      return 0;
    }
    ref = branch;
    token = inputs.syncToken;
    if (!token) return fail('sync-token is required on the default branch');
  } else {
    return fail(`unsupported event ${event}`);
  }

  const project = inputs.project || policy.project;
  const client = decant(deps.fetch, inputs.decantUrl, token, { sleep: deps.sleep });
  const res = await client.syncPolicy(project, raw, env.GITHUB_SHA ?? '', ref);
  if (res.status < 200 || res.status >= 300) return fail(`decant rejected the policy (HTTP ${res.status}): ${errorText(res.body)}`);
  if (event !== 'pull_request') await sendDependencySummary(deps, client, inputs.workingDirectory, project, env.GITHUB_SHA ?? '');
  setOutput('ref', ref, env);
  return 0;
}
