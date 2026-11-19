import { join } from 'node:path';
import { parsePolicy } from '../../../src/policy/schema';
import { decant } from '../decant-client';
import { isForkPr, readPayload, type Payload } from '../event';
import { error, mask, notice, setOutput } from '../gh-io';
import type { ModeCtx } from '../inputs';

function fail(msg: string): number {
  error(msg);
  process.stderr.write(`${msg}\n`);
  return 1;
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
  } else if (event === 'push') {
    const branch = env.GITHUB_REF_NAME || (env.GITHUB_REF ?? '').replace(/^refs\/heads\//, '');
    if (!branch || branch !== payload.repository?.default_branch) {
      notice('not the default branch; nothing to sync');
      return 0;
    }
    ref = branch;
    token = inputs.syncToken;
    if (!token) return fail('sync-token is required on the default branch');
  } else {
    return fail(`unsupported event ${event}`);
  }

  const project = inputs.project || parsed.policy.project;
  const res = await decant(deps.fetch, inputs.decantUrl, token).syncPolicy(project, raw, env.GITHUB_SHA ?? '', ref);
  if (res.status < 200 || res.status >= 300) {
    const b = res.body;
    const msg =
      typeof b === 'object' && b !== null && typeof (b as { error?: unknown }).error === 'string'
        ? (b as { error: string }).error
        : typeof b === 'string'
          ? b
          : JSON.stringify(b);
    return fail(`decant rejected the policy (HTTP ${res.status}): ${msg}`);
  }
  setOutput('ref', ref, env);
  return 0;
}
