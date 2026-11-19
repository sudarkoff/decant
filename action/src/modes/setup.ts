import { appendSummary, error, exportVar, mask, warning } from '../gh-io';
import type { ModeCtx } from '../inputs';

function fail(msg: string): number {
  error(msg);
  process.stderr.write(`${msg}\n`);
  return 1;
}

export async function run({ deps, inputs }: ModeCtx): Promise<number> {
  mask(inputs.token);
  const env = deps.env;
  const home = env.HOME;
  if (!home) return fail('HOME is not set');
  const npmrc = `${home}/.npmrc`;
  const netrc = `${home}/.netrc`;

  // The CI runner is ephemeral, so an existing ~/.npmrc is replaced entirely rather than merged.
  if (inputs.bypass) {
    // Emergency last resort: a deliberate manual step, never automatic. Writes no token.
    if (!inputs.bypassReason) return fail('bypass requires bypass-reason');
    await deps.fs.writeFile(npmrc, 'registry=https://registry.npmjs.org/\nignore-scripts=true\n');
    exportVar('GOPROXY', 'https://proxy.golang.org', env);
    const actor = env.GITHUB_ACTOR ?? '';
    warning(`decant BYPASSED by ${actor}: ${inputs.bypassReason}`);
    const runUrl = `${env.GITHUB_SERVER_URL ?? ''}/${env.GITHUB_REPOSITORY ?? ''}/actions/runs/${env.GITHUB_RUN_ID ?? ''}`;
    appendSummary(`## ⚠️ decant bypassed\n\nActor: ${actor} · Reason: ${inputs.bypassReason} · Run: ${runUrl}`, env);
    return 0;
  }

  if (!inputs.token) return fail('token is required (read token)');
  const base = inputs.decantUrl.replace(/\/+$/, '');
  const host = new URL(base).host;
  await deps.fs.writeFile(npmrc, `registry=${base}/npm/\n//${host}/npm/:_authToken=${inputs.token}\nignore-scripts=true\n`);
  await deps.fs.writeFile(netrc, `machine ${host} login decant password ${inputs.token}\n`, 0o600);
  exportVar('GOPROXY', `${base}/go`, env);
  return 0;
}
