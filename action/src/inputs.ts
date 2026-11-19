import { getInput } from './gh-io';
import type { ActionDeps } from './deps';

export type Inputs = {
  mode: string;
  decantUrl: string;
  token: string;
  syncToken: string;
  githubToken: string;
  policyPath: string;
  failOn: string;
  workingDirectory: string;
  bypass: boolean;
  bypassReason: string;
  /** Empty means: policy.project if a policy exists, else the repo name. */
  project: string;
};

export type ModeCtx = { deps: ActionDeps; inputs: Inputs };

export function readInputs(env: ActionDeps['env']): Inputs {
  const g = (n: string, d = ''): string => getInput(n, env) || d;
  return {
    mode: g('mode'),
    decantUrl: g('decant-url'),
    token: g('token'),
    syncToken: g('sync-token'),
    githubToken: g('github-token'),
    policyPath: g('policy-path', 'decant.json'),
    failOn: g('fail-on', 'high'),
    workingDirectory: g('working-directory', '.'),
    bypass: g('bypass', 'false').toLowerCase() === 'true',
    bypassReason: g('bypass-reason'),
    project: g('project'),
  };
}
