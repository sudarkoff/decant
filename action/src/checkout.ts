import type { ActionDeps } from './deps';
import type { GitHubClient } from './github';

/**
 * Modes that commit checkout content (audit, adopt) must run on a checkout of the live default
 * branch head; otherwise they would write older files on top of newer ones. Returns the default
 * branch and the checkout sha (the base for new branches), or an error message.
 */
export async function defaultHeadCheckout(
  gh: GitHubClient,
  env: ActionDeps['env'],
  mode: string,
): Promise<{ ok: true; base: string; sha: string } | { ok: false; message: string }> {
  const base = await gh.defaultBranch();
  if (env.GITHUB_REF !== `refs/heads/${base}`) {
    return { ok: false, message: `decant ${mode} runs on the default branch (${base}), not ${env.GITHUB_REF || '(unknown ref)'}` };
  }
  const sha = env.GITHUB_SHA ?? '';
  if (!sha || (await gh.branchHead(base)) !== sha) return { ok: false, message: 'default branch moved since checkout; re-run' };
  return { ok: true, base, sha };
}
