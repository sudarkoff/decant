import type { RequestCtx } from '../auth';
import type { Deps, Ecosystem, Env } from '../types';
import { decide, type Decision } from './decide';
import { blockedVersions, loadPolicyView, type PinnedTime } from './store';

/** Loads blocks and the policy view once; returns a per-version decision function. */
export async function decider(env: Env, deps: Deps, rc: RequestCtx, eco: Ecosystem, name: string) {
  const [blocks, view] = await Promise.all([blockedVersions(env, eco, name), loadPolicyView(env, rc.projectId, rc.ref, eco, name)]);
  const allowed = view.allowed;
  const now = deps.now();
  return (version: string, pin: PinnedTime | null | undefined): Decision =>
    decide({
      publishTime: pin?.publishTime ?? null,
      conflict: pin?.conflict ?? false,
      blocked: blocks.has(version),
      allowed: allowed.has(version),
      cooldownDays: view.cooldownDays,
      now,
    });
}
