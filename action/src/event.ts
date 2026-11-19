import type { ActionDeps } from './deps';

export type Payload = {
  action?: string;
  pull_request?: {
    number?: number;
    base?: { sha?: string };
    head?: { sha?: string; repo?: { full_name?: string } | null };
  };
  repository?: { default_branch?: string; full_name?: string };
};

/** The event payload at GITHUB_EVENT_PATH ({} when unset). Throws a readable error if unreadable. */
export async function readPayload(deps: ActionDeps): Promise<Payload> {
  const p = deps.env.GITHUB_EVENT_PATH;
  if (!p) return {};
  try {
    return JSON.parse(await deps.fs.readFile(p)) as Payload;
  } catch {
    throw new Error(`cannot read event payload at ${p}`);
  }
}

/** A PR whose head repo is not this repo (or is deleted): GitHub gives it no secrets. */
export function isForkPr(payload: Payload): boolean {
  const head = payload.pull_request?.head?.repo;
  return !head || head.full_name !== payload.repository?.full_name;
}
