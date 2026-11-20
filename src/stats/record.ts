import { noRetry } from '../d1-retry';
import type { Ecosystem, Env } from '../types';

export type Kind = 'metadata' | 'download';
export type Outcome = 'served' | 'cooldown' | 'blocked' | 'stale' | 'failed';

/**
 * Runs `work` after the response via waitUntil. Recording must never affect an install:
 * every error (sync or async, including from waitUntil itself) is caught and logged without detail.
 */
function background(ctx: ExecutionContext, what: string, work: () => Promise<unknown>): void {
  try {
    ctx.waitUntil(
      (async () => {
        try {
          await work();
        } catch {
          console.warn(`stats: ${what} failed`);
        }
      })(),
    );
  } catch {
    console.warn(`stats: ${what} not scheduled`);
  }
}

/**
 * One upsert into request_counts for (project, UTC day, eco, kind, outcome). Never retried (noRetry):
 * `n = n + 1` is not idempotent, so a retry after a lost acknowledgement would count the request twice.
 */
export function recordRequest(
  env: Env,
  ctx: ExecutionContext,
  projectId: string,
  eco: Ecosystem,
  kind: Kind,
  outcome: Outcome,
  now: Date,
): void {
  background(ctx, 'request count', () =>
    noRetry(env.DB).prepare(
      `INSERT INTO request_counts (project_id, day, eco, kind, outcome, n) VALUES (?, ?, ?, ?, ?, 1)
       ON CONFLICT(project_id, day, eco, kind, outcome) DO UPDATE SET n = n + 1`,
    )
      .bind(projectId, now.toISOString().slice(0, 10), eco, kind, outcome)
      .run(),
  );
}

/**
 * Upserts the upstream latest version of a package. A null time keeps a known time for the
 * same latest version (abbreviated npm documents carry no times).
 */
export function notePackageLatest(
  env: Env,
  ctx: ExecutionContext,
  eco: Ecosystem,
  name: string,
  latest: string,
  latestTime: string | null,
  now: Date,
): void {
  background(ctx, 'package latest', () =>
    env.DB.prepare(
      `INSERT INTO packages (eco, name, latest, latest_time, checked_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(eco, name) DO UPDATE SET
         latest_time = CASE WHEN excluded.latest = packages.latest
                            THEN COALESCE(excluded.latest_time, packages.latest_time)
                            ELSE excluded.latest_time END,
         latest = excluded.latest,
         checked_at = excluded.checked_at`,
    )
      .bind(eco, name, latest, latestTime, now.toISOString())
      .run(),
  );
}

// Refusals look like any other 404 on the wire; handlers tag them so they can be counted.
const tagged = new WeakMap<Response, Outcome>();

/** Marks a response with its outcome (for refusals, which are otherwise a plain 404). */
export function tagOutcome(res: Response, outcome: Outcome): Response {
  tagged.set(res, outcome);
  return res;
}

/**
 * The counted outcome of a handler response, or null when it is not counted
 * (unknown package or route, 405, any other 4xx).
 */
export function outcomeOf(res: Response): Outcome | null {
  const t = tagged.get(res);
  if (t) return t;
  if (res.status === 200) return res.headers.get('x-decant-stale') === '1' ? 'stale' : 'served';
  if (res.status >= 500) return 'failed';
  return null;
}
