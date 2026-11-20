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

/*
 * Request counts are buffered per isolate and written as one batch of upserts at most every
 * STATS_INTERVAL_MS or STATS_MAX_PENDING increments, whichever comes first: one D1 round trip per
 * flush instead of one per request. Best-effort by design: counts still buffered when the isolate is
 * evicted, or in a flush that fails, are lost (never retried; see flushRequestCounts).
 */
export const STATS_INTERVAL_MS = 10_000;
export const STATS_MAX_PENDING = 200;

interface Pending {
  projectId: string;
  day: string;
  eco: Ecosystem;
  kind: Kind;
  outcome: Outcome;
  n: number;
}

const buffer = new Map<string, Pending>();
let increments = 0;
let lastFlush = Date.now();
let wake: (() => void) | null = null; // resolves the scheduled flush's sleep, when one is waiting
const policy = { intervalMs: STATS_INTERVAL_MS, maxPending: STATS_MAX_PENDING, timer: true };

/** Test hook: the flush interval and size (intervalMs 0 flushes on every request); timer false never schedules a flush. */
export function configureStatsBuffer(p: Partial<typeof policy>): void {
  Object.assign(policy, p);
  lastFlush = Date.now();
}

/**
 * Adds one to the buffered count for (project, UTC day, eco, kind, outcome). Flushes in the background
 * when the buffer is due; otherwise makes sure a flush is scheduled for when it will be, so a quiet
 * isolate's last few counts are written too (as long as it lives that long).
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
  const day = now.toISOString().slice(0, 10);
  const key = `${projectId}\u0000${day}\u0000${eco}\u0000${kind}\u0000${outcome}`;
  const row = buffer.get(key);
  if (row) row.n++;
  else buffer.set(key, { projectId, day, eco, kind, outcome, n: 1 });
  increments++;

  const due = lastFlush + policy.intervalMs - Date.now();
  if (increments >= policy.maxPending || due <= 0) {
    background(ctx, 'request counts', () => flushRequestCounts(env));
  } else if (!wake && policy.timer) {
    background(ctx, 'request counts', async () => {
      await new Promise<void>((resolve) => {
        const t = setTimeout(done, due);
        function done() {
          clearTimeout(t);
          if (wake === done) wake = null;
          resolve();
        }
        wake = done;
      });
      await flushRequestCounts(env);
    });
  }
}

/**
 * Writes every buffered count as one batch of upserts and empties the buffer. Never retried (noRetry):
 * `n = n + ?` is not idempotent, so a retry after a lost acknowledgement would count requests twice.
 * A failed flush loses its counts.
 */
export async function flushRequestCounts(env: Env): Promise<void> {
  const rows = [...buffer.values()];
  buffer.clear();
  increments = 0;
  lastFlush = Date.now();
  wake?.();
  if (rows.length === 0) return;
  const db = noRetry(env.DB);
  const upsert = db.prepare(
    `INSERT INTO request_counts (project_id, day, eco, kind, outcome, n) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(project_id, day, eco, kind, outcome) DO UPDATE SET n = n + excluded.n`,
  );
  await db.batch(rows.map((r) => upsert.bind(r.projectId, r.day, r.eco, r.kind, r.outcome, r.n)));
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
