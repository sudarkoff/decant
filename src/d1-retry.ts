/**
 * A D1 binding that retries a transiently failed statement or batch up to RETRIES times, with jittered
 * backoff. Only for registry routes, whose writes are all idempotent (INSERT OR IGNORE, COALESCE,
 * conflict = 1). Stats counters bypass it via noRetry(). After the last retry the error propagates and
 * the request fails closed (502).
 *
 * Retried: errors whose message looks like load shedding or a transient failure (isTransient); D1's
 * documented retryable errors include "D1 DB is overloaded. Requests queued for too long.", "... Too many
 * requests queued.", "Network connection lost.", "... storage caused object to be reset.", "Cannot resolve
 * D1 DB due to transient issue on remote node." Matching is on loose substrings, so a reworded message
 * of the same kind still retries. Anything else (SQL errors, constraint failures) fails at once.
 *
 * A per-isolate budget (RETRY_BUDGET per RETRY_WINDOW_MS) caps retries: when D1 is truly down, retrying
 * every request would only add load, so past the budget errors propagate on the first failure.
 */

export const RETRIES = 2;
/** Backoff before retry i (0-based): uniform in [BASE·2^i, 2.5·BASE·2^i), so 50–125 ms then 100–250 ms. */
const BASE_DELAY_MS = 50;
export const RETRY_BUDGET = 100;
export const RETRY_WINDOW_MS = 10_000;

const TRANSIENT = /overloaded|queued|network connection lost|busy|reset|timed out|timeout|internal error|transient|try again|disconnected/i;

export function isTransient(err: unknown): boolean {
  return err instanceof Error && TRANSIENT.test(err.message);
}

const budget = { max: RETRY_BUDGET, windowMs: RETRY_WINDOW_MS, used: 0, windowStart: Date.now() };

/** Test hook: the retry budget; also resets the current window. */
export function configureRetryBudget(p: { max?: number; windowMs?: number } = {}): void {
  budget.max = p.max ?? RETRY_BUDGET;
  budget.windowMs = p.windowMs ?? RETRY_WINDOW_MS;
  budget.used = 0;
  budget.windowStart = Date.now();
}

function takeRetry(): boolean {
  const now = Date.now();
  if (now - budget.windowStart >= budget.windowMs || now < budget.windowStart) {
    budget.windowStart = now;
    budget.used = 0;
  }
  if (budget.used >= budget.max) return false;
  budget.used++;
  return true;
}

const pause = (i: number) => {
  const lo = BASE_DELAY_MS * 2 ** i;
  return new Promise<void>((r) => setTimeout(r, lo + Math.floor(Math.random() * 1.5 * lo)));
};

async function withRetries<T>(op: () => Promise<T>): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await op();
    } catch (err) {
      if (i >= RETRIES || !isTransient(err) || !takeRetry()) throw err;
      await pause(i);
    }
  }
}

// Wrapped statement → the statement it wraps, so batch() can hand the binding its own objects.
const inner = new WeakMap<object, D1PreparedStatement>();

function unwrap(s: D1PreparedStatement): D1PreparedStatement {
  return inner.get(s) ?? s;
}

function wrapStmt(s: D1PreparedStatement): D1PreparedStatement {
  const w = {
    bind: (...values: unknown[]) => wrapStmt(s.bind(...values)),
    first: (col?: string) => withRetries(() => (col === undefined ? s.first() : s.first(col))),
    run: () => withRetries(() => s.run()),
    all: () => withRetries(() => s.all()),
    raw: (opts?: { columnNames?: boolean }) => withRetries(() => s.raw(opts as { columnNames?: false })),
  };
  inner.set(w, s);
  return w as unknown as D1PreparedStatement;
}

// Retrying binding → the binding it wraps.
const unwrapped = new WeakMap<object, D1Database>();

/**
 * The binding without retries. For non-idempotent writes (the request_counts `n = n + 1` upsert): a
 * retry after a lost acknowledgement would count one request twice.
 */
export function noRetry(db: D1Database): D1Database {
  return unwrapped.get(db) ?? db;
}

export function retryingD1(db: D1Database): D1Database {
  const r = {
    prepare: (q: string) => wrapStmt(db.prepare(q)),
    batch: <T>(stmts: D1PreparedStatement[]) => withRetries(() => db.batch<T>(stmts.map(unwrap))),
    exec: (q: string) => db.exec(q),
    withSession: (c?: D1SessionBookmark | D1SessionConstraint) => db.withSession(c),
    dump: () => db.dump(),
  } as D1Database;
  unwrapped.set(r, db);
  return r;
}
