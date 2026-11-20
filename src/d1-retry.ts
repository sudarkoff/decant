/**
 * A D1 binding that retries a failed statement or batch up to RETRIES times, with jittered backoff.
 *
 * Under a burst (a parallel `npm ci` + `go mod download`) D1 answers with transient errors: "D1 DB is
 * overloaded", "Requests queued for too long", "Too many requests queued", network connection lost,
 * SQLITE_BUSY. Every error is treated as retryable, whatever its message: the exact wording varies and
 * a deterministic error only costs a few hundred ms before it propagates. After the last retry the error
 * propagates and the request fails closed (502). Only for registry routes, whose writes are all
 * idempotent (INSERT OR IGNORE, COALESCE, conflict = 1). Stats counters bypass it via noRetry().
 */

export const RETRIES = 2;
/** Backoff before retry i (0-based): uniform in [BASE·2^i, 2.5·BASE·2^i), so 50–125 ms then 100–250 ms. */
const BASE_DELAY_MS = 50;

const pause = (i: number) => {
  const lo = BASE_DELAY_MS * 2 ** i;
  return new Promise<void>((r) => setTimeout(r, lo + Math.floor(Math.random() * 1.5 * lo)));
};

async function withRetries<T>(op: () => Promise<T>): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await op();
    } catch (err) {
      if (i >= RETRIES) throw err;
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
