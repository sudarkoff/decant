/**
 * A D1 binding that retries a failed statement or batch once, after a short jittered pause.
 *
 * Under a burst of cold-cache requests (a `go build` fetching dozens of modules at once) D1 can
 * answer a statement with a transient error: overloaded, queue timeout, network connection lost,
 * SQLITE_BUSY. One retry rides those out. Only for registry routes, whose writes are all
 * idempotent (INSERT OR IGNORE, COALESCE, conflict = 1). Stats counters bypass it via noRetry().
 */

const RETRY_DELAY_MS = 30;

const pause = () => new Promise<void>((r) => setTimeout(r, RETRY_DELAY_MS + Math.floor(Math.random() * RETRY_DELAY_MS)));

async function once<T>(op: () => Promise<T>): Promise<T> {
  try {
    return await op();
  } catch {
    await pause();
    return op();
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
    first: (col?: string) => once(() => (col === undefined ? s.first() : s.first(col))),
    run: () => once(() => s.run()),
    all: () => once(() => s.all()),
    raw: (opts?: { columnNames?: boolean }) => once(() => s.raw(opts as { columnNames?: false })),
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
    batch: <T>(stmts: D1PreparedStatement[]) => once(() => db.batch<T>(stmts.map(unwrap))),
    exec: (q: string) => db.exec(q),
    withSession: (c?: D1SessionBookmark | D1SessionConstraint) => db.withSession(c),
    dump: () => db.dump(),
  } as D1Database;
  unwrapped.set(r, db);
  return r;
}
