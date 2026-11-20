import type { Deps, Env } from './types';

export interface CachedFetchOpts {
  key: string;
  url: string;
  accept?: string;
  maxAgeSec?: number;
  immutable?: boolean;
}

export type CachedFetchResult =
  /** fresh: this call fetched the body from upstream (not served from R2). */
  | { status: 'ok'; body: ArrayBuffer; stale: boolean; fresh: boolean }
  | { status: 'not-found' }
  | { status: 'unavailable' };

const DEFAULT_MAX_AGE_SEC = 300;
export const UPSTREAM_TIMEOUT_MS = 10_000;

export function upstreamTimeout(deps: Deps): number {
  return deps.timeoutMs ?? UPSTREAM_TIMEOUT_MS;
}

/**
 * fetch with a timeout on the response headers only: aborts if they haven't arrived in time,
 * then clears the timer so a slow body (a large tarball) can stream for as long as it takes.
 */
export async function fetchHeaders(deps: Deps, url: string, init: RequestInit = {}): Promise<Response> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new Error('upstream timeout')), upstreamTimeout(deps));
  try {
    return await deps.fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(timer);
  }
}

// One in-flight promise per key within this isolate, shared by concurrent requests.
const inflight = new Map<string, Promise<CachedFetchResult>>();

/**
 * The shared promise belongs to the request that started it. If that request is cancelled (its client
 * went away) the promise may never settle, so a joining request waits at most this long and then
 * fetches for itself.
 */
function joinWaitMs(deps: Deps): number {
  return 2 * upstreamTimeout(deps) + 1000;
}

export function cachedFetch(env: Env, deps: Deps, opts: CachedFetchOpts): Promise<CachedFetchResult> {
  const existing = inflight.get(opts.key);
  if (existing) return join(existing, () => safeRun(env, deps, opts), joinWaitMs(deps));
  const p = safeRun(env, deps, opts).finally(() => {
    if (inflight.get(opts.key) === p) inflight.delete(opts.key);
  });
  inflight.set(opts.key, p);
  return p;
}

async function join(shared: Promise<CachedFetchResult>, own: () => Promise<CachedFetchResult>, waitMs: number): Promise<CachedFetchResult> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<null>((r) => {
    timer = setTimeout(() => r(null), waitMs);
  });
  try {
    return (await Promise.race([shared, timedOut])) ?? (await own());
  } finally {
    clearTimeout(timer);
  }
}

/** Never rejects: an R2 or runtime failure is 'unavailable', like an upstream outage, for every waiter. */
async function safeRun(env: Env, deps: Deps, opts: CachedFetchOpts): Promise<CachedFetchResult> {
  try {
    return await run(env, deps, opts);
  } catch (err) {
    console.warn(`cached fetch failed for key ${opts.key}: ${err instanceof Error ? err.name : typeof err}`);
    return { status: 'unavailable' };
  }
}

/** The stored object and its body, or null if there is none or R2 can't be read (then upstream decides). */
async function readStored(env: Env, key: string): Promise<{ body: ArrayBuffer; fetchedAt: number } | null> {
  try {
    const stored = await env.BUCKET.get(key);
    if (!stored) return null;
    return { body: await stored.arrayBuffer(), fetchedAt: Date.parse(stored.customMetadata?.fetchedAt ?? '') };
  } catch {
    console.warn(`upstream cache read failed for key ${key}`);
    return null;
  }
}

async function run(env: Env, deps: Deps, opts: CachedFetchOpts): Promise<CachedFetchResult> {
  const stored = await readStored(env, opts.key);
  let storedBody: ArrayBuffer | null = null;
  if (stored) {
    storedBody = stored.body;
    if (opts.immutable) return { status: 'ok', body: storedBody, stale: false, fresh: false };
    const fetchedAt = stored.fetchedAt;
    const maxAgeMs = (opts.maxAgeSec ?? DEFAULT_MAX_AGE_SEC) * 1000;
    if (!Number.isNaN(fetchedAt) && deps.now().getTime() - fetchedAt <= maxAgeMs) {
      return { status: 'ok', body: storedBody, stale: false, fresh: false };
    }
  }

  const fallback = (): CachedFetchResult =>
    storedBody ? { status: 'ok', body: storedBody, stale: true, fresh: false } : { status: 'unavailable' };

  // The whole exchange (headers and body) shares one timeout: a hung upstream falls back to the stored copy.
  const signal = AbortSignal.timeout(upstreamTimeout(deps));
  let res: Response;
  try {
    res = await deps.fetch(opts.url, { signal, ...(opts.accept ? { headers: { Accept: opts.accept } } : {}) });
  } catch {
    return fallback();
  }

  if (res.status === 200) {
    let body: ArrayBuffer;
    try {
      body = await res.arrayBuffer();
    } catch {
      return fallback();
    }
    storedBody = null; // superseded; don't hold two copies
    try {
      await env.BUCKET.put(opts.key, body, { customMetadata: { fetchedAt: deps.now().toISOString() } });
    } catch {
      // Cache write is best-effort; we already have the body.
      console.warn(`upstream cache write failed for key ${opts.key}`);
    }
    return { status: 'ok', body, stale: false, fresh: true };
  }
  if (res.status === 404) {
    return storedBody ? { status: 'ok', body: storedBody, stale: true, fresh: false } : { status: 'not-found' };
  }
  // 5xx (incl. 429) and anything else unexpected: serve stored copy if any.
  return fallback();
}
