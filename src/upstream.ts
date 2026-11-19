import type { Deps, Env } from './types';

export interface CachedFetchOpts {
  key: string;
  url: string;
  accept?: string;
  maxAgeSec?: number;
  immutable?: boolean;
}

export type CachedFetchResult =
  | { status: 'ok'; body: ArrayBuffer; stale: boolean }
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

// One in-flight promise per key within this isolate.
const inflight = new Map<string, Promise<CachedFetchResult>>();

export function cachedFetch(env: Env, deps: Deps, opts: CachedFetchOpts): Promise<CachedFetchResult> {
  const existing = inflight.get(opts.key);
  if (existing) return existing;
  const p = run(env, deps, opts).finally(() => {
    if (inflight.get(opts.key) === p) inflight.delete(opts.key);
  });
  inflight.set(opts.key, p);
  return p;
}

async function run(env: Env, deps: Deps, opts: CachedFetchOpts): Promise<CachedFetchResult> {
  const stored = await env.BUCKET.get(opts.key);
  let storedBody: ArrayBuffer | null = null;
  if (stored) {
    storedBody = await stored.arrayBuffer();
    if (opts.immutable) return { status: 'ok', body: storedBody, stale: false };
    const fetchedAt = Date.parse(stored.customMetadata?.fetchedAt ?? '');
    const maxAgeMs = (opts.maxAgeSec ?? DEFAULT_MAX_AGE_SEC) * 1000;
    if (!Number.isNaN(fetchedAt) && deps.now().getTime() - fetchedAt <= maxAgeMs) {
      return { status: 'ok', body: storedBody, stale: false };
    }
  }

  const fallback = (): CachedFetchResult =>
    storedBody ? { status: 'ok', body: storedBody, stale: true } : { status: 'unavailable' };

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
    return { status: 'ok', body, stale: false };
  }
  if (res.status === 404) {
    return storedBody ? { status: 'ok', body: storedBody, stale: true } : { status: 'not-found' };
  }
  // 5xx (incl. 429) and anything else unexpected: serve stored copy if any.
  return fallback();
}
