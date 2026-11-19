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

// One in-flight promise per key within this isolate.
const inflight = new Map<string, Promise<CachedFetchResult>>();

export function upstreamUnavailable(): Response {
  return new Response('upstream unavailable and nothing cached', { status: 502 });
}

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

  let res: Response;
  try {
    res = await deps.fetch(opts.url, opts.accept ? { headers: { Accept: opts.accept } } : undefined);
  } catch {
    return fallback();
  }

  if (res.status === 200) {
    const body = await res.arrayBuffer();
    await env.BUCKET.put(opts.key, body, { customMetadata: { fetchedAt: deps.now().toISOString() } });
    return { status: 'ok', body, stale: false };
  }
  if (res.status === 404) {
    return storedBody ? { status: 'ok', body: storedBody, stale: true } : { status: 'not-found' };
  }
  // 5xx (incl. 429) and anything else unexpected: serve stored copy if any.
  return fallback();
}
