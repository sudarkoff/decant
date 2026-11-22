/**
 * Minimal OCI distribution client for anonymous public pulls: resolve a tag to its manifest digest, or
 * confirm a digest exists. Pure apart from the injected fetch; used by the Worker (to verify a digest
 * before starting its shared cooldown clock) and by the action (fix-it messages, audit candidates).
 *
 * Only registries whose anonymous token flow decant knows are contacted: Docker Hub and ghcr.io.
 * Anything else is 'unsupported': decant never sends a request to a registry host taken from a Dockerfile.
 * Optional Docker Hub credentials (a read-only PAT) go only to auth.docker.io, to lift the anonymous rate limit.
 */
import { DIGEST_RE } from './ids';

export const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(', ');

type Registry = { api: string; token: (path: string) => string };

const REGISTRIES: Record<string, Registry> = {
  'docker.io': {
    api: 'https://registry-1.docker.io',
    token: (path) => `https://auth.docker.io/token?${new URLSearchParams({ service: 'registry.docker.io', scope: `repository:${path}:pull` })}`,
  },
  'ghcr.io': {
    api: 'https://ghcr.io',
    token: (path) => `https://ghcr.io/token?${new URLSearchParams({ service: 'ghcr.io', scope: `repository:${path}:pull` })}`,
  },
};

/** True for registries decant can query anonymously (and Grype can scan without credentials). */
export const isKnownRegistry = (registry: string) => Object.hasOwn(REGISTRIES, registry);

/** Splits a normalized repository (docker.io/library/node) into registry host and path. */
export function splitRepo(name: string): { registry: string; path: string } {
  const i = name.indexOf('/');
  return { registry: name.slice(0, i), path: name.slice(i + 1) };
}

export type ManifestResult =
  | { status: 'ok'; digest: string }
  /** The registry says the manifest (tag or digest) does not exist. */
  | { status: 'not-found' }
  /** Anonymous pull refused: a private (or nonexistent) repository. */
  | { status: 'denied' }
  /** A registry decant does not query. */
  | { status: 'unsupported' }
  /** Network error, timeout, 429 ('rate limited') or 5xx, or a malformed answer: try again later. */
  | { status: 'error'; message: string };

/** A pull token shared across clients (e.g. per isolate) until `expires` (ms since epoch). */
export type TokenCache = Map<string, { token: string; expires: number }>;

export type OciOpts = {
  fetch: typeof fetch;
  timeoutMs?: number;
  /** Docker Hub username and read-only access token: sent as HTTP Basic to auth.docker.io only. */
  dockerHub?: { username: string; token: string };
  /** Shares tokens beyond this client, honouring expires_in. Without it, tokens live as long as the client. */
  tokenCache?: TokenCache;
  /** Clock for tokenCache expiry (ms). Default Date.now. */
  now?: () => number;
};

/** Seconds a cached token is dropped before the registry's expires_in; expires_in defaults to 60 (distribution spec). */
const TOKEN_MARGIN_S = 30;
const MAX_CACHED_TOKENS = 1000;

class RateLimited extends Error {}

const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;

/** A manifest larger than this is not one decant hashes (an index or manifest is a few KB). */
export const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;

/** The body, or null when it is larger than `max` (stops reading at the cap). */
async function readCapped(res: Response, max: number): Promise<ArrayBuffer | null> {
  if (Number(res.headers.get('content-length') ?? '0') > max) {
    await res.body?.cancel().catch(() => {});
    return null;
  }
  if (!res.body) return new ArrayBuffer(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out.buffer;
}

async function sha256(bytes: ArrayBuffer): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return `sha256:${[...h].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * One OCI client; pull tokens are cached per registry, repository and credentials for its lifetime (one request or
 * run), and in `tokenCache` (if given) until they expire.
 */
export function ociClient(o: OciOpts) {
  const timeoutMs = o.timeoutMs ?? 10_000;
  const now = o.now ?? Date.now;
  const tokens = new Map<string, Promise<string | 'denied'>>();

  async function get(url: string, init: RequestInit = {}): Promise<Response> {
    // No redirects: a 3xx is an error (decant talks only to the registry hosts it knows).
    return o.fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  }

  async function token(registry: string, reg: Registry, path: string): Promise<string | 'denied'> {
    // Credentials only ever for docker.io (auth.docker.io); every other registry stays anonymous.
    const creds = registry === 'docker.io' ? o.dockerHub : undefined;
    const key = `${creds ? `user:${creds.username}@` : ''}${registry}/${path}`;
    let t = tokens.get(key);
    if (!t) {
      const hit = o.tokenCache?.get(key);
      if (hit && hit.expires > now()) return hit.token;
      t = (async () => {
        const init: RequestInit = creds ? { headers: { authorization: `Basic ${btoa(`${creds.username}:${creds.token}`)}` } } : {};
        const res = await get(reg.token(path), init);
        if (res.status === 429) throw new RateLimited();
        if (creds && (res.status === 401 || res.status === 403)) throw new Error(`Docker Hub credentials rejected (HTTP ${res.status})`);
        if (res.status === 401 || res.status === 403) return 'denied';
        if (!res.ok || res.status >= 300) throw new Error(`token endpoint HTTP ${res.status}`);
        const body = (await res.json()) as { token?: unknown; access_token?: unknown; expires_in?: unknown };
        const v = typeof body.token === 'string' ? body.token : typeof body.access_token === 'string' ? body.access_token : '';
        if (!v) throw new Error('token endpoint returned no token');
        const ttl = (typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 60) - TOKEN_MARGIN_S;
        if (o.tokenCache && ttl > 0) {
          const at = now();
          if (o.tokenCache.size >= MAX_CACHED_TOKENS) {
            for (const [k, e] of o.tokenCache) if (e.expires <= at) o.tokenCache.delete(k);
            if (o.tokenCache.size >= MAX_CACHED_TOKENS) o.tokenCache.clear();
          }
          o.tokenCache.set(key, { token: v, expires: at + ttl * 1000 });
        }
        return v;
      })();
      tokens.set(key, t);
      t.catch(() => tokens.delete(key));
    }
    return t;
  }

  /**
   * HEAD the manifest at `reference` (a tag or a sha256 digest); returns the digest the registry serves.
   * A digest reference must come back as itself. Without a Docker-Content-Digest header the manifest is
   * fetched and hashed.
   */
  async function manifest(name: string, reference: string): Promise<ManifestResult> {
    const { registry, path } = splitRepo(name);
    const reg = REGISTRIES[registry];
    if (!reg) return { status: 'unsupported' };
    const byDigest = DIGEST_RE.test(reference);
    if (!byDigest && !TAG_RE.test(reference)) return { status: 'error', message: 'invalid tag' };
    try {
      const t = await token(registry, reg, path);
      if (t === 'denied') return { status: 'denied' };
      const url = `${reg.api}/v2/${path}/manifests/${reference}`;
      const headers = { accept: MANIFEST_ACCEPT, authorization: `Bearer ${t}` };
      let res = await get(url, { method: 'HEAD', headers });
      if (res.status === 404) return { status: 'not-found' };
      if (res.status === 429) return { status: 'error', message: 'rate limited' };
      // Refused with the token the registry just issued: not evidence of a private image; try again later.
      if (res.status === 401 || res.status === 403) {
        return { status: 'error', message: `HTTP ${res.status} with ${registry === 'docker.io' && o.dockerHub ? 'a Docker Hub token' : 'an anonymous token'}` };
      }
      if (!res.ok || res.status >= 300) return { status: 'error', message: `HTTP ${res.status}` };
      let digest = res.headers.get('docker-content-digest');
      if (digest === null) {
        res = await get(url, { headers });
        if (res.status === 404) return { status: 'not-found' };
        if (res.status === 429) return { status: 'error', message: 'rate limited' };
        if (!res.ok || res.status >= 300) return { status: 'error', message: `HTTP ${res.status}` };
        const body = await readCapped(res, MAX_MANIFEST_BYTES);
        if (body === null) return { status: 'error', message: 'manifest larger than 4 MB' };
        digest = await sha256(body);
      }
      if (!DIGEST_RE.test(digest)) return { status: 'error', message: 'registry returned a malformed digest' };
      if (byDigest && digest !== reference) return { status: 'error', message: 'registry returned a different digest' };
      return { status: 'ok', digest };
    } catch (e) {
      const err = e as Error;
      if (err instanceof RateLimited) return { status: 'error', message: 'rate limited' };
      return { status: 'error', message: ['TimeoutError', 'AbortError'].includes(err?.name) ? 'timed out' : String(err?.message ?? e) };
    }
  }

  return {
    manifest,
    /** The digest a tag currently resolves to. */
    resolveTag: (name: string, tag: string) => manifest(name, tag),
    /** Whether the registry serves this digest. */
    verifyDigest: (name: string, digest: string) => manifest(name, digest),
  };
}
