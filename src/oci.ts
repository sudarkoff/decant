/**
 * Minimal OCI distribution client for anonymous public pulls: resolve a tag to its manifest digest, or
 * confirm a digest exists. Pure apart from the injected fetch; used by the Worker (to verify a digest
 * before starting its shared cooldown clock) and by the action (fix-it messages, audit candidates).
 *
 * Only registries whose anonymous token flow decant knows are contacted: Docker Hub and ghcr.io, plus two fixed
 * Docker Hub mirrors (mirror.gcr.io, public.ecr.aws) for digest verification when Docker Hub cannot answer.
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

type Mirror = { host: string; api: string; repo: (path: string) => string | null; token?: (repo: string) => string };

/**
 * Docker Hub mirrors, asked anonymously and in this order, only to verify a docker.io digest when Docker Hub itself
 * answers 429, 5xx or not at all (Docker Hub rate-limits Cloudflare's shared egress even with credentials).
 *
 * Why a mirror's 200 is proof: a mirror only serves content it fetched from Docker Hub, and a digest is the hash of
 * the manifest, so a 200 for this digest means the manifest was pushed to Docker Hub; it cannot be pre-seeded.
 * A mirror's 404 or 429 proves nothing (it may simply not have it), so only Docker Hub's own 404 is "not found".
 * public.ecr.aws carries Docker Official Images only (docker.io/library/<name> at docker/library/<name>).
 */
const DOCKER_HUB_MIRRORS: Mirror[] = [
  { host: 'mirror.gcr.io', api: 'https://mirror.gcr.io', repo: (path) => path },
  {
    host: 'public.ecr.aws',
    api: 'https://public.ecr.aws',
    repo: (path) => (/^library\/[a-z0-9][a-z0-9._-]*$/.test(path) ? `docker/${path}` : null),
    token: (repo) => `https://public.ecr.aws/token/?${new URLSearchParams({ scope: `repository:${repo}:pull` })}`,
  },
];

/** True for registries decant can query anonymously (and Grype can scan without credentials). */
export const isKnownRegistry = (registry: string) => Object.hasOwn(REGISTRIES, registry);

/** Splits a normalized repository (docker.io/library/node) into registry host and path. */
export function splitRepo(name: string): { registry: string; path: string } {
  const i = name.indexOf('/');
  return { registry: name.slice(0, i), path: name.slice(i + 1) };
}

export type ManifestResult =
  /** `via`: the Docker Hub mirror that verified the digest, when Docker Hub itself could not answer. */
  | { status: 'ok'; digest: string; via?: string }
  /** The registry says the manifest (tag or digest) does not exist. */
  | { status: 'not-found' }
  /** Anonymous pull refused: a private (or nonexistent) repository. */
  | { status: 'denied' }
  /** A registry decant does not query. */
  | { status: 'unsupported' }
  /**
   * Network error, timeout, 429 or 5xx, or a malformed answer: try again later. `rateLimited` when the registry
   * answered 429; `message` names each source that failed (e.g. "docker hub: rate limited (manifest); mirror.gcr.io: HTTP 404").
   */
  | { status: 'error'; message: string; rateLimited?: boolean };

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
/** A non-2xx answer from a token endpoint. */
class HttpError extends Error {
  constructor(readonly status: number) {
    super(`HTTP ${status}`);
  }
}
/** A token endpoint answer that retrying will not fix (rejected credentials, no token). */
class Final extends Error {}

/** One source's answer: a digest, an HTTP status other than 2xx, or a malformed answer. */
type Lookup = { digest: string } | { status: number } | { message: string };

/** The registry's own error; `retry` when transient (429, 5xx, network), so a Docker Hub mirror may still answer. */
type RegistryError = { status: 'error'; message: string; rateLimited?: boolean; retry?: boolean };

const errText = (e: unknown) => (['TimeoutError', 'AbortError'].includes((e as Error)?.name) ? 'timed out' : String((e as Error)?.message ?? e));

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

  /** A pull token for `path` from `tokenUrl`. `registry` keys the cache; only 'docker.io' ever gets credentials. */
  async function token(registry: string, tokenUrl: string, path: string): Promise<string | 'denied'> {
    // Credentials only ever for docker.io (auth.docker.io); every other registry and every mirror stays anonymous.
    const creds = registry === 'docker.io' ? o.dockerHub : undefined;
    const key = `${creds ? `user:${creds.username}@` : ''}${registry}/${path}`;
    let t = tokens.get(key);
    if (!t) {
      const hit = o.tokenCache?.get(key);
      if (hit && hit.expires > now()) return hit.token;
      t = (async () => {
        const init: RequestInit = creds ? { headers: { authorization: `Basic ${btoa(`${creds.username}:${creds.token}`)}` } } : {};
        const res = await get(tokenUrl, init);
        if (res.status === 429) throw new RateLimited();
        if (creds && (res.status === 401 || res.status === 403)) throw new Final(`Docker Hub credentials rejected (HTTP ${res.status})`);
        if (res.status === 401 || res.status === 403) return 'denied';
        if (!res.ok || res.status >= 300) throw new HttpError(res.status);
        const body = (await res.json()) as { token?: unknown; access_token?: unknown; expires_in?: unknown };
        const v = typeof body.token === 'string' ? body.token : typeof body.access_token === 'string' ? body.access_token : '';
        if (!v) throw new Final('token endpoint returned no token');
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
   * HEAD the manifest at `url`; returns the digest served. A digest reference must come back as itself. Without a
   * Docker-Content-Digest header the manifest is fetched (at most 4 MB) and hashed.
   */
  async function lookup(url: string, headers: Record<string, string>, reference: string, byDigest: boolean): Promise<Lookup> {
    let res = await get(url, { method: 'HEAD', headers });
    if (!res.ok || res.status >= 300) return { status: res.status };
    let digest = res.headers.get('docker-content-digest');
    if (digest === null) {
      res = await get(url, { headers });
      if (!res.ok || res.status >= 300) return { status: res.status };
      const body = await readCapped(res, MAX_MANIFEST_BYTES);
      if (body === null) return { message: 'manifest larger than 4 MB' };
      digest = await sha256(body);
    }
    if (!DIGEST_RE.test(digest)) return { message: 'registry returned a malformed digest' };
    if (byDigest && digest !== reference) return { message: 'registry returned a different digest' };
    return { digest };
  }

  /** The registry's own answer. Docker Hub messages start "docker hub: " and end with the call that failed. */
  async function fromRegistry(registry: string, reg: Registry, path: string, reference: string, byDigest: boolean): Promise<ManifestResult | RegistryError> {
    const hub = registry === 'docker.io';
    const err = (message: string, where: string, extra: { rateLimited?: boolean; retry?: boolean } = {}): RegistryError => ({
      status: 'error',
      message: hub ? `docker hub: ${message} (${where})` : message,
      ...extra,
    });
    let t: string | 'denied';
    try {
      t = await token(registry, reg.token(path), path);
    } catch (e) {
      if (e instanceof RateLimited) return err('rate limited', 'token endpoint', { rateLimited: true, retry: true });
      if (e instanceof HttpError) return err(e.message, 'token endpoint', { retry: e.status >= 500 });
      if (e instanceof Final) return { status: 'error', message: e.message };
      return err(errText(e), 'token endpoint', { retry: true });
    }
    if (t === 'denied') return { status: 'denied' };
    let r: Lookup;
    try {
      r = await lookup(`${reg.api}/v2/${path}/manifests/${reference}`, { accept: MANIFEST_ACCEPT, authorization: `Bearer ${t}` }, reference, byDigest);
    } catch (e) {
      return err(errText(e), 'manifest', { retry: true });
    }
    if ('digest' in r) return { status: 'ok', digest: r.digest };
    if ('message' in r) return err(r.message, 'manifest');
    if (r.status === 404) return { status: 'not-found' };
    if (r.status === 429) return err('rate limited', 'manifest', { rateLimited: true, retry: true });
    // Refused with the token the registry just issued: not evidence of a private image; try again later.
    if (r.status === 401 || r.status === 403) {
      return err(`HTTP ${r.status} with ${hub && o.dockerHub ? 'a Docker Hub token' : 'an anonymous token'}`, 'manifest');
    }
    return err(`HTTP ${r.status}`, 'manifest', { retry: r.status >= 500 });
  }

  /** A Docker Hub mirror's answer for a digest: the digest, or why not. Never sends Docker Hub credentials. */
  async function fromMirror(m: Mirror, repo: string, digest: string): Promise<{ digest: string } | { message: string }> {
    try {
      const headers: Record<string, string> = { accept: MANIFEST_ACCEPT };
      if (m.token) {
        // Keyed by the mirror's host, which is never 'docker.io': token() sends no credentials.
        const t = await token(m.host, m.token(repo), repo);
        if (t === 'denied') return { message: 'pull refused (token endpoint)' };
        headers.authorization = `Bearer ${t}`;
      }
      const r = await lookup(`${m.api}/v2/${repo}/manifests/${digest}`, headers, digest, true);
      if ('status' in r) return { message: r.status === 429 ? 'rate limited' : `HTTP ${r.status}` };
      return r;
    } catch (e) {
      if (e instanceof RateLimited) return { message: 'rate limited (token endpoint)' };
      if (e instanceof HttpError || e instanceof Final) return { message: `${e.message} (token endpoint)` };
      return { message: errText(e) };
    }
  }

  /**
   * The digest `reference` (a tag or a sha256 digest) resolves to. A docker.io digest Docker Hub cannot answer for
   * (429, 5xx, network) is asked of DOCKER_HUB_MIRRORS in turn; a tag never is (a mirror's copy of a tag may be stale).
   */
  async function manifest(name: string, reference: string): Promise<ManifestResult> {
    const { registry, path } = splitRepo(name);
    const reg = REGISTRIES[registry];
    if (!reg) return { status: 'unsupported' };
    const byDigest = DIGEST_RE.test(reference);
    if (!byDigest && !TAG_RE.test(reference)) return { status: 'error', message: 'invalid tag' };
    const r = await fromRegistry(registry, reg, path, reference, byDigest);
    if (r.status !== 'error') return r;
    const { retry, ...res } = r as RegistryError;
    if (registry !== 'docker.io' || !byDigest || !retry) return res;
    const failures = [res.message];
    for (const m of DOCKER_HUB_MIRRORS) {
      const repo = m.repo(path);
      if (repo === null) continue;
      const v = await fromMirror(m, repo, reference);
      if ('digest' in v) return { status: 'ok', digest: v.digest, via: m.host };
      failures.push(`${m.host}: ${v.message}`);
    }
    return { ...res, message: failures.join('; ') };
  }

  return {
    manifest,
    /** The digest a tag currently resolves to. */
    resolveTag: (name: string, tag: string) => manifest(name, tag),
    /** Whether the registry serves this digest. */
    verifyDigest: (name: string, digest: string) => manifest(name, digest),
  };
}
