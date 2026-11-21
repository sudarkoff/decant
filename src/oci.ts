/**
 * Minimal OCI distribution client for anonymous public pulls: resolve a tag to its manifest digest, or
 * confirm a digest exists. Pure apart from the injected fetch; used by the Worker (to verify a digest
 * before starting its shared cooldown clock) and by the action (fix-it messages, audit candidates).
 *
 * Only registries whose anonymous token flow decant knows are contacted: Docker Hub and ghcr.io.
 * Anything else is 'unsupported': decant never sends a request to a registry host taken from a Dockerfile.
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
  /** Network error, timeout, 429 or 5xx, or a malformed answer: try again later. */
  | { status: 'error'; message: string };

export type OciOpts = { fetch: typeof fetch; timeoutMs?: number };

const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;

async function sha256(bytes: ArrayBuffer): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return `sha256:${[...h].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/** One OCI client; anonymous pull tokens are cached per repository for its lifetime (one request or run). */
export function ociClient(o: OciOpts) {
  const timeoutMs = o.timeoutMs ?? 10_000;
  const tokens = new Map<string, Promise<string | 'denied'>>();

  async function get(url: string, init: RequestInit = {}): Promise<Response> {
    return o.fetch(url, { ...init, redirect: 'follow', signal: AbortSignal.timeout(timeoutMs) });
  }

  async function token(reg: Registry, path: string): Promise<string | 'denied'> {
    let t = tokens.get(path);
    if (!t) {
      t = (async () => {
        const res = await get(reg.token(path));
        if (res.status === 401 || res.status === 403) return 'denied';
        if (!res.ok) throw new Error(`token endpoint HTTP ${res.status}`);
        const body = (await res.json()) as { token?: unknown; access_token?: unknown };
        const v = typeof body.token === 'string' ? body.token : typeof body.access_token === 'string' ? body.access_token : '';
        if (!v) throw new Error('token endpoint returned no token');
        return v;
      })();
      tokens.set(path, t);
      t.catch(() => tokens.delete(path));
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
      const t = await token(reg, path);
      if (t === 'denied') return { status: 'denied' };
      const url = `${reg.api}/v2/${path}/manifests/${reference}`;
      const headers = { accept: MANIFEST_ACCEPT, authorization: `Bearer ${t}` };
      let res = await get(url, { method: 'HEAD', headers });
      if (res.status === 404) return { status: 'not-found' };
      if (res.status === 401 || res.status === 403) return { status: 'denied' };
      if (!res.ok) return { status: 'error', message: `HTTP ${res.status}` };
      let digest = res.headers.get('docker-content-digest');
      if (digest === null) {
        res = await get(url, { headers });
        if (res.status === 404) return { status: 'not-found' };
        if (!res.ok) return { status: 'error', message: `HTTP ${res.status}` };
        digest = await sha256(await res.arrayBuffer());
      }
      if (!DIGEST_RE.test(digest)) return { status: 'error', message: 'registry returned a malformed digest' };
      if (byDigest && digest !== reference) return { status: 'error', message: 'registry returned a different digest' };
      return { status: 'ok', digest };
    } catch (e) {
      const err = e as Error;
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
