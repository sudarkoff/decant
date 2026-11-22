import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { isKnownRegistry, MANIFEST_ACCEPT, ociClient, splitRepo } from '../../src/oci';
import { fakeFetch, jsonRes, type FetchCall } from './fakes';

const D = `sha256:${'a'.repeat(64)}`;
const HUB_TOKEN = 'https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fnode%3Apull';
const HUB_MANIFEST = (ref: string) => `https://registry-1.docker.io/v2/library/node/manifests/${ref}`;

function registry(handler: (c: FetchCall) => Response | undefined) {
  return fakeFetch((c) => {
    if (c.url === HUB_TOKEN) return jsonRes({ token: 'anon-tok' });
    if (c.url === 'https://ghcr.io/token?service=ghcr.io&scope=repository%3Aacme%2Fapi%3Apull') return jsonRes({ token: 'gh-anon' });
    return handler(c);
  });
}

describe('oci client', () => {
  it('resolves a Docker Hub tag with an anonymous pull token and the manifest-list Accept header', async () => {
    const f = registry((c) => (c.url === HUB_MANIFEST('22') && c.method === 'HEAD' ? new Response(null, { headers: { 'docker-content-digest': D } }) : undefined));
    expect(await ociClient({ fetch: f }).resolveTag('docker.io/library/node', '22')).toEqual({ status: 'ok', digest: D });
    const head = f.calls.find((c) => c.method === 'HEAD')!;
    expect(head.headers.get('authorization')).toBe('Bearer anon-tok');
    expect(head.headers.get('accept')).toBe(MANIFEST_ACCEPT);
    expect(MANIFEST_ACCEPT).toContain('application/vnd.oci.image.index.v1+json');
    expect(MANIFEST_ACCEPT).toContain('application/vnd.docker.distribution.manifest.list.v2+json');
  });

  it('hashes the manifest when the registry sends no Docker-Content-Digest', async () => {
    const body = '{"schemaVersion":2}';
    const digest = `sha256:${createHash('sha256').update(body).digest('hex')}`;
    const f = registry((c) => {
      if (c.url !== HUB_MANIFEST('22')) return undefined;
      return c.method === 'HEAD' ? new Response(null) : new Response(body);
    });
    expect(await ociClient({ fetch: f }).resolveTag('docker.io/library/node', '22')).toEqual({ status: 'ok', digest });
  });

  it('verifies a digest on ghcr.io; a different digest back is an error', async () => {
    const f = registry((c) =>
      c.url === `https://ghcr.io/v2/acme/api/manifests/${D}` ? new Response(null, { headers: { 'docker-content-digest': `sha256:${'b'.repeat(64)}` } }) : undefined,
    );
    expect(await ociClient({ fetch: f }).verifyDigest('ghcr.io/acme/api', D)).toEqual({ status: 'error', message: 'registry returned a different digest' });
  });

  it('404 is not-found; a refused token or 401 is denied; 5xx and network errors are errors', async () => {
    const c404 = registry(() => new Response('', { status: 404 }));
    expect(await ociClient({ fetch: c404 }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'not-found' });
    const denied = fakeFetch(() => new Response('', { status: 401 }));
    expect(await ociClient({ fetch: denied }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'denied' });
    const down = registry(() => new Response('', { status: 503 }));
    expect(await ociClient({ fetch: down }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'error', message: 'docker hub: HTTP 503 (manifest); mirror.gcr.io: HTTP 503; public.ecr.aws: HTTP 503 (token endpoint)' });
    const boom = fakeFetch(() => {
      throw new TypeError('fetch failed');
    });
    expect(await ociClient({ fetch: boom }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'error', message: 'docker hub: fetch failed (token endpoint); mirror.gcr.io: fetch failed; public.ecr.aws: fetch failed' });
  });

  it('never contacts a registry it does not know', async () => {
    const f = fakeFetch(() => undefined);
    expect(await ociClient({ fetch: f }).resolveTag('quay.io/acme/api', '1')).toEqual({ status: 'unsupported' });
    expect(f.calls).toEqual([]);
    expect(isKnownRegistry('docker.io')).toBe(true);
    expect(isKnownRegistry('quay.io')).toBe(false);
    expect(splitRepo('registry.example.com:5000/a/b')).toEqual({ registry: 'registry.example.com:5000', path: 'a/b' });
  });

  it('reuses one token per repository', async () => {
    const f = registry((c) => (c.method === 'HEAD' ? new Response(null, { headers: { 'docker-content-digest': D } }) : undefined));
    const oci = ociClient({ fetch: f });
    await oci.resolveTag('docker.io/library/node', '22');
    await oci.resolveTag('docker.io/library/node', '20');
    expect(f.calls.filter((c) => c.url === HUB_TOKEN)).toHaveLength(1);
  });

  it('tokens are cached per registry and repository: docker.io/acme/app and ghcr.io/acme/app do not share one', async () => {
    const f = fakeFetch((c) => {
      const u = new URL(c.url);
      if (u.pathname === '/token') return jsonRes({ token: u.host === 'ghcr.io' ? 'gh' : 'hub' });
      const want = u.host === 'ghcr.io' ? 'Bearer gh' : 'Bearer hub';
      return c.headers.get('authorization') === want ? new Response(null, { headers: { 'docker-content-digest': D } }) : new Response('', { status: 401 });
    });
    const oci = ociClient({ fetch: f });
    expect(await oci.verifyDigest('docker.io/acme/app', D)).toEqual({ status: 'ok', digest: D });
    expect(await oci.verifyDigest('ghcr.io/acme/app', D)).toEqual({ status: 'ok', digest: D });
    expect(f.calls.filter((c) => new URL(c.url).pathname === '/token')).toHaveLength(2);
  });

  it('a 401/403 on the manifest after a fresh anonymous token is an error (unverified), never denied', async () => {
    for (const status of [401, 403]) {
      const f = registry(() => new Response('', { status }));
      expect(await ociClient({ fetch: f }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'error', message: `docker hub: HTTP ${status} with an anonymous token (manifest)` });
    }
  });

  it('never follows redirects (3xx is an error); a manifest over 4 MB is not hashed', async () => {
    const r = registry((c) => (c.method === 'HEAD' ? new Response(null, { status: 307, headers: { location: 'https://elsewhere.example/x' } }) : undefined));
    expect(await ociClient({ fetch: r }).resolveTag('docker.io/library/node', '22')).toEqual({ status: 'error', message: 'docker hub: HTTP 307 (manifest)' });
    expect(r.calls.some((c) => c.url.includes('elsewhere'))).toBe(false);
    const big = registry((c) => (c.method === 'HEAD' ? new Response(null) : new Response(new Uint8Array(4 * 1024 * 1024 + 1))));
    expect(await ociClient({ fetch: big }).resolveTag('docker.io/library/node', '22')).toEqual({ status: 'error', message: 'docker hub: manifest larger than 4 MB (manifest)' });
  });

  it('anonymous by default: the token request carries no Authorization header', async () => {
    const f = registry((c) => (c.method === 'HEAD' ? new Response(null, { headers: { 'docker-content-digest': D } }) : undefined));
    expect(await ociClient({ fetch: f }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'ok', digest: D });
    expect(f.calls.find((c) => c.url === HUB_TOKEN)!.headers.get('authorization')).toBeNull();
  });

  it('with Docker Hub credentials, the auth.docker.io token request uses HTTP Basic (same scope and service)', async () => {
    const f = registry((c) => (c.method === 'HEAD' ? new Response(null, { headers: { 'docker-content-digest': D } }) : undefined));
    const oci = ociClient({ fetch: f, dockerHub: { username: 'hubuser', token: 'dckr_pat_secret' } });
    expect(await oci.verifyDigest('docker.io/library/node', D)).toEqual({ status: 'ok', digest: D });
    const tok = f.calls.find((c) => c.url === HUB_TOKEN)!;
    expect(tok.headers.get('authorization')).toBe(`Basic ${btoa('hubuser:dckr_pat_secret')}`);
    expect(f.calls.find((c) => c.method === 'HEAD')!.headers.get('authorization')).toBe('Bearer anon-tok');
  });

  it('never sends Docker Hub credentials to ghcr.io (or anywhere but auth.docker.io)', async () => {
    const f = registry((c) => (c.method === 'HEAD' ? new Response(null, { headers: { 'docker-content-digest': D } }) : undefined));
    const oci = ociClient({ fetch: f, dockerHub: { username: 'hubuser', token: 'dckr_pat_secret' } });
    expect(await oci.verifyDigest('ghcr.io/acme/api', D)).toEqual({ status: 'ok', digest: D });
    expect(await oci.verifyDigest('docker.io/library/node', D)).toEqual({ status: 'ok', digest: D });
    const basic = `Basic ${btoa('hubuser:dckr_pat_secret')}`;
    for (const c of f.calls) {
      const leaks = c.url.includes('dckr_pat_secret') || [...c.headers.values()].some((v) => v.includes('dckr_pat_secret') || v === basic);
      expect(leaks).toBe(new URL(c.url).host === 'auth.docker.io' && c.url === HUB_TOKEN);
    }
    expect(f.calls.filter((c) => new URL(c.url).host === 'ghcr.io').every((c) => c.headers.get('authorization') !== basic)).toBe(true);
  });

  it('credentials rejected by auth.docker.io are an error (unverified), not a private image', async () => {
    const f = fakeFetch(() => new Response('', { status: 401 }));
    expect(await ociClient({ fetch: f, dockerHub: { username: 'u', token: 't' } }).verifyDigest('docker.io/library/node', D)).toEqual({
      status: 'error',
      message: 'Docker Hub credentials rejected (HTTP 401)',
    });
  });

  it('HTTP 429 from the token endpoint or the manifest is rateLimited, and says which call', async () => {
    const tok429 = fakeFetch(() => new Response('', { status: 429 }));
    expect(await ociClient({ fetch: tok429 }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'error', rateLimited: true, message: 'docker hub: rate limited (token endpoint); mirror.gcr.io: rate limited; public.ecr.aws: rate limited (token endpoint)' });
    const head429 = registry(() => new Response('', { status: 429 }));
    expect(await ociClient({ fetch: head429 }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'error', rateLimited: true, message: 'docker hub: rate limited (manifest); mirror.gcr.io: rate limited; public.ecr.aws: rate limited (token endpoint)' });
  });

  it('a shared token cache reuses a token across clients until expires_in (minus a margin), keyed by credentials', async () => {
    let now = 1_000_000;
    const f = fakeFetch((c) => {
      if (c.url === HUB_TOKEN) return jsonRes({ token: c.headers.get('authorization') ? 'auth-tok' : 'anon-tok', expires_in: 300 });
      return new Response(null, { headers: { 'docker-content-digest': D } });
    });
    const cache = new Map();
    const mk = (creds?: { username: string; token: string }) => ociClient({ fetch: f, tokenCache: cache, now: () => now, dockerHub: creds });
    const toks = () => f.calls.filter((c) => c.url === HUB_TOKEN).length;
    await mk().verifyDigest('docker.io/library/node', D);
    await mk().verifyDigest('docker.io/library/node', D);
    expect(toks()).toBe(1);
    await mk({ username: 'u', token: 't' }).verifyDigest('docker.io/library/node', D);
    expect(toks()).toBe(2); // an anonymous token is never used for an authenticated client
    expect(f.calls.at(-1)!.headers.get('authorization')).toBe('Bearer auth-tok');
    now += 269_000;
    await mk().verifyDigest('docker.io/library/node', D);
    expect(toks()).toBe(2);
    now += 2_000; // past expires_in minus 30 s
    await mk().verifyDigest('docker.io/library/node', D);
    expect(toks()).toBe(3);
  });

  it('rejects an invalid tag without a request', async () => {
    const f = fakeFetch(() => undefined);
    expect((await ociClient({ fetch: f }).resolveTag('docker.io/library/node', '../x')).status).toBe('error');
    expect(f.calls).toEqual([]);
  });
});

describe('Docker Hub mirrors (digest verification fallback)', () => {
  const GCR = (path: string) => `https://mirror.gcr.io/v2/${path}/manifests/${D}`;
  const ECR_TOKEN = 'https://public.ecr.aws/token/?scope=repository%3Adocker%2Flibrary%2Fnode%3Apull';
  const ECR = `https://public.ecr.aws/v2/docker/library/node/manifests/${D}`;
  const ok = () => new Response(null, { headers: { 'docker-content-digest': D } });
  const hubHost = (u: string) => ['auth.docker.io', 'registry-1.docker.io'].includes(new URL(u).host);
  const creds = { username: 'hubuser', token: 'dckr_pat_secret' };

  it('Hub 429 -> mirror.gcr.io 200: verified via mirror.gcr.io (anonymous HEAD by digest, same Accept)', async () => {
    const f = registry((c) => (hubHost(c.url) ? new Response('', { status: 429 }) : c.url === GCR('library/node') && c.method === 'HEAD' ? ok() : undefined));
    expect(await ociClient({ fetch: f }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'ok', digest: D, via: 'mirror.gcr.io' });
    const head = f.calls.find((c) => c.url === GCR('library/node'))!;
    expect(head.method).toBe('HEAD');
    expect(head.headers.get('accept')).toBe(MANIFEST_ACCEPT);
    expect(head.headers.get('authorization')).toBeNull();
    expect(head.signal).toBeDefined();
    expect(f.calls.some((c) => new URL(c.url).host === 'public.ecr.aws')).toBe(false);
  });

  it('Hub 429 -> gcr 429 -> public.ecr.aws 200 (library image): verified via public.ecr.aws', async () => {
    const f = fakeFetch((c) => {
      if (hubHost(c.url) || new URL(c.url).host === 'mirror.gcr.io') return new Response('', { status: 429 });
      if (c.url === ECR_TOKEN) return jsonRes({ token: 'ecr-tok' });
      if (c.url === ECR && c.headers.get('authorization') === 'Bearer ecr-tok') return ok();
      return undefined;
    });
    expect(await ociClient({ fetch: f }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'ok', digest: D, via: 'public.ecr.aws' });
  });

  it('non-library image: Hub 429 + gcr 404 -> unverified (rate limited), never denied; public.ecr.aws not asked', async () => {
    const f = fakeFetch((c) => (hubHost(c.url) ? new Response('', { status: 429 }) : c.url === GCR('acme/app') ? new Response('', { status: 404 }) : undefined));
    expect(await ociClient({ fetch: f }).verifyDigest('docker.io/acme/app', D)).toEqual({
      status: 'error',
      rateLimited: true,
      message: 'docker hub: rate limited (token endpoint); mirror.gcr.io: HTTP 404',
    });
    expect(f.calls.some((c) => new URL(c.url).host === 'public.ecr.aws')).toBe(false);
  });

  it('a library image no source has: every failure is in the message', async () => {
    const f = registry((c) => (hubHost(c.url) ? new Response('', { status: 429 }) : new URL(c.url).host === 'mirror.gcr.io' ? new Response('', { status: 429 }) : c.url === ECR_TOKEN ? jsonRes({ token: 'e' }) : new Response('', { status: 404 })));
    expect(await ociClient({ fetch: f }).verifyDigest('docker.io/library/node', D)).toEqual({
      status: 'error',
      rateLimited: true,
      message: 'docker hub: rate limited (manifest); mirror.gcr.io: rate limited; public.ecr.aws: HTTP 404',
    });
  });

  it('Hub 5xx or a network error also falls back', async () => {
    const down = registry((c) => (hubHost(c.url) ? new Response('', { status: 503 }) : c.url === GCR('library/node') ? ok() : undefined));
    expect(await ociClient({ fetch: down }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'ok', digest: D, via: 'mirror.gcr.io' });
    const boom = fakeFetch((c) => {
      if (hubHost(c.url)) throw new TypeError('fetch failed');
      return c.url === GCR('library/node') ? ok() : undefined;
    });
    expect(await ociClient({ fetch: boom }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'ok', digest: D, via: 'mirror.gcr.io' });
  });

  it("Hub's own 404 is final: not-found, no mirror is asked", async () => {
    const f = registry((c) => (hubHost(c.url) ? new Response('', { status: 404 }) : ok()));
    expect(await ociClient({ fetch: f }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'not-found' });
    expect(f.calls.every((c) => hubHost(c.url))).toBe(true);
  });

  it('a mirror serving a different digest does not verify', async () => {
    const f = registry((c) => (hubHost(c.url) ? new Response('', { status: 429 }) : c.url === GCR('acme/app') ? new Response(null, { headers: { 'docker-content-digest': `sha256:${'b'.repeat(64)}` } }) : undefined));
    expect(await ociClient({ fetch: f }).verifyDigest('docker.io/acme/app', D)).toMatchObject({ status: 'error', message: 'docker hub: rate limited (token endpoint); mirror.gcr.io: registry returned a different digest' });
  });

  it('a mirror redirect is not followed', async () => {
    const f = fakeFetch((c) => (hubHost(c.url) ? new Response('', { status: 429 }) : c.url === GCR('acme/app') ? new Response(null, { status: 302, headers: { location: 'https://elsewhere.example/' } }) : undefined));
    expect(await ociClient({ fetch: f }).verifyDigest('docker.io/acme/app', D)).toMatchObject({ status: 'error', message: expect.stringContaining('mirror.gcr.io: HTTP 302') });
    expect(f.calls.some((c) => c.url.includes('elsewhere'))).toBe(false);
  });

  it('Docker Hub credentials are never sent to the mirrors', async () => {
    const basic = `Basic ${btoa('hubuser:dckr_pat_secret')}`;
    const f = fakeFetch((c) => {
      if (hubHost(c.url) || new URL(c.url).host === 'mirror.gcr.io') return new Response('', { status: 429 });
      if (c.url === ECR_TOKEN) return jsonRes({ token: 'ecr-tok' });
      return c.url === ECR ? ok() : undefined;
    });
    expect(await ociClient({ fetch: f, dockerHub: creds }).verifyDigest('docker.io/library/node', D)).toMatchObject({ status: 'ok', via: 'public.ecr.aws' });
    const mirrorCalls = f.calls.filter((c) => !hubHost(c.url));
    expect(mirrorCalls.map((c) => new URL(c.url).host).sort()).toEqual(['mirror.gcr.io', 'public.ecr.aws', 'public.ecr.aws']);
    for (const c of mirrorCalls) {
      expect(c.url).not.toContain('dckr_pat_secret');
      expect([...c.headers.values()].some((v) => v === basic || v.includes('dckr_pat_secret') || v.includes('hubuser'))).toBe(false);
    }
  });

  it('tags and other registries never use the mirrors', async () => {
    const f = registry((c) => (hubHost(c.url) || new URL(c.url).host === 'ghcr.io' ? new Response('', { status: 429 }) : ok()));
    expect(await ociClient({ fetch: f }).resolveTag('docker.io/library/node', '22')).toEqual({ status: 'error', rateLimited: true, message: 'docker hub: rate limited (manifest)' });
    expect(await ociClient({ fetch: f }).verifyDigest('ghcr.io/acme/api', D)).toEqual({ status: 'error', rateLimited: true, message: 'rate limited' });
    expect(f.calls.every((c) => hubHost(c.url) || new URL(c.url).host === 'ghcr.io')).toBe(true);
  });
});
