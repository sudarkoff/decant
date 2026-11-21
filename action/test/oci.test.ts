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
    expect(await ociClient({ fetch: down }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'error', message: 'HTTP 503' });
    const boom = fakeFetch(() => {
      throw new TypeError('fetch failed');
    });
    expect(await ociClient({ fetch: boom }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'error', message: 'fetch failed' });
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
      expect(await ociClient({ fetch: f }).verifyDigest('docker.io/library/node', D)).toEqual({ status: 'error', message: `HTTP ${status} with an anonymous token` });
    }
  });

  it('never follows redirects (3xx is an error); a manifest over 4 MB is not hashed', async () => {
    const r = registry((c) => (c.method === 'HEAD' ? new Response(null, { status: 307, headers: { location: 'https://elsewhere.example/x' } }) : undefined));
    expect(await ociClient({ fetch: r }).resolveTag('docker.io/library/node', '22')).toEqual({ status: 'error', message: 'HTTP 307' });
    expect(r.calls.some((c) => c.url.includes('elsewhere'))).toBe(false);
    const big = registry((c) => (c.method === 'HEAD' ? new Response(null) : new Response(new Uint8Array(4 * 1024 * 1024 + 1))));
    expect(await ociClient({ fetch: big }).resolveTag('docker.io/library/node', '22')).toEqual({ status: 'error', message: 'manifest larger than 4 MB' });
  });

  it('rejects an invalid tag without a request', async () => {
    const f = fakeFetch(() => undefined);
    expect((await ociClient({ fetch: f }).resolveTag('docker.io/library/node', '../x')).status).toBe('error');
    expect(f.calls).toEqual([]);
  });
});
