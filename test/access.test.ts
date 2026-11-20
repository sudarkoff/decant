import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { verifyAccess } from '../src/dashboard/access';
import { handle } from '../src/index';
import type { Deps, Env } from '../src/types';
import { fakeFetch, fixedClock, seedProject } from './helpers';

const AUD = 'aud-0123456789abcdef';
const T0 = '2026-11-19T12:00:00Z';
const T0S = Date.parse(T0) / 1000;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

let domainSeq = 0;
/** Each test gets its own team domain so the module-level JWKS cache never leaks between tests. */
function freshDomain(): string {
  return `team${++domainSeq}-${Math.random().toString(36).slice(2, 8)}.cloudflareaccess.com`;
}

const enc = new TextEncoder();
function b64url(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? enc.encode(data) : data;
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface KeyPair { priv: CryptoKey; jwk: JsonWebKey & { kid: string }; spki: Uint8Array }
async function keyPair(kid: string): Promise<KeyPair> {
  const kp = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey;
  const spki = new Uint8Array((await crypto.subtle.exportKey('spki', kp.publicKey)) as ArrayBuffer);
  return { priv: kp.privateKey, jwk: { ...jwk, kid, alg: 'RS256', use: 'sig' }, spki };
}

async function signRS256(k: KeyPair, payload: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  const h = b64url(JSON.stringify({ alg: 'RS256', kid: k.jwk.kid, typ: 'JWT', ...header }));
  const p = b64url(JSON.stringify(payload));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', k.priv, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
}

function claims(domain: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    aud: [AUD],
    iss: `https://${domain}`,
    exp: T0S + 300,
    iat: T0S - 10,
    nbf: T0S - 10,
    email: 'george@example.com',
    sub: 'u1',
    ...over,
  };
}

function certsUrl(domain: string): string {
  return `https://${domain}/cdn-cgi/access/certs`;
}

function jwksResponse(...keys: object[]): Response {
  return new Response(JSON.stringify({ keys }), { headers: { 'content-type': 'application/json' } });
}

/** `aud` defaults to AUD; pass null for "unset" (an explicit undefined would hit the default). */
function accessEnv(domain: string | undefined, aud: string | null = AUD): Env {
  return { ...(env as unknown as Env), ACCESS_TEAM_DOMAIN: domain, ACCESS_AUD: aud ?? undefined };
}

function req(path: string, token?: string, method = 'GET'): Request {
  const headers: Record<string, string> = {};
  if (token !== undefined) headers['Cf-Access-Jwt-Assertion'] = token;
  return new Request(`https://decant.test${path}`, { method, headers });
}

let kA: KeyPair;
let kB: KeyPair;

beforeAll(async () => {
  kA = await keyPair('kid-a');
  kB = await keyPair('kid-b');
});

describe('verifyAccess', () => {
  async function verify(token: string | undefined, opts: { now?: string; domain?: string } = {}) {
    const domain = opts.domain ?? freshDomain();
    const fetch = fakeFetch({ [certsUrl(domain)]: jwksResponse(kA.jwk) });
    const deps: Deps = { fetch, now: fixedClock(opts.now ?? T0) };
    return { result: await verifyAccess(req('/dashboard', token), accessEnv(domain), deps), fetch, domain };
  }

  it('accepts a valid token and returns the email', async () => {
    const domain = freshDomain();
    const { result } = await verify(await signRS256(kA, claims(domain)), { domain });
    expect(result).toEqual({ email: 'george@example.com' });
  });

  it('accepts aud as a plain string', async () => {
    const domain = freshDomain();
    const { result } = await verify(await signRS256(kA, claims(domain, { aud: AUD })), { domain });
    expect(result).toEqual({ email: 'george@example.com' });
  });

  it('returns email null when the token has no email', async () => {
    const domain = freshDomain();
    const { result } = await verify(await signRS256(kA, claims(domain, { email: undefined })), { domain });
    expect(result).toEqual({ email: null });
  });

  it('accepts exp within the 60 s leeway and nbf within the leeway', async () => {
    const domain = freshDomain();
    const tok = await signRS256(kA, claims(domain, { exp: T0S - 30, nbf: T0S + 30 }));
    expect((await verify(tok, { domain })).result).not.toBeNull();
  });

  const bad: [string, (d: string) => Promise<string>][] = [
    ['wrong aud', (d) => signRS256(kA, claims(d, { aud: ['other'] }))],
    ['wrong aud (string)', (d) => signRS256(kA, claims(d, { aud: 'other' }))],
    ['missing aud', (d) => signRS256(kA, claims(d, { aud: undefined }))],
    ['wrong iss', (d) => signRS256(kA, claims(d, { iss: 'https://evil.cloudflareaccess.com' }))],
    ['iss with trailing slash', (d) => signRS256(kA, claims(d, { iss: `https://${d}/` }))],
    ['expired beyond leeway', (d) => signRS256(kA, claims(d, { exp: T0S - 61 }))],
    ['missing exp', (d) => signRS256(kA, claims(d, { exp: undefined }))],
    ['non-numeric exp', (d) => signRS256(kA, claims(d, { exp: String(T0S + 300) }))],
    ['nbf beyond leeway', (d) => signRS256(kA, claims(d, { nbf: T0S + 61 }))],
    ['signed by an unknown key with a known kid', (d) => signRS256({ ...kB, jwk: { ...kB.jwk, kid: 'kid-a' } }, claims(d))],
    ['crit header', (d) => signRS256(kA, claims(d), { crit: ['exp'] })],
    ['empty kid', (d) => signRS256(kA, claims(d), { kid: '' })],
    ['missing kid', (d) => signRS256(kA, claims(d), { kid: undefined })],
    ['alg rs256 lowercase', (d) => signRS256(kA, claims(d), { alg: 'rs256' })],
    ['alg none', async (d) => {
      const h = b64url(JSON.stringify({ alg: 'none', kid: 'kid-a', typ: 'JWT' }));
      return `${h}.${b64url(JSON.stringify(claims(d)))}.`;
    }],
    ['alg none without signature segment', async (d) => {
      const h = b64url(JSON.stringify({ alg: 'none', kid: 'kid-a' }));
      return `${h}.${b64url(JSON.stringify(claims(d)))}`;
    }],
    ['alg HS256 keyed with the public key (alg confusion)', async (d) => {
      const h = b64url(JSON.stringify({ alg: 'HS256', kid: 'kid-a', typ: 'JWT' }));
      const p = b64url(JSON.stringify(claims(d)));
      const out: string[] = [];
      // Try both common "secret" encodings of the public key.
      for (const secret of [kA.spki, enc.encode(JSON.stringify(kA.jwk))]) {
        const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${p}`));
        out.push(`${h}.${p}.${b64url(new Uint8Array(sig))}`);
      }
      return out[0]!;
    }],
    ['tampered payload', async (d) => {
      const t = await signRS256(kA, claims(d));
      const [h, , s] = t.split('.');
      return `${h}.${b64url(JSON.stringify(claims(d, { email: 'mallory@example.com' })))}.${s}`;
    }],
    ['bad signature bytes', async (d) => {
      const t = await signRS256(kA, claims(d));
      const [h, p] = t.split('.');
      return `${h}.${p}.${b64url(new Uint8Array(256))}`;
    }],
    ['four segments', async (d) => `${await signRS256(kA, claims(d))}.x`],
    ['garbage', async () => 'not-a-jwt'],
    ['non-JSON header', async (d) => {
      const t = await signRS256(kA, claims(d));
      return `${b64url('nope')}.${t.split('.').slice(1).join('.')}`;
    }],
    ['payload that is a JSON array', async (d) => {
      const h = b64url(JSON.stringify({ alg: 'RS256', kid: 'kid-a' }));
      const p = b64url('[]');
      const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', kA.priv, enc.encode(`${h}.${p}`));
      void d;
      return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
    }],
  ];
  for (const [name, make] of bad) {
    it(`rejects: ${name}`, async () => {
      const domain = freshDomain();
      const { result } = await verify(await make(domain), { domain });
      expect(result).toBeNull();
    });
  }

  it('rejects HS256 tokens for every public-key secret encoding', async () => {
    const domain = freshDomain();
    const h = b64url(JSON.stringify({ alg: 'HS256', kid: 'kid-a', typ: 'JWT' }));
    const p = b64url(JSON.stringify(claims(domain)));
    for (const secret of [kA.spki, enc.encode(JSON.stringify(kA.jwk)), enc.encode(kA.jwk.n!)]) {
      const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${p}`));
      const { result } = await verify(`${h}.${p}.${b64url(new Uint8Array(sig))}`, { domain });
      expect(result).toBeNull();
    }
  });

  it('rejects a missing header without fetching the JWKS', async () => {
    const { result, fetch } = await verify(undefined);
    expect(result).toBeNull();
    expect(fetch.calls).toEqual([]);
  });

  it('denies when the JWKS fetch fails', async () => {
    const domain = freshDomain();
    const fetch = fakeFetch({ [certsUrl(domain)]: new Response('oops', { status: 500 }) });
    const deps: Deps = { fetch, now: fixedClock(T0) };
    expect(await verifyAccess(req('/dashboard', await signRS256(kA, claims(domain))), accessEnv(domain), deps)).toBeNull();
  });

  it('denies when the JWKS fetch throws', async () => {
    const domain = freshDomain();
    const fetch = fakeFetch({ [certsUrl(domain)]: () => { throw new Error('network'); } });
    const deps: Deps = { fetch, now: fixedClock(T0) };
    expect(await verifyAccess(req('/dashboard', await signRS256(kA, claims(domain))), accessEnv(domain), deps)).toBeNull();
  });

  it('ignores non-RSA keys in the JWKS', async () => {
    const domain = freshDomain();
    const ec = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const ecJwk = { ...((await crypto.subtle.exportKey('jwk', ec.publicKey)) as JsonWebKey), kid: 'kid-a' };
    const fetch = fakeFetch({ [certsUrl(domain)]: jwksResponse(ecJwk) });
    const deps: Deps = { fetch, now: fixedClock(T0) };
    expect(await verifyAccess(req('/dashboard', await signRS256(kA, claims(domain))), accessEnv(domain), deps)).toBeNull();
  });

  it('caches the JWKS across requests', async () => {
    const domain = freshDomain();
    const fetch = fakeFetch({ [certsUrl(domain)]: jwksResponse(kA.jwk) });
    const deps: Deps = { fetch, now: fixedClock(T0) };
    const tok = await signRS256(kA, claims(domain));
    expect(await verifyAccess(req('/dashboard', tok), accessEnv(domain), deps)).not.toBeNull();
    expect(await verifyAccess(req('/dashboard', tok), accessEnv(domain), deps)).not.toBeNull();
    expect(fetch.calls).toHaveLength(1);
  });

  it('unknown kid: refetches once, then denies', async () => {
    const domain = freshDomain();
    const fetch = fakeFetch({ [certsUrl(domain)]: jwksResponse(kA.jwk) });
    const e = accessEnv(domain);
    // Prime the cache at T0.
    expect(await verifyAccess(req('/dashboard', await signRS256(kA, claims(domain))), e, { fetch, now: fixedClock(T0) })).not.toBeNull();
    expect(fetch.calls).toHaveLength(1);
    // 61 s later a token with an unknown kid triggers exactly one refetch, then 403.
    const later = new Date(Date.parse(T0) + 61_000).toISOString();
    const tok = await signRS256(kB, claims(domain));
    expect(await verifyAccess(req('/dashboard', tok), e, { fetch, now: fixedClock(later) })).toBeNull();
    expect(fetch.calls).toHaveLength(2);
  });

  it('unknown kid on a cold cache does not fetch twice in one request', async () => {
    const domain = freshDomain();
    const fetch = fakeFetch({ [certsUrl(domain)]: jwksResponse(kA.jwk) });
    const tok = await signRS256(kB, claims(domain));
    expect(await verifyAccess(req('/dashboard', tok), accessEnv(domain), { fetch, now: fixedClock(T0) })).toBeNull();
    expect(fetch.calls).toHaveLength(1);
  });

  it('unknown kid within 60 s of the last fetch does not refetch (no refetch storm)', async () => {
    const domain = freshDomain();
    const fetch = fakeFetch({ [certsUrl(domain)]: jwksResponse(kA.jwk) });
    const e = accessEnv(domain);
    expect(await verifyAccess(req('/dashboard', await signRS256(kA, claims(domain))), e, { fetch, now: fixedClock(T0) })).not.toBeNull();
    const soon = new Date(Date.parse(T0) + 30_000).toISOString();
    for (let i = 0; i < 5; i++) {
      const forged = await signRS256(kB, claims(domain), { kid: `forged-${i}` });
      expect(await verifyAccess(req('/dashboard', forged), e, { fetch, now: fixedClock(soon) })).toBeNull();
    }
    expect(fetch.calls).toHaveLength(1);
  });

  it('key rotation: an unknown kid that appears after refetch is accepted', async () => {
    const domain = freshDomain();
    let keys: object[] = [kA.jwk];
    const fetch = fakeFetch({ [certsUrl(domain)]: () => jwksResponse(...keys) });
    const e = accessEnv(domain);
    expect(await verifyAccess(req('/dashboard', await signRS256(kA, claims(domain))), e, { fetch, now: fixedClock(T0) })).not.toBeNull();
    keys = [kA.jwk, kB.jwk];
    const later = new Date(Date.parse(T0) + 61_000).toISOString();
    const tok = await signRS256(kB, claims(domain, { exp: T0S + 600 }));
    expect(await verifyAccess(req('/dashboard', tok), e, { fetch, now: fixedClock(later) })).toEqual({ email: 'george@example.com' });
    expect(fetch.calls).toHaveLength(2);
  });

  it('reads the token only from the Cf-Access-Jwt-Assertion header, not cookies', async () => {
    const domain = freshDomain();
    const fetch = fakeFetch({ [certsUrl(domain)]: jwksResponse(kA.jwk) });
    const tok = await signRS256(kA, claims(domain));
    const r = new Request('https://decant.test/dashboard', { headers: { cookie: `CF_Authorization=${tok}` } });
    expect(await verifyAccess(r, accessEnv(domain), { fetch, now: fixedClock(T0) })).toBeNull();
  });
});

describe('/dashboard routing', () => {
  function setup(domain: string | undefined = freshDomain(), aud: string | null = AUD) {
    const routes: Record<string, Response> = {};
    if (domain) routes[certsUrl(domain)] = jwksResponse(kA.jwk);
    const fetch = fakeFetch(routes);
    return { e: accessEnv(domain, aud), deps: { fetch, now: fixedClock(T0) } as Deps, fetch, domain: domain ?? '' };
  }

  it('serves the page placeholder at /dashboard and /dashboard/ with a valid token', async () => {
    const { e, deps, domain } = setup();
    const tok = await signRS256(kA, claims(domain));
    for (const path of ['/dashboard', '/dashboard/']) {
      const res = await handle(req(path, tok), e, deps, ctx);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toMatch(/^text\/html/);
      expect(res.headers.get('cache-control')).toBe('no-store');
      expect(await res.text()).toContain('decant dashboard');
    }
  });

  it('HEAD is allowed', async () => {
    const { e, deps, domain } = setup();
    const res = await handle(req('/dashboard', await signRS256(kA, claims(domain)), 'HEAD'), e, deps, ctx);
    expect(res.status).toBe(200);
  });

  it('/dashboard/api/* reaches the API stub (404) after auth', async () => {
    const { e, deps, domain } = setup();
    const res = await handle(req('/dashboard/api/projects', await signRS256(kA, claims(domain))), e, deps, ctx);
    expect(res.status).toBe(404);
  });

  it('non-GET methods get 405 after auth, 403 before', async () => {
    const { e, deps, domain } = setup();
    const ok = await handle(req('/dashboard', await signRS256(kA, claims(domain)), 'POST'), e, deps, ctx);
    expect(ok.status).toBe(405);
    const anon = await handle(req('/dashboard', undefined, 'POST'), e, deps, ctx);
    expect(anon.status).toBe(403);
  });

  for (const path of ['/dashboard', '/dashboard/', '/dashboard/api/projects', '/dashboard/anything']) {
    it(`403 with an empty no-store body for a bad token on ${path}`, async () => {
      const { e, deps, domain } = setup();
      const tok = await signRS256(kA, claims(domain, { aud: ['other'] }));
      for (const t of [tok, undefined]) {
        const res = await handle(req(path, t), e, deps, ctx);
        expect(res.status).toBe(403);
        expect(res.headers.get('cache-control')).toBe('no-store');
        expect(await res.text()).toBe('');
      }
    });
  }

  const unset: [string, string | undefined, string | null][] = [
    ['both unset', undefined, null],
    ['domain unset', undefined, AUD],
    ['aud unset', 'x.cloudflareaccess.com', null],
    ['domain empty', '', AUD],
    ['aud empty', 'x.cloudflareaccess.com', ''],
    ['domain not a hostname', 'evil.com/path?', AUD],
    ['domain with scheme', 'https://x.cloudflareaccess.com', AUD],
  ];
  for (const [name, domain, aud] of unset) {
    it(`config ${name} → 404 on every /dashboard path, no JWKS fetch`, async () => {
      const fetch = fakeFetch({});
      const deps: Deps = { fetch, now: fixedClock(T0) };
      for (const path of ['/dashboard', '/dashboard/', '/dashboard/api/projects']) {
        const res = await handle(req(path, 'x.y.z'), accessEnv(domain, aud), deps, ctx);
        expect(res.status).toBe(404);
      }
      expect(fetch.calls).toEqual([]);
    });
  }

  it('/dashboardx is not a dashboard path', async () => {
    const { e, deps, fetch } = setup();
    const res = await handle(req('/dashboardx'), e, deps, ctx);
    expect(res.status).toBe(404);
    expect(fetch.calls).toEqual([]);
  });

  it('/npm/x with a read token is unaffected by the dashboard config', async () => {
    const domain = freshDomain();
    const { read } = await seedProject(env as unknown as Env, 'acc');
    const fetch = fakeFetch({
      'https://registry.npmjs.org/x': new Response('{"error":"not found"}', { status: 404 }),
    });
    const deps: Deps = { fetch, now: fixedClock(T0) };
    const r = new Request('https://decant.test/npm/x', { headers: { authorization: `Bearer ${read}` } });
    const res = await handle(r, accessEnv(domain), deps, ctx);
    expect(res.status).not.toBe(403);
    expect(fetch.calls).toEqual(['https://registry.npmjs.org/x']);
    expect(fetch.calls.some((u) => u.includes('cdn-cgi'))).toBe(false);
  });

  it('/healthz is unaffected', async () => {
    const { e, deps } = setup();
    const res = await handle(req('/healthz'), e, deps, ctx);
    expect(res.status).toBe(200);
  });
});
