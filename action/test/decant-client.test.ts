import { describe, expect, it } from 'vitest';
import { decant } from '../src/decant-client';
import { fakeFetch, jsonRes } from './fakes';

const URL_ = 'https://decant.example';
const TOKEN = 'dk_ci_SECRETSECRET';

const notAvailable = (id: string, why: string) => jsonRes({ error: `${id} is not available: ${why}` }, 404);

describe('decant client', () => {
  it('sends Bearer auth and a timeout signal', async () => {
    const f = fakeFetch(() => jsonRes({ blocks: [] }));
    await decant(f, URL_, TOKEN).blocks();
    expect(f.calls[0]!.url).toBe(`${URL_}/api/blocks`);
    expect(f.calls[0]!.headers.get('authorization')).toBe(`Bearer ${TOKEN}`);
    expect(f.calls[0]!.signal).toBeInstanceOf(AbortSignal);
  });

  it('syncPolicy PUTs {policy, sha, ref} and returns status and body without throwing', async () => {
    const f = fakeFetch(() => jsonRes({ error: 'sync main first' }, 409));
    const r = await decant(f, `${URL_}/`, TOKEN).syncPolicy('proj', { project: 'proj' }, 'abc', 'pr-3');
    expect(r).toEqual({ status: 409, body: { error: 'sync main first' } });
    expect(f.calls[0]!.method).toBe('PUT');
    expect(f.calls[0]!.url).toBe(`${URL_}/api/projects/proj/policy`);
    expect(JSON.parse(f.calls[0]!.body!)).toEqual({ policy: { project: 'proj' }, sha: 'abc', ref: 'pr-3' });
  });

  it('getVerdicts queries by package id; putVerdict PUTs', async () => {
    const v = { package: 'npm:a@1.0.0', scanner: 's', scannerVersion: '1', result: 'clean' as const };
    const f = fakeFetch((c) => (c.method === 'GET' ? jsonRes({ verdicts: [v] }) : new Response(null, { status: 204 })));
    const c = decant(f, URL_, TOKEN);
    expect(await c.getVerdicts('npm:@s/a@1.0.0')).toEqual([v]);
    expect(f.calls[0]!.url).toBe(`${URL_}/api/verdicts?package=npm%3A%40s%2Fa%401.0.0`);
    await c.putVerdict(v);
    expect(f.calls[1]!.method).toBe('PUT');
    expect(JSON.parse(f.calls[1]!.body!)).toEqual(v);
  });

  it('downloadNpm fetches the tarball named by the overlay metadata', async () => {
    const tgz = new Uint8Array([1, 2, 3]);
    const f = fakeFetch((c) => {
      if (c.url === `${URL_}/r/pr-7/npm/@s%2fa`) {
        return jsonRes({ name: '@s/a', versions: { '1.0.0': { dist: { tarball: `${URL_}/r/pr-7/npm/@s/a/-/a-1.0.0.tgz` } } } });
      }
      if (c.url === `${URL_}/r/pr-7/npm/@s/a/-/a-1.0.0.tgz`) return new Response(tgz);
    });
    const r = await decant(f, URL_, TOKEN).downloadNpm('@s/a', '1.0.0', 'pr-7');
    expect(r).toEqual({ status: 'ok', bytes: tgz });
    expect(f.calls.every((c) => c.headers.get('authorization') === `Bearer ${TOKEN}`)).toBe(true);
  });

  it('downloadNpm maps a 404 "in cooldown" to cooldown and "blocked" to blocked', async () => {
    const meta = jsonRes({ name: 'a', versions: {} });
    let why = 'in cooldown';
    const f = fakeFetch((c) => (c.url.endsWith('/npm/a') ? meta.clone() : notAvailable('npm:a@1.0.0', why)));
    const c = decant(f, URL_, TOKEN);
    expect(await c.downloadNpm('a', '1.0.0')).toEqual({ status: 'cooldown' });
    expect(f.calls[1]!.url).toBe(`${URL_}/npm/a/-/a-1.0.0.tgz`);
    why = 'blocked';
    expect(await c.downloadNpm('a', '1.0.0')).toEqual({ status: 'blocked' });
  });

  it('downloadNpm maps a plain 404 to missing', async () => {
    const f = fakeFetch(() => jsonRes({ error: 'npm:a not found' }, 404));
    expect(await decant(f, URL_, TOKEN).downloadNpm('a', '1.0.0')).toEqual({ status: 'missing' });
  });

  it('downloadNpm refuses a tarball on another host and never sends the token there', async () => {
    const f = fakeFetch((c) => {
      if (c.url.endsWith('/npm/a')) return jsonRes({ name: 'a', versions: { '1.0.0': { dist: { tarball: 'https://evil.example/a-1.0.0.tgz' } } } });
      return new Response('x');
    });
    await expect(decant(f, URL_, TOKEN).downloadNpm('a', '1.0.0')).rejects.toThrow(/host/);
    expect(f.calls.some((c) => c.url.startsWith('https://evil.example'))).toBe(false);
  });

  it('downloadGo uses Basic decant:<token>, escaped paths, and maps blocked', async () => {
    const f = fakeFetch((c) =>
      c.url.endsWith('v1.0.0.zip') ? new Response(new Uint8Array([9])) : new Response('github.com/A/b@v2.0.0 is not available: blocked', { status: 404 }),
    );
    const c = decant(f, URL_, TOKEN);
    expect(await c.downloadGo('github.com/A/b', 'v1.0.0', 'pr-1')).toEqual({ status: 'ok', bytes: new Uint8Array([9]) });
    expect(f.calls[0]!.url).toBe(`${URL_}/r/pr-1/go/github.com/!a/b/@v/v1.0.0.zip`);
    expect(f.calls[0]!.headers.get('authorization')).toBe(`Basic ${Buffer.from(`decant:${TOKEN}`).toString('base64')}`);
    expect(f.calls[0]!.url).not.toContain(TOKEN);
    expect(await c.downloadGo('github.com/A/b', 'v2.0.0')).toEqual({ status: 'blocked' });
  });

  it('never puts the token in a thrown error', async () => {
    const echo = fakeFetch((c) => new Response(`bad auth ${c.headers.get('authorization')}`, { status: 500 }));
    const err = await decant(echo, URL_, TOKEN).blocks().catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).not.toContain(TOKEN);
    const boom = (async (_u: string, init: RequestInit) => {
      throw new Error(`connect failed with ${new Headers(init.headers).get('authorization')}`);
    }) as unknown as typeof fetch;
    const err2 = await decant(boom, URL_, TOKEN).downloadGo('m', 'v1.0.0').catch((e: Error) => e);
    expect((err2 as Error).message).not.toContain(TOKEN);
    expect((err2 as Error).message).not.toContain(Buffer.from(`decant:${TOKEN}`).toString('base64'));
  });
});

describe('retries connection-level failures', () => {
  /** What undici's fetch throws when the connection drops before a response. */
  const netErr = (code: string, message = `read ${code}`) => new TypeError('fetch failed', { cause: Object.assign(new Error(message), { code }) });
  const v = { package: 'npm:a@1.0.0', scanner: 's', scannerVersion: '1', result: 'clean' as const };

  /** A fetch that plays `script` in order (a thrown Error or a Response), recording calls. */
  function scripted(script: (Error | Response)[]) {
    const calls: { method: string; url: string; body: unknown }[] = [];
    const f = (async (u: string, init: RequestInit) => {
      calls.push({ method: init.method ?? 'GET', url: u, body: init.body });
      const next = script.shift();
      if (!next) throw new Error('script exhausted');
      if (next instanceof Error) throw next;
      return next;
    }) as unknown as typeof fetch;
    const sleeps: number[] = [];
    const client = decant(f, URL_, TOKEN, { sleep: async (ms) => void sleeps.push(ms), random: () => 0.5 });
    return { client, calls, sleeps };
  }

  it('a GET that drops twice then succeeds returns the result after backoff', async () => {
    const s = scripted([netErr('ECONNRESET'), netErr('ECONNRESET'), jsonRes({ verdicts: [v] })]);
    expect(await s.client.getVerdicts('npm:a@1.0.0')).toEqual([v]);
    expect(s.calls).toHaveLength(3);
    expect(s.sleeps).toEqual([500, 1000]);
  });

  it('gives up after 4 attempts with the cause in the message', async () => {
    const s = scripted([netErr('ECONNRESET'), netErr('ECONNRESET'), netErr('ECONNRESET'), netErr('ECONNRESET')]);
    await expect(s.client.getVerdicts('npm:a@1.0.0')).rejects.toThrow(/^decant GET \/api\/verdicts: fetch failed \(ECONNRESET\) after 4 attempts$/);
    expect(s.calls).toHaveLength(4);
    expect(s.sleeps).toEqual([500, 1000, 2000]);
  });

  it('names a cause without its code in the message', async () => {
    const s = scripted(Array.from({ length: 4 }, () => netErr('UND_ERR_SOCKET', 'other side closed')));
    await expect(s.client.blocks()).rejects.toThrow('decant GET /api/blocks: fetch failed (UND_ERR_SOCKET: other side closed) after 4 attempts');
  });

  it('jitters the backoff', async () => {
    const sleeps: number[] = [];
    let n = 0;
    const f = (async () => {
      if (n++ < 3) throw netErr('ETIMEDOUT');
      return jsonRes({ blocks: [] });
    }) as unknown as typeof fetch;
    await decant(f, URL_, TOKEN, { sleep: async (ms) => void sleeps.push(ms), random: () => 0 }).blocks();
    const hi: number[] = [];
    n = 0;
    await decant(f, URL_, TOKEN, { sleep: async (ms) => void hi.push(ms), random: () => 0.999 }).blocks();
    for (const [i, base] of [500, 1000, 2000].entries()) {
      expect(sleeps[i]).toBeGreaterThanOrEqual(base * 0.75);
      expect(hi[i]).toBeLessThanOrEqual(base * 1.25);
      expect(hi[i]).toBeGreaterThan(sleeps[i]!);
    }
  });

  it('PUT /api/verdicts retries 502/503/504 with the same body', async () => {
    const s = scripted([new Response('bad gateway', { status: 502 }), new Response('', { status: 503 }), new Response('', { status: 504 }), new Response(null, { status: 204 })]);
    await s.client.putVerdict(v);
    expect(s.calls.map((c) => c.method)).toEqual(['PUT', 'PUT', 'PUT', 'PUT']);
    expect(new Set(s.calls.map((c) => c.body)).size).toBe(1);
  });

  it('a 5xx that persists is reported as that HTTP status after 4 attempts', async () => {
    const s = scripted(Array.from({ length: 4 }, () => new Response('unavailable', { status: 503 })));
    await expect(s.client.putVerdict(v)).rejects.toThrow(/^decant PUT \/api\/verdicts: HTTP 503 unavailable$/);
    expect(s.calls).toHaveLength(4);
  });

  it('the policy sync (idempotent PUT) retries a 503 and returns the final status', async () => {
    const s = scripted([new Response('', { status: 503 }), jsonRes({ ref: 'pr-3' })]);
    expect(await s.client.syncPolicy('proj', { project: 'proj' }, 'abc', 'pr-3')).toEqual({ status: 200, body: { ref: 'pr-3' } });
    expect(s.calls).toHaveLength(2);
  });

  it('never retries a 4xx or a plain 500', async () => {
    for (const status of [400, 401, 404, 409, 429, 500]) {
      const s = scripted([new Response('no', { status }), new Response(null, { status: 204 })]);
      await s.client.putVerdict(v).catch(() => {});
      expect(s.calls).toHaveLength(1);
      expect(s.sleeps).toEqual([]);
    }
  });

  it('retries a timeout', async () => {
    const t = () => Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });
    const s = scripted([t(), t(), t(), t()]);
    await expect(s.client.blocks()).rejects.toThrow('decant GET /api/blocks: timed out (30s) after 4 attempts');
  });

  it('never puts the token in the final error', async () => {
    const leaky = new TypeError('fetch failed', { cause: Object.assign(new Error(`socket for Bearer ${TOKEN}`), { code: 'ECONNRESET' }) });
    const s = scripted([leaky, leaky, leaky, leaky]);
    const err = await s.client.blocks().catch((e: Error) => e);
    expect((err as Error).message).toContain('after 4 attempts');
    expect((err as Error).message).not.toContain(TOKEN);
  });
});

describe('availability (review fix: cached verdicts still check the ref)', () => {
  it('npm: a listed version is ok after one metadata GET, with no tarball download', async () => {
    const f = fakeFetch(() => jsonRes({ versions: { '1.0.0': { dist: { tarball: `${URL_}/r/pr-1/npm/a/-/a-1.0.0.tgz` } } } }));
    expect(await decant(f, URL_, TOKEN).availability('npm', 'a', '1.0.0', 'pr-1')).toBe('ok');
    expect(f.calls.map((c) => c.url)).toEqual([`${URL_}/r/pr-1/npm/a`]);
  });
  it('npm: an unlisted version asks the tarball path why (cooldown/blocked)', async () => {
    const f = fakeFetch((c) => (c.url.endsWith('.tgz') ? notAvailable('a@1.0.0', 'in cooldown') : jsonRes({ versions: {} })));
    expect(await decant(f, URL_, TOKEN).availability('npm', 'a', '1.0.0', 'pr-1')).toBe('cooldown');
  });
  it('go: GETs .info through the ref', async () => {
    const f = fakeFetch(() => notAvailable('m@v1.0.0', 'blocked'));
    expect(await decant(f, URL_, TOKEN).availability('go', 'example.com/m', 'v1.0.0', 'pr-1')).toBe('blocked');
    expect(f.calls[0]!.url).toBe(`${URL_}/r/pr-1/go/example.com/m/@v/v1.0.0.info`);
    const ok = fakeFetch(() => jsonRes({ Version: 'v1.0.0', Time: '2026-01-01T00:00:00Z' }));
    expect(await decant(ok, URL_, TOKEN).availability('go', 'example.com/m', 'v1.0.0', 'pr-1')).toBe('ok');
  });
});
