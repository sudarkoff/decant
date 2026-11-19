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
