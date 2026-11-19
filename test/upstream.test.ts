import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { cachedFetch } from '../src/upstream';
import type { Deps, Env } from '../src/types';
import { fakeFetch, hang } from './helpers';

const e = env as unknown as Env;
let n = 0;
const k = () => `test-upstream/${++n}`;
const T0 = Date.parse('2026-11-19T00:00:00Z');
function mk(f: typeof fetch, t: { ms: number }): Deps {
  return { fetch: f, now: () => new Date(t.ms) };
}
const text = (b: ArrayBuffer) => new TextDecoder().decode(b);

describe('cachedFetch', () => {
  it('fetches first, serves fresh within 300s, refetches at 301s', async () => {
    const key = k();
    const url = 'https://u.test/a';
    const f = fakeFetch({ [url]: new Response('v1') });
    const t = { ms: T0 };
    const d = mk(f, t);
    const r1 = await cachedFetch(e, d, { key, url });
    expect(r1).toMatchObject({ status: 'ok', stale: false });
    t.ms = T0 + 300_000;
    await cachedFetch(e, d, { key, url });
    expect(f.calls.length).toBe(1);
    t.ms = T0 + 301_000;
    await cachedFetch(e, d, { key, url });
    expect(f.calls.length).toBe(2);
  });

  it('sends Accept header', async () => {
    const url = 'https://u.test/acc';
    let seen = '';
    const f = fakeFetch({
      [url]: (r) => {
        seen = r.headers.get('accept') ?? '';
        return new Response('x');
      },
    });
    await cachedFetch(e, mk(f, { ms: T0 }), { key: k(), url, accept: 'application/vnd.npm.install-v1+json' });
    expect(seen).toBe('application/vnd.npm.install-v1+json');
  });

  it('500 with stored copy serves stale; with nothing stored is unavailable', async () => {
    const key = k();
    const url = 'https://u.test/b';
    let status = 200;
    const f = fakeFetch({ [url]: () => new Response('body', { status }) });
    const t = { ms: T0 };
    const d = mk(f, t);
    await cachedFetch(e, d, { key, url });
    status = 500;
    t.ms = T0 + 400_000;
    const r = await cachedFetch(e, d, { key, url });
    expect(r.status).toBe('ok');
    if (r.status === 'ok') {
      expect(r.stale).toBe(true);
      expect(text(r.body)).toBe('body');
    }
    expect(await cachedFetch(e, d, { key: k(), url })).toEqual({ status: 'unavailable' });
  });

  it('429 and network error serve stale', async () => {
    const key = k();
    const url = 'https://u.test/c';
    let mode: 'ok' | '429' | 'throw' = 'ok';
    const f = (async () => {
      if (mode === 'throw') throw new Error('net');
      return mode === '429' ? new Response('', { status: 429 }) : new Response('good');
    }) as unknown as typeof fetch;
    const t = { ms: T0 };
    const d = mk(f, t);
    await cachedFetch(e, d, { key, url });
    t.ms = T0 + 400_000;
    mode = '429';
    expect(await cachedFetch(e, d, { key, url })).toMatchObject({ status: 'ok', stale: true });
    mode = 'throw';
    expect(await cachedFetch(e, d, { key, url })).toMatchObject({ status: 'ok', stale: true });
    expect(await cachedFetch(e, d, { key: k(), url })).toEqual({ status: 'unavailable' });
  });

  it('404 with stored copy serves stale; 404 with none is not-found and not stored', async () => {
    const key = k();
    const url = 'https://u.test/d';
    let status = 200;
    const f = fakeFetch({ [url]: () => new Response('gone-soon', { status }) });
    const t = { ms: T0 };
    const d = mk(f, t);
    await cachedFetch(e, d, { key, url });
    status = 404;
    t.ms = T0 + 400_000;
    expect(await cachedFetch(e, d, { key, url })).toMatchObject({ status: 'ok', stale: true });
    const key2 = k();
    expect(await cachedFetch(e, d, { key: key2, url })).toEqual({ status: 'not-found' });
    expect(await e.BUCKET.head(key2)).toBeNull();
  });

  it('concurrent calls share one fetch', async () => {
    const url = 'https://u.test/e';
    const f = fakeFetch({ [url]: new Response('x') });
    const d = mk(f, { ms: T0 });
    const key = k();
    const [a, b] = await Promise.all([cachedFetch(e, d, { key, url }), cachedFetch(e, d, { key, url })]);
    expect(f.calls.length).toBe(1);
    expect(a.status).toBe('ok');
    expect(b.status).toBe('ok');
  });

  it('immutable never refetches', async () => {
    const url = 'https://u.test/f';
    const key = k();
    const f = fakeFetch({ [url]: new Response('x') });
    const t = { ms: T0 };
    const d = mk(f, t);
    await cachedFetch(e, d, { key, url, immutable: true });
    t.ms = T0 + 999_999_000;
    await cachedFetch(e, d, { key, url, immutable: true });
    expect(f.calls.length).toBe(1);
  });

  it('R2 put failure still returns the body', async () => {
    const url = 'https://u.test/g';
    const f = fakeFetch({ [url]: new Response('data') });
    const badEnv = {
      BUCKET: { get: async () => null, put: async () => { throw new Error('r2 down'); } },
    } as unknown as Env;
    const r = await cachedFetch(badEnv, mk(f, { ms: T0 }), { key: k(), url });
    expect(r.status).toBe('ok');
    if (r.status === 'ok') {
      expect(r.stale).toBe(false);
      expect(text(r.body)).toBe('data');
    }
  });

  it('hung upstream times out: stored copy served stale; nothing stored is unavailable', async () => {
    const key = k();
    const url = 'https://u.test/hang';
    let hung = false;
    const ok = fakeFetch({ [url]: new Response('old') });
    const h = fakeFetch({ [url]: hang() });
    const f = ((i: RequestInfo | URL, init?: RequestInit) => (hung ? h(i, init) : ok(i, init))) as typeof fetch;
    const t = { ms: T0 };
    const d: Deps = { ...mk(f, t), timeoutMs: 20 };
    await cachedFetch(e, d, { key, url });
    hung = true;
    t.ms = T0 + 400_000;
    const r = await cachedFetch(e, d, { key, url });
    expect(r).toMatchObject({ status: 'ok', stale: true });
    if (r.status === 'ok') expect(text(r.body)).toBe('old');
    expect(await cachedFetch(e, d, { key: k(), url })).toEqual({ status: 'unavailable' });
  });
});
