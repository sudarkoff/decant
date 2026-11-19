import { describe, expect, it } from 'vitest';
import { goPublishTime, npmPublishTime } from '../src/registries';
import { fakeFetch, jsonRes } from './fakes';

describe('npmPublishTime', () => {
  it('reads time[version] from the public registry', async () => {
    const f = fakeFetch(() => jsonRes({ time: { '1.0.0': '2026-01-02T03:04:05.000Z' } }));
    expect(await npmPublishTime(f, '@s/a', '1.0.0')).toEqual(new Date('2026-01-02T03:04:05.000Z'));
    expect(f.calls[0]!.url).toBe('https://registry.npmjs.org/@s%2fa');
  });
  it('null for an unknown version or package', async () => {
    expect(await npmPublishTime(fakeFetch(() => jsonRes({ time: {} })), 'a', '1.0.0')).toBeNull();
    expect(await npmPublishTime(fakeFetch(() => jsonRes({}, 404)), 'a', '1.0.0')).toBeNull();
  });
  it('throws on a server error', async () => {
    await expect(npmPublishTime(fakeFetch(() => new Response('x', { status: 503 })), 'a', '1.0.0')).rejects.toThrow(/503/);
  });
});

describe('goPublishTime', () => {
  it('reads Time from the escaped .info', async () => {
    const f = fakeFetch(() => jsonRes({ Version: 'v1.2.3', Time: '2026-02-03T00:00:00Z' }));
    expect(await goPublishTime(f, 'github.com/Foo/bar', 'v1.2.3')).toEqual(new Date('2026-02-03T00:00:00Z'));
    expect(f.calls[0]!.url).toBe('https://proxy.golang.org/github.com/!foo/bar/@v/v1.2.3.info');
  });
  it('null on 404/410', async () => {
    expect(await goPublishTime(fakeFetch(() => new Response('gone', { status: 410 })), 'm', 'v1.0.0')).toBeNull();
  });
});
