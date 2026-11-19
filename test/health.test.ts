import { env } from 'cloudflare:workers';
import { expect, it } from 'vitest';
import { handle } from '../src/index';
import { fakeFetch, fixedClock } from './helpers';
import type { Env } from '../src/types';

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

it('GET /healthz returns ok', async () => {
  const deps = { fetch: fakeFetch({}), now: fixedClock('2026-11-19T00:00:00Z') };
  const res = await handle(new Request('https://decant.test/healthz'), env as unknown as Env, deps, ctx);
  expect(res.status).toBe(200);
  expect(await res.text()).toBe('ok');
});
