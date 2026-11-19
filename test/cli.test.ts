import { expect, it } from 'vitest';
import { hashToken } from '../src/auth';
import { buildRequest, makeOperatorToken } from '../scripts/cli-lib';

const env = { DECANT_URL: 'https://d.example.com', DECANT_OPERATOR_TOKEN: 'dk_op_x' };

it('project create -> POST /api/projects with operator bearer', async () => {
  const r = buildRequest(['project', 'create', 'twocal'], env);
  if ('error' in r) throw new Error(r.error);
  expect(r.method).toBe('POST');
  expect(r.url).toBe('https://d.example.com/api/projects');
  expect(r.headers.get('authorization')).toBe('Bearer dk_op_x');
  expect(await r.json()).toEqual({ id: 'twocal' });
});

it('trailing slash on DECANT_URL is tolerated', () => {
  const r = buildRequest(['project', 'create', 'a'], { ...env, DECANT_URL: 'https://d.example.com/' });
  expect('error' in r ? r.error : r.url).toBe('https://d.example.com/api/projects');
});

it('token create -> POST /api/projects/:id/tokens', async () => {
  const r = buildRequest(['token', 'create', 'twocal', 'ci'], env);
  if ('error' in r) throw new Error(r.error);
  expect(r.url).toBe('https://d.example.com/api/projects/twocal/tokens');
  expect(await r.json()).toEqual({ kind: 'ci' });
});

it('missing DECANT_URL or token -> error', () => {
  expect(buildRequest(['project', 'create', 'a'], { DECANT_OPERATOR_TOKEN: 't' })).toEqual({ error: 'DECANT_URL is not set' });
  expect(buildRequest(['project', 'create', 'a'], { DECANT_URL: 'https://x' })).toEqual({ error: 'DECANT_OPERATOR_TOKEN is not set' });
});

it('bad kind -> error', () => {
  expect(buildRequest(['token', 'create', 'twocal', 'admin'], env)).toEqual({ error: 'kind must be read, ci or sync' });
});

it('usage errors', () => {
  expect('error' in buildRequest([], env)).toBe(true);
  expect('error' in buildRequest(['project', 'create'], env)).toBe(true);
  expect('error' in buildRequest(['nope'], env)).toBe(true);
});

it('op-token has the dk_op_ format and a matching SHA-256 hex hash', async () => {
  const { token, hash } = await makeOperatorToken();
  expect(token).toMatch(/^dk_op_[A-Za-z0-9_-]{43}$/);
  expect(hash).toBe(await hashToken(token));
  expect(hash).toMatch(/^[0-9a-f]{64}$/);
});

it('token create sync builds a sync-kind request', async () => {
  const r = buildRequest(['token', 'create', 'twocal', 'sync'], env);
  if (!(r instanceof Request)) throw new Error('expected request');
  expect(await r.json()).toEqual({ kind: 'sync' });
});
