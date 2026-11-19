import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import type { Env } from '../src/types';

// Setup (runs via vitest setupFiles): apply migrations/ to the test D1.
await applyD1Migrations(
  (env as unknown as Env).DB,
  (env as unknown as { TEST_MIGRATIONS: Parameters<typeof applyD1Migrations>[1] }).TEST_MIGRATIONS,
);

export function fixedClock(iso: string): () => Date {
  return () => new Date(iso);
}

type Route = Response | ((req: Request) => Response | Promise<Response>);

export function fakeFetch(routes: Record<string, Route>): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const fn = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const req = new Request(input, init);
    calls.push(req.url);
    const route = routes[req.url];
    if (route === undefined) throw new Error(`fakeFetch: unexpected URL ${req.url}`);
    return typeof route === 'function' ? route(req) : route.clone();
  };
  return Object.assign(fn, { calls }) as typeof fetch & { calls: string[] };
}

export async function seedProject(_env: Env, _id: string): Promise<{ read: string; ci: string }> {
  throw new Error('not implemented until Task 3');
}
