import { env } from 'cloudflare:workers';
import { applyD1Migrations } from 'cloudflare:test';
import { hashToken, newToken } from '../src/auth';
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

export async function seedProject(env: Env, id: string): Promise<{ read: string; ci: string }> {
  const read = newToken('read');
  const ci = newToken('ci');
  const at = '2026-11-19T00:00:00Z';
  await env.DB.batch([
    env.DB.prepare('INSERT INTO projects (id, created_at) VALUES (?, ?)').bind(id, at),
    env.DB.prepare('INSERT INTO tokens (hash, project_id, kind, created_at) VALUES (?, ?, ?, ?)').bind(
      await hashToken(read), id, 'read', at),
    env.DB.prepare('INSERT INTO tokens (hash, project_id, kind, created_at) VALUES (?, ?, ?, ?)').bind(
      await hashToken(ci), id, 'ci', at),
  ]);
  return { read, ci };
}

/** A route that never answers but honors the request's abort signal, like a hung upstream. */
export function hang(): (req: Request) => Promise<Response> {
  return (req) =>
    new Promise((_, reject) => {
      if (req.signal.aborted) return reject(req.signal.reason);
      req.signal.addEventListener('abort', () => reject(req.signal.reason));
    });
}
