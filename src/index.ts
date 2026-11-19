import { notFound, text } from './http';
import type { Deps, Env } from './types';

export async function handle(req: Request, _env: Env, _deps: Deps, _ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === '/healthz') return text('ok');
  return notFound();
}

function defaultDeps(): Deps {
  return { fetch: (input, init) => fetch(input, init), now: () => new Date() };
}

export default {
  fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handle(req, env, defaultDeps(), ctx);
  },
  async scheduled(_event: ScheduledController, _env: Env, _ctx: ExecutionContext): Promise<void> {
    // Cron sweep arrives in a later task.
  },
};
