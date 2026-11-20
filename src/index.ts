import { handleAdmin } from './admin/handler';
import { authenticate, type RequestCtx } from './auth';
import { runScheduled } from './cron';
import { accessConfig, verifyAccess } from './dashboard/access';
import { handleDashboardApi } from './dashboard/api';
import { dashboardPage } from './dashboard/page';
import { handleGo } from './go/handler';
import { notFound, text } from './http';
import { handleNpm } from './npm/handler';
import type { Deps, Env } from './types';

const REF_RE = /^[A-Za-z0-9._-]{1,64}$/;

function unauthorized(): Response {
  return text('unauthorized', 401, { 'www-authenticate': 'Basic realm="decant"' });
}

const DASHBOARD_API = '/dashboard/api/';

async function handleDashboard(req: Request, env: Env, deps: Deps, p: string): Promise<Response> {
  if (!accessConfig(env)) return notFound();
  if (!(await verifyAccess(req, env, deps))) {
    return new Response(null, { status: 403, headers: { 'cache-control': 'no-store' } });
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return new Response(null, { status: 405, headers: { allow: 'GET, HEAD', 'cache-control': 'no-store' } });
  }
  if (p === '/dashboard' || p === '/dashboard/') return dashboardPage();
  if (p.startsWith(DASHBOARD_API)) return handleDashboardApi(req, env, deps, p.slice(DASHBOARD_API.length));
  return notFound();
}

export async function handle(req: Request, env: Env, deps: Deps, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname;
  if (p === '/healthz') return text('ok');

  if (p === '/api' || p.startsWith('/api/')) {
    const auth = await authenticate(req, env);
    if (!auth) return unauthorized();
    return handleAdmin(req, env, deps, ctx, auth, p);
  }

  if (p === '/dashboard' || p.startsWith('/dashboard/')) return handleDashboard(req, env, deps, p);

  // /(r/<ref>/)?(npm|go)(/...)?
  const m = /^(?:\/r\/([^/]+))?\/(npm|go)(\/.*)?$/.exec(p);
  if (!m) return notFound();
  const ref = m[1] ?? null;
  if (ref !== null && !REF_RE.test(ref)) return notFound();

  const auth = await authenticate(req, env);
  if (!auth) return unauthorized();
  if (auth.kind === 'operator' || auth.kind === 'sync') return text('forbidden', 403);

  const rc: RequestCtx = {
    projectId: auth.projectId,
    ref,
    base: url.origin + (ref === null ? '' : `/r/${ref}`),
  };
  const rest = m[3] ?? '/';
  return m[2] === 'npm'
    ? handleNpm(req, env, deps, ctx, rc, rest)
    : handleGo(req, env, deps, ctx, rc, rest);
}

function defaultDeps(): Deps {
  return { fetch: (input, init) => fetch(input, init), now: () => new Date() };
}

export default {
  fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handle(req, env, defaultDeps(), ctx);
  },
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runScheduled(env, defaultDeps()));
  },
};
