import { handleAdmin } from './admin/handler';
import { retryingD1 } from './d1-retry';
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

type RouteKind = 'npm' | 'go' | 'api' | 'dashboard' | 'other';

function routeKind(p: string): RouteKind {
  if (p === '/api' || p.startsWith('/api/')) return 'api';
  if (p === '/dashboard' || p.startsWith('/dashboard/')) return 'dashboard';
  const m = /^(?:\/r\/[^/]+)?\/(npm|go)(?:\/|$)/.exec(p);
  return m ? (m[1] as 'npm' | 'go') : 'other';
}

/**
 * ctx with a waitUntil that cannot leak a rejection: background work is best-effort and must never
 * surface as an unhandled rejection. Everything else passes through to the real context.
 */
function safeCtx(ctx: ExecutionContext, kind: RouteKind): ExecutionContext {
  const waitUntil = (p: Promise<unknown>) => {
    try {
      ctx.waitUntil(Promise.resolve(p).catch((err: unknown) => console.warn(`decant: background ${kind} failed: ${errName(err)}`)));
    } catch {
      console.warn(`decant: background ${kind} not scheduled`);
    }
  };
  return new Proxy(ctx, {
    get(target, prop) {
      if (prop === 'waitUntil') return waitUntil;
      const v: unknown = Reflect.get(target, prop, target);
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
}

function errName(err: unknown): string {
  return err instanceof Error ? err.name : typeof err;
}

const MAX_REASON = 200;

/**
 * One line naming the error: name and message, whitespace collapsed, cut to MAX_REASON characters.
 * Anything token-shaped (dk_ tokens, long hex such as token hashes) is masked: a D1 message can quote SQL
 * and values. Request paths are never logged.
 */
export function errReason(err: unknown): string {
  if (!(err instanceof Error)) return typeof err;
  const msg = err.message
    .replace(/dk_[A-Za-z0-9_-]+/g, 'dk_***')
    .replace(/[0-9a-fA-F]{32,}/g, '<hex>')
    .replace(/\s+/g, ' ')
    .trim();
  const line = msg ? `${err.name}: ${msg}` : err.name;
  return line.length > MAX_REASON ? `${line.slice(0, MAX_REASON)}…` : line;
}

/**
 * The Worker's request entry point. Any exception becomes a plain 502 (registry routes) or 500, so the
 * client never sees Cloudflare's 1101 page. Logs the route kind and a masked one-line reason (errReason),
 * so Workers observability shows why; never the URL.
 */
export async function handle(req: Request, env: Env, deps: Deps, ctx: ExecutionContext): Promise<Response> {
  let kind: RouteKind = 'other';
  try {
    kind = routeKind(new URL(req.url).pathname);
    const registry = kind === 'npm' || kind === 'go';
    // Registry routes only: their writes are idempotent, so retrying a failed D1 statement once is safe.
    const e = registry ? { ...env, DB: retryingD1(env.DB) } : env;
    return await route(req, e, deps, safeCtx(ctx, kind));
  } catch (err) {
    console.error(`decant: internal error (${kind}): ${errReason(err)}`);
    const registry = kind === 'npm' || kind === 'go';
    return text('decant: internal error', registry ? 502 : 500, { 'cache-control': 'no-store' });
  }
}

async function route(req: Request, env: Env, deps: Deps, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname;
  if (p === '/healthz') return text('ok');

  if (p === '/api' || p.startsWith('/api/')) {
    const auth = await authenticate(req, env, deps.now().getTime());
    if (!auth) return unauthorized();
    return handleAdmin(req, env, deps, ctx, auth, p);
  }

  if (p === '/dashboard' || p.startsWith('/dashboard/')) return handleDashboard(req, env, deps, p);

  // /(r/<ref>/)?(npm|go)(/...)?
  const m = /^(?:\/r\/([^/]+))?\/(npm|go)(\/.*)?$/.exec(p);
  if (!m) return notFound();
  const ref = m[1] ?? null;
  if (ref !== null && !REF_RE.test(ref)) return notFound();

  const auth = await authenticate(req, env, deps.now().getTime());
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
