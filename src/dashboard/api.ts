import { json } from '../http';
import type { Deps, Env } from '../types';
import { attention } from './attention';
import { activity, freshness, listProjects, packageList, policies, security, uptime, windowDays } from './queries';

const NO_STORE = { 'cache-control': 'no-store' };
const RANGES = new Set(['7', '30', '90']);
const MAX_PAGE = 10_000;

class BadRequest extends Error {}

const ok = (body: unknown) => json(body, 200, NO_STORE);
const err = (status: number, error: string) => json({ error }, status, NO_STORE);

/**
 * Dashboard JSON API. Called only after Access verification.
 * `path` is the part after `/dashboard/api/` (e.g. `projects`).
 */
export async function handleDashboardApi(req: Request, env: Env, deps: Deps, path: string): Promise<Response> {
  if (req.method !== 'GET' && req.method !== 'HEAD') return new Response(null, { status: 405, headers: { allow: 'GET, HEAD', ...NO_STORE } });
  const qs = new URL(req.url).searchParams;
  const db = env.DB;
  try {
    const range = (): string[] => {
      const r = qs.get('range') ?? '30';
      if (!RANGES.has(r)) throw new BadRequest('range must be 7, 30 or 90');
      return windowDays(deps.now(), Number(r));
    };
    const project = async (): Promise<string> => {
      const p = qs.get('project') ?? 'all';
      if (p === 'all') return p;
      const row = await db.prepare('SELECT 1 AS x FROM projects WHERE id = ?').bind(p).first();
      if (!row) throw new BadRequest('unknown project');
      return p;
    };

    switch (path) {
      case 'projects':
        return ok({ projects: (await listProjects(db)).map((id) => ({ id })) });
      case 'activity': {
        const days = range();
        return ok(await activity(db, await project(), days));
      }
      case 'uptime': {
        const days = range();
        return ok(await uptime(db, await project(), days));
      }
      case 'security': {
        const days = range();
        return ok(await security(db, await project(), days[0]!));
      }
      case 'freshness': {
        const days = range();
        return ok(await freshness(db, await project(), days[0]!, deps.now()));
      }
      case 'attention': {
        range();
        const r = Number(qs.get('range') ?? '30') as 7 | 30 | 90;
        const p = await project();
        // attention() writes alerts_state; a HEAD must not run the diff.
        if (req.method === 'HEAD') return new Response(null, { status: 200, headers: { 'content-type': 'application/json', ...NO_STORE } });
        return ok(await attention(env, p, r, deps.now()));
      }
      case 'policy':
        return ok(await policies(db, await project()));
      case 'packages': {
        const days = range();
        const raw = qs.get('page') ?? '1';
        if (!/^[1-9]\d{0,4}$/.test(raw) || Number(raw) > MAX_PAGE) throw new BadRequest('page must be a positive integer');
        const q = qs.get('q') ?? '';
        if (q.length > 200) throw new BadRequest('q is too long');
        return ok(await packageList(db, await project(), days[0]!, q, Number(raw)));
      }
      default:
        return err(404, 'not found');
    }
  } catch (e) {
    if (e instanceof BadRequest) return err(400, e.message);
    console.error('dashboard api failed', e instanceof Error ? e.name : 'error');
    return err(500, 'internal');
  }
}
