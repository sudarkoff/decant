import { notFound } from '../http';
import type { Deps, Env } from '../types';

/**
 * Dashboard JSON API. Called only after Access verification and a GET/HEAD check.
 * `path` is the part after `/dashboard/api/` (e.g. `projects`). Stub until Task 5.
 */
export async function handleDashboardApi(_req: Request, _env: Env, _deps: Deps, _path: string): Promise<Response> {
  return notFound();
}
