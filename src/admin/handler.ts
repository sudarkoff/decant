import type { AuthCtx } from '../auth';
import { notFound } from '../http';
import type { Deps, Env } from '../types';

// Stub: replaced in Task 5. Per-route authorization (operator vs CI) lives there.
export async function handleAdmin(
  _req: Request,
  _env: Env,
  _deps: Deps,
  _ctx: ExecutionContext,
  _auth: AuthCtx,
  _path: string,
): Promise<Response> {
  return notFound();
}
