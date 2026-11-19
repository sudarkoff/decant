import type { RequestCtx } from '../auth';
import { text } from '../http';
import type { Deps, Env } from '../types';

// Stub: replaced in Task 8.
export async function handleNpm(
  _req: Request,
  _env: Env,
  _deps: Deps,
  _ctx: ExecutionContext,
  _rc: RequestCtx,
  _path: string,
): Promise<Response> {
  return text('not implemented', 501);
}
