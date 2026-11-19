import type { ModeCtx } from '../inputs';

export async function notImplemented(_ctx: ModeCtx): Promise<number> {
  process.stderr.write('not implemented\n');
  return 1;
}
