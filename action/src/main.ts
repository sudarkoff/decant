import type { ActionDeps } from './deps';
import { error } from './gh-io';
import { readInputs, type ModeCtx } from './inputs';
import * as adopt from './modes/adopt';
import * as audit from './modes/audit';
import * as scan from './modes/scan';
import * as setup from './modes/setup';
import * as sync from './modes/sync';

const modes: Record<string, { run(ctx: ModeCtx): Promise<number> }> = { setup, sync, scan, audit, adopt };

export async function run(deps: ActionDeps): Promise<number> {
  const inputs = readInputs(deps.env);
  const mode = Object.hasOwn(modes, inputs.mode) ? modes[inputs.mode] : undefined;
  if (!mode) {
    const msg = `unknown mode ${inputs.mode}`;
    error(msg);
    process.stderr.write(`${msg}\n`);
    return 1;
  }
  return mode.run({ deps, inputs });
}
