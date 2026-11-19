import { pathToFileURL } from 'node:url';
import { defaultDeps, type ActionDeps } from './deps';
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

// Only when executed as the entry (bundle or `node main.ts`), never when imported by tests.
const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) {
  run(defaultDeps()).then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      error(e instanceof Error ? e.message : String(e));
      process.exitCode = 1;
    },
  );
}
