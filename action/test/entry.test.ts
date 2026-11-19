import { spawnSync } from 'node:child_process';
import { mkdtempSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { buildOptions } from '../build.mjs';

describe('built bundle', () => {
  it('runs when invoked through a symlinked directory', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'decant-bundle-'));
    await build({ ...buildOptions, outfile: join(dir, 'real', 'index.js') });
    symlinkSync(join(dir, 'real'), join(dir, 'link'));
    const r = spawnSync('node', [join(dir, 'link', 'index.js')], { env: { ...process.env, INPUT_MODE: 'nope' }, encoding: 'utf8' });
    expect(r.status).toBe(1);
    expect(r.stdout + r.stderr).toContain('unknown mode nope');
  });
});
