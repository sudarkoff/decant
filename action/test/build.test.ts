import { createHash } from 'node:crypto';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { buildOptions } from '../build.mjs';

async function hash() {
  const r = await build({ ...buildOptions, write: false });
  const h = createHash('sha256');
  for (const f of r.outputFiles) h.update(f.path).update(f.contents);
  return h.digest('hex');
}

describe('build', () => {
  it('is byte-for-byte reproducible', async () => {
    expect(await hash()).toBe(await hash());
  });
});
