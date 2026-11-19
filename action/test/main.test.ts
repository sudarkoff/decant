import { afterEach, describe, expect, it, vi } from 'vitest';
import { run } from '../src/main';
import { fakeDeps } from './fakes';

afterEach(() => vi.restoreAllMocks());

function capErr() {
  const err: string[] = [];
  vi.spyOn(process.stderr, 'write').mockImplementation(((s: string) => (err.push(String(s)), true)) as typeof process.stderr.write);
  vi.spyOn(process.stdout, 'write').mockImplementation((() => true) as typeof process.stdout.write);
  return err;
}

describe('run', () => {
  it('unknown mode exits 1', async () => {
    const err = capErr();
    const code = await run(fakeDeps({ env: { INPUT_MODE: 'nope' } }));
    expect(code).toBe(1);
    expect(err.join('')).toContain('unknown mode nope');
  });
});
