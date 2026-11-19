import { describe, expect, it } from 'vitest';
import { defaultExec, scrubEnv } from '../src/exec';

describe('scrubEnv (review fix: no secrets to child processes)', () => {
  it('drops INPUT_*, ACTIONS_* and TOKEN/SECRET/KEY/PASSWORD names; keeps the rest', () => {
    expect(
      scrubEnv({
        PATH: '/bin',
        HOME: '/h',
        RUNNER_TEMP: '/rt',
        INPUT_TOKEN: 'a',
        INPUT_MODE: 'scan',
        ACTIONS_RUNTIME_TOKEN: 'b',
        ACTIONS_ID_TOKEN_REQUEST_URL: 'c',
        GITHUB_TOKEN: 'd',
        NPM_SECRET: 'e',
        AWS_SECRET_ACCESS_KEY: 'f',
        MY_api_key: 'g',
        DB_PASSWORD: 'h',
        UNSET: undefined,
      }),
    ).toEqual({ PATH: '/bin', HOME: '/h', RUNNER_TEMP: '/rt' });
  });

  it('defaultExec does not pass a token var through, but explicit opts.env wins', async () => {
    process.env.INPUT_TOKEN = 'leak-me';
    process.env.DECANT_TEST_SECRET = 'leak-me-too';
    try {
      const r = await defaultExec(process.execPath, ['-e', 'process.stdout.write(JSON.stringify(process.env))'], {
        env: { EXPLICIT_TOKEN: 'given' },
      });
      const env = JSON.parse(r.stdout) as Record<string, string>;
      expect(env.INPUT_TOKEN).toBeUndefined();
      expect(env.DECANT_TEST_SECRET).toBeUndefined();
      expect(env.EXPLICIT_TOKEN).toBe('given');
      expect(env.PATH).toBe(process.env.PATH);
    } finally {
      delete process.env.INPUT_TOKEN;
      delete process.env.DECANT_TEST_SECRET;
    }
  });
});
