import { defineConfig } from 'vitest/config';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';

export default defineConfig(async () => {
  const migrations = await readD1Migrations('./migrations');
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: {
          // Installed workerd supports up to 2026-08-22; production uses wrangler.jsonc's date.
          compatibilityDate: '2026-08-01',
          bindings: { TEST_MIGRATIONS: migrations, OPERATOR_TOKEN_HASH: '' },
        },
      }),
    ],
    test: {
      // helpers.ts applies migrations/ to the test D1 before each test file.
      setupFiles: ['./test/helpers.ts'],
      exclude: ['action/**', 'node_modules/**'],
    },
  };
});
