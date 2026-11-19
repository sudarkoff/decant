import { build } from 'esbuild';
import { pathToFileURL } from 'node:url';

export const buildOptions = {
  entryPoints: ['action/src/main.ts'],
  outfile: 'action/dist/index.js',
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'esm',
  minify: false,
  legalComments: 'none',
  logLevel: 'warning',
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await build(buildOptions);
}
