import type { BuildOptions } from 'esbuild';

export const buildOptions: BuildOptions & { entryPoints: string[]; outfile: string };
