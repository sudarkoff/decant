import * as nodeFs from 'node:fs/promises';
import { defaultExec, type Exec } from './exec';

export type Fs = {
  readFile(p: string): Promise<string>;
  writeFile(p: string, data: string, mode?: number): Promise<void>;
  readdir(p: string): Promise<{ name: string; isDir: boolean; isSymlink: boolean }[]>;
  exists(p: string): Promise<boolean>;
  mkdir(p: string): Promise<void>;
};

export type ActionDeps = {
  env: Record<string, string | undefined>;
  fetch: typeof fetch;
  exec: Exec;
  now: () => Date;
  fs: Fs;
};

export const defaultFs: Fs = {
  readFile: (p) => nodeFs.readFile(p, 'utf8'),
  writeFile: (p, data, mode) => nodeFs.writeFile(p, data, mode === undefined ? undefined : { mode }),
  async readdir(p) {
    const entries = await nodeFs.readdir(p, { withFileTypes: true });
    return entries.map((e) => ({ name: e.name, isDir: e.isDirectory(), isSymlink: e.isSymbolicLink() }));
  },
  async exists(p) {
    try {
      await nodeFs.access(p);
      return true;
    } catch {
      return false;
    }
  },
  async mkdir(p) {
    await nodeFs.mkdir(p, { recursive: true });
  },
};

export function defaultDeps(): ActionDeps {
  return {
    env: process.env,
    fetch: globalThis.fetch,
    exec: defaultExec,
    now: () => new Date(),
    fs: defaultFs,
  };
}
