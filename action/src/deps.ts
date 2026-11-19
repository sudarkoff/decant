import * as nodeFs from 'node:fs/promises';
import { defaultExec, type Exec } from './exec';

export type Fs = {
  readFile(p: string): Promise<string>;
  writeFile(p: string, data: string, mode?: number): Promise<void>;
  writeBytes(p: string, data: Uint8Array): Promise<void>;
  readdir(p: string): Promise<{ name: string; isDir: boolean; isSymlink: boolean }[]>;
  exists(p: string): Promise<boolean>;
  mkdir(p: string): Promise<void>;
  chmod(p: string, mode: number): Promise<void>;
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
  writeBytes: (p, data) => nodeFs.writeFile(p, data),
  async readdir(p) {
    const entries = await nodeFs.readdir(p, { withFileTypes: true });
    // A Dirent for a symlink is never a directory; stat the target so isDir says what the link points to.
    return Promise.all(
      entries.map(async (e) => {
        const isSymlink = e.isSymbolicLink();
        let isDir = e.isDirectory();
        if (isSymlink) isDir = await nodeFs.stat(`${p}/${e.name}`).then((s) => s.isDirectory(), () => false);
        return { name: e.name, isDir, isSymlink };
      }),
    );
  },
  async exists(p) {
    try {
      await nodeFs.access(p);
      return true;
    } catch {
      return false;
    }
  },
  chmod: (p, mode) => nodeFs.chmod(p, mode),
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
