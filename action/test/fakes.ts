import type { ActionDeps, Fs } from '../src/deps';
import type { Exec } from '../src/exec';

export function memFs(files: Record<string, string> = {}, symlinks: string[] = []): Fs & { files: Map<string, string> } {
  const m = new Map(Object.entries(files));
  const dirs = new Set<string>();
  return {
    files: m,
    async readFile(p) {
      const v = m.get(p);
      if (v === undefined) throw new Error(`ENOENT: ${p}`);
      return v;
    },
    async writeFile(p, data) {
      m.set(p, data);
    },
    async readdir(p) {
      const prefix = p.endsWith('/') ? p : `${p}/`;
      const out = new Map<string, boolean>();
      const links = new Set<string>();
      for (const k of m.keys()) {
        if (!k.startsWith(prefix)) continue;
        const rest = k.slice(prefix.length);
        const i = rest.indexOf('/');
        const n = i < 0 ? rest : rest.slice(0, i);
        if (i < 0) out.set(n, false);
        else out.set(n, true);
        if (symlinks.includes(`${prefix}${n}`)) links.add(n);
      }
      return [...out].map(([name, isDir]) => ({ name, isDir, isSymlink: links.has(name) }));
    },
    async exists(p) {
      return m.has(p) || dirs.has(p) || [...m.keys()].some((k) => k.startsWith(`${p}/`));
    },
    async mkdir(p) {
      dirs.add(p);
    },
  };
}

export type ExecCall = { cmd: string; args: string[]; opts?: Parameters<Exec>[2] };

export function fakeExec(handler?: (call: ExecCall) => { code?: number; stdout?: string; stderr?: string }): Exec & { calls: ExecCall[] } {
  const calls: ExecCall[] = [];
  const fn = (async (cmd, args, opts) => {
    const call = { cmd, args, opts };
    calls.push(call);
    const r = handler?.(call) ?? {};
    return { code: r.code ?? 0, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  }) as Exec & { calls: ExecCall[] };
  fn.calls = calls;
  return fn;
}

export function fakeDeps(over: Partial<ActionDeps> = {}): ActionDeps {
  return {
    env: {},
    fetch: (async () => new Response('not stubbed', { status: 599 })) as typeof fetch,
    exec: fakeExec(),
    now: () => new Date('2026-11-19T00:00:00Z'),
    fs: memFs(),
    ...over,
  };
}
