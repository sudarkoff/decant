import type { ActionDeps, Fs } from '../src/deps';
import type { Exec } from '../src/exec';

export function memFs(files: Record<string, string> = {}, symlinks: string[] = []): Fs & { files: Map<string, string>; modes: Map<string, number>; bytes: Map<string, Uint8Array>; dirs: Set<string> } {
  const modes = new Map<string, number>();
  const bytes = new Map<string, Uint8Array>();
  const m = new Map(Object.entries(files));
  const dirs = new Set<string>();
  return {
    files: m,
    dirs,
    modes,
    bytes,
    async writeBytes(p, data) {
      bytes.set(p, data);
    },
    async rm(p) {
      for (const k of [...m.keys()]) if (k === p || k.startsWith(`${p}/`)) m.delete(k);
      for (const k of [...modes.keys()]) if (k === p || k.startsWith(`${p}/`)) modes.delete(k);
      dirs.delete(p);
    },
    async mkdtemp(prefix) {
      let i = 0;
      while (dirs.has(`${prefix}${String(i).padStart(6, '0')}`)) i++;
      const d = `${prefix}${String(i).padStart(6, '0')}`;
      dirs.add(d);
      modes.set(d, 0o700);
      return d;
    },
    async chmod(p, mode) {
      modes.set(p, mode);
    },
    async readFile(p) {
      const v = m.get(p);
      if (v === undefined) throw new Error(`ENOENT: ${p}`);
      return v;
    },
    async writeFile(p, data, mode) {
      m.set(p, data);
      if (mode !== undefined && !modes.has(p)) modes.set(p, mode);
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

export type FetchCall = { url: string; method: string; headers: Headers; body: string | undefined; signal: AbortSignal | undefined };

/** A fake fetch that records calls and answers from `handler`; unmatched calls get a 599. */
export function fakeFetch(handler: (call: FetchCall) => Response | undefined): typeof fetch & { calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const fn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const call: FetchCall = {
      url,
      method: (init?.method ?? 'GET').toUpperCase(),
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : undefined,
      signal: init?.signal ?? undefined,
    };
    calls.push(call);
    return handler(call) ?? new Response('not stubbed', { status: 599 });
  }) as typeof fetch & { calls: FetchCall[] };
  fn.calls = calls;
  return fn;
}

export const jsonRes = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
