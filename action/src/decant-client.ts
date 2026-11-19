import { escapeModulePath } from '../../src/go/escape';
import { httpError, readJson, request, TIMEOUT_MS } from './http';

export type VerdictResult = 'clean' | 'flagged' | 'malicious';
export type Verdict = {
  package: string;
  scanner: string;
  scannerVersion: string;
  result: VerdictResult;
  details?: unknown;
  scannedAt?: string;
};
export type Block = { package: string; source: string; reason: string; at: string };
export type ProjectStatus = {
  mainSha: string | null;
  syncedAt: string | null;
  overlays: { ref: string; syncedAt: string }[];
  globalBlocks: number;
};
export type Download = { status: 'ok'; bytes: Uint8Array } | { status: 'cooldown' | 'blocked' | 'missing' };

export type DecantClient = ReturnType<typeof decant>;

/** Maps a 404 body from the npm/go handlers to a download status. */
function classify404(body: string): 'cooldown' | 'blocked' | 'missing' {
  if (/is not available: in cooldown/.test(body)) return 'cooldown';
  if (/is not available: blocked/.test(body)) return 'blocked';
  return 'missing';
}

/** "@s/n" → "@s%2fn" (the form npm clients request); unscoped names unchanged. */
function npmMetaPath(name: string): string {
  return name
    .split('/')
    .map((p) => encodeURIComponent(p).replace(/^%40/, '@'))
    .join('%2f');
}

/**
 * Client for the decant Worker. `token` is a ci token for /api (verdicts, blocks, status, overlay
 * syncs) or a sync token for main-ref policy syncs. The token goes only to `url`'s origin.
 */
export function decant(f: typeof fetch, url: string, token: string) {
  const base = url.replace(/\/+$/, '');
  const origin = new URL(base).origin;
  const basic = Buffer.from(`decant:${token}`).toString('base64');
  const secrets = [token, basic];
  const bearer = { authorization: `Bearer ${token}` };

  async function call(method: string, path: string, opts: { body?: unknown; headers?: Record<string, string> } = {}): Promise<Response> {
    const target = path.startsWith('https://') || path.startsWith('http://') ? path : `${base}${path}`;
    if (new URL(target).origin !== origin) throw new Error(`decant: refusing to send credentials to another host (${new URL(target).host})`);
    const headers: Record<string, string> = { ...bearer, ...opts.headers };
    let body: string | undefined;
    if (opts.body !== undefined) {
      headers['content-type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }
    return request(f, target, { method, headers, body }, { label: `decant ${method} ${new URL(target).pathname}`, timeoutMs: TIMEOUT_MS, secrets });
  }

  async function ok<T>(res: Response, label: string): Promise<T> {
    if (!res.ok) throw await httpError(res, { label, secrets });
    return readJson<T>(res, label);
  }

  const prefix = (ref?: string) => (ref ? `/r/${encodeURIComponent(ref)}` : '');

  async function bytesOr404(res: Response, label: string): Promise<Download> {
    if (res.status === 404 || res.status === 410) return { status: classify404(await res.text().catch(() => '')) };
    if (!res.ok) throw await httpError(res, { label, secrets });
    return { status: 'ok', bytes: new Uint8Array(await res.arrayBuffer()) };
  }

  return {
    /** PUT the policy for `ref`. Never throws on an HTTP status: the caller reports {status, body}. */
    async syncPolicy(project: string, policy: unknown, sha: string, ref: string): Promise<{ status: number; body: unknown }> {
      const parsed = typeof policy === 'string' ? (JSON.parse(policy) as unknown) : policy;
      const res = await call('PUT', `/api/projects/${encodeURIComponent(project)}/policy`, { body: { policy: parsed, sha, ref } });
      const text = await res.text();
      let body: unknown = text;
      try {
        body = JSON.parse(text);
      } catch {
        // keep text
      }
      return { status: res.status, body };
    },

    async getVerdicts(pkgId: string): Promise<Verdict[]> {
      const res = await call('GET', `/api/verdicts?package=${encodeURIComponent(pkgId)}`);
      return (await ok<{ verdicts?: Verdict[] }>(res, 'decant GET /api/verdicts')).verdicts ?? [];
    },

    async putVerdict(v: Verdict): Promise<void> {
      const res = await call('PUT', '/api/verdicts', { body: v });
      if (!res.ok) throw await httpError(res, { label: 'decant PUT /api/verdicts', secrets });
    },

    async blocks(): Promise<Block[]> {
      return (await ok<{ blocks?: Block[] }>(await call('GET', '/api/blocks'), 'decant GET /api/blocks')).blocks ?? [];
    },

    async status(project: string): Promise<ProjectStatus> {
      const path = `/api/projects/${encodeURIComponent(project)}/status`;
      return ok<ProjectStatus>(await call('GET', path), `decant GET ${path}`);
    },

    /**
     * Reads `<prefix>/npm/<name>` metadata (filtered by decant for that ref) and fetches the version's
     * dist.tarball. A version filtered out of the metadata is requested at its canonical tarball path
     * so decant's 404 says why (cooldown or blocked).
     */
    async downloadNpm(name: string, version: string, ref?: string): Promise<Download> {
      const npmBase = `${base}${prefix(ref)}/npm`;
      const metaLabel = `decant GET ${prefix(ref)}/npm/${name}`;
      const meta = await call('GET', `${npmBase}/${npmMetaPath(name)}`, { headers: { accept: 'application/json' } });
      if (meta.status === 404) return { status: classify404(await meta.text().catch(() => '')) };
      const doc = await ok<{ versions?: Record<string, { dist?: { tarball?: unknown } }> }>(meta, metaLabel);
      const tarball = doc.versions?.[version]?.dist?.tarball;
      let target: string;
      if (typeof tarball === 'string') {
        let u: URL;
        try {
          u = new URL(tarball);
        } catch {
          throw new Error(`${metaLabel}: invalid tarball URL`);
        }
        if (u.origin !== origin) throw new Error(`${metaLabel}: tarball host ${u.host} is not the decant host`);
        target = u.href;
      } else {
        const basename = name.slice(name.lastIndexOf('/') + 1);
        target = `${npmBase}/${name}/-/${basename}-${encodeURIComponent(version)}.tgz`;
      }
      const res = await call('GET', target);
      return bytesOr404(res, `decant GET ${new URL(target).pathname}`);
    },

    /** Fetches `<prefix>/go/<module>/@v/<version>.zip` with Basic decant:<token>. */
    async downloadGo(module: string, version: string, ref?: string): Promise<Download> {
      const path = `${prefix(ref)}/go/${escapeModulePath(module)}/@v/${escapeModulePath(version)}.zip`;
      const res = await call('GET', path, { headers: { authorization: `Basic ${basic}` } });
      return bytesOr404(res, `decant GET ${path}`);
    },
  };
}
