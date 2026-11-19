import { escapeModulePath } from '../../src/go/escape';
import { httpError, readJson, request, TIMEOUT_MS } from './http';

const NPM = 'https://registry.npmjs.org';
const GOPROXY = 'https://proxy.golang.org';

function toDate(v: unknown): Date | null {
  if (typeof v !== 'string') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Publish time of name@version on the public npm registry; null if the package or version is unknown. */
export async function npmPublishTime(f: typeof fetch, name: string, version: string): Promise<Date | null> {
  const label = `npm registry GET ${name}`;
  const res = await request(f, `${NPM}/${name.replace('/', '%2f')}`, { headers: { accept: 'application/json' } }, { label, timeoutMs: TIMEOUT_MS });
  if (res.status === 404) return null;
  if (!res.ok) throw await httpError(res, { label });
  const doc = await readJson<{ time?: Record<string, unknown> }>(res, label);
  return toDate(doc.time?.[version]);
}

/** Publish time from proxy.golang.org's .info; null if the module or version is unknown. */
export async function goPublishTime(f: typeof fetch, module: string, version: string): Promise<Date | null> {
  const label = `Go proxy GET ${module}@${version}.info`;
  const url = `${GOPROXY}/${escapeModulePath(module)}/@v/${escapeModulePath(version)}.info`;
  const res = await request(f, url, {}, { label, timeoutMs: TIMEOUT_MS });
  if (res.status === 404 || res.status === 410) return null;
  if (!res.ok) throw await httpError(res, { label });
  const info = await readJson<{ Time?: unknown }>(res, label);
  return toDate(info.Time);
}
