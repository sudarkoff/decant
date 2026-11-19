import type { RequestCtx } from '../auth';
import { json } from '../http';
import { maliciousIds } from '../osv';
import { decide, type Decision } from '../policy/decide';
import {
  addGlobalBlock,
  blockedVersions,
  getPinnedTimes,
  getVersionState,
  loadPolicyView,
  logServe,
  markOsvChecked,
  markStored,
  pinPublishTimes,
  type PinnedTime,
} from '../policy/store';
import { formatPackageId, type Deps, type Env, type PackageRef } from '../types';
import { cachedFetch } from '../upstream';
import { filterPackument, type Packument } from './filter';

const REGISTRY = 'https://registry.npmjs.org';
const ABBREV = 'application/vnd.npm.install-v1+json';
const MAX_BUFFER = 64 * 1024 * 1024;
const AUDIT_PATHS = new Set(['/-/npm/v1/security/advisories/bulk', '/-/npm/v1/security/audits/quick']);
// npm names: optional @scope/, no leading '.' or '_', URL-safe characters only.
const NAME_RE = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const NO_STORE = { 'cache-control': 'no-store' };

function err(status: number, message: string, headers: Record<string, string> = {}): Response {
  return json({ error: message }, status, { ...NO_STORE, ...headers });
}

/** "/<name>" or "/<name>/-/<file>", with the scope separator as '/' or %2f (any case). */
function parsePath(path: string): { name: string; file: string | null } | null {
  let p = path.replace(/%2f/gi, '/');
  try {
    p = decodeURIComponent(p);
  } catch {
    return null;
  }
  const m = /^\/((?:@[^/]+\/)?[^/@][^/]*)(?:\/-\/([^/]+))?$/.exec(p);
  if (!m || !NAME_RE.test(m[1]!)) return null;
  return { name: m[1]!, file: m[2] ?? null };
}

type DocResult = { ok: true; doc: Packument } | { ok: false; res: Response };

async function fetchDoc(env: Env, deps: Deps, name: string, abbrev: boolean): Promise<DocResult> {
  const r = await cachedFetch(env, deps, {
    key: `npm/meta/${abbrev ? 'abbrev' : 'full'}/${name}.json`,
    url: `${REGISTRY}/${name.replace('/', '%2f')}`,
    accept: abbrev ? ABBREV : 'application/json',
  });
  if (r.status === 'not-found') return { ok: false, res: err(404, `npm:${name} not found`) };
  if (r.status === 'unavailable') return { ok: false, res: err(502, 'upstream unavailable and nothing cached') };
  try {
    const doc = JSON.parse(new TextDecoder().decode(r.body)) as Packument;
    if (doc && typeof doc === 'object' && typeof doc.name === 'string') return { ok: true, doc };
  } catch {
    // fall through
  }
  return { ok: false, res: err(502, 'invalid upstream document') };
}

/** Publish times of listed versions, from a full document's `time`. */
function publishTimes(full: Packument): Map<string, Date> {
  const out = new Map<string, Date>();
  const versions = full.versions ?? {};
  for (const [v, t] of Object.entries(full.time ?? {})) {
    if (!(v in versions) || typeof t !== 'string') continue;
    const d = new Date(t);
    if (!Number.isNaN(d.getTime())) out.set(v, d);
  }
  return out;
}

async function decider(env: Env, deps: Deps, rc: RequestCtx, name: string) {
  const [blocks, view] = await Promise.all([
    blockedVersions(env, 'npm', name),
    loadPolicyView(env, rc.projectId, rc.ref),
  ]);
  const allowed = view.allowedFor('npm', name);
  const now = deps.now();
  return (version: string, pin: PinnedTime | null | undefined): Decision =>
    decide({
      publishTime: pin?.publishTime ?? null,
      conflict: pin?.conflict ?? false,
      blocked: blocks.has(version),
      allowed: allowed.has(version),
      cooldownDays: view.cooldownDays,
      now,
    });
}

async function handleMetadata(req: Request, env: Env, deps: Deps, rc: RequestCtx, name: string): Promise<Response> {
  const abbrev = (req.headers.get('accept') ?? '').includes(ABBREV);
  const r = await fetchDoc(env, deps, name, abbrev);
  if (!r.ok) return r.res;
  const doc = r.doc;
  const versions = Object.keys(doc.versions ?? {});
  const now = deps.now();

  let pinned: Map<string, PinnedTime>;
  if (!abbrev) {
    pinned = await pinPublishTimes(env, 'npm', name, publishTimes(doc), now);
  } else {
    pinned = await getPinnedTimes(env, 'npm', name, versions);
    if (versions.some((v) => !pinned.has(v))) {
      // Times only live in the full document. If it can't be had, unpinned versions stay hidden.
      const full = await fetchDoc(env, deps, name, false);
      if (full.ok) {
        for (const [v, p] of await pinPublishTimes(env, 'npm', name, publishTimes(full.doc), now)) pinned.set(v, p);
      }
    }
  }

  const d = await decider(env, deps, rc, name);
  const allowed = new Set(versions.filter((v) => d(v, pinned.get(v)) === 'allow'));
  const out = filterPackument(doc, allowed, `${rc.base}/npm`);
  return new Response(JSON.stringify(out), {
    headers: { 'content-type': abbrev ? ABBREV : 'application/json', vary: 'Accept', ...NO_STORE },
  });
}

/** Streams the bytes untouched. No-store: policy can change after a serve. */
function tarballResponse(body: ReadableStream): Response {
  return new Response(body, { headers: { 'content-type': 'application/octet-stream', ...NO_STORE } });
}

/** The sha512 digest (base64) from an SRI string, or null if there is none. */
function sha512Of(integrity: unknown): string | null {
  if (typeof integrity !== 'string') return null;
  for (const part of integrity.trim().split(/\s+/)) {
    if (part.startsWith('sha512-')) return part.slice(7).replace(/\?.*$/, '');
  }
  return null;
}

function b64(buf: ArrayBuffer): string {
  let s = '';
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s);
}

/** Reads the whole stream, or cancels it and returns null once it exceeds `max` bytes. */
async function readUpTo(stream: ReadableStream<Uint8Array>, max: number): Promise<Uint8Array | null> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

async function pump(stream: ReadableStream<Uint8Array>, sinks: WritableStreamDefaultWriter<Uint8Array>[]): Promise<void> {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      await Promise.all(sinks.map((w) => w.write(value)));
    }
    await Promise.all(sinks.map((w) => w.close()));
  } catch (e) {
    await Promise.allSettled([reader.cancel(e), ...sinks.map((w) => w.abort(e))]);
    throw e;
  }
}

async function storeTarball(
  env: Env,
  stream: ReadableStream<Uint8Array>,
  length: number | null,
  key: string,
  ref: PackageRef,
  expected: string | null,
  now: Date,
): Promise<void> {
  const id = formatPackageId(ref);
  try {
    let digest: ArrayBuffer;
    if (length === null) {
      const buf = await readUpTo(stream, MAX_BUFFER);
      if (buf === null) {
        console.warn(`tarball over 64 MB with no content-length, not stored ${id}`);
        return;
      }
      [digest] = await Promise.all([crypto.subtle.digest('SHA-512', buf), env.BUCKET.put(key, buf)]);
    } else {
      // One pump feeds both the digest and R2 (workerd can't pipeTo between two TransformStreams).
      const ds = new crypto.DigestStream('SHA-512');
      const fl = new FixedLengthStream(length);
      const put = env.BUCKET.put(key, fl.readable);
      const [, , d] = await Promise.all([pump(stream, [ds.getWriter(), fl.writable.getWriter()]), put, ds.digest]);
      digest = d;
    }
    if (expected === null) {
      console.warn(`no sha512 integrity ${id}`);
    } else if (b64(digest) !== expected) {
      await env.BUCKET.delete(key);
      console.error(`integrity mismatch ${id}`);
      return;
    }
    await markStored(env, ref, now);
  } catch {
    console.error(`tarball store failed ${id}`);
    try {
      await env.BUCKET.delete(key);
    } catch {
      // nothing else to do
    }
  }
}

async function handleTarball(
  env: Env,
  deps: Deps,
  ctx: ExecutionContext,
  rc: RequestCtx,
  name: string,
  file: string,
): Promise<Response> {
  const basename = name.split('/').pop()!;
  if (!file.startsWith(`${basename}-`) || !file.endsWith('.tgz')) return err(404, 'not found');
  const version = file.slice(basename.length + 1, -'.tgz'.length);
  if (!version) return err(404, 'not found');
  const ref: PackageRef = { eco: 'npm', name, version };
  const id = formatPackageId(ref);
  const now = deps.now();

  let full: Packument | null = null;
  let state = await getVersionState(env, ref);
  if (!state) {
    const r = await fetchDoc(env, deps, name, false);
    if (!r.ok) return r.res;
    full = r.doc;
    if (!full.versions?.[version]) return err(404, `${id} not found`);
    await pinPublishTimes(env, 'npm', name, publishTimes(full), now);
    state = await getVersionState(env, ref);
  }

  const d = (await decider(env, deps, rc, name))(version, state);
  if (d !== 'allow') return err(404, `${id} is not available: ${d === 'blocked' ? 'blocked' : 'in cooldown'}`);

  const serve = () => ctx.waitUntil(logServe(env, rc.projectId, ref, now).catch(() => console.warn(`serve log failed ${id}`)));
  const key = `npm/tar/${name}/${file}`;
  const obj = await env.BUCKET.get(key);
  if (obj) {
    serve();
    return tarballResponse(obj.body);
  }

  if (!state?.osvCheckedAt) {
    const mal = await maliciousIds(deps, [ref]);
    if (mal !== null) {
      // The cron re-checks anything left with osv_checked_at null (including OSV-down cases).
      await markOsvChecked(env, [ref], now);
      const ids = mal.get(id);
      if (ids && ids.length > 0) {
        await addGlobalBlock(env, ref, 'osv', ids.join(', '), now);
        return err(404, `${id} is not available: blocked`);
      }
    }
  }

  if (!full) {
    const r = await fetchDoc(env, deps, name, false);
    if (!r.ok) return r.res;
    full = r.doc;
  }
  const dist = full.versions?.[version]?.dist;
  const tarballUrl: unknown = dist?.tarball;
  if (typeof tarballUrl !== 'string' || !tarballUrl.startsWith('https://')) return err(404, `${id} not found`);

  let res: Response;
  try {
    res = await deps.fetch(tarballUrl);
  } catch {
    return err(502, 'upstream unavailable and nothing cached');
  }
  if (res.status === 404) return err(404, `${id} not found`);
  if (res.status !== 200 || !res.body) return err(502, 'upstream unavailable and nothing cached');

  const lenHeader = res.headers.get('content-length');
  const length = lenHeader !== null && /^\d+$/.test(lenHeader) ? Number(lenHeader) : null;
  const [toClient, toStore] = res.body.tee();
  ctx.waitUntil(storeTarball(env, toStore, length, key, ref, sha512Of(dist?.integrity), now));
  serve();
  return tarballResponse(toClient);
}

async function handleAudit(req: Request, deps: Deps, path: string): Promise<Response> {
  // Only the body and its encoding go upstream — never Authorization or other client headers.
  const headers = new Headers();
  for (const h of ['content-type', 'content-encoding']) {
    const v = req.headers.get(h);
    if (v !== null) headers.set(h, v);
  }
  let res: Response;
  try {
    res = await deps.fetch(`${REGISTRY}${path}`, { method: 'POST', headers, body: await req.arrayBuffer() });
  } catch {
    return err(502, 'upstream unavailable');
  }
  const out: Record<string, string> = { ...NO_STORE };
  const ct = res.headers.get('content-type');
  if (ct !== null) out['content-type'] = ct;
  return new Response(res.body, { status: res.status, headers: out });
}

export async function handleNpm(
  req: Request,
  env: Env,
  deps: Deps,
  ctx: ExecutionContext,
  rc: RequestCtx,
  path: string,
): Promise<Response> {
  if (req.method === 'PUT' || req.method === 'DELETE') return err(405, 'method not allowed', { allow: 'GET, POST' });
  if (req.method === 'POST') return AUDIT_PATHS.has(path) ? handleAudit(req, deps, path) : err(404, 'not found');
  if (req.method !== 'GET') return err(404, 'not found');

  const parsed = parsePath(path);
  if (!parsed) return err(404, 'not found');
  return parsed.file === null
    ? handleMetadata(req, env, deps, rc, parsed.name)
    : handleTarball(env, deps, ctx, rc, parsed.name, parsed.file);
}
