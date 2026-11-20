import type { RequestCtx } from '../auth';
import { json } from '../http';
import { loadDecision, type VersionState } from '../policy/decider';
import { osvMalicious, storedObject } from '../policy/first-serve';
import { logServe, markStored, pinnedFrom, pinPublishTimes, selectPinnedStmt, type PinnedTime, type VersionRow } from '../policy/store';
import { notePackageLatest, outcomeOf, recordRequest, tagOutcome } from '../stats/record';
import { pump, readUpTo } from '../streams';
import { formatPackageId, type Deps, type Env, type PackageRef } from '../types';
import { cachedFetch, fetchHeaders } from '../upstream';
import { filterPackument, type Packument } from './filter';

const REGISTRY = 'https://registry.npmjs.org';
const ABBREV = 'application/vnd.npm.install-v1+json';
const MAX_BUFFER = 32 * 1024 * 1024; // cap for tarballs with no content-length
const UPSTREAM_HOST = 'registry.npmjs.org';
const AUDIT_PATHS = new Set(['/-/npm/v1/security/advisories/bulk', '/-/npm/v1/security/audits/quick']);
// npm names: optional @scope/, no leading '.' or '_', URL-safe characters only.
const NAME_RE = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const NO_STORE = { 'cache-control': 'no-store' };

function err(status: number, message: string, headers: Record<string, string> = {}): Response {
  if (status >= 500) console.error(`decant: npm ${status}: ${message}`);
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

type DocResult = { ok: true; doc: Packument; stale: boolean } | { ok: false; res: Response };

/** Recording context: notes the upstream latest version whenever a document is refetched. */
interface Rec {
  ctx: ExecutionContext;
  now: Date;
}

async function fetchDoc(env: Env, deps: Deps, rec: Rec, name: string, abbrev: boolean): Promise<DocResult> {
  const r = await cachedFetch(env, deps, {
    key: `npm/meta/${abbrev ? 'abbrev' : 'full'}/${name}.json`,
    url: `${REGISTRY}/${name.replace('/', '%2f')}`,
    accept: abbrev ? ABBREV : 'application/json',
  });
  if (r.status === 'not-found') return { ok: false, res: err(404, `npm:${name} not found`) };
  if (r.status === 'unavailable') return { ok: false, res: err(502, 'upstream unavailable and nothing cached') };
  // Only the parsed object leaves this function: the raw bytes and decoded text become garbage on return,
  // before the caller filters and re-stringifies. Each call parses its own object, so callers may mutate it.
  const doc = parseDoc(r.body);
  if (doc && r.fresh) noteLatest(env, rec, name, doc, abbrev);
  return doc ? { ok: true, doc, stale: r.stale } : { ok: false, res: err(502, 'invalid upstream document') };
}

function parseDoc(body: ArrayBuffer): Packument | null {
  try {
    const doc = JSON.parse(new TextDecoder().decode(body)) as Packument;
    if (doc && typeof doc === 'object' && typeof doc.name === 'string') return doc;
  } catch {
    // fall through
  }
  return null;
}

/** Abbreviated documents carry no `time`, so their latest is noted without one. */
function noteLatest(env: Env, rec: Rec, name: string, doc: Packument, abbrev: boolean): void {
  const latest: unknown = doc['dist-tags']?.latest;
  if (typeof latest !== 'string') return;
  const t: unknown = abbrev ? null : doc.time?.[latest];
  notePackageLatest(env, rec.ctx, 'npm', name, latest, typeof t === 'string' ? t : null, rec.now);
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

/** Publish times from the full document; the (large) full document itself is dropped on return. */
async function fullDocTimes(
  env: Env,
  deps: Deps,
  rec: Rec,
  name: string,
): Promise<{ times: Map<string, Date>; stale: boolean } | null> {
  const full = await fetchDoc(env, deps, rec, name, false);
  return full.ok ? { times: publishTimes(full.doc), stale: full.stale } : null;
}

async function handleMetadata(req: Request, env: Env, deps: Deps, rec: Rec, rc: RequestCtx, name: string): Promise<Response> {
  const abbrev = (req.headers.get('accept') ?? '').includes(ABBREV);
  const r = await fetchDoc(env, deps, rec, name, abbrev);
  if (!r.ok) return r.res;
  const doc = r.doc;
  const versions = Object.keys(doc.versions ?? {});
  const now = rec.now;
  let stale = r.stale;

  // The package's pinned times are read in the same round trip as the decision inputs.
  const docTimes = abbrev ? null : publishTimes(doc);
  const wanted = docTimes ? [...docTimes.keys()] : versions;
  const extra = wanted.length > 0 ? selectPinnedStmt(env, 'npm', name, wanted) : undefined;
  const loaded = await loadDecision<VersionRow>(env, deps, rc, 'npm', name, { extra });
  const rows = loaded.extra?.results ?? [];

  let pinned: Map<string, PinnedTime>;
  if (docTimes) {
    pinned = await pinPublishTimes(env, 'npm', name, docTimes, now, rows);
  } else {
    pinned = pinnedFrom(rows, versions);
    if (versions.some((v) => !pinned.has(v))) {
      // Times only live in the full document. If it can't be had, unpinned versions stay hidden.
      const times = await fullDocTimes(env, deps, rec, name);
      if (times) {
        stale ||= times.stale;
        for (const [v, p] of await pinPublishTimes(env, 'npm', name, times.times, now)) pinned.set(v, p);
      }
    }
  }

  const allowed = new Set(versions.filter((v) => loaded.decide(v, pinned.get(v)) === 'allow'));
  const out = filterPackument(doc, allowed, `${rc.base}/npm`);
  return new Response(JSON.stringify(out), {
    headers: {
      'content-type': abbrev ? ABBREV : 'application/json',
      vary: 'Accept',
      ...NO_STORE,
      ...(stale ? { 'x-decant-stale': '1' } : {}),
    },
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

/**
 * Writes to a temp key, verifies the sha512, then copies to `key` and marks the version stored.
 * Readers only serve `key` once stored_at is set, so unverified bytes are never served from R2.
 */
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
  const tmp = `npm/tmp/${crypto.randomUUID()}`;
  const reader = stream.getReader();
  const writers: WritableStreamDefaultWriter<Uint8Array>[] = [];
  try {
    let digest: ArrayBuffer;
    if (length === null) {
      const buf = await readUpTo(reader, MAX_BUFFER);
      if (buf === null) {
        console.warn(`tarball over 32 MB with no content-length, not stored ${id}`);
        return;
      }
      [digest] = await Promise.all([crypto.subtle.digest('SHA-512', buf), env.BUCKET.put(tmp, buf)]);
    } else {
      // One pump feeds both the digest and R2 (workerd can't pipeTo between two TransformStreams).
      const ds = new crypto.DigestStream('SHA-512');
      const fl = new FixedLengthStream(length);
      writers.push(ds.getWriter(), fl.writable.getWriter());
      const put = env.BUCKET.put(tmp, fl.readable);
      const [, , d] = await Promise.all([pump(reader, writers), put, ds.digest]);
      digest = d;
    }
    if (expected === null) {
      console.warn(`no sha512 integrity ${id}`);
    } else if (b64(digest) !== expected) {
      console.error(`integrity mismatch ${id}`);
      return;
    }
    // R2 has no rename: copy the verified temp object to the final key.
    const obj = await env.BUCKET.get(tmp);
    if (!obj) throw new Error('temp object missing');
    await env.BUCKET.put(key, obj.body);
    await markStored(env, ref, now);
  } catch {
    console.error(`tarball store failed ${id}`);
    // Stop reading so the unread tee branch doesn't buffer the rest of the tarball.
    await Promise.allSettled([reader.cancel(), ...writers.map((w) => w.abort())]);
  } finally {
    try {
      await env.BUCKET.delete(tmp);
    } catch {
      // best effort
    }
  }
}

function notAvailable(id: string, blocked: boolean): Response {
  return tagOutcome(err(404, `${id} is not available: ${blocked ? 'blocked' : 'in cooldown'}`), blocked ? 'blocked' : 'cooldown');
}

async function handleTarball(
  env: Env,
  deps: Deps,
  rec: Rec,
  rc: RequestCtx,
  name: string,
  file: string,
): Promise<Response> {
  const { ctx, now } = rec;
  const basename = name.split('/').pop()!;
  if (!file.startsWith(`${basename}-`) || !file.endsWith('.tgz')) return err(404, 'not found');
  const version = file.slice(basename.length + 1, -'.tgz'.length);
  if (!version) return err(404, 'not found');
  const ref: PackageRef = { eco: 'npm', name, version };
  const id = formatPackageId(ref);

  let full: Packument | null = null;
  const loaded = await loadDecision(env, deps, rc, 'npm', name, { version, needStored: true });
  let state: VersionState | null = loaded.state;
  if (!state) {
    const r = await fetchDoc(env, deps, rec, name, false);
    if (!r.ok) return r.res;
    full = r.doc;
    if (!full.versions?.[version]) return err(404, `${id} not found`);
    // As in the go handler: a just-pinned version is neither stored nor OSV-checked. Saves a D1 read.
    const pin = (await pinPublishTimes(env, 'npm', name, publishTimes(full), now)).get(version);
    state = pin ? { ...pin, storedAt: null, osvCheckedAt: null } : null;
  }

  const d = loaded.decide(version, state);
  if (d !== 'allow') return notAvailable(id, d === 'blocked');

  const serve = () => ctx.waitUntil(logServe(env, rc.projectId, ref, now).catch(() => console.warn(`serve log failed ${id}`)));
  const key = `npm/tar/${name}/${file}`;
  // Only a verified copy (stored_at set) is served from R2; anything else goes upstream again.
  const obj = state?.storedAt ? await storedObject(env, key) : null;
  if (obj) {
    serve();
    return tarballResponse(obj.body);
  }

  if (!state?.osvCheckedAt && (await osvMalicious(env, deps, ref, now))) return notAvailable(id, true);

  if (!full) {
    const r = await fetchDoc(env, deps, rec, name, false);
    if (!r.ok) return r.res;
    full = r.doc;
  }
  const dist = full.versions?.[version]?.dist;
  const tarballUrl: unknown = dist?.tarball;
  if (typeof tarballUrl !== 'string') return err(404, `${id} not found`);
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(tarballUrl);
  } catch {
    return err(404, 'unexpected tarball host');
  }
  if (parsedUrl.protocol !== 'https:' || parsedUrl.host !== UPSTREAM_HOST) return err(404, 'unexpected tarball host');

  let res: Response;
  try {
    res = await fetchHeaders(deps, tarballUrl);
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
    res = await fetchHeaders(deps, `${REGISTRY}${path}`, { method: 'POST', headers, body: await req.arrayBuffer() });
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
  const rec: Rec = { ctx, now: deps.now() };
  const res =
    parsed.file === null
      ? await handleMetadata(req, env, deps, rec, rc, parsed.name)
      : await handleTarball(env, deps, rec, rc, parsed.name, parsed.file);
  const outcome = outcomeOf(res);
  if (outcome) recordRequest(env, ctx, rc.projectId, 'npm', parsed.file === null ? 'metadata' : 'download', outcome, rec.now);
  return res;
}
