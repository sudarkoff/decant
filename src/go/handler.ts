import type { RequestCtx } from '../auth';
import { text } from '../http';
import type { Decision } from '../policy/decide';
import { loadDecision, type VersionState } from '../policy/decider';
import { osvMalicious, storedObject } from '../policy/first-serve';
import { logServe, markStored, pinnedFrom, pinPublishTimes, selectPinnedStmt, type PinnedTime, type VersionRow } from '../policy/store';
import { compareVersions, isPrerelease, parseVersion } from '../semver';
import { notePackageLatest, outcomeOf, recordRequest, tagOutcome } from '../stats/record';
import { pump, readUpTo } from '../streams';
import { formatPackageId, type Deps, type Env, type PackageRef } from '../types';
import { cachedFetch, fetchHeaders } from '../upstream';
import { escapeModulePath, unescapeModulePath } from './escape';

const PROXY = 'https://proxy.golang.org';
const UPSTREAM_HOST = 'proxy.golang.org';
const MAX_INFO_FETCHES = 10; // lazy .info fetches per list request
const MAX_BUFFER = 32 * 1024 * 1024; // cap for zips with no content-length
const NO_STORE = { 'cache-control': 'no-store' };
// Escaped module path: lowercase, digits, -._~ and '!' escapes; no empty, '.' or '..' elements.
const ESCAPED_RE = /^[a-z0-9._~!-]+(?:\/[a-z0-9._~!-]+)*$/;

function err(status: number, message: string): Response {
  if (status >= 500) console.error(`decant: go ${status}: ${message}`);
  return text(message, status, NO_STORE);
}

const unavailable = () => err(502, 'upstream unavailable and nothing cached');

/** A module, escaped (for keys and upstream URLs) and unescaped (for policy, store and OSV). */
interface Mod {
  esc: string;
  name: string;
}

type Route =
  | { kind: 'list'; mod: Mod }
  | { kind: 'latest'; mod: Mod }
  | { kind: 'file'; mod: Mod; escVer: string; version: string; ext: 'info' | 'mod' | 'zip' };

function parseMod(esc: string): Mod | null {
  if (!ESCAPED_RE.test(esc) || esc.split('/').some((s) => s === '.' || s === '..')) return null;
  const name = unescapeModulePath(esc);
  return name === null ? null : { esc, name };
}

function parsePath(path: string): Route | null {
  if (!path.startsWith('/')) return null;
  // The go client percent-encodes the '!' of case-escaped paths (%21). Accept that one escape; reject any other.
  const p = path.slice(1).replace(/%21/gi, '!');
  if (p.includes('%')) return null;
  if (p.endsWith('/@latest')) {
    const mod = parseMod(p.slice(0, -'/@latest'.length));
    return mod && { kind: 'latest', mod };
  }
  const at = p.lastIndexOf('/@v/');
  if (at < 0) return null;
  const mod = parseMod(p.slice(0, at));
  if (!mod) return null;
  const file = p.slice(at + '/@v/'.length);
  if (file === 'list') return { kind: 'list', mod };
  const m = /^(.+)\.(info|mod|zip)$/.exec(file);
  if (!m) return null;
  const escVer = m[1]!;
  const version = unescapeModulePath(escVer);
  if (version === null || version.includes('/') || !parseVersion(version, 'go')) return null;
  return { kind: 'file', mod, escVer, version, ext: m[2] as 'info' | 'mod' | 'zip' };
}

const fileKey = (mod: Mod, escVer: string, ext: string) => `go/${mod.esc}/@v/${escVer}.${ext}`;
const fileUrl = (mod: Mod, escVer: string, ext: string) => `${PROXY}/${mod.esc}/@v/${escVer}.${ext}`;

/** Version and Time of a .info document, or null if malformed. */
function parseInfo(body: ArrayBuffer): { version: string; time: Date } | null {
  try {
    const o = JSON.parse(new TextDecoder().decode(body)) as { Version?: unknown; Time?: unknown };
    if (typeof o.Version !== 'string' || typeof o.Time !== 'string') return null;
    const time = new Date(o.Time);
    return Number.isNaN(time.getTime()) ? null : { version: o.Version, time };
  } catch {
    return null;
  }
}

function fetchInfo(env: Env, deps: Deps, mod: Mod, version: string) {
  const escVer = escapeModulePath(version);
  return cachedFetch(env, deps, { key: fileKey(mod, escVer, 'info'), url: fileUrl(mod, escVer, 'info'), immutable: true });
}

/** Fetches .info for `version` and pins its Time. Returns the pin, or null if unavailable/malformed. */
async function pinFromInfo(env: Env, deps: Deps, mod: Mod, version: string): Promise<PinnedTime | null> {
  const r = await fetchInfo(env, deps, mod, version);
  if (r.status !== 'ok') return null;
  const i = parseInfo(r.body);
  if (!i || i.version !== version) return null;
  const pinned = await pinPublishTimes(env, 'go', mod.name, new Map([[version, i.time]]), deps.now());
  return pinned.get(version) ?? null;
}

type ListResult = { ok: true; allowed: string[]; stale: boolean } | { ok: false; res: Response };

/** Upstream list filtered to allowed versions, in upstream order. */
async function allowedList(env: Env, deps: Deps, rc: RequestCtx, mod: Mod): Promise<ListResult> {
  const r = await cachedFetch(env, deps, { key: `go/${mod.esc}/@v/list.raw`, url: `${PROXY}/${mod.esc}/@v/list` });
  if (r.status === 'not-found') return { ok: false, res: err(404, `${mod.name} not found`) };
  if (r.status === 'unavailable') return { ok: false, res: unavailable() };
  const seen = new Set<string>();
  const versions: string[] = [];
  for (const line of new TextDecoder().decode(r.body).split('\n')) {
    const v = line.trim();
    if (v && !seen.has(v) && parseVersion(v, 'go')) {
      seen.add(v);
      versions.push(v);
    }
  }

  // Pinned times are read in the same round trip as the decision inputs.
  const extra = versions.length > 0 ? selectPinnedStmt(env, 'go', mod.name, versions) : undefined;
  const loaded = await loadDecision<VersionRow>(env, deps, rc, 'go', mod.name, { extra });
  const pinned = pinnedFrom(loaded.extra?.results ?? [], versions);
  const unpinned = versions
    .filter((v) => !pinned.has(v))
    .sort((a, b) => compareVersions(b, a, 'go'))
    .slice(0, MAX_INFO_FETCHES);
  const pins = await Promise.all(unpinned.map((v) => pinFromInfo(env, deps, mod, v)));
  unpinned.forEach((v, i) => {
    const p = pins[i];
    if (p) pinned.set(v, p);
  });

  return { ok: true, allowed: versions.filter((v) => loaded.decide(v, pinned.get(v)) === 'allow'), stale: r.stale };
}

function staleHeader(stale: boolean): Record<string, string> {
  return stale ? { 'x-decant-stale': '1' } : {};
}

async function handleList(env: Env, deps: Deps, rc: RequestCtx, mod: Mod): Promise<Response> {
  const r = await allowedList(env, deps, rc, mod);
  if (!r.ok) return r.res;
  const body = r.allowed.map((v) => `${v}\n`).join('');
  return text(body, 200, { ...NO_STORE, ...staleHeader(r.stale) });
}

function infoResponse(body: ArrayBuffer, stale = false): Response {
  return new Response(body, { headers: { 'content-type': 'application/json', ...NO_STORE, ...staleHeader(stale) } });
}

async function handleLatest(
  env: Env,
  deps: Deps,
  ctx: ExecutionContext,
  now: Date,
  rc: RequestCtx,
  mod: Mod,
): Promise<Response> {
  const up = await cachedFetch(env, deps, { key: `go/${mod.esc}/@latest.raw`, url: `${PROXY}/${mod.esc}/@latest` });
  if (up.status === 'ok') {
    const i = parseInfo(up.body);
    if (i && parseVersion(i.version, 'go')) {
      if (up.fresh) notePackageLatest(env, ctx, 'go', mod.name, i.version, i.time.toISOString(), now);
      // Pinning here also catches an upstream time change for an already-pinned version.
      const extra = selectPinnedStmt(env, 'go', mod.name, [i.version]);
      const loaded = await loadDecision<VersionRow>(env, deps, rc, 'go', mod.name, { extra });
      const times = new Map([[i.version, i.time]]);
      const pin = (await pinPublishTimes(env, 'go', mod.name, times, now, loaded.extra?.results ?? [])).get(i.version);
      if (loaded.decide(i.version, pin) === 'allow') return infoResponse(up.body, up.stale);
    }
  }

  const list = await allowedList(env, deps, rc, mod);
  if (!list.ok) return list.res;
  const best = list.allowed
    .filter((v) => !isPrerelease(v, 'go'))
    .sort((a, b) => compareVersions(b, a, 'go'))[0];
  if (!best) return err(404, `${mod.name}: no allowed version`);
  const r = await fetchInfo(env, deps, mod, best);
  if (r.status === 'not-found') return err(404, `${mod.name}@${best} not found`);
  if (r.status === 'unavailable') return unavailable();
  return infoResponse(r.body, list.stale);
}

function notAvailable(id: string, d: Decision): Response {
  const blocked = d === 'blocked';
  return tagOutcome(err(404, `${id} is not available: ${blocked ? 'blocked' : 'in cooldown'}`), blocked ? 'blocked' : 'cooldown');
}

/**
 * Streams to a temp key, then copies to `key` and marks the version stored. No digest check:
 * the go client verifies zips against sumdb. Readers serve `key` only once stored_at is set.
 */
async function storeZip(
  env: Env,
  stream: ReadableStream<Uint8Array>,
  length: number | null,
  key: string,
  ref: PackageRef,
  now: Date,
): Promise<void> {
  const id = formatPackageId(ref);
  const tmp = `go/tmp/${crypto.randomUUID()}`;
  const reader = stream.getReader();
  const writers: WritableStreamDefaultWriter<Uint8Array>[] = [];
  try {
    if (length === null) {
      const buf = await readUpTo(reader, MAX_BUFFER);
      if (buf === null) {
        console.warn(`zip over 32 MB with no content-length, not stored ${id}`);
        return;
      }
      await env.BUCKET.put(tmp, buf);
    } else {
      const fl = new FixedLengthStream(length);
      writers.push(fl.writable.getWriter());
      await Promise.all([pump(reader, writers), env.BUCKET.put(tmp, fl.readable)]);
    }
    // R2 has no rename: copy the complete temp object to the final key.
    const obj = await env.BUCKET.get(tmp);
    if (!obj) throw new Error('temp object missing');
    await env.BUCKET.put(key, obj.body);
    await markStored(env, ref, now);
  } catch {
    console.error(`zip store failed ${id}`);
    await Promise.allSettled([reader.cancel(), ...writers.map((w) => w.abort())]);
  } finally {
    try {
      await env.BUCKET.delete(tmp);
    } catch {
      // best effort
    }
  }
}

function zipResponse(body: ReadableStream): Response {
  return new Response(body, { headers: { 'content-type': 'application/zip', ...NO_STORE } });
}

async function handleFile(
  env: Env,
  deps: Deps,
  ctx: ExecutionContext,
  now: Date,
  rc: RequestCtx,
  route: Extract<Route, { kind: 'file' }>,
): Promise<Response> {
  const { mod, escVer, version, ext } = route;
  const ref: PackageRef = { eco: 'go', name: mod.name, version };
  const id = `${mod.name}@${version}`;

  const loaded = await loadDecision(env, deps, rc, 'go', mod.name, { version, needStored: ext === 'zip' });
  let state: VersionState | null = loaded.state;
  if (!state) {
    const r = await fetchInfo(env, deps, mod, version);
    if (r.status === 'not-found') return err(404, `${id} not found`);
    if (r.status === 'unavailable') return unavailable();
    const i = parseInfo(r.body);
    if (!i || i.version !== version) return err(502, 'invalid upstream .info');
    // The pin is the state of a version just seen: nothing stored or OSV-checked yet (if a concurrent
    // request did either, redoing it is harmless). Saves a D1 read per cold request.
    const pin = (await pinPublishTimes(env, 'go', mod.name, new Map([[version, i.time]]), now)).get(version);
    state = pin ? { ...pin, storedAt: null, osvCheckedAt: null } : null;
  }

  const d = loaded.decide(version, state);
  if (d !== 'allow') return notAvailable(id, d);

  if (ext !== 'zip') {
    const r = await cachedFetch(env, deps, { key: fileKey(mod, escVer, ext), url: fileUrl(mod, escVer, ext), immutable: true });
    if (r.status === 'not-found') return err(404, `${id} not found`);
    if (r.status === 'unavailable') return unavailable();
    if (ext === 'info') return infoResponse(r.body);
    return new Response(r.body, { headers: { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE } });
  }

  const serve = () =>
    ctx.waitUntil(logServe(env, rc.projectId, ref, now).catch(() => console.warn(`serve log failed ${formatPackageId(ref)}`)));
  const key = fileKey(mod, escVer, 'zip');
  const obj = state?.storedAt ? await storedObject(env, key) : null;
  if (obj) {
    serve();
    return zipResponse(obj.body);
  }

  if (!state?.osvCheckedAt && (await osvMalicious(env, deps, ref, now))) return notAvailable(id, 'blocked');

  const url = fileUrl(mod, escVer, 'zip');
  // Built here from a validated path, but assert the host anyway before fetching.
  if (new URL(url).host !== UPSTREAM_HOST) return err(404, 'unexpected upstream host');
  let res: Response;
  try {
    res = await fetchHeaders(deps, url);
  } catch {
    return unavailable();
  }
  if (res.status === 404 || res.status === 410) return err(404, `${id} not found`);
  if (res.status !== 200 || !res.body) return unavailable();

  const lenHeader = res.headers.get('content-length');
  const length = lenHeader !== null && /^\d+$/.test(lenHeader) ? Number(lenHeader) : null;
  const [toClient, toStore] = res.body.tee();
  ctx.waitUntil(storeZip(env, toStore, length, key, ref, now));
  serve();
  return zipResponse(toClient);
}

export async function handleGo(
  req: Request,
  env: Env,
  deps: Deps,
  ctx: ExecutionContext,
  rc: RequestCtx,
  path: string,
): Promise<Response> {
  if (req.method !== 'GET' && req.method !== 'HEAD') return text('method not allowed', 405, { ...NO_STORE, allow: 'GET, HEAD' });
  // Decant does not proxy sumdb; the go client falls back to sum.golang.org directly.
  if (path === '/sumdb' || path.startsWith('/sumdb/')) return err(404, 'not found');
  const route = parsePath(path);
  if (!route) return err(404, 'not found');
  const now = deps.now();
  let res: Response;
  switch (route.kind) {
    case 'list':
      res = await handleList(env, deps, rc, route.mod);
      break;
    case 'latest':
      res = await handleLatest(env, deps, ctx, now, rc, route.mod);
      break;
    case 'file':
      res = await handleFile(env, deps, ctx, now, rc, route);
      break;
  }
  // list, .info and @latest are metadata; .mod and .zip are downloads.
  const kind = route.kind === 'file' && route.ext !== 'info' ? 'download' : 'metadata';
  const outcome = outcomeOf(res);
  if (outcome) recordRequest(env, ctx, rc.projectId, 'go', kind, outcome, now);
  return res;
}
