// Cloudflare Access gate for /dashboard*. Every failure returns null (deny); callers answer 403
// with no detail. Only RS256 tokens signed by a key from the team's JWKS are accepted.
import type { Deps, Env } from '../types';

const LEEWAY_S = 60;
/** Minimum spacing between unknown-kid refetches per team domain, so forged kids can't cause a fetch storm. */
const REFETCH_MIN_MS = 60_000;
const HOST_RE = /^[a-z0-9.-]+$/i;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

interface JwksEntry {
  keys: Map<string, CryptoKey>;
  /** When the last fetch attempt (successful or not) started, in ms; gates refetches. */
  fetchedAt: number;
}
const jwksCache = new Map<string, JwksEntry>();

export interface AccessConfig {
  teamDomain: string;
  aud: string;
}

/** The dashboard is enabled only when both vars are set and the team domain looks like a hostname. */
export function accessConfig(env: Env): AccessConfig | null {
  const teamDomain = env.ACCESS_TEAM_DOMAIN;
  const aud = env.ACCESS_AUD;
  if (!teamDomain || !aud) return null;
  if (!HOST_RE.test(teamDomain) || teamDomain.length > 253) return null;
  return { teamDomain, aud };
}

function b64urlDecode(s: string): Uint8Array | null {
  if (!B64URL_RE.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function decodeJsonObject(s: string): Record<string, unknown> | null {
  const bytes = b64urlDecode(s);
  if (!bytes) return null;
  try {
    const v: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function fetchJwks(teamDomain: string, deps: Deps): Promise<Map<string, CryptoKey> | null> {
  try {
    const res = await deps.fetch(`https://${teamDomain}/cdn-cgi/access/certs`, {
      signal: AbortSignal.timeout(deps.timeoutMs ?? 10_000),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { keys?: unknown };
    if (!Array.isArray(body.keys)) return null;
    const keys = new Map<string, CryptoKey>();
    for (const k of body.keys as Record<string, unknown>[]) {
      if (!k || typeof k !== 'object' || k.kty !== 'RSA') continue;
      if (typeof k.kid !== 'string' || k.kid === '') continue;
      if (k.alg !== undefined && k.alg !== 'RS256') continue;
      if (k.use !== undefined && k.use !== 'sig') continue;
      try {
        const key = await crypto.subtle.importKey(
          'jwk',
          { kty: 'RSA', n: k.n as string, e: k.e as string },
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          false,
          ['verify'],
        );
        keys.set(k.kid, key);
      } catch {
        // Malformed key: skip it.
      }
    }
    return keys;
  } catch {
    return null;
  }
}

/** Finds the key for `kid`, fetching the JWKS on a cold cache, or refetching at most once (rate-limited) on an unknown kid. */
async function keyFor(teamDomain: string, kid: string, deps: Deps): Promise<CryptoKey | null> {
  const nowMs = deps.now().getTime();
  let entry = jwksCache.get(teamDomain);
  if (!entry) {
    const keys = await fetchJwks(teamDomain, deps);
    if (!keys) return null;
    entry = { keys, fetchedAt: nowMs };
    jwksCache.set(teamDomain, entry);
    return entry.keys.get(kid) ?? null;
  }
  const hit = entry.keys.get(kid);
  if (hit) return hit;
  if (nowMs - entry.fetchedAt < REFETCH_MIN_MS) return null;
  entry.fetchedAt = nowMs;
  const keys = await fetchJwks(teamDomain, deps);
  if (!keys) return null; // keep the old keys; the attempt still counts toward the rate limit
  entry.keys = keys;
  return keys.get(kid) ?? null;
}

function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

/** Verifies the Cf-Access-Jwt-Assertion header. Null means deny. */
export async function verifyAccess(req: Request, env: Env, deps: Deps): Promise<{ email: string | null } | null> {
  try {
    const cfg = accessConfig(env);
    if (!cfg) return null;
    const token = req.headers.get('Cf-Access-Jwt-Assertion');
    if (!token) return null;

    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, s] = parts as [string, string, string];
    const header = decodeJsonObject(h);
    const payload = decodeJsonObject(p);
    const sig = b64urlDecode(s);
    if (!header || !payload || !sig || sig.length === 0) return null;

    if (header.alg !== 'RS256') return null;
    if (typeof header.kid !== 'string' || header.kid === '') return null;
    if ('crit' in header) return null;

    // Claims first (cheap, and avoids JWKS fetches for junk).
    const now = deps.now().getTime() / 1000;
    if (!isFiniteNumber(payload.exp) || now > payload.exp + LEEWAY_S) return null;
    if (payload.nbf !== undefined && (!isFiniteNumber(payload.nbf) || payload.nbf > now + LEEWAY_S)) return null;
    if (payload.iss !== `https://${cfg.teamDomain}`) return null;
    const aud = payload.aud;
    const audOk = typeof aud === 'string'
      ? aud === cfg.aud
      : Array.isArray(aud) && aud.some((a) => a === cfg.aud);
    if (!audOk) return null;

    const key = await keyFor(cfg.teamDomain, header.kid, deps);
    if (!key) return null;
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, new TextEncoder().encode(`${h}.${p}`));
    if (!ok) return null;

    return { email: typeof payload.email === 'string' ? payload.email : null };
  } catch {
    return null;
  }
}
