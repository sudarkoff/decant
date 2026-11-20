import { TtlCache } from './cache';
import type { Env } from './types';

export type AuthCtx = { kind: 'operator' } | { kind: 'read' | 'ci' | 'sync'; projectId: string };

/** Per-request context handed to the npm/go handlers. base = origin + prefix, e.g. https://h/r/pr-12 */
export interface RequestCtx {
  projectId: string;
  ref: string | null;
  base: string;
}

function b64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function newToken(kind: 'read' | 'ci' | 'sync' | 'op'): string {
  return `dk_${kind}_${b64url(crypto.getRandomValues(new Uint8Array(32)))}`;
}

export async function hashToken(t: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Constant-time for equal-length strings; no early exit. */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function extractToken(req: Request): string | null {
  const h = req.headers.get('authorization');
  if (!h) return null;
  const m = /^(Bearer|Basic)\s+(\S+)\s*$/i.exec(h);
  if (!m) return null;
  if (m[1]!.toLowerCase() === 'bearer') return m[2]!;
  try {
    const decoded = atob(m[2]!);
    const i = decoded.indexOf(':');
    return i < 0 ? null : decoded.slice(i + 1);
  } catch {
    return null;
  }
}

/**
 * Token rows found in D1, cached per isolate for TOKEN_TTL_MS: a deleted (revoked) token stops working
 * within that bound. A token not found is never cached, so a new token works at once.
 */
export const TOKEN_TTL_MS = 60_000;
const tokens = new TtlCache<AuthCtx>(1_000);

export function clearAuthCache(): void {
  tokens.clear();
}

export async function authenticate(req: Request, env: Env, nowMs: number = Date.now()): Promise<AuthCtx | null> {
  const token = extractToken(req);
  if (!token) return null;
  const hash = await hashToken(token);
  // Tolerate a pasted secret with stray whitespace or uppercase hex. An empty hash never authenticates.
  const op = (env.OPERATOR_TOKEN_HASH ?? '').trim().toLowerCase();
  if (op !== '' && constantTimeEqual(hash, op)) return { kind: 'operator' };
  const cached = tokens.get(hash, nowMs);
  if (cached) return cached;
  const row = await env.DB.prepare('SELECT project_id, kind FROM tokens WHERE hash = ?')
    .bind(hash)
    .first<{ project_id: string; kind: 'read' | 'ci' | 'sync' }>();
  if (!row) return null;
  const auth: AuthCtx = { kind: row.kind, projectId: row.project_id };
  tokens.set(hash, auth, nowMs, TOKEN_TTL_MS);
  return auth;
}
